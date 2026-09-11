use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use salvage_core::lifecycle::{
    CancellationToken, ResourceManager, StageDeadline, StageExecutionError,
};
use salvage_core::manifest::AppArtifact;

use crate::container::ContainerHandle;
use crate::runtime::ContainerRuntime;

pub fn check_compat(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    app: &AppArtifact,
    declared_pg_version: Option<&str>,
    _resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<(), StageExecutionError> {
    let repo_is_postgres = app
        .repository
        .as_deref()
        .map(|r| r.to_lowercase().contains("postgres"))
        .unwrap_or(false);
    if !repo_is_postgres {
        return Ok(());
    }
    let declared = declared_pg_version.unwrap_or("");
    if declared.trim().is_empty() {
        return Ok(());
    }
    let observed = exec_postgres_version(runtime, container, deadline, cancel)?;
    let declared_major = parse_major(declared).ok_or_else(|| {
        StageExecutionError::failed(
            "app/unsupported-version",
            format!("unable to parse declared postgres version {:?}", declared),
        )
    })?;
    let observed_major = parse_major(&observed).ok_or_else(|| {
        StageExecutionError::failed(
            "app/unsupported-version",
            format!("unable to parse container postgres version {:?}", observed),
        )
    })?;
    if declared_major != observed_major {
        return Err(StageExecutionError::failed(
            "app/unsupported-version",
            format!(
                "postgres major mismatch: manifest declares {} but container reports {}",
                declared_major,
                observed.trim(),
            ),
        ));
    }
    Ok(())
}

fn exec_postgres_version(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<String, StageExecutionError> {
    let mut cmd = Command::new(runtime.bin());
    cmd.arg("exec");
    cmd.arg(&container.id);
    cmd.arg("postgres");
    cmd.arg("--version");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| {
        StageExecutionError::failed(
            "app/missing-prerequisite",
            format!("failed to spawn docker exec postgres --version: {}", e),
        )
    })?;
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::cancelled(
                cancel.cancellation_signal(),
                "postgres version check cancelled",
            ));
        }
        if deadline.is_expired() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::TimedOut);
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::failed(
                "app/unsupported-version",
                "postgres --version timed out",
            ));
        }
        match child.try_wait().map_err(|e| {
            StageExecutionError::failed(
                "app/missing-prerequisite",
                format!("failed waiting on postgres --version: {}", e),
            )
        })? {
            Some(status) => {
                let output = child.wait_with_output().map_err(|e| {
                    StageExecutionError::failed(
                        "app/missing-prerequisite",
                        format!("failed reading postgres --version: {}", e),
                    )
                })?;
                if !status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(StageExecutionError::failed(
                        "app/unsupported-version",
                        format!("postgres --version failed: {}", stderr.trim()),
                    ));
                }
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
            None => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

pub fn reverify_post_boot(
    pg_socket_dir: Option<&std::path::Path>,
    dbname: Option<&str>,
    expected_tables: &[String],
    postgres_version: Option<&str>,
    _resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<(), StageExecutionError> {
    let socket = match pg_socket_dir {
        Some(s) => s,
        None => return Ok(()),
    };
    let db = match dbname {
        Some(d) => d,
        None => return Ok(()),
    };
    if cancel.is_cancelled() {
        return Err(StageExecutionError::cancelled(
            cancel.cancellation_signal(),
            "cancelled before post-boot re-verify",
        ));
    }
    if deadline.is_expired() {
        return Err(StageExecutionError::TimedOut);
    }
    let binaries = salvage_postgres::PostgresBinaries::discover(
        postgres_version.map(|s| s.to_owned()).as_deref(),
    )
    .map_err(|e| match e {
        StageExecutionError::Failed { code, message } => StageExecutionError::failed(code, message),
        other => other,
    })?;
    let target = salvage_postgres::EphemeralPostgresTarget {
        socket_dir: socket.to_path_buf(),
        data_dir: socket.to_path_buf(),
        superuser: "postgres".to_owned(),
        binaries,
    };
    let observed = match salvage_postgres::verify_structural_integrity(&target, db, None) {
        Ok(tbls) => tbls,
        Err(StageExecutionError::Failed { message, .. }) => {
            return Err(StageExecutionError::failed("app/incompatible", message));
        }
        Err(other) => return Err(other),
    };
    if observed.is_empty() {
        return Err(StageExecutionError::failed(
            "app/incompatible",
            "post-boot re-verify found no user tables",
        ));
    }
    for exp in expected_tables {
        if !observed.iter().any(|tbl| tbl == exp) {
            return Err(StageExecutionError::failed(
                "app/incompatible",
                "post-boot re-verify missing expected table",
            ));
        }
    }
    Ok(())
}

fn parse_major(version: &str) -> Option<u32> {
    for token in version.split(|c: char| !c.is_ascii_digit()) {
        if token.is_empty() {
            continue;
        }
        if let Ok(num) = token.parse::<u32>()
            && (1..=100).contains(&num)
        {
            return Some(num);
        }
        break;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvage_core::manifest::AppReadiness;

    fn pg_app(repo: &str) -> AppArtifact {
        AppArtifact {
            digest: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                .to_string(),
            repository: Some(repo.to_string()),
            tag: None,
            readiness: AppReadiness::Tcp {
                host: None,
                port: 5432,
            },
        }
    }

    #[test]
    fn skips_non_postgres_images() {
        let app = pg_app("registry.example.com/team/web");
        assert!(
            !app.repository
                .as_deref()
                .unwrap()
                .to_lowercase()
                .contains("postgres")
        );
        assert_eq!(parse_major("16.4"), Some(16));
        assert_eq!(parse_major("postgres (PostgreSQL) 16.4"), Some(16));
    }

    #[test]
    fn detects_major_mismatch_logic() {
        assert_eq!(parse_major("16.4"), Some(16));
        assert_eq!(parse_major("postgres (PostgreSQL) 15.7"), Some(15));
        assert_ne!(parse_major("16.4"), parse_major("15.7"));
    }

    #[test]
    fn parses_various_postgres_versions() {
        assert_eq!(parse_major("postgres (PostgreSQL) 16.4 (Debian)"), Some(16));
        assert_eq!(parse_major("14.22"), Some(14));
        assert_eq!(parse_major(""), None);
    }
}
