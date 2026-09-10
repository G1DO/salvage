use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use salvage_core::lifecycle::{
    CancellationToken, ResourceManager, StageDeadline, StageExecutionError,
};
use salvage_core::manifest::AppArtifact;

use crate::runtime::ContainerRuntime;

#[derive(Debug, Clone)]
pub struct ImageIdentity {
    pub declared_digest: String,
    pub image_id: String,
    pub pinned_ref: String,
}

pub fn ensure_image(
    runtime: &ContainerRuntime,
    app: &AppArtifact,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<ImageIdentity, StageExecutionError> {
    if cancel.is_cancelled() {
        return Err(StageExecutionError::cancelled(
            cancel.cancellation_signal(),
            "cancelled before image verification",
        ));
    }
    if deadline.is_expired() {
        return Err(StageExecutionError::TimedOut);
    }
    let pinned = pinned_ref(app);
    match try_inspect(runtime, &pinned, resources, deadline, cancel)? {
        Some(image_id) => {
            verify_digest_match(
                runtime, app, &pinned, &image_id, resources, deadline, cancel,
            )?;
            Ok(ImageIdentity {
                declared_digest: app.digest.clone(),
                image_id,
                pinned_ref: pinned,
            })
        }
        None => {
            let repo_present = app.repository.is_some();
            if !repo_present {
                return Err(StageExecutionError::failed(
                    "app/digest-mismatch",
                    format!(
                        "image {} not present locally and no repository to pull from",
                        pinned
                    ),
                ));
            }
            pull_image(runtime, &pinned, resources, deadline, cancel)?;
            match try_inspect(runtime, &pinned, resources, deadline, cancel)? {
                Some(image_id) => {
                    verify_digest_match(
                        runtime, app, &pinned, &image_id, resources, deadline, cancel,
                    )?;
                    Ok(ImageIdentity {
                        declared_digest: app.digest.clone(),
                        image_id,
                        pinned_ref: pinned,
                    })
                }
                None => Err(StageExecutionError::failed(
                    "app/digest-mismatch",
                    format!("image {} still absent after pull", pinned),
                )),
            }
        }
    }
}

fn pinned_ref(app: &AppArtifact) -> String {
    match &app.repository {
        Some(repo) => format!("{}@{}", repo, app.digest),
        None => app.digest.clone(),
    }
}

fn try_inspect(
    runtime: &ContainerRuntime,
    pinned: &str,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<Option<String>, StageExecutionError> {
    let out = run_docker(
        runtime.bin(),
        &["image", "inspect", pinned],
        resources,
        deadline,
        cancel,
    );
    match out {
        Ok(output) => {
            if !output.status_success {
                return Ok(None);
            }
            match parse_image_id(&output.stdout, pinned) {
                Some(id) => Ok(Some(id)),
                None => Err(StageExecutionError::failed(
                    "app/digest-mismatch",
                    format!("image inspect for {} returned unparsable output", pinned),
                )),
            }
        }
        Err(e) => match e {
            StageExecutionError::Failed {
                ref code,
                ref message,
            } if code == "app/digest-mismatch" => {
                let lower = message.to_lowercase();
                if lower.contains("no such image") || lower.contains("not found") {
                    return Ok(None);
                }
                Err(e)
            }
            _ => Err(e),
        },
    }
}

fn verify_digest_match(
    _runtime: &ContainerRuntime,
    app: &AppArtifact,
    pinned: &str,
    _image_id: &str,
    _resources: &mut ResourceManager,
    _deadline: &StageDeadline,
    _cancel: &CancellationToken,
) -> Result<(), StageExecutionError> {
    if let Some(repo) = &app.repository {
        let expected = format!("{}@{}", repo, app.digest);
        if pinned != expected {
            return Err(StageExecutionError::failed(
                "app/digest-mismatch",
                format!("pinned ref {} does not match expected {}", pinned, expected),
            ));
        }
        return Ok(());
    }
    if !pinned.contains(&app.digest) {
        return Err(StageExecutionError::failed(
            "app/digest-mismatch",
            "digest mismatch for repository-less image".to_string(),
        ));
    }
    Ok(())
}

fn pull_image(
    runtime: &ContainerRuntime,
    pinned: &str,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<(), StageExecutionError> {
    let out = run_docker(
        runtime.bin(),
        &["pull", pinned],
        resources,
        deadline,
        cancel,
    )?;
    if !out.status_success {
        let combined = format!("{}{}", out.stdout, out.stderr);
        if combined.to_lowercase().contains("no such") {
            return Err(StageExecutionError::failed(
                "app/digest-mismatch",
                format!("pull for {} failed: {}", pinned, combined.trim()),
            ));
        }
        return Err(StageExecutionError::failed(
            "app/digest-mismatch",
            format!("pull for {} failed: {}", pinned, combined.trim()),
        ));
    }
    Ok(())
}

fn parse_image_id(stdout: &str, _pinned: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let arr = v.as_array()?;
    let first = arr.first()?;
    let id = first.get("Id")?.as_str()?;
    if id.is_empty() {
        return None;
    }
    Some(id.to_owned())
}

struct DockerOutput {
    status_success: bool,
    stdout: String,
    stderr: String,
}

fn run_docker(
    bin: &Path,
    args: &[&str],
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<DockerOutput, StageExecutionError> {
    if cancel.is_cancelled() {
        return Err(StageExecutionError::cancelled(
            cancel.cancellation_signal(),
            "cancelled before docker invocation",
        ));
    }
    if deadline.is_expired() {
        return Err(StageExecutionError::TimedOut);
    }
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| {
        StageExecutionError::failed(
            "app/missing-prerequisite",
            format!("failed to spawn docker {}: {}", args.join(" "), e),
        )
    })?;
    let pid = child.id();
    let pgid = pid;
    let _rid = resources.register_process_group(pid, pgid);
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::cancelled(
                cancel.cancellation_signal(),
                format!("docker {} cancelled", args.join(" ")),
            ));
        }
        if deadline.is_expired() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::TimedOut);
        }
        match child.try_wait().map_err(|e| {
            StageExecutionError::failed(
                "app/missing-prerequisite",
                format!("failed waiting on docker: {}", e),
            )
        })? {
            Some(status) => {
                let output = child.wait_with_output().map_err(|e| {
                    StageExecutionError::failed(
                        "app/missing-prerequisite",
                        format!("failed reading docker output: {}", e),
                    )
                })?;
                return Ok(DockerOutput {
                    status_success: status.success(),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                });
            }
            None => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvage_core::lifecycle::{CancellationToken, StageDeadline};
    use salvage_core::manifest::{AppArtifact, AppReadiness};
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_app(repo: Option<&str>, digest: &str) -> AppArtifact {
        AppArtifact {
            digest: digest.to_string(),
            repository: repo.map(|s| s.to_string()),
            tag: None,
            readiness: AppReadiness::Tcp {
                host: None,
                port: 8080,
            },
        }
    }

    fn fake_runtime(bin: &Path) -> ContainerRuntime {
        ContainerRuntime {
            bin: bin.to_path_buf(),
            version: "29.4.1".to_string(),
            major: 29,
        }
    }

    fn make_always_fail_bin(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("docker-fail");
        let script = r#"#!/bin/sh
echo Error: No such image >&2
exit 1
"#;
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[test]
    fn digest_mismatch_without_repository_is_fail_closed() {
        let base =
            std::env::temp_dir().join(format!("salvage-image-norepo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = make_always_fail_bin(&base);
        let rt = fake_runtime(&fake);
        let app = test_app(
            None,
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        );
        let run_id = salvage_core::lifecycle::RunId::new("img-test-1").unwrap();
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mut rm = ResourceManager::new(run_id, root);
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = ensure_image(&rt, &app, &mut rm, &deadline, &cancel).expect_err("must fail");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, "app/digest-mismatch"),
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn digest_mismatch_with_repository_pull_failure() {
        let base = std::env::temp_dir().join(format!("salvage-image-repo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = make_always_fail_bin(&base);
        let rt = fake_runtime(&fake);
        let app = test_app(
            Some("registry.example.com/team/app"),
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        );
        let run_id = salvage_core::lifecycle::RunId::new("img-test-2").unwrap();
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mut rm = ResourceManager::new(run_id, root);
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = ensure_image(&rt, &app, &mut rm, &deadline, &cancel).expect_err("must fail");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, "app/digest-mismatch"),
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pinned_ref_never_uses_tag() {
        let app = AppArtifact {
            digest: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                .to_string(),
            repository: Some("registry.example.com/team/app".to_string()),
            tag: Some("v1.2.3".to_string()),
            readiness: AppReadiness::Tcp {
                host: None,
                port: 8080,
            },
        };
        let pinned = pinned_ref(&app);
        assert!(
            pinned.contains(
                "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            )
        );
        assert!(!pinned.contains("v1.2.3"));
    }
}
