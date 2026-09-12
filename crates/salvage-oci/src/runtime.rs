use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use salvage_core::lifecycle::StageExecutionError;

pub const MIN_DOCKER_MAJOR: u32 = 24;

#[derive(Debug, Clone)]
pub struct ContainerRuntime {
    pub bin: PathBuf,
    pub version: String,
    pub major: u32,
}

impl ContainerRuntime {
    pub fn discover() -> Result<Self, StageExecutionError> {
        let bin = resolve_docker_bin()?;
        let version = query_server_version(&bin)?;
        let major = parse_major(&version).ok_or_else(|| {
            StageExecutionError::failed(
                "app/unsupported-version",
                format!("unable to parse Docker major version from {:?}", version),
            )
        })?;
        if major < MIN_DOCKER_MAJOR {
            return Err(StageExecutionError::failed(
                "app/unsupported-version",
                format!(
                    "Docker major version {} is below minimum supported {}",
                    major, MIN_DOCKER_MAJOR
                ),
            ));
        }
        Ok(Self {
            bin,
            version,
            major,
        })
    }

    pub fn bin(&self) -> &Path {
        &self.bin
    }
}

fn resolve_docker_bin() -> Result<PathBuf, StageExecutionError> {
    if let Ok(val) = std::env::var("SALVAGE_DOCKER_BIN") {
        let trimmed = val.trim().to_owned();
        if trimmed.is_empty() {
            return Err(StageExecutionError::failed(
                "app/missing-prerequisite",
                "SALVAGE_DOCKER_BIN is set but empty",
            ));
        }
        let path = PathBuf::from(trimmed);
        if !is_executable(&path) {
            return Err(StageExecutionError::failed(
                "app/missing-prerequisite",
                format!(
                    "container runtime override {:?} is not executable",
                    path.display().to_string()
                ),
            ));
        }
        return Ok(path);
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("docker");
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    Err(StageExecutionError::failed(
        "app/missing-prerequisite",
        "missing required container runtime docker in PATH and SALVAGE_DOCKER_BIN is unset",
    ))
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            return meta.permissions().mode() & 0o111 != 0;
        }
        false
    }
    #[cfg(not(unix))]
    {
        return true;
    }
}

fn query_server_version(bin: &Path) -> Result<String, StageExecutionError> {
    let mut cmd = Command::new(bin);
    cmd.arg("info");
    cmd.arg("--format");
    cmd.arg("{{.ServerVersion}}");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| {
        StageExecutionError::failed(
            "app/missing-prerequisite",
            format!("failed to spawn docker info: {}", e),
        )
    })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait().map_err(|e| {
            StageExecutionError::failed(
                "app/missing-prerequisite",
                format!("failed waiting on docker info: {}", e),
            )
        })? {
            Some(status) => {
                let output = child.wait_with_output().map_err(|e| {
                    StageExecutionError::failed(
                        "app/missing-prerequisite",
                        format!("failed reading docker info output: {}", e),
                    )
                })?;
                if !status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(StageExecutionError::failed(
                        "app/missing-prerequisite",
                        format!("docker info failed: {}", stderr.trim()),
                    ));
                }
                let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if version.is_empty() {
                    return Err(StageExecutionError::failed(
                        "app/missing-prerequisite",
                        "docker info returned empty server version",
                    ));
                }
                return Ok(version);
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(StageExecutionError::failed(
                        "app/missing-prerequisite",
                        "docker info timed out after 5s",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn parse_major(version: &str) -> Option<u32> {
    for token in version.split(|c: char| !c.is_ascii_digit()) {
        if token.is_empty() {
            continue;
        }
        if let Ok(num) = token.parse::<u32>()
            && (1..=200).contains(&num)
        {
            return Some(num);
        }
        break;
    }
    let first = version.split('.').next().unwrap_or("");
    let digits: String = first.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn make_fake_docker(dir: &Path, version: &str) -> PathBuf {
        let bin = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
echo {}
exit 0
"#,
            version
        );
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[test]
    fn discover_with_stub_bin() {
        let _guard = env_lock();
        let base = std::env::temp_dir().join(format!("salvage-runtime-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = make_fake_docker(&base, "29.4.1");
        let prev = std::env::var("SALVAGE_DOCKER_BIN").ok();
        unsafe {
            std::env::set_var("SALVAGE_DOCKER_BIN", &fake);
        }
        let rt = ContainerRuntime::discover().expect("stub discover must succeed");
        assert_eq!(rt.major, 29);
        assert!(rt.version.contains("29.4.1"));
        match prev {
            Some(v) => unsafe { std::env::set_var("SALVAGE_DOCKER_BIN", v) },
            None => unsafe { std::env::remove_var("SALVAGE_DOCKER_BIN") },
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rejects_old_version() {
        let _guard = env_lock();
        let base = std::env::temp_dir().join(format!("salvage-runtime-old-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = make_fake_docker(&base, "20.10.7");
        let prev = std::env::var("SALVAGE_DOCKER_BIN").ok();
        unsafe {
            std::env::set_var("SALVAGE_DOCKER_BIN", &fake);
        }
        let err = ContainerRuntime::discover().expect_err("old version must fail");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, "app/unsupported-version"),
            other => panic!("unexpected {:?}", other),
        }
        match prev {
            Some(v) => unsafe { std::env::set_var("SALVAGE_DOCKER_BIN", v) },
            None => unsafe { std::env::remove_var("SALVAGE_DOCKER_BIN") },
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_binary_reports_prerequisite() {
        let _guard = env_lock();
        let prev = std::env::var("SALVAGE_DOCKER_BIN").ok();
        unsafe {
            std::env::set_var("SALVAGE_DOCKER_BIN", "/nonexistent-salvage-docker-bin-xyz");
        }
        let err = ContainerRuntime::discover().expect_err("missing must fail");
        match err {
            StageExecutionError::Failed { code, .. } => {
                assert_eq!(code, "app/missing-prerequisite")
            }
            other => panic!("unexpected {:?}", other),
        }
        match prev {
            Some(v) => unsafe { std::env::set_var("SALVAGE_DOCKER_BIN", v) },
            None => unsafe { std::env::remove_var("SALVAGE_DOCKER_BIN") },
        }
    }
}
