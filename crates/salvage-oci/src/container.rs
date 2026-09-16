use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use salvage_core::lifecycle::{
    CancellationToken, ResourceManager, RunId, StageDeadline, StageExecutionError,
};
use salvage_core::manifest::{AppArtifact, Limits};

use crate::image::ImageIdentity;
use crate::isolation::{NetworkPolicy, ensure_isolated_network};
use crate::runtime::ContainerRuntime;

#[derive(Debug, Clone)]
pub struct ContainerHandle {
    pub id: String,
    pub name: String,
    pub image_id: String,
    pub mapped_ports: BTreeMap<u16, u16>,
}

#[allow(clippy::too_many_arguments)]
pub fn start_app_container(
    runtime: &ContainerRuntime,
    image: &ImageIdentity,
    _app: &AppArtifact,
    run_id: &RunId,
    limits: &Limits,
    pg_socket_dir: Option<&Path>,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<ContainerHandle, StageExecutionError> {
    start_app_container_with_allowlist(
        runtime,
        image,
        _app,
        run_id,
        limits,
        pg_socket_dir,
        &[],
        resources,
        deadline,
        cancel,
    )
}

/// Starts the app container on the per-run default-deny isolated network.
///
/// `allowlist` is validated like manifest `egress_allow` but still denied in
/// O3-3 (reserved for a future proxy). Any policy error fails closed: no
/// container is started and there is no fallback to `bridge`. The network is
/// registered in `resources`, so engine `release_all` removes container +
/// network on both pass and fail paths.
#[allow(clippy::too_many_arguments)]
pub fn start_app_container_with_allowlist(
    runtime: &ContainerRuntime,
    image: &ImageIdentity,
    _app: &AppArtifact,
    run_id: &RunId,
    limits: &Limits,
    pg_socket_dir: Option<&Path>,
    allowlist: &[String],
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<ContainerHandle, StageExecutionError> {
    if cancel.is_cancelled() {
        return Err(StageExecutionError::cancelled(
            cancel.cancellation_signal(),
            "cancelled before container start",
        ));
    }
    if deadline.is_expired() {
        return Err(StageExecutionError::TimedOut);
    }
    let name = format!("salvage-{}", run_id.as_str());
    // Default-deny isolation first (fail-closed): any policy error aborts
    // before `docker run`, never falling back to `bridge`. The network is
    // registered for cleanup, so a later `run` failure still removes it.
    let network = ensure_isolated_network(runtime, run_id, allowlist, resources, deadline, cancel)?;
    let policy = NetworkPolicy::default_deny_with_allowlist(run_id, allowlist)?;
    debug_assert_eq!(policy.network_name(), network.as_str());
    // Best-effort stale cleanup: a previous leaked run with the same run-id
    // would make `docker run --name` fail with a name conflict and leak the
    // new attempt. `rm -f` is idempotent (missing name is success).
    remove_stale_name(runtime, &name, resources, deadline, cancel);
    let cpus = format!("{}", limits.cpu_millicores as f64 / 1000.0);
    let memory = format!("{}m", limits.memory_mib);
    let mut args: Vec<String> = vec![
        "run".to_string(),
        "-d".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        name.clone(),
        "--network".to_string(),
        network,
        "-P".to_string(),
        "--cpus".to_string(),
        cpus,
        "--memory".to_string(),
        memory,
    ];
    if let Some(sock) = pg_socket_dir {
        args.push("-v".to_string());
        args.push(format!("{}:/var/run/salvage:ro", sock.display()));
    }
    args.push(image.image_id.clone());
    let output = run_docker_capture(runtime.bin(), &args, resources, deadline, cancel)?;
    if !output.status_success {
        let combined = format!("{}{}", output.stdout, output.stderr);
        return Err(StageExecutionError::failed(
            "app/crash",
            format!("docker run failed: {}", combined.trim()),
        ));
    }
    let id = output.stdout.trim().to_owned();
    if id.is_empty() {
        return Err(StageExecutionError::failed(
            "app/crash",
            "docker run returned empty container id",
        ));
    }
    let _container_rid = resources.register_container(id.clone(), runtime.bin().to_path_buf());
    spawn_log_tail(runtime, &id, resources);
    let mapped = query_mapped_ports(runtime, &id, resources, deadline, cancel)?;
    Ok(ContainerHandle {
        id,
        name,
        image_id: image.image_id.clone(),
        mapped_ports: mapped,
    })
}

fn remove_stale_name(
    runtime: &ContainerRuntime,
    name: &str,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) {
    // Ignore all outcomes: missing name is the common case, and a failing
    // rm must not mask the subsequent `run` error.
    let _ = run_docker_capture(
        runtime.bin(),
        &["rm".to_string(), "-f".to_string(), name.to_string()],
        resources,
        deadline,
        cancel,
    );
}

fn spawn_log_tail(runtime: &ContainerRuntime, id: &str, resources: &mut ResourceManager) {
    let mut cmd = Command::new(runtime.bin());
    cmd.arg("logs");
    cmd.arg("-f");
    cmd.arg(id);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.process_group(0);
    if let Ok(child) = cmd.spawn() {
        let pid = child.id();
        let pgid = pid;
        let _ = resources.register_process_group(pid, pgid);
        std::mem::forget(child);
    }
}

fn query_mapped_ports(
    runtime: &ContainerRuntime,
    id: &str,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<BTreeMap<u16, u16>, StageExecutionError> {
    let output = run_docker_capture(
        runtime.bin(),
        &["port".to_string(), id.to_string()],
        resources,
        deadline,
        cancel,
    )?;
    if !output.status_success {
        return Ok(BTreeMap::new());
    }
    Ok(parse_docker_port(&output.stdout))
}

pub fn parse_docker_port(text: &str) -> BTreeMap<u16, u16> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(slash) = line.find("/") {
            let container_part = &line[..slash];
            if let Ok(cport) = container_part.trim().parse::<u16>()
                && let Some(arrow) = line.find("->")
            {
                let right = line[arrow + 2..].trim();
                if let Some(colon) = right.rfind(":") {
                    let host_part = right[colon + 1..].trim();
                    let host_digits: String = host_part
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if let Ok(hport) = host_digits.parse::<u16>() {
                        map.insert(cport, hport);
                    }
                }
            }
        }
    }
    map
}

struct DockerOutput {
    status_success: bool,
    stdout: String,
    stderr: String,
}

fn run_docker_capture(
    bin: &Path,
    args: &[String],
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
            format!("failed to spawn docker: {}", e),
        )
    })?;
    let pid = child.id();
    let pgid = pid;
    let _ = resources.register_process_group(pid, pgid);
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::cancelled(
                cancel.cancellation_signal(),
                "docker invocation cancelled",
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
                let mut stdout_buf = Vec::new();
                let mut stderr_buf = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_end(&mut stdout_buf);
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_end(&mut stderr_buf);
                }
                return Ok(DockerOutput {
                    status_success: status.success(),
                    stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
                    stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
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

    #[test]
    fn parses_docker_port_output() {
        let sample = "8080/tcp -> 0.0.0.0:32768\n443/tcp -> 0.0.0.0:32769\n";
        let map = parse_docker_port(sample);
        assert_eq!(map.get(&8080), Some(&32768));
        assert_eq!(map.get(&443), Some(&32769));
    }

    #[test]
    fn parses_ipv6_port_output() {
        let sample = "8080/tcp -> [::]:32768\n";
        let map = parse_docker_port(sample);
        assert_eq!(map.get(&8080), Some(&32768));
    }

    #[test]
    fn empty_port_output_gives_empty_map() {
        assert!(parse_docker_port("").is_empty());
        assert!(parse_docker_port("not-a-port-line\n").is_empty());
    }

    #[test]
    fn start_uses_isolated_network_never_bridge() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        let base =
            std::env::temp_dir().join(format!("salvage-container-net-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let log = base.join("args.log");
        let fake = base.join("docker");
        // Fake `docker`: log args, succeed for network/create/rm/run/port.
        let script = format!(
            "#!/bin/sh\necho \"$*\" >> {}\nif echo \"$*\" | grep -q \"network create\"; then echo deadbeef; exit 0; fi\nif echo \"$*\" | grep -q \"^run \"; then echo abc123def456; exit 0; fi\nexit 0\n",
            log.display()
        );
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rt = ContainerRuntime {
            bin: fake.clone(),
            version: "29.4.1".to_owned(),
            major: 29,
        };
        let app = AppArtifact {
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_owned(),
            repository: None,
            tag: None,
            readiness: salvage_core::manifest::AppReadiness::Tcp {
                host: None,
                port: 8080,
            },
        };
        let image = ImageIdentity {
            declared_digest: app.digest.clone(),
            image_id: "sha256:abc".to_owned(),
            pinned_ref: app.digest.clone(),
        };
        let limits = Limits {
            cpu_millicores: 500,
            memory_mib: 512,
            disk_mib: 5120,
        };
        let run_id = RunId::new("iso-net-test").unwrap();
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mut rm = ResourceManager::new(run_id, root);
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let handle = start_app_container(
            &rt,
            &image,
            &app,
            &RunId::new("iso-net-test").unwrap(),
            &limits,
            None,
            &mut rm,
            &deadline,
            &cancel,
        )
        .expect("fake start must succeed");
        assert_eq!(handle.name, "salvage-iso-net-test");
        let logged = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            logged.contains("--internal"),
            "network create must be --internal, got {logged:?}"
        );
        assert!(
            logged.contains("salvage-net-iso-net-test"),
            "must use per-run network, got {logged:?}"
        );
        assert!(
            !logged.contains("--network bridge"),
            "must never fall back to bridge, got {logged:?}"
        );
        assert!(
            rm.resources()
                .iter()
                .any(|r| r.resource_id == "network:salvage-net-iso-net-test"),
            "network must be registered for cleanup"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn start_with_bad_allowlist_fails_closed_without_run() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        let base =
            std::env::temp_dir().join(format!("salvage-container-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let log = base.join("args.log");
        let fake = base.join("docker");
        let script = format!("#!/bin/sh\necho \"$*\" >> {}\nexit 0\n", log.display());
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rt = ContainerRuntime {
            bin: fake,
            version: "29.4.1".to_owned(),
            major: 29,
        };
        let app = AppArtifact {
            digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_owned(),
            repository: None,
            tag: None,
            readiness: salvage_core::manifest::AppReadiness::Tcp {
                host: None,
                port: 8080,
            },
        };
        let image = ImageIdentity {
            declared_digest: app.digest.clone(),
            image_id: "sha256:abc".to_owned(),
            pinned_ref: app.digest.clone(),
        };
        let limits = Limits {
            cpu_millicores: 500,
            memory_mib: 512,
            disk_mib: 5120,
        };
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mut rm = ResourceManager::new(RunId::new("iso-bad-test").unwrap(), root);
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = start_app_container_with_allowlist(
            &rt,
            &image,
            &app,
            &RunId::new("iso-bad-test").unwrap(),
            &limits,
            None,
            &["https://api.example.com".to_owned()],
            &mut rm,
            &deadline,
            &cancel,
        )
        .expect_err("bad allowlist must fail closed");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, "isolation/policy-failed"),
            other => panic!("unexpected {other:?}"),
        }
        let logged = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            !logged.contains(" --run ") && !logged.contains("\nrun "),
            "failed policy must not attempt `docker run`, got {logged:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
