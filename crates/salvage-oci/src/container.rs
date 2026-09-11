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
        "bridge".to_string(),
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
}
