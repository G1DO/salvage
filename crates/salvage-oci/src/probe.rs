use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use salvage_core::lifecycle::{CancellationToken, StageDeadline, StageExecutionError};
use salvage_core::manifest::AppReadiness;

use crate::container::ContainerHandle;
use crate::runtime::ContainerRuntime;

pub fn wait_ready(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    readiness: &AppReadiness,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<(), StageExecutionError> {
    loop {
        if cancel.is_cancelled() {
            return Err(StageExecutionError::cancelled(
                cancel.cancellation_signal(),
                "cancelled while waiting for app readiness",
            ));
        }
        if deadline.is_expired() {
            return Err(StageExecutionError::TimedOut);
        }
        if let Some(crash) = check_crash(runtime, container, deadline, cancel)? {
            return Err(crash);
        }
        let ready = match readiness {
            AppReadiness::Tcp { host, port } => {
                let (h, hp) = resolve_target(container, host.as_deref(), *port);
                tcp_probe_once(&h, hp)
            }
            AppReadiness::Http { host, port, path } => {
                let (h, hp) = resolve_target(container, host.as_deref(), *port);
                let p = path.as_deref().unwrap_or("/");
                http_probe_once(&h, hp, p)
            }
            AppReadiness::Exec { command } => {
                exec_probe_once(runtime, container, command, deadline, cancel)?
            }
        };
        if ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn resolve_target(container: &ContainerHandle, host: Option<&str>, port: i64) -> (String, u16) {
    let h = host.unwrap_or("127.0.0.1").to_owned();
    let cport = port as u16;
    let hport = container.mapped_ports.get(&cport).copied().unwrap_or(cport);
    (h, hport)
}

pub fn tcp_probe_once(host: &str, port: u16) -> bool {
    let addr_str = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(_) => return false,
    };
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }
    }
    false
}

pub fn http_probe_once(host: &str, port: u16, path: &str) -> bool {
    let addr_str = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(_) => return false,
    };
    for addr in addrs {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            let req = format!(
                "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path, host
            );
            if stream.write_all(req.as_bytes()).is_err() {
                continue;
            }
            let mut buf = [0u8; 8192];
            let mut total = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total.extend_from_slice(&buf[..n]);
                        if total.len() >= 8192 {
                            break;
                        }
                        if total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&total);
            if let Some(first_line) = text.lines().next()
                && let Some(code) = parse_http_status(first_line)
                && (200..300).contains(&code)
            {
                return true;
            }
        }
    }
    false
}

fn parse_http_status(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let _proto = parts.next()?;
    let code = parts.next()?;
    code.parse::<u16>().ok()
}

fn exec_probe_once(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    command: &[String],
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<bool, StageExecutionError> {
    if command.is_empty() {
        return Ok(true);
    }
    let mut cmd = Command::new(runtime.bin());
    cmd.arg("exec");
    cmd.arg(&container.id);
    for c in command {
        cmd.arg(c);
    }
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| {
        StageExecutionError::failed(
            "app/missing-prerequisite",
            format!("failed to spawn docker exec: {}", e),
        )
    })?;
    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::cancelled(
                cancel.cancellation_signal(),
                "docker exec cancelled",
            ));
        }
        if deadline.is_expired() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::TimedOut);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        match child.try_wait().map_err(|e| {
            StageExecutionError::failed(
                "app/missing-prerequisite",
                format!("failed waiting on docker exec: {}", e),
            )
        })? {
            Some(status) => {
                return Ok(status.success());
            }
            None => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn check_crash(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<Option<StageExecutionError>, StageExecutionError> {
    let running = docker_inspect_field(runtime, container, "{{.State.Running}}", deadline, cancel)?;
    let running_trim = running.trim().to_lowercase();
    if running_trim == "true" {
        return Ok(None);
    }
    if running_trim.is_empty() {
        return Ok(Some(StageExecutionError::failed(
            "app/crash",
            "container not found, likely exited and removed via rm",
        )));
    }
    let exit_code =
        docker_inspect_field(runtime, container, "{{.State.ExitCode}}", deadline, cancel)
            .unwrap_or_else(|_| "unknown".to_string());
    let logs = docker_logs_tail(runtime, container).unwrap_or_default();
    let redacted = redact_logs(&logs);
    let last20: Vec<&str> = redacted
        .lines()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let tail = last20.join("\n");
    Ok(Some(StageExecutionError::failed(
        "app/crash",
        format!(
            "container {} exited prematurely (exit {}): {}",
            container.id,
            exit_code.trim(),
            tail
        ),
    )))
}

fn docker_inspect_field(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    format_str: &str,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<String, StageExecutionError> {
    let mut cmd = Command::new(runtime.bin());
    cmd.arg("inspect");
    cmd.arg("--format");
    cmd.arg(format_str);
    cmd.arg(&container.id);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| {
        StageExecutionError::failed(
            "app/missing-prerequisite",
            format!("failed to spawn docker inspect: {}", e),
        )
    })?;
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::cancelled(
                cancel.cancellation_signal(),
                "docker inspect cancelled",
            ));
        }
        if deadline.is_expired() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageExecutionError::TimedOut);
        }
        if start.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(String::new());
        }
        match child.try_wait().map_err(|e| {
            StageExecutionError::failed(
                "app/missing-prerequisite",
                format!("failed waiting on docker inspect: {}", e),
            )
        })? {
            Some(status) => {
                let output = child.wait_with_output().map_err(|e| {
                    StageExecutionError::failed(
                        "app/missing-prerequisite",
                        format!("failed reading docker inspect: {}", e),
                    )
                })?;
                if !status.success() {
                    return Ok(String::new());
                }
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
            None => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn docker_logs_tail(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
) -> Result<String, StageExecutionError> {
    let mut cmd = Command::new(runtime.bin());
    cmd.arg("logs");
    cmd.arg("--tail");
    cmd.arg("20");
    cmd.arg(&container.id);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| {
        StageExecutionError::failed(
            "app/missing-prerequisite",
            format!("failed to spawn docker logs: {}", e),
        )
    })?;
    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|e| {
            StageExecutionError::failed(
                "app/missing-prerequisite",
                format!("failed waiting on docker logs: {}", e),
            )
        })? {
            Some(_) => {
                let output = child.wait_with_output().map_err(|e| {
                    StageExecutionError::failed(
                        "app/missing-prerequisite",
                        format!("failed reading docker logs: {}", e),
                    )
                })?;
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                return Ok(combined);
            }
            None => {
                if start.elapsed() > Duration::from_secs(5) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(String::new());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn redact_logs(text: &str) -> String {
    let mut out = text.to_owned();
    for (key, val) in std::env::vars() {
        let upper = key.to_uppercase();
        if (upper.contains("PASSWORD") || upper.contains("SECRET") || upper.contains("TOKEN"))
            && !val.is_empty()
        {
            out = out.replace(&val, "[REDACTED]");
        }
    }
    out.lines()
        .map(|line| {
            let lower = line.to_lowercase();
            if lower.contains("password") || lower.contains("secret") || lower.contains("token") {
                "[REDACTED log line]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_probe_against_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        assert!(tcp_probe_once("127.0.0.1", port));
        drop(listener);
    }

    #[test]
    fn tcp_probe_fails_on_closed_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(!tcp_probe_once("127.0.0.1", port));
    }

    #[test]
    fn http_probe_expects_2xx() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            }
        });
        assert!(http_probe_once("127.0.0.1", port, "/healthz"));
        let _ = handle.join();
    }

    #[test]
    fn http_probe_rejects_500() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ =
                    stream.write_all(b"HTTP/1.0 500 Internal Error\r\nContent-Length: 0\r\n\r\n");
            }
        });
        assert!(!http_probe_once("127.0.0.1", port, "/"));
        let _ = handle.join();
    }
}
