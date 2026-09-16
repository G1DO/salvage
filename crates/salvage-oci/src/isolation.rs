//! Default-deny boot isolation plus forbidden-egress evidence (O3-3).
//!
//! Boot containers run on a per-run `docker network create --internal`
//! network (`salvage-net-<run-id>`, see ADR 0004). `--internal` denies
//! container-to-outside egress while published ports (`-P`) stay reachable
//! from the host, so TCP/HTTP readiness probes keep working. The `none`
//! driver was rejected: it also breaks host-to-container readiness.
//!
//! - Absent `egress_allow` means deny-all (manifest default-deny, ADR 0003).
//!   O3-3 validates the allowlist shape but still denies everything: no
//!   egress rule is added. A future slice may add a proxy for allowlisted
//!   hosts.
//! - [`probe_forbidden_egress`] attempts a declared-forbidden fake host
//!   (`.invalid`, RFC 2606, never leaves the lab). Blocked returns
//!   `allowed:false`; reachable returns
//!   [`StageExecutionError::Failed`] with [`CODE_EGRESS_ALLOWED`].
//! - Any policy-apply error returns [`CODE_POLICY_FAILED`] and never falls
//!   back to an open network (fail-closed).
//! - Networks are owned by [`ResourceManager`]: containers are removed
//!   before their network on both pass and fail paths.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use salvage_core::lifecycle::{
    CancellationToken, ResourceManager, RunId, StageDeadline, StageExecutionError,
};
use salvage_evidence::SecretRedactor;

use crate::container::ContainerHandle;
use crate::runtime::ContainerRuntime;

/// Typed diagnostic when forbidden egress is reachable (must never verify).
pub const CODE_EGRESS_ALLOWED: &str = "isolation/egress-allowed";
/// Typed diagnostic when the isolation policy itself cannot be applied.
///
/// Fail-closed: callers must abort boot, never fall back to `bridge`.
pub const CODE_POLICY_FAILED: &str = "isolation/policy-failed";
/// Declared-forbidden fake host for the egress probe.
///
/// `.invalid` (RFC 2606) never resolves externally, so the probe has no
/// external network dependency; all fakes stay local.
pub const FORBIDDEN_EGRESS_HOST: &str = "prod-forbidden.invalid";

/// Default-deny network policy for one boot run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    network_name: String,
    allowlist: Vec<String>,
}

impl NetworkPolicy {
    /// Builds a deny-all policy for `run_id` (no egress, allowlist empty).
    #[must_use]
    pub fn default_deny(run_id: &RunId) -> Self {
        Self {
            network_name: isolated_network_name(run_id),
            allowlist: Vec::new(),
        }
    }

    /// Builds a default-deny policy with a validated allowlist.
    ///
    /// Entries are validated like manifest `egress_allow` (hosts, no `://`,
    /// no whitespace, non-blank). O3-3 still denies everything; the list is
    /// retained for evidence and a future allowlist proxy. Invalid entries
    /// fail closed with [`CODE_POLICY_FAILED`].
    pub fn default_deny_with_allowlist(
        run_id: &RunId,
        allowlist: &[String],
    ) -> Result<Self, StageExecutionError> {
        Ok(Self {
            network_name: isolated_network_name(run_id),
            allowlist: validate_allowlist(allowlist)?,
        })
    }

    /// Returns the per-run isolated network name.
    #[must_use]
    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    /// Returns the validated (still denied in O3-3) allowlist.
    #[must_use]
    pub fn allowlist(&self) -> &[String] {
        &self.allowlist
    }

    /// Returns `docker run --network <isolated>` args, fail-closed.
    pub fn docker_run_network_args(&self) -> Result<Vec<String>, StageExecutionError> {
        validate_network_name(&self.network_name)?;
        Ok(vec!["--network".to_owned(), self.network_name.clone()])
    }
}

/// Returns the per-run isolated network name for `run_id`.
#[must_use]
pub fn isolated_network_name(run_id: &RunId) -> String {
    format!("salvage-net-{}", run_id.as_str())
}

/// Validates an egress allowlist (hosts, no `://`, no whitespace).
fn validate_allowlist(entries: &[String]) -> Result<Vec<String>, StageExecutionError> {
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        let trimmed = entry.trim().to_owned();
        if trimmed.is_empty() {
            return Err(StageExecutionError::failed(
                CODE_POLICY_FAILED,
                "egress allowlist entries must be non-blank",
            ));
        }
        if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(StageExecutionError::failed(
                CODE_POLICY_FAILED,
                format!("egress allowlist entry {trimmed:?} must not contain whitespace"),
            ));
        }
        if trimmed.contains("://") {
            return Err(StageExecutionError::failed(
                CODE_POLICY_FAILED,
                format!("egress allowlist entry {trimmed:?} must be a host, not a URL"),
            ));
        }
        normalized.push(trimmed);
    }
    Ok(normalized)
}

/// Validates a network name fail-closed (never fall back to open network).
fn validate_network_name(name: &str) -> Result<(), StageExecutionError> {
    if name.trim().is_empty() {
        return Err(StageExecutionError::failed(
            CODE_POLICY_FAILED,
            "isolated network name must be non-blank (refusing open network)",
        ));
    }
    if name.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(StageExecutionError::failed(
            CODE_POLICY_FAILED,
            format!("isolated network name {name:?} must not contain whitespace"),
        ));
    }
    Ok(())
}

/// Redacts probe/policy detail before it becomes evidence.
fn redact_detail(text: &str) -> String {
    let mut redactor = SecretRedactor::new();
    redactor.add_env_secrets();
    redactor.redact_text(text)
}

/// Ensures the per-run `--internal` network exists and registers it.
///
/// Best-effort stale `network rm` first (same run-id leak would make
/// `create` fail). Any `create` error returns [`CODE_POLICY_FAILED`];
/// callers must abort, never fall back to `bridge`.
pub fn ensure_isolated_network(
    runtime: &ContainerRuntime,
    run_id: &RunId,
    allowlist: &[String],
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<String, StageExecutionError> {
    if cancel.is_cancelled() {
        return Err(StageExecutionError::cancelled(
            cancel.cancellation_signal(),
            "cancelled before network isolation",
        ));
    }
    if deadline.is_expired() {
        return Err(StageExecutionError::TimedOut);
    }
    let policy = NetworkPolicy::default_deny_with_allowlist(run_id, allowlist)?;
    let network = policy.network_name().to_owned();
    validate_network_name(&network)?;
    // Best-effort stale cleanup: a leaked network with the same name would
    // make `create` fail. Missing network is the common case; ignore outcome.
    let _ = run_docker_capture(
        runtime.bin(),
        &["network".to_owned(), "rm".to_owned(), network.clone()],
        resources,
        deadline,
        cancel,
    );
    let create_args = vec![
        "network".to_owned(),
        "create".to_owned(),
        "--internal".to_owned(),
        "--label".to_owned(),
        format!("salvage-run={}", run_id.as_str()),
        "--label".to_owned(),
        "salvage-isolation=default-deny".to_owned(),
        network.clone(),
    ];
    let output = run_docker_capture(runtime.bin(), &create_args, resources, deadline, cancel)?;
    if !output.status_success {
        let combined = format!("{}{}", output.stdout, output.stderr);
        // `create` can report "already exists" if a concurrent stale cleanup
        // raced us; the network is still isolated, so reuse it.
        if combined.to_lowercase().contains("already exists") {
            let _ = resources.register_network(network.clone(), runtime.bin().to_path_buf());
            return Ok(network);
        }
        return Err(StageExecutionError::failed(
            CODE_POLICY_FAILED,
            format!(
                "failed to create isolated network {network:?}: {} (refusing open network)",
                redact_detail(combined.trim())
            ),
        ));
    }
    let _ = resources.register_network(network.clone(), runtime.bin().to_path_buf());
    Ok(network)
}

/// Outcome of a forbidden-egress probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProbeResult {
    /// Always `false` on success (blocked). Reachable is an `Err`, never `true`.
    pub allowed: bool,
    /// Forbidden host that was attempted.
    pub host: String,
    /// Redacted detail (safe for evidence).
    pub detail: String,
}

/// Attempts a declared-forbidden host from inside the booted container.
///
/// - Blocked (`wget`/`curl` non-zero without tool-missing) returns
///   `Ok(allowed:false)`.
/// - Reachable (exit 0) returns `Err(Failed{isolation/egress-allowed})`.
/// - Missing probe tools or `docker exec` spawn failure returns
///   `Err(Failed{isolation/policy-failed})` fail-closed (no silent pass).
/// - `TimedOut`/`Cancelled` propagate unchanged.
#[allow(clippy::too_many_arguments)]
pub fn probe_forbidden_egress(
    runtime: &ContainerRuntime,
    container: &ContainerHandle,
    forbidden_host: &str,
    resources: &mut ResourceManager,
    deadline: &StageDeadline,
    cancel: &CancellationToken,
) -> Result<EgressProbeResult, StageExecutionError> {
    let host = forbidden_host.trim().to_owned();
    if host.is_empty() {
        return Err(StageExecutionError::failed(
            CODE_POLICY_FAILED,
            "forbidden egress host must be non-blank",
        ));
    }
    let url = format!("http://{host}/");
    // Busybox-friendly first: `wget` ships in busybox:1.36 (tiny-http).
    let wget_args = vec![
        "exec".to_owned(),
        container.id.clone(),
        "wget".to_owned(),
        "-qO-".to_owned(),
        "--timeout=2".to_owned(),
        url.clone(),
    ];
    let wget_out = run_docker_capture(runtime.bin(), &wget_args, resources, deadline, cancel)?;
    if wget_out.status_success {
        return Err(StageExecutionError::failed(
            CODE_EGRESS_ALLOWED,
            format!(
                "forbidden egress to {host:?} reachable from container {} (isolation failure)",
                container.id
            ),
        ));
    }
    let wget_combined = format!("{}{}", wget_out.stdout, wget_out.stderr);
    if !is_tool_missing(&wget_combined) {
        return Ok(EgressProbeResult {
            allowed: false,
            host,
            detail: redact_detail(&format!("wget blocked: {}", wget_combined.trim())),
        });
    }
    // `wget` missing: fall back to `curl` before giving up.
    let curl_args = vec![
        "exec".to_owned(),
        container.id.clone(),
        "curl".to_owned(),
        "--max-time".to_owned(),
        "2".to_owned(),
        "--fail".to_owned(),
        "-s".to_owned(),
        url,
    ];
    let curl_out = run_docker_capture(runtime.bin(), &curl_args, resources, deadline, cancel)?;
    if curl_out.status_success {
        return Err(StageExecutionError::failed(
            CODE_EGRESS_ALLOWED,
            format!(
                "forbidden egress to {host:?} reachable from container {} (isolation failure)",
                container.id
            ),
        ));
    }
    let curl_combined = format!("{}{}", curl_out.stdout, curl_out.stderr);
    if is_tool_missing(&curl_combined) {
        return Err(StageExecutionError::failed(
            CODE_POLICY_FAILED,
            format!(
                "egress probe tools missing in container {} for host {host:?}: {} (refusing silent pass)",
                container.id,
                redact_detail(curl_combined.trim()),
            ),
        ));
    }
    Ok(EgressProbeResult {
        allowed: false,
        host,
        detail: redact_detail(&format!("curl blocked: {}", curl_combined.trim())),
    })
}

/// Heuristic for "probe binary not installed" vs "blocked by policy".
///
/// Missing tools exit non-zero with `not found`/`No such file`/127-style
/// text; blocked egress reports bad address/unreachable/timeout instead.
/// Unknown text is treated as blocked (tool ran and failed), never as
/// missing, so a real block is not misclassified as a policy error.
fn is_tool_missing(combined: &str) -> bool {
    let lower = combined.to_lowercase();
    lower.contains("not found")
        || lower.contains("no such file")
        || lower.contains("unknown command")
        || lower.contains("executable file not found")
        || lower.contains("exec failed")
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
            CODE_POLICY_FAILED,
            format!(
                "failed to spawn docker {}: {e} (refusing open network)",
                args.join(" ")
            ),
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
                CODE_POLICY_FAILED,
                format!("failed waiting on docker: {e} (refusing open network)"),
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
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn test_runtime(bin: &Path) -> ContainerRuntime {
        ContainerRuntime {
            bin: bin.to_path_buf(),
            version: "29.4.1".to_owned(),
            major: 29,
        }
    }

    fn test_resources(label: &str) -> (ResourceManager, std::path::PathBuf) {
        let base =
            std::env::temp_dir().join(format!("salvage-isolation-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let run_id = RunId::new(format!("iso-test-{label}")).unwrap();
        (ResourceManager::new(run_id, root), base)
    }

    fn write_fake_docker(dir: &Path, script: &str) -> std::path::PathBuf {
        let bin = dir.join("docker");
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[test]
    fn default_deny_policy_never_uses_bridge() {
        let run_id = RunId::new("run-abc").unwrap();
        let policy = NetworkPolicy::default_deny(&run_id);
        assert_eq!(policy.network_name(), "salvage-net-run-abc");
        assert!(policy.allowlist().is_empty());
        let args = policy.docker_run_network_args().unwrap();
        assert_eq!(
            args,
            vec!["--network".to_owned(), "salvage-net-run-abc".to_owned()]
        );
        assert!(!args.iter().any(|a| a == "bridge"));
        assert!(!args.iter().any(|a| a == "none"));
    }

    #[test]
    fn empty_network_name_fails_closed() {
        let policy = NetworkPolicy {
            network_name: String::new(),
            allowlist: Vec::new(),
        };
        let err = policy
            .docker_run_network_args()
            .expect_err("must fail closed");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, CODE_POLICY_FAILED),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allowlist_rejects_urls_blanks_whitespace() {
        let run_id = RunId::new("run-allow").unwrap();
        for bad in ["", "   ", "https://api.example.com", "api example.com"] {
            let err = NetworkPolicy::default_deny_with_allowlist(&run_id, &[bad.to_owned()])
                .expect_err("must fail closed");
            match err {
                StageExecutionError::Failed { code, .. } => assert_eq!(code, CODE_POLICY_FAILED),
                other => panic!("unexpected {other:?}"),
            }
        }
        let ok =
            NetworkPolicy::default_deny_with_allowlist(&run_id, &["api.example.com".to_owned()])
                .unwrap();
        assert_eq!(ok.allowlist(), &["api.example.com".to_owned()]);
    }

    #[test]
    fn network_create_failure_fails_closed_without_fallback() {
        let base = std::env::temp_dir().join(format!("salvage-iso-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = write_fake_docker(
            &base,
            "#!/bin/sh\nif echo \"$*\" | grep -q \"network create\"; then echo daemon exploded >&2; exit 1; fi\nexit 0\n",
        );
        let rt = test_runtime(&fake);
        let (mut rm, _guard) = test_resources("fail");
        let run_id = RunId::new("iso-fail-net").unwrap();
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = ensure_isolated_network(&rt, &run_id, &[], &mut rm, &deadline, &cancel)
            .expect_err("create failure must fail closed");
        match err {
            StageExecutionError::Failed { code, message } => {
                assert_eq!(code, CODE_POLICY_FAILED);
                assert!(!message.contains("bridge"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    fn fake_probe_runtime(dir: &Path, mode: &str) -> std::path::PathBuf {
        // mode: blocked | reachable | missing
        let script = match mode {
            "reachable" => "#!/bin/sh\nexit 0\n",
            "missing" => {
                "#!/bin/sh\necho \"wget: not found\" >&2\necho \"curl: not found\" >&2\nexit 127\n"
            }
            _ => "#!/bin/sh\necho \"wget: bad address 'prod-forbidden.invalid'\" >&2\nexit 1\n",
        };
        write_fake_docker(dir, script)
    }

    fn test_handle() -> ContainerHandle {
        ContainerHandle {
            id: "abc123".to_owned(),
            name: "salvage-test".to_owned(),
            image_id: "sha256:deadbeef".to_owned(),
            mapped_ports: Default::default(),
        }
    }

    #[test]
    fn forbidden_probe_blocked_records_allowed_false() {
        let base = std::env::temp_dir().join(format!("salvage-probe-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = fake_probe_runtime(&base, "blocked");
        let rt = test_runtime(&fake);
        let (mut rm, _guard) = test_resources("blocked");
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let result = probe_forbidden_egress(
            &rt,
            &test_handle(),
            FORBIDDEN_EGRESS_HOST,
            &mut rm,
            &deadline,
            &cancel,
        )
        .expect("blocked must be Ok");
        assert!(!result.allowed);
        assert_eq!(result.host, FORBIDDEN_EGRESS_HOST);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn forbidden_probe_reachable_is_isolation_failure() {
        let base = std::env::temp_dir().join(format!("salvage-probe-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = fake_probe_runtime(&base, "reachable");
        let rt = test_runtime(&fake);
        let (mut rm, _guard) = test_resources("reachable");
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = probe_forbidden_egress(
            &rt,
            &test_handle(),
            FORBIDDEN_EGRESS_HOST,
            &mut rm,
            &deadline,
            &cancel,
        )
        .expect_err("reachable must be isolation failure");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, CODE_EGRESS_ALLOWED),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn forbidden_probe_tools_missing_fails_closed() {
        let base = std::env::temp_dir().join(format!("salvage-probe-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = fake_probe_runtime(&base, "missing");
        let rt = test_runtime(&fake);
        let (mut rm, _guard) = test_resources("missing");
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = probe_forbidden_egress(
            &rt,
            &test_handle(),
            FORBIDDEN_EGRESS_HOST,
            &mut rm,
            &deadline,
            &cancel,
        )
        .expect_err("missing tools must not silently pass");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, CODE_POLICY_FAILED),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn blank_forbidden_host_fails_closed() {
        let base = std::env::temp_dir().join(format!("salvage-probe-blank-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fake = fake_probe_runtime(&base, "blocked");
        let rt = test_runtime(&fake);
        let (mut rm, _guard) = test_resources("blank");
        let deadline = StageDeadline::new(Duration::from_secs(10), None);
        let cancel = CancellationToken::new();
        let err = probe_forbidden_egress(&rt, &test_handle(), "   ", &mut rm, &deadline, &cancel)
            .expect_err("blank host must fail closed");
        match err {
            StageExecutionError::Failed { code, .. } => assert_eq!(code, CODE_POLICY_FAILED),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
