//! Bounded contract execution for `sql` / `http` / `exec`.
//!
//! Classification order (first match wins): `timeout` > `malformed` >
//! `crash` > `oversized` > `assert-failed` > `passed`.
//!
//! - `sql` / `http` run through injected backends so tests stay hermetic (no
//!   Docker, no PG, no real sockets). Production backends arrive in later
//!   slices; the timeout/cap/redaction core here is backend-agnostic.
//! - `exec` spawns real children directly (`Command::new(argv0)`, never a
//!   shell) in an isolated process group and kills the group on timeout via
//!   `terminate_process_group` (`crates/salvage-core/src/lifecycle/process.rs`).
//! - SQL handles are socket-only: callers pass a Unix `socket_dir`; there is
//!   no TCP host/port parameter by design.
//! - Every captured byte goes through `SecretRedactor` (with env secrets)
//!   before caps, assert, or persistence.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use salvage_core::manifest::{Contract, ContractKind, ContractSpec};
use salvage_evidence::SecretRedactor;

use crate::caps::ContractCaps;
use crate::outcome::{
    CODE_ASSERT_FAILED, CODE_CRASH, CODE_MALFORMED, CODE_OVERSIZED, ContractResult,
};

/// Grace period for `SIGTERM` before `SIGKILL` on contract timeouts.
const TERMINATE_GRACE: Duration = Duration::from_millis(100);
/// Poll interval while supervising `exec` children.
const EXEC_POLL: Duration = Duration::from_millis(10);

/// Backend failure that selects the `contract/*` code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// Spec/shape rejected without running (schema error, never a panic).
    Malformed(String),
    /// Backend crashed (panic, signal death, transport failure).
    Crash(String),
    /// Backend ran but the contract assertion failed.
    AssertFailed(String),
}

/// Injected SQL runner (fake in O3-2 tests, PG socket backend later).
///
/// `socket_dir` is the Unix socket directory of the ephemeral cluster; there
/// is deliberately no TCP parameter. Owned parameters keep fake backends
/// higher-ranked-lifetime-free and `'static`-free for scoped timeout threads.
pub trait SqlBackend: Send + Sync {
    /// Runs `query` and returns output rows.
    fn query(&self, query: String, socket_dir: PathBuf) -> Result<Vec<String>, BackendError>;
}

/// Injected HTTP fetcher (fake in O3-2 tests, policy-checked client later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes as text.
    pub body: String,
}

/// Injected HTTP backend.
///
/// Owned parameters keep fake backends higher-ranked-lifetime-free and
/// `'static`-free for scoped timeout threads.
pub trait HttpBackend: Send + Sync {
    /// Fetches `url` with `method` (already upper-cased, defaults to `GET`).
    fn fetch(&self, url: String, method: String) -> Result<HttpResponse, BackendError>;
}

/// Extra expectations for `exec` contracts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOptions {
    /// When set, exit-0 output must contain this substring (after redaction),
    /// otherwise the result is `contract/assert-failed`.
    pub expected_contains: Option<String>,
}

impl ExecOptions {
    /// Options with no output expectation.
    #[must_use]
    pub fn none() -> Self {
        Self {
            expected_contains: None,
        }
    }
}

/// Bounded contract executor sharing one [`ContractCaps`].
#[derive(Debug, Clone)]
pub struct ContractExecutor {
    caps: ContractCaps,
}

impl Default for ContractExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ContractExecutor {
    /// Creates an executor with default caps.
    #[must_use]
    pub fn new() -> Self {
        Self {
            caps: ContractCaps::default(),
        }
    }

    /// Creates an executor with explicit caps.
    #[must_use]
    pub fn with_caps(caps: ContractCaps) -> Self {
        Self { caps }
    }

    /// Returns the active caps.
    #[must_use]
    pub const fn caps(&self) -> &ContractCaps {
        &self.caps
    }

    /// Redacts captured output before assert/persist.
    fn redact(&self, text: &str) -> String {
        let mut redactor = SecretRedactor::new();
        redactor.add_env_secrets();
        redactor.redact_text(text)
    }

    /// Dispatches a declared `v3` contract to its kind runner.
    pub fn execute(
        &self,
        contract: &Contract,
        socket_dir: &Path,
        sql: &impl SqlBackend,
        http: &impl HttpBackend,
        exec: &ExecOptions,
    ) -> ContractResult {
        match contract.kind {
            ContractKind::Sql => self.run_sql(contract, socket_dir, sql),
            ContractKind::Http => self.run_http(contract, http),
            ContractKind::Exec => self.run_exec(contract, exec),
        }
    }

    /// Runs a `sql` contract through `backend` with timeout, caps, redaction.
    pub fn run_sql(
        &self,
        contract: &Contract,
        socket_dir: &Path,
        backend: &impl SqlBackend,
    ) -> ContractResult {
        const KIND: &str = "sql";
        let start = Instant::now();
        let name = contract.name.clone();

        let query = match (&contract.kind, &contract.spec) {
            (ContractKind::Sql, ContractSpec::Sql(spec)) if !spec.query.trim().is_empty() => {
                spec.query.clone()
            }
            _ => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_MALFORMED,
                    self.redact("spec shape does not match kind `sql` or query is blank"),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };
        let timeout = match contract_timeout(contract) {
            Ok(timeout) => timeout,
            Err(message) => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_MALFORMED,
                    self.redact(&message),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };

        let socket: PathBuf = socket_dir.to_path_buf();
        match run_bounded(timeout, move || backend.query(query, socket)) {
            BoundedOutcome::Timeout => {
                ContractResult::timed_out(name, KIND, start.elapsed().as_millis() as u64)
            }
            BoundedOutcome::Panic(message) => ContractResult::failed(
                name,
                KIND,
                CODE_CRASH,
                self.redact(&message),
                false,
                start.elapsed().as_millis() as u64,
                0,
            ),
            BoundedOutcome::Done(Err(BackendError::Malformed(message))) => ContractResult::failed(
                name,
                KIND,
                CODE_MALFORMED,
                self.redact(&message),
                false,
                start.elapsed().as_millis() as u64,
                0,
            ),
            BoundedOutcome::Done(Err(BackendError::Crash(message))) => ContractResult::failed(
                name,
                KIND,
                CODE_CRASH,
                self.redact(&message),
                false,
                start.elapsed().as_millis() as u64,
                0,
            ),
            BoundedOutcome::Done(Err(BackendError::AssertFailed(message))) => {
                ContractResult::failed(
                    name,
                    KIND,
                    CODE_ASSERT_FAILED,
                    self.redact(&message),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                )
            }
            BoundedOutcome::Done(Ok(rows)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                if rows.is_empty() {
                    return ContractResult::failed(
                        name,
                        KIND,
                        CODE_ASSERT_FAILED,
                        self.redact("query succeeded but returned 0 rows"),
                        false,
                        elapsed,
                        0,
                    );
                }
                let row_count = rows.len();
                let joined = rows.join("\n");
                let redacted = self.redact(&joined);
                if row_count > self.caps.max_rows || redacted.len() > self.caps.max_output_bytes {
                    let (output, _) = self.caps.truncate_output(&redacted);
                    return ContractResult::failed(
                        name,
                        KIND,
                        CODE_OVERSIZED,
                        output,
                        true,
                        elapsed,
                        row_count,
                    );
                }
                let mut result = ContractResult::passed(name, KIND, redacted, elapsed, row_count);
                result.rows = row_count;
                result
            }
        }
    }

    /// Runs an `http` contract through `backend` with timeout, caps, redaction.
    pub fn run_http(&self, contract: &Contract, backend: &impl HttpBackend) -> ContractResult {
        const KIND: &str = "http";
        let start = Instant::now();
        let name = contract.name.clone();

        let (url, method) = match (&contract.kind, &contract.spec) {
            (ContractKind::Http, ContractSpec::Http(spec))
                if !spec.url.trim().is_empty()
                    && (spec.url.starts_with("http://") || spec.url.starts_with("https://")) =>
            {
                let method = spec.method.clone().unwrap_or_else(|| "GET".to_owned());
                (spec.url.clone(), method)
            }
            _ => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_MALFORMED,
                    self.redact("spec shape does not match kind `http` or url is not http(s)"),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };
        let timeout = match contract_timeout(contract) {
            Ok(timeout) => timeout,
            Err(message) => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_MALFORMED,
                    self.redact(&message),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };

        match run_bounded(timeout, move || backend.fetch(url, method)) {
            BoundedOutcome::Timeout => {
                ContractResult::timed_out(name, KIND, start.elapsed().as_millis() as u64)
            }
            BoundedOutcome::Panic(message) => ContractResult::failed(
                name,
                KIND,
                CODE_CRASH,
                self.redact(&message),
                false,
                start.elapsed().as_millis() as u64,
                0,
            ),
            BoundedOutcome::Done(Err(BackendError::Malformed(message))) => ContractResult::failed(
                name,
                KIND,
                CODE_MALFORMED,
                self.redact(&message),
                false,
                start.elapsed().as_millis() as u64,
                0,
            ),
            BoundedOutcome::Done(Err(BackendError::Crash(message))) => ContractResult::failed(
                name,
                KIND,
                CODE_CRASH,
                self.redact(&message),
                false,
                start.elapsed().as_millis() as u64,
                0,
            ),
            BoundedOutcome::Done(Err(BackendError::AssertFailed(message))) => {
                ContractResult::failed(
                    name,
                    KIND,
                    CODE_ASSERT_FAILED,
                    self.redact(&message),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                )
            }
            BoundedOutcome::Done(Ok(response)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let redacted = self.redact(&response.body);
                if redacted.len() > self.caps.max_output_bytes {
                    let (output, _) = self.caps.truncate_output(&redacted);
                    return ContractResult::failed(
                        name,
                        KIND,
                        CODE_OVERSIZED,
                        output,
                        true,
                        elapsed,
                        0,
                    );
                }
                if !(200..300).contains(&response.status) {
                    return ContractResult::failed(
                        name,
                        KIND,
                        CODE_ASSERT_FAILED,
                        redacted,
                        false,
                        elapsed,
                        0,
                    );
                }
                ContractResult::passed(name, KIND, redacted, elapsed, 0)
            }
        }
    }

    /// Runs an `exec` contract as a real child (no shell) with timeout, caps,
    /// redaction, and process-group kill on timeout.
    pub fn run_exec(&self, contract: &Contract, options: &ExecOptions) -> ContractResult {
        const KIND: &str = "exec";
        let start = Instant::now();
        let name = contract.name.clone();

        let command = match (&contract.kind, &contract.spec) {
            (ContractKind::Exec, ContractSpec::Exec(spec))
                if !spec.command.is_empty()
                    && spec.command.iter().all(|entry| !entry.trim().is_empty()) =>
            {
                spec.command.clone()
            }
            _ => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_MALFORMED,
                    self.redact("spec shape does not match kind `exec` or command is empty/blank"),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };
        if !self.caps.is_exec_allowed(&command[0]) {
            return ContractResult::failed(
                name,
                KIND,
                CODE_MALFORMED,
                self.redact("argv[0] is not in the exec allowlist"),
                false,
                start.elapsed().as_millis() as u64,
                0,
            );
        }
        let timeout = match contract_timeout(contract) {
            Ok(timeout) => timeout,
            Err(message) => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_MALFORMED,
                    self.redact(&message),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };

        // No shell: argv is passed directly to the binary.
        let mut cmd = Command::new(&command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.process_group(0);
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                return ContractResult::failed(
                    name,
                    KIND,
                    CODE_CRASH,
                    self.redact(&format!("failed to spawn exec contract: {error}")),
                    false,
                    start.elapsed().as_millis() as u64,
                    0,
                );
            }
        };
        let pid = child.id();
        let pgid = pid;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let output = match child.wait_with_output() {
                        Ok(output) => output,
                        Err(error) => {
                            return with_pid(
                                ContractResult::failed(
                                    name,
                                    KIND,
                                    CODE_CRASH,
                                    self.redact(&format!("failed reading exec output: {error}")),
                                    false,
                                    elapsed,
                                    0,
                                ),
                                pid,
                            );
                        }
                    };
                    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push('\n');
                        }
                        combined.push_str(&stderr);
                    }
                    let redacted = self.redact(&combined);
                    if !status.success() {
                        let (output, truncated) = if redacted.len() > self.caps.max_output_bytes {
                            let (text, _) = self.caps.truncate_output(&redacted);
                            (text, true)
                        } else {
                            (redacted, false)
                        };
                        return with_pid(
                            ContractResult::failed(
                                name, KIND, CODE_CRASH, output, truncated, elapsed, 0,
                            ),
                            pid,
                        );
                    }
                    if redacted.len() > self.caps.max_output_bytes {
                        let (output, _) = self.caps.truncate_output(&redacted);
                        return with_pid(
                            ContractResult::failed(
                                name,
                                KIND,
                                CODE_OVERSIZED,
                                output,
                                true,
                                elapsed,
                                0,
                            ),
                            pid,
                        );
                    }
                    if let Some(needle) = options.expected_contains.as_deref()
                        && !redacted.contains(needle)
                    {
                        return with_pid(
                            ContractResult::failed(
                                name,
                                KIND,
                                CODE_ASSERT_FAILED,
                                redacted,
                                false,
                                elapsed,
                                0,
                            ),
                            pid,
                        );
                    }
                    return with_pid(
                        ContractResult::passed(name, KIND, redacted, elapsed, 0),
                        pid,
                    );
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ =
                            salvage_core::lifecycle::terminate_process_group(pgid, TERMINATE_GRACE);
                        let _ = child.wait();
                        return with_pid(
                            ContractResult::timed_out(
                                name,
                                KIND,
                                start.elapsed().as_millis() as u64,
                            ),
                            pid,
                        );
                    }
                    std::thread::sleep(EXEC_POLL);
                }
                Err(error) => {
                    return with_pid(
                        ContractResult::failed(
                            name,
                            KIND,
                            CODE_CRASH,
                            self.redact(&format!("failed waiting on exec contract: {error}")),
                            false,
                            start.elapsed().as_millis() as u64,
                            0,
                        ),
                        pid,
                    );
                }
            }
        }
    }
}

/// Attaches the spawned pid so timeout tests can assert the group is gone.
fn with_pid(mut result: ContractResult, pid: u32) -> ContractResult {
    result.pid = Some(pid);
    result
}

/// Converts `timeout_ms` to a [`Duration`]; non-positive values are malformed.
fn contract_timeout(contract: &Contract) -> Result<Duration, String> {
    if contract.timeout_ms <= 0 {
        return Err(format!(
            "contracts[{}].timeout_ms must be positive, got {}",
            contract.name, contract.timeout_ms
        ));
    }
    Ok(Duration::from_millis(contract.timeout_ms as u64))
}

/// Outcome of a bounded background computation.
enum BoundedOutcome<T> {
    /// Finished in time (including backend `Err` values).
    Done(T),
    /// Exceeded the deadline.
    Timeout,
    /// Worker panicked (mapped to `contract/crash`, never propagated).
    Panic(String),
}

/// Runs `f` on a scoped worker thread and waits up to `timeout`.
///
/// Panics are caught and reported as [`BoundedOutcome::Panic`]; a hung worker
/// is abandoned after the deadline for classification purposes (`exec`
/// children are killed separately via their process group). Scoped threads let
/// fake backends borrow from the caller, keeping tests hermetic without
/// `'static` bounds.
fn run_bounded<T: Send>(timeout: Duration, f: impl FnOnce() -> T + Send) -> BoundedOutcome<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|s| {
        s.spawn(|| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            let _ = tx.send(outcome);
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok(value)) => BoundedOutcome::Done(value),
            Ok(Err(_)) => BoundedOutcome::Panic("contract backend panicked".to_owned()),
            Err(RecvTimeoutError::Timeout) => BoundedOutcome::Timeout,
            Err(RecvTimeoutError::Disconnected) => {
                BoundedOutcome::Panic("contract backend worker died".to_owned())
            }
        }
    })
}
