//! O3-2 acceptance matrix: each kind (`sql`/`http`/`exec`) has pass plus
//! negative tests for hang (`timed-out`), malformed (schema error, no panic),
//! oversized (truncated + `oversized`), and crash (`crash`).
//!
//! Hermetic by construction: these tests open no real sockets (no
//! `TcpListener`/`TcpStream`/`UdpSocket`), use no Docker and no PG. `sql` and
//! `http` run through in-memory fake backends; `exec` spawns real local
//! children directly (no shell) so the timeout path can prove it reaps the
//! owned process group.

use std::path::PathBuf;
use std::time::Instant;

use salvage_contracts::{
    BackendError, ContractCaps, ContractExecutor, ContractStatus, ExecOptions, HttpBackend,
    HttpResponse, SqlBackend,
};
use salvage_core::manifest::{Contract, ContractKind, ContractSpec, ExecSpec, HttpSpec, SqlSpec};

/// Hang budget used across kinds; slack keeps CI non-flaky.
const HANG_TIMEOUT_MS: i64 = 200;
/// Upper bound for a hang test's wall clock (`deadline + slack`).
const HANG_SLACK_MS: u64 = 3_000;

fn sql_contract(name: &str, query: &str, timeout_ms: i64) -> Contract {
    Contract {
        name: name.to_owned(),
        kind: ContractKind::Sql,
        spec: ContractSpec::Sql(SqlSpec {
            query: query.to_owned(),
        }),
        timeout_ms,
        egress_allow: None,
    }
}

fn http_contract(name: &str, url: &str, timeout_ms: i64) -> Contract {
    Contract {
        name: name.to_owned(),
        kind: ContractKind::Http,
        spec: ContractSpec::Http(HttpSpec {
            url: url.to_owned(),
            method: Some("GET".to_owned()),
        }),
        timeout_ms,
        egress_allow: Some(vec!["api.example.com".to_owned()]),
    }
}

fn exec_contract(name: &str, command: &[&str], timeout_ms: i64) -> Contract {
    Contract {
        name: name.to_owned(),
        kind: ContractKind::Exec,
        spec: ContractSpec::Exec(ExecSpec {
            command: command.iter().map(|entry| (*entry).to_owned()).collect(),
        }),
        timeout_ms,
        egress_allow: None,
    }
}

struct ClosureSql<F>(F);

impl<F> SqlBackend for ClosureSql<F>
where
    F: Fn(String, std::path::PathBuf) -> Result<Vec<String>, BackendError> + Send + Sync,
{
    fn query(
        &self,
        query: String,
        socket_dir: std::path::PathBuf,
    ) -> Result<Vec<String>, BackendError> {
        (self.0)(query, socket_dir)
    }
}

struct ClosureHttp<F>(F);

impl<F> HttpBackend for ClosureHttp<F>
where
    F: Fn(String, String) -> Result<HttpResponse, BackendError> + Send + Sync,
{
    fn fetch(&self, url: String, method: String) -> Result<HttpResponse, BackendError> {
        (self.0)(url, method)
    }
}

fn socket_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("salvage-contracts-test.sock.d")
}

// ---------------------------------------------------------------------------
// sql
// ---------------------------------------------------------------------------

#[test]
fn sql_pass_returns_rows() {
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|query: String, _socket: PathBuf| {
        assert!(query.contains("salvage_records"));
        Ok(vec!["1".to_owned()])
    });
    let contract = sql_contract("users-count", "SELECT count(*) FROM salvage_records", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.status, ContractStatus::Passed);
    assert_eq!(result.code, None);
    assert_eq!(result.rows, 1);
    assert!(!result.truncated);
}

#[test]
fn sql_hang_times_out_within_slack() {
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|_query, _socket| {
        std::thread::sleep(std::time::Duration::from_millis(600));
        Ok(vec!["late".to_owned()])
    });
    let contract = sql_contract("hang", "SELECT 1", HANG_TIMEOUT_MS);
    let start = Instant::now();
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    let elapsed_ms = start.elapsed().as_millis() as u64;
    assert_eq!(result.status, ContractStatus::TimedOut);
    assert_eq!(result.code.as_deref(), Some("contract/timeout"));
    assert!(elapsed_ms >= HANG_TIMEOUT_MS as u64, "elapsed={elapsed_ms}");
    assert!(
        elapsed_ms < HANG_TIMEOUT_MS as u64 + HANG_SLACK_MS,
        "elapsed={elapsed_ms}"
    );
}

#[test]
fn sql_malformed_spec_is_schema_error_not_panic() {
    let executor = ContractExecutor::new();
    // Panics if the executor calls it: rejection must happen before the call.
    let backend = ClosureSql(|_query, _socket| -> Result<Vec<String>, BackendError> {
        panic!("sql backend must not run for a malformed spec")
    });
    let contract = sql_contract("bad", "   ", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.status, ContractStatus::Failed);
    assert_eq!(result.code.as_deref(), Some("contract/malformed"));
}

#[test]
fn sql_malformed_backend_error_is_classified() {
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|_query, _socket| Err(BackendError::Malformed("empty query".into())));
    let contract = sql_contract("bad", "SELECT 1", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.code.as_deref(), Some("contract/malformed"));
}

#[test]
fn sql_oversized_truncates_output() {
    let caps = ContractCaps::with_bounds(1024, 10);
    let executor = ContractExecutor::with_caps(caps);
    let backend = ClosureSql(|_query, _socket| Ok(vec!["x".repeat(200); 20]));
    let contract = sql_contract("big", "SELECT data FROM salvage_records", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.status, ContractStatus::Failed);
    assert_eq!(result.code.as_deref(), Some("contract/oversized"));
    assert!(result.truncated);
    assert!(result.output.len() <= 1024);
    assert_eq!(result.rows, 20);
}

#[test]
fn sql_crash_is_classified() {
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|_query, _socket| Err(BackendError::Crash("segfault".into())));
    let contract = sql_contract("crash", "SELECT 1", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.code.as_deref(), Some("contract/crash"));
}

#[test]
fn sql_backend_panic_maps_to_crash_not_harness_panic() {
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|_query, _socket| -> Result<Vec<String>, BackendError> {
        panic!("simulated backend panic")
    });
    let contract = sql_contract("panic", "SELECT 1", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.code.as_deref(), Some("contract/crash"));
}

#[test]
fn sql_zero_rows_is_assert_failed() {
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|_query, _socket| Ok(Vec::new()));
    let contract = sql_contract("empty", "SELECT 1", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.code.as_deref(), Some("contract/assert-failed"));
}

#[test]
fn sql_output_is_redacted_before_assert() {
    unsafe {
        std::env::set_var(
            "SALVAGE_CONTRACTS_SQL_SECRET_CANARY_XYZ",
            "sql-canary-9f8e7d6c5b4a",
        );
    }
    let executor = ContractExecutor::new();
    let backend = ClosureSql(|_query, _socket| Ok(vec!["row sql-canary-9f8e7d6c5b4a".into()]));
    let contract = sql_contract("secret", "SELECT 1", 5_000);
    let result = executor.run_sql(&contract, &socket_dir(), &backend);
    assert_eq!(result.status, ContractStatus::Passed);
    assert!(!result.output.contains("sql-canary-9f8e7d6c5b4a"));
    assert!(result.output.contains("[REDACTED]"));
}

// ---------------------------------------------------------------------------
// http
// ---------------------------------------------------------------------------

#[test]
fn http_pass_on_2xx() {
    let executor = ContractExecutor::new();
    let backend = ClosureHttp(|url: String, method: String| {
        assert!(url.starts_with("https://"));
        assert_eq!(method, "GET");
        Ok(HttpResponse {
            status: 200,
            body: "OK".to_owned(),
        })
    });
    let contract = http_contract("health", "https://api.example.com/healthz", 5_000);
    let result = executor.run_http(&contract, &backend);
    assert_eq!(result.status, ContractStatus::Passed);
    assert_eq!(result.output, "OK");
}

#[test]
fn http_hang_times_out_within_slack() {
    let executor = ContractExecutor::new();
    let backend = ClosureHttp(|_url, _method| {
        std::thread::sleep(std::time::Duration::from_millis(600));
        Ok(HttpResponse {
            status: 200,
            body: "late".to_owned(),
        })
    });
    let contract = http_contract("hang", "https://api.example.com/healthz", HANG_TIMEOUT_MS);
    let start = Instant::now();
    let result = executor.run_http(&contract, &backend);
    let elapsed_ms = start.elapsed().as_millis() as u64;
    assert_eq!(result.status, ContractStatus::TimedOut);
    assert_eq!(result.code.as_deref(), Some("contract/timeout"));
    assert!(elapsed_ms >= HANG_TIMEOUT_MS as u64, "elapsed={elapsed_ms}");
    assert!(
        elapsed_ms < HANG_TIMEOUT_MS as u64 + HANG_SLACK_MS,
        "elapsed={elapsed_ms}"
    );
}

#[test]
fn http_malformed_url_is_schema_error_not_panic() {
    let executor = ContractExecutor::new();
    let backend = ClosureHttp(|_url, _method| -> Result<HttpResponse, BackendError> {
        panic!("http backend must not run for a malformed spec")
    });
    let contract = http_contract("bad", "ftp://api.example.com/x", 5_000);
    let result = executor.run_http(&contract, &backend);
    assert_eq!(result.code.as_deref(), Some("contract/malformed"));
}

#[test]
fn http_oversized_truncates_body() {
    let caps = ContractCaps::with_bounds(1024, 100);
    let executor = ContractExecutor::with_caps(caps);
    let backend = ClosureHttp(|_url, _method| {
        Ok(HttpResponse {
            status: 200,
            body: "y".repeat(8_000),
        })
    });
    let contract = http_contract("big", "https://api.example.com/healthz", 5_000);
    let result = executor.run_http(&contract, &backend);
    assert_eq!(result.code.as_deref(), Some("contract/oversized"));
    assert!(result.truncated);
    assert!(result.output.len() <= 1024);
}

#[test]
fn http_crash_is_classified() {
    let executor = ContractExecutor::new();
    let backend = ClosureHttp(|_url, _method| Err(BackendError::Crash("reset".into())));
    let contract = http_contract("crash", "https://api.example.com/healthz", 5_000);
    let result = executor.run_http(&contract, &backend);
    assert_eq!(result.code.as_deref(), Some("contract/crash"));
}

#[test]
fn http_non_2xx_is_assert_failed() {
    let executor = ContractExecutor::new();
    let backend = ClosureHttp(|_url, _method| {
        Ok(HttpResponse {
            status: 500,
            body: "boom".to_owned(),
        })
    });
    let contract = http_contract("unstable", "https://api.example.com/healthz", 5_000);
    let result = executor.run_http(&contract, &backend);
    assert_eq!(result.code.as_deref(), Some("contract/assert-failed"));
}

// ---------------------------------------------------------------------------
// exec (real children, no shell, no sockets)
// ---------------------------------------------------------------------------

#[test]
fn exec_pass_runs_allowlisted_binary() {
    let executor = ContractExecutor::new();
    let contract = exec_contract("hello", &["echo", "hello"], 5_000);
    let result = executor.run_exec(&contract, &ExecOptions::none());
    assert_eq!(result.status, ContractStatus::Passed, "{result:?}");
    assert!(result.output.contains("hello"));
    assert!(result.pid.is_some());
}

#[test]
fn exec_hang_kills_process_group_without_leak() {
    let executor = ContractExecutor::new();
    let contract = exec_contract("hang", &["sleep", "30"], HANG_TIMEOUT_MS);
    let start = Instant::now();
    let result = executor.run_exec(&contract, &ExecOptions::none());
    let elapsed_ms = start.elapsed().as_millis() as u64;
    assert_eq!(result.status, ContractStatus::TimedOut);
    assert_eq!(result.code.as_deref(), Some("contract/timeout"));
    assert!(elapsed_ms >= HANG_TIMEOUT_MS as u64, "elapsed={elapsed_ms}");
    assert!(
        elapsed_ms < HANG_TIMEOUT_MS as u64 + HANG_SLACK_MS,
        "elapsed={elapsed_ms}"
    );
    // The owned child ran in its own group (pgid == pid); the group is gone.
    let pid = result.pid.expect("exec timeout must report its pid");
    let probe = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
    assert_eq!(probe, -1, "process group {pid} must be reaped");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn exec_malformed_allowlist_rejects_without_spawn() {
    let executor = ContractExecutor::new();
    let contract = exec_contract("evil", &["rm", "-rf", "/"], 5_000);
    let result = executor.run_exec(&contract, &ExecOptions::none());
    assert_eq!(result.code.as_deref(), Some("contract/malformed"));
    assert_eq!(result.pid, None);
}

#[test]
fn exec_malformed_empty_command_rejects_without_spawn() {
    let executor = ContractExecutor::new();
    let contract = Contract {
        name: "empty".to_owned(),
        kind: ContractKind::Exec,
        spec: ContractSpec::Exec(ExecSpec { command: vec![] }),
        timeout_ms: 5_000,
        egress_allow: None,
    };
    let result = executor.run_exec(&contract, &ExecOptions::none());
    assert_eq!(result.code.as_deref(), Some("contract/malformed"));
    assert_eq!(result.pid, None);
}

#[test]
fn exec_oversized_truncates_output() {
    let caps = ContractCaps::with_bounds(1024, 100);
    let executor = ContractExecutor::with_caps(caps);
    let big = "x".repeat(8_000);
    let contract = exec_contract("big", &["echo", &big], 5_000);
    let result = executor.run_exec(&contract, &ExecOptions::none());
    assert_eq!(result.code.as_deref(), Some("contract/oversized"));
    assert!(result.truncated);
    assert!(result.output.len() <= 1024);
}

#[test]
fn exec_crash_on_nonzero_exit() {
    let executor = ContractExecutor::new();
    let contract = exec_contract("crash", &["false"], 5_000);
    let result = executor.run_exec(&contract, &ExecOptions::none());
    assert_eq!(result.code.as_deref(), Some("contract/crash"), "{result:?}");
}

#[test]
fn exec_assert_failed_on_output_mismatch() {
    let executor = ContractExecutor::new();
    let contract = exec_contract("check", &["echo", "hello"], 5_000);
    let options = ExecOptions {
        expected_contains: Some("goodbye".to_owned()),
    };
    let result = executor.run_exec(&contract, &options);
    assert_eq!(result.code.as_deref(), Some("contract/assert-failed"));
}

#[test]
fn exec_output_is_redacted_before_assert() {
    unsafe {
        std::env::set_var(
            "SALVAGE_CONTRACTS_EXEC_TOKEN_CANARY_XYZ",
            "exec-canary-1a2b3c4d5e6f",
        );
    }
    let executor = ContractExecutor::new();
    let contract = exec_contract("secret", &["echo", "exec-canary-1a2b3c4d5e6f"], 5_000);
    let result = executor.run_exec(&contract, &ExecOptions::none());
    assert_eq!(result.status, ContractStatus::Passed, "{result:?}");
    assert!(!result.output.contains("exec-canary-1a2b3c4d5e6f"));
    assert!(result.output.contains("[REDACTED]"));
}

#[test]
fn dispatch_executes_declared_kind() {
    let executor = ContractExecutor::new();
    let sql = ClosureSql(|_query, _socket| Ok(vec!["1".to_owned()]));
    let http = ClosureHttp(|_url, _method| {
        Ok(HttpResponse {
            status: 200,
            body: "OK".to_owned(),
        })
    });
    let contract = sql_contract("users-count", "SELECT 1", 5_000);
    let result = executor.execute(&contract, &socket_dir(), &sql, &http, &ExecOptions::none());
    assert_eq!(result.status, ContractStatus::Passed);
    assert_eq!(result.kind, "sql");
}
