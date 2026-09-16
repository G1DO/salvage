use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_salvage"))
        .args(args)
        .output()
        .expect("failed to start salvage")
}

fn manifest_fixture(name: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("../../tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn evidence_fixture(name: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("../../tests/fixtures/evidence")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn check_emits_machine_readable_success() {
    let output = run(&["check"]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"{"status":"ok","component":"workspace","postgres_adapter":"postgres"}"#
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unsupported_command_emits_machine_readable_usage_error() {
    let output = run(&["unknown-command"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        r#"{"status":"error","code":"usage","message":"expected `salvage check | salvage manifest check <path> | salvage evidence check <path> | salvage evidence report <path> | salvage run <path> [--backup <path>] [--artifact <repo@sha256:...>]`"}"#
    );
}

#[test]
fn manifest_check_prints_normalized_hash_without_restoring() {
    let path = manifest_fixture("manifest-valid-v1.json");
    let output = run(&["manifest", "check", &path]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""status":"ok""#)
            && stdout.contains(r#""command":"manifest-check""#)
            && stdout.contains(r#""manifest_hash":"sha256:"#),
        "unexpected stdout: {stdout}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn manifest_check_rejects_invalid_manifest_with_typed_code() {
    let path = manifest_fixture("manifest-invalid-v1-zero-limits.json");
    let output = run(&["manifest", "check", &path]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""status":"error""#)
            && stderr.contains(r#""code":"manifest/semantic/limits""#),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn manifest_check_reports_non_utf8_input_as_parse_error() {
    let path = std::env::temp_dir().join("salvage-non-utf8-manifest.json");
    std::fs::write(&path, b"\xff\xfe{\"schema_version\": \"v1\"}").expect("write fixture");
    let output = run(&["manifest", "check", &path.to_string_lossy()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""status":"error""#) && stderr.contains(r#""code":"manifest/parse""#),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn evidence_check_accepts_valid_complete_bundle() {
    let path = evidence_fixture("evidence-valid-v1-verified.json");
    let output = run(&["evidence", "check", &path]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""status":"ok""#)
            && stdout.contains(r#""command":"evidence-check""#)
            && stdout.contains(r#""completeness":"complete""#)
            && stdout.contains(r#""verdict_classification":"verified""#),
        "unexpected stdout: {stdout}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn evidence_check_rejects_incomplete_bundle() {
    let path = evidence_fixture("evidence-valid-v1-incomplete.json");
    let output = run(&["evidence", "check", &path]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""status":"error""#)
            && stderr.contains(r#""code":"evidence/incomplete""#),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn evidence_check_rejects_unsupported_version() {
    let path = evidence_fixture("evidence-invalid-unsupported-version.json");
    let output = run(&["evidence", "check", &path]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""status":"error""#)
            && stderr.contains(r#""code":"evidence/unsupported-version""#),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn evidence_report_renders_html() {
    let path = evidence_fixture("evidence-valid-v1-verified.json");
    let output = run(&["evidence", "report", &path]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"));
    assert!(stdout.contains("Salvage Recovery Evidence"));
    assert!(stdout.contains("drill-20260908-001"));
    assert!(stdout.contains("VERIFIED"));
}

#[test]
fn run_without_path_emits_usage_error() {
    let output = run(&["run"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#""status":"error""#));
    assert!(stderr.contains(r#""code":"usage""#));
}

#[test]
fn run_nonexistent_manifest_reports_io_error() {
    let output = run(&["run", "nonexistent-manifest.json"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#""status":"error""#));
    assert!(stderr.contains(r#""code":"io""#));
}

#[test]
fn run_with_wrong_artifact_digest_fails_closed() {
    let path = manifest_fixture("manifest-valid-v2-boot-tcp.json");
    let output = run(&[
        "run",
        &path,
        "--artifact",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#""code":"app/digest-mismatch""#));
}

#[test]
fn run_with_artifact_flag_on_v1_reports_usage() {
    let path = manifest_fixture("manifest-valid-v1.json");
    let output = run(&[
        "run",
        &path,
        "--artifact",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#""code":"usage""#));
}

#[test]
fn manifest_check_accepts_v3_contracts() {
    let path = manifest_fixture("manifest-valid-v3-contracts.json");
    let output = run(&["manifest", "check", &path]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#""status":"ok""#) && stdout.contains(r#""schema_version":"v3""#),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn run_v3_with_wrong_artifact_digest_fails_closed() {
    // Proves v3 is CLI-wired past the old `usage` early-return (O3-4):
    // artifact mismatch is checked before any Docker/PG work.
    let path = manifest_fixture("manifest-valid-v3-contracts.json");
    let output = run(&[
        "run",
        &path,
        "--artifact",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#""code":"app/digest-mismatch""#));
}

#[test]
fn evidence_check_rejects_verified_with_failed_contracts() {
    // `Verified` with failed contracts can never verify (O3-4 gating).
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "salvage-o34-bad-verified-{}.json",
        std::process::id()
    ));
    let bundle = serde_json::json!({
        "schema_version": "v1",
        "completeness": "complete",
        "run": {"run_id": "o34-bad", "owner": "op", "created_at": "2026-09-16T00:00:00Z",
                "completed_at": "2026-09-16T00:00:10Z", "total_duration_ms": 10000},
        "tool": {"name": "salvage", "version": "0.1.0"},
        "manifest": {"canonical_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                     "declared": {}},
        "backup": {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                   "source": "local", "restore_type": "full"},
        "versions": {"declared_postgres": "16.4"},
        "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120,
                   "restore_seconds": 60, "verify_seconds": 30},
        "stages": [{"stage": "contracts", "status": "failed", "duration_ms": 5}],
        "contracts": [{"name": "health", "kind": "http", "status": "failed",
                       "code": "contract/assert-failed", "output": "non-2xx",
                       "truncated": false, "duration_ms": 5, "rows": 0}],
        "verdict": {"verdict": "passed"},
        "verdict_classification": "verified",
        "cleanup": {"status": "success", "errors": []},
        "events": [],
        "telemetry": {}
    });
    std::fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
    let output = run(&["evidence", "check", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("evidence/incomplete"),
        "unexpected stderr: {stderr}"
    );
}
