//! End-to-end black-box integration tests for the complete recovery outcome.
//!
//! Verifies the full exit gate:
//! - One documented CLI command from manifest to terminal verdict
//! - Known-good fixture restores schema and seeded records
//! - Machine-readable evidence bundle validation and HTML report projection
//! - Failure matrix: corrupt input, unsupported version, timeout, SIGINT, child failure
//! - Zero resource leaks (processes, directories, sockets)
//! - Semantic equivalence across 3 consecutive clean-environment runs

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn salvage_bin() -> &'static str {
    env!("CARGO_BIN_EXE_salvage")
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "salvage-e2e-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_e2e_known_good_recovery_produces_verified_verdict_and_evidence() {
    let temp_dir = unique_temp_dir("known-good");
    let manifest = fixture_path("manifest-valid-pg16-restore.json");
    let dump = fixture_path("valid-pg16-custom.dump");

    // 1. Run salvage run from manifest to terminal verdict
    let output = Command::new(salvage_bin())
        .args([
            "run",
            manifest.to_str().unwrap(),
            "--backup",
            dump.to_str().unwrap(),
            "--run-dir",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("execute salvage run");

    assert!(
        output.status.success(),
        "salvage run failed: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""status":"ok""#));
    assert!(stdout.contains(r#""command":"run""#));
    assert!(stdout.contains(r#""verdict":"passed""#));
    assert!(stdout.contains(r#""verdict_classification":"verified""#));
    assert!(stdout.contains(r#""cleanup_status":"success""#));

    // 2. Validate evidence.json was written and validates
    let evidence_path = temp_dir.join("evidence.json");
    assert!(
        evidence_path.exists(),
        "evidence.json must exist in run_dir"
    );

    let check_output = Command::new(salvage_bin())
        .args(["evidence", "check", evidence_path.to_str().unwrap()])
        .output()
        .expect("salvage evidence check");

    assert!(
        check_output.status.success(),
        "evidence check failed: {}",
        String::from_utf8_lossy(&check_output.stderr)
    );
    let check_stdout = String::from_utf8_lossy(&check_output.stdout);
    assert!(check_stdout.contains(r#""completeness":"complete""#));
    assert!(check_stdout.contains(r#""verdict_classification":"verified""#));

    // 3. Validate HTML report generation
    let report_output = Command::new(salvage_bin())
        .args(["evidence", "report", evidence_path.to_str().unwrap()])
        .output()
        .expect("salvage evidence report");

    assert!(report_output.status.success());
    let report_html = String::from_utf8_lossy(&report_output.stdout);
    assert!(report_html.contains("<!DOCTYPE html>"));
    assert!(report_html.contains("VERIFIED"));
    assert!(report_html.contains("salvage_records"));

    // 4. Inspect evidence content for required fields
    let evidence_str = fs::read_to_string(&evidence_path).unwrap();
    let bundle = salvage_evidence::parse_evidence_bundle(&evidence_str).unwrap();

    assert_eq!(bundle.schema_version, "v1");
    assert_eq!(
        bundle.completeness,
        salvage_evidence::EvidenceCompleteness::Complete
    );
    assert_eq!(
        bundle.verdict_classification,
        salvage_evidence::VerdictClassification::Verified
    );
    assert!(
        bundle
            .versions
            .observed_server
            .as_deref()
            .unwrap_or("")
            .contains("PostgreSQL 16")
    );
    assert!(
        bundle
            .versions
            .observed_client
            .as_deref()
            .unwrap_or("")
            .contains("pg_restore")
    );
    assert!(
        bundle
            .telemetry
            .verified_tables
            .contains(&"salvage_records".to_owned()),
        "salvage_records should be verified"
    );
    assert_eq!(bundle.cleanup.as_ref().unwrap().status, "success");

    // 5. Zero-leak check: ensure ephemeral postgres cluster was completely removed
    assert!(
        !temp_dir.join("postgres").exists(),
        "ephemeral postgres directory must be cleaned up"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_auto_discovery_of_backup_by_digest() {
    let temp_dir = unique_temp_dir("auto-discovery");
    let manifest = fixture_path("manifest-valid-pg16-restore.json");

    // Run without --backup; CLI discovers valid-pg16-custom.dump in same directory
    let output = Command::new(salvage_bin())
        .args([
            "run",
            manifest.to_str().unwrap(),
            "--run-dir",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("execute salvage run");

    assert!(
        output.status.success(),
        "auto-discovery run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""verdict":"passed""#));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_corrupt_input_matrix_fails_cleanly() {
    // 1. Digest mismatch
    {
        let temp_dir = unique_temp_dir("mismatch");
        let manifest_content =
            fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json")).unwrap();
        let altered_manifest = manifest_content.replace(
            "f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let manifest_path = temp_dir.join("manifest.json");
        fs::write(&manifest_path, altered_manifest).unwrap();

        let output = Command::new(salvage_bin())
            .args([
                "run",
                manifest_path.to_str().unwrap(),
                "--backup",
                fixture_path("valid-pg16-custom.dump").to_str().unwrap(),
                "--run-dir",
                temp_dir.to_str().unwrap(),
            ])
            .output()
            .expect("execute");

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("restore/digest-mismatch"));
        assert!(!temp_dir.join("postgres").exists());
        let _ = fs::remove_dir_all(&temp_dir);
    }

    // 2. Truncated corrupt archive
    {
        let temp_dir = unique_temp_dir("truncated");
        let manifest_content =
            fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json")).unwrap();
        let corrupt_manifest = manifest_content.replace(
            "f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454",
            "0d2c292dcdd11b91917d1cf4d935218414f8d2b95b35696c774be79de7f26cdb",
        );
        let manifest_path = temp_dir.join("manifest.json");
        fs::write(&manifest_path, corrupt_manifest).unwrap();

        let output = Command::new(salvage_bin())
            .args([
                "run",
                manifest_path.to_str().unwrap(),
                "--backup",
                fixture_path("corrupt-truncated.dump").to_str().unwrap(),
                "--run-dir",
                temp_dir.to_str().unwrap(),
            ])
            .output()
            .expect("execute");

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("restore/corrupt-backup"));
        assert!(!temp_dir.join("postgres").exists());

        // Validate evidence bundle was written and is schema-valid
        let evidence_path = temp_dir.join("evidence.json");
        assert!(evidence_path.exists());
        let check_output = Command::new(salvage_bin())
            .args(["evidence", "check", evidence_path.to_str().unwrap()])
            .output()
            .expect("evidence check");
        assert!(check_output.status.success());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    // 3. Bad magic bytes (non-archive)
    {
        let temp_dir = unique_temp_dir("magic");
        let manifest_content =
            fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json")).unwrap();
        let magic_manifest = manifest_content.replace(
            "f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454",
            "8c3472ee103090f0e183c58e24d640fb3436e3c08692a37e404d225cd27be435",
        );
        let manifest_path = temp_dir.join("manifest.json");
        fs::write(&manifest_path, magic_manifest).unwrap();

        let output = Command::new(salvage_bin())
            .args([
                "run",
                manifest_path.to_str().unwrap(),
                "--backup",
                fixture_path("invalid-non-archive.dump").to_str().unwrap(),
                "--run-dir",
                temp_dir.to_str().unwrap(),
            ])
            .output()
            .expect("execute");

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("restore/corrupt-backup"));
        assert!(!temp_dir.join("postgres").exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

#[test]
fn test_e2e_unsupported_version_fails_closed() {
    let temp_dir = unique_temp_dir("unsupported-ver");
    let manifest_content =
        fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json")).unwrap();
    let unsupported_manifest =
        manifest_content.replace(r#""version": "16.4""#, r#""version": "99.0""#);
    let manifest_path = temp_dir.join("manifest.json");
    fs::write(&manifest_path, unsupported_manifest).unwrap();

    let output = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            fixture_path("valid-pg16-custom.dump").to_str().unwrap(),
            "--run-dir",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("execute");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("restore/unsupported-version"));
    assert!(!temp_dir.join("postgres").exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_child_failure_missing_expected_table() {
    let temp_dir = unique_temp_dir("missing-table");
    let manifest = fixture_path("manifest-valid-pg16-restore.json");
    let dump = fixture_path("valid-pg16-custom.dump");

    let output = Command::new(salvage_bin())
        .args([
            "run",
            manifest.to_str().unwrap(),
            "--backup",
            dump.to_str().unwrap(),
            "--expected-table",
            "nonexistent_table_xyz",
            "--run-dir",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("execute");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("restore/structural-verification-failed"));
    assert!(!temp_dir.join("postgres").exists());

    let evidence_path = temp_dir.join("evidence.json");
    assert!(evidence_path.exists());
    let check_output = Command::new(salvage_bin())
        .args(["evidence", "check", evidence_path.to_str().unwrap()])
        .output()
        .expect("evidence check");
    assert!(check_output.status.success());
    let check_stdout = String::from_utf8_lossy(&check_output.stdout);
    assert!(
        check_stdout.contains(r#""verdict_classification":"orchestration-failed""#)
            || check_stdout.contains(r#""verdict_classification":"verification-failed""#)
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_timeout_fails_cleanly_without_leaks() {
    let temp_dir = unique_temp_dir("timeout");
    let manifest_content =
        fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json")).unwrap();
    // Configure restore deadline to 1 second
    let timeout_manifest =
        manifest_content.replace(r#""restore_seconds": 60"#, r#""restore_seconds": 1"#);
    let manifest_path = temp_dir.join("manifest.json");
    fs::write(&manifest_path, timeout_manifest).unwrap();

    let output = Command::new(salvage_bin())
        .args([
            "run",
            manifest_path.to_str().unwrap(),
            "--backup",
            fixture_path("valid-pg16-custom.dump").to_str().unwrap(),
            "--run-dir",
            temp_dir.to_str().unwrap(),
        ])
        .env("SALVAGE_TEST_RESTORE_DELAY_MS", "1500")
        .output()
        .expect("execute");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""verdict":"timed-out""#),
        "expected timed-out verdict, got: {stderr}"
    );
    assert!(!temp_dir.join("postgres").exists());

    let evidence_path = temp_dir.join("evidence.json");
    assert!(evidence_path.exists());
    let check_output = Command::new(salvage_bin())
        .args(["evidence", "check", evidence_path.to_str().unwrap()])
        .output()
        .expect("evidence check");
    assert!(check_output.status.success());
    let check_stdout = String::from_utf8_lossy(&check_output.stdout);
    assert!(check_stdout.contains(r#""verdict_classification":"timed-out""#));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_sigint_cancellation_cleans_up_and_records_verdict() {
    let temp_dir = unique_temp_dir("sigint");
    let manifest = fixture_path("manifest-valid-pg16-restore.json");
    let dump = fixture_path("valid-pg16-custom.dump");

    // Spawn salvage run with a simulated delay
    let child = Command::new(salvage_bin())
        .args([
            "run",
            manifest.to_str().unwrap(),
            "--backup",
            dump.to_str().unwrap(),
            "--run-dir",
            temp_dir.to_str().unwrap(),
        ])
        .env("SALVAGE_TEST_RESTORE_DELAY_MS", "3000")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn child process");

    let pid = child.id() as libc::pid_t;

    // Sleep briefly so it enters the restore stage
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Send SIGINT to the process
    unsafe {
        libc::kill(pid, libc::SIGINT);
    }

    let output = child.wait_with_output().expect("wait on child");

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 on signal cancellation"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#""verdict":"cancelled""#),
        "expected cancelled verdict in stderr: {stderr}"
    );

    // Ephemeral target cluster must be cleaned up
    assert!(
        !temp_dir.join("postgres").exists(),
        "postgres directory must be cleaned up on SIGINT"
    );

    // Evidence bundle must be marked complete and reflect Cancelled
    let evidence_path = temp_dir.join("evidence.json");
    assert!(
        evidence_path.exists(),
        "evidence.json must be written on cancellation"
    );

    let check_output = Command::new(salvage_bin())
        .args(["evidence", "check", evidence_path.to_str().unwrap()])
        .output()
        .expect("evidence check");

    assert!(check_output.status.success());
    let check_stdout = String::from_utf8_lossy(&check_output.stdout);
    assert!(check_stdout.contains(r#""completeness":"complete""#));
    assert!(check_stdout.contains(r#""verdict_classification":"cancelled""#));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_three_consecutive_runs_produce_semantically_equivalent_evidence() {
    let manifest = fixture_path("manifest-valid-pg16-restore.json");
    let dump = fixture_path("valid-pg16-custom.dump");

    let mut bundles: Vec<serde_json::Value> = Vec::new();

    for i in 1..=3 {
        let temp_dir = unique_temp_dir(&format!("run-{i}"));

        let output = Command::new(salvage_bin())
            .args([
                "run",
                manifest.to_str().unwrap(),
                "--backup",
                dump.to_str().unwrap(),
                "--run-dir",
                temp_dir.to_str().unwrap(),
            ])
            .output()
            .expect("execute");

        assert!(
            output.status.success(),
            "run {i} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let evidence_path = temp_dir.join("evidence.json");
        let content = fs::read_to_string(&evidence_path).expect("read evidence.json");
        let mut bundle_json: serde_json::Value =
            serde_json::from_str(&content).expect("parse evidence json");

        // Normalize documented nondeterministic fields:
        // - run_id, created_at, completed_at, total_duration_ms
        // - stage durations
        // - event timestamps, run_ids, duration_ms
        if let Some(run_obj) = bundle_json.get_mut("run").and_then(|r| r.as_object_mut()) {
            run_obj.insert("run_id".to_string(), serde_json::json!("NORMALIZED_RUN_ID"));
            run_obj.insert(
                "created_at".to_string(),
                serde_json::json!("NORMALIZED_TIMESTAMP"),
            );
            if run_obj.contains_key("completed_at") {
                run_obj.insert(
                    "completed_at".to_string(),
                    serde_json::json!("NORMALIZED_TIMESTAMP"),
                );
            }
            if run_obj.contains_key("total_duration_ms") {
                run_obj.insert("total_duration_ms".to_string(), serde_json::json!(1000));
            }
        }

        if let Some(stages) = bundle_json.get_mut("stages").and_then(|s| s.as_array_mut()) {
            for stage in stages.iter_mut() {
                if let Some(obj) = stage.as_object_mut()
                    && obj.contains_key("duration_ms")
                {
                    obj.insert("duration_ms".to_string(), serde_json::json!(100));
                }
            }
        }

        if let Some(events) = bundle_json.get_mut("events").and_then(|e| e.as_array_mut()) {
            for event in events.iter_mut() {
                if let Some(obj) = event.as_object_mut() {
                    obj.insert(
                        "timestamp_rfc3339".to_string(),
                        serde_json::json!("NORMALIZED_TIMESTAMP"),
                    );
                    obj.insert("run_id".to_string(), serde_json::json!("NORMALIZED_RUN_ID"));
                    if obj.contains_key("duration_ms") {
                        obj.insert("duration_ms".to_string(), serde_json::json!(50));
                    }
                }
            }
        }

        bundles.push(bundle_json);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    assert_eq!(bundles.len(), 3);
    assert_eq!(
        bundles[0], bundles[1],
        "run 1 and run 2 evidence bundles must be semantically equivalent"
    );
    assert_eq!(
        bundles[1], bundles[2],
        "run 2 and run 3 evidence bundles must be semantically equivalent"
    );
}
