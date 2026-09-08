//! End-to-end integration tests for PostgreSQL backup restore into isolated targets.

use std::fs;
use std::path::{Path, PathBuf};

use salvage_core::lifecycle::{RunConfig, RunEngine, RunId, Stage, Verdict};
use salvage_core::manifest::parse_manifest;
use salvage_postgres::PostgresStageExecutor;

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "salvage-pg-test-{label}-{}-{}",
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
fn test_postgres_restore_happy_path() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    let manifest = parse_manifest(&manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("happy-path");
    let run_id = RunId::new("test-pg16-happy").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let dump_path = fixture_path("valid-pg16-custom.dump");
    let mut executor = PostgresStageExecutor::new(dump_path).with_expected_table("salvage_records");

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    assert!(
        outcome.verdict.is_passed(),
        "expected verdict Passed, got {:?}",
        outcome.verdict
    );
    assert!(
        outcome.cleanup_status.is_success(),
        "expected cleanup status Success, got {:?}",
        outcome.cleanup_status
    );

    // Verify telemetry
    let telemetry = executor.telemetry();
    assert!(
        telemetry.server_version.is_some(),
        "server version should be captured"
    );
    assert!(
        telemetry.client_version.is_some(),
        "client version should be captured"
    );
    assert!(
        telemetry.restore_duration.is_some(),
        "restore duration should be captured"
    );
    assert!(
        telemetry
            .verified_tables
            .contains(&"salvage_records".to_owned()),
        "salvage_records must be verified in tables: {:?}",
        telemetry.verified_tables
    );

    // Ensure all target resources and socket directory were released
    assert!(
        !temp_dir.join("postgres").exists(),
        "postgres dir should be cleaned up"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_digest_mismatch_fails_closed_without_target() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    // Replace with a deliberate mismatched checksum
    let altered_manifest_text = manifest_text.replace(
        "f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let manifest = parse_manifest(&altered_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("digest-mismatch");
    let run_id = RunId::new("test-pg-mismatch").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let dump_path = fixture_path("valid-pg16-custom.dump");
    let mut executor = PostgresStageExecutor::new(dump_path);

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    assert_eq!(
        outcome.verdict,
        Verdict::failed(
            Stage::Validation,
            "restore/digest-mismatch",
            "checksum mismatch: manifest declared `sha256:0000000000000000000000000000000000000000000000000000000000000000`, backup has `sha256:f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454`"
        )
    );
    assert!(outcome.cleanup_status.is_success());

    // Target database cluster must NEVER have been provisioned
    assert!(
        !temp_dir.join("postgres").exists(),
        "postgres cluster must NOT be created when validation fails"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_corrupt_truncated_backup() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    // Digest of corrupt-truncated.dump
    let corrupt_manifest_text = manifest_text.replace(
        "f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454",
        "0d2c292dcdd11b91917d1cf4d935218414f8d2b95b35696c774be79de7f26cdb",
    );
    let manifest = parse_manifest(&corrupt_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("corrupt-backup");
    let run_id = RunId::new("test-pg-corrupt").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let dump_path = fixture_path("corrupt-truncated.dump");
    let mut executor = PostgresStageExecutor::new(dump_path);

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    if let Verdict::Failed {
        stage,
        code,
        message,
    } = &outcome.verdict
    {
        assert_eq!(*stage, Stage::Restore);
        assert_eq!(code, "restore/corrupt-backup");
        assert!(
            message.contains("pg_restore"),
            "message should mention pg_restore: {message}"
        );
    } else {
        panic!("expected failed verdict, got {:?}", outcome.verdict);
    }

    assert!(outcome.cleanup_status.is_success());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_invalid_magic_bytes() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    // Digest of invalid-non-archive.dump
    let non_archive_manifest_text = manifest_text.replace(
        "f49be1627938919ee0a05a667efdf4cb90c303f9b07335814625f11bedcd2454",
        "8c3472ee103090f0e183c58e24d640fb3436e3c08692a37e404d225cd27be435",
    );
    let manifest = parse_manifest(&non_archive_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("invalid-magic");
    let run_id = RunId::new("test-pg-magic").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let dump_path = fixture_path("invalid-non-archive.dump");
    let mut executor = PostgresStageExecutor::new(dump_path);

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    if let Verdict::Failed {
        stage,
        code,
        message,
    } = &outcome.verdict
    {
        assert_eq!(*stage, Stage::Validation);
        assert_eq!(code, "restore/corrupt-backup");
        assert!(
            message.contains("magic bytes"),
            "message should mention magic bytes: {message}"
        );
    } else {
        panic!("expected failed verdict, got {:?}", outcome.verdict);
    }

    assert!(outcome.cleanup_status.is_success());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_unsupported_version() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    // Require PostgreSQL version 99
    let bad_version_manifest_text =
        manifest_text.replace(r#""version": "16.4""#, r#""version": "99.0""#);
    let manifest = parse_manifest(&bad_version_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("unsupported-ver");
    let run_id = RunId::new("test-pg-ver").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let dump_path = fixture_path("valid-pg16-custom.dump");
    let mut executor = PostgresStageExecutor::new(dump_path);

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    if let Verdict::Failed { stage, code, .. } = &outcome.verdict {
        assert_eq!(*stage, Stage::Validation);
        assert_eq!(code, "restore/unsupported-version");
    } else {
        panic!(
            "expected unsupported-version failure, got {:?}",
            outcome.verdict
        );
    }

    assert!(outcome.cleanup_status.is_success());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_missing_backup_file() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    let manifest = parse_manifest(&manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("missing-file");
    let run_id = RunId::new("test-pg-missing").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let missing_path = temp_dir.join("nonexistent.dump");
    let mut executor = PostgresStageExecutor::new(missing_path);

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    if let Verdict::Failed { stage, code, .. } = &outcome.verdict {
        assert_eq!(*stage, Stage::Validation);
        assert_eq!(code, "restore/missing-prerequisite");
    } else {
        panic!(
            "expected missing-prerequisite failure, got {:?}",
            outcome.verdict
        );
    }

    assert!(outcome.cleanup_status.is_success());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_structural_verification_missing_table() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    let manifest = parse_manifest(&manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("struct-fail");
    let run_id = RunId::new("test-pg-struct").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let dump_path = fixture_path("valid-pg16-custom.dump");
    // Expect a table that does NOT exist in the backup
    let mut executor =
        PostgresStageExecutor::new(dump_path).with_expected_table("missing_table_xyz");

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    if let Verdict::Failed {
        stage,
        code,
        message,
    } = &outcome.verdict
    {
        assert_eq!(*stage, Stage::Restore);
        assert_eq!(code, "restore/structural-verification-failed");
        assert!(message.contains("missing_table_xyz"), "message: {message}");
    } else {
        panic!(
            "expected structural-verification-failed, got {:?}",
            outcome.verdict
        );
    }

    assert!(outcome.cleanup_status.is_success());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_cancellation_during_validation() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    let manifest = parse_manifest(&manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("cancel-val");
    let run_id = RunId::new("test-pg-cancel").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    // Pre-cancel token
    config.cancellation_token.cancel();

    let dump_path = fixture_path("valid-pg16-custom.dump");
    let mut executor = PostgresStageExecutor::new(dump_path);

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    assert!(
        matches!(outcome.verdict, Verdict::Cancelled { .. }),
        "expected cancelled verdict, got {:?}",
        outcome.verdict
    );
    assert!(outcome.cleanup_status.is_success());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_postgres_restore_stage_timeout_terminates_target_cleanly() {
    let manifest_text = fs::read_to_string(fixture_path("manifest-valid-pg16-restore.json"))
        .expect("read manifest fixture");
    // Set restore deadline to 1 second
    let timeout_manifest_text =
        manifest_text.replace(r#""restore_seconds": 60"#, r#""restore_seconds": 1"#);
    let manifest = parse_manifest(&timeout_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("timeout");
    let run_id = RunId::new("test-pg-timeout").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    struct TimeoutExecutor {
        inner: PostgresStageExecutor,
    }

    impl salvage_core::lifecycle::StageExecutor for TimeoutExecutor {
        fn execute_validation(
            &mut self,
            ctx: &mut salvage_core::lifecycle::StageContext<'_>,
        ) -> Result<(), salvage_core::lifecycle::StageExecutionError> {
            self.inner.execute_validation(ctx)
        }

        fn execute_restore(
            &mut self,
            ctx: &mut salvage_core::lifecycle::StageContext<'_>,
        ) -> Result<(), salvage_core::lifecycle::StageExecutionError> {
            // Wait until deadline expires
            while !ctx.deadline.is_expired() {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            self.inner.execute_restore(ctx)
        }
    }

    let dump_path = fixture_path("valid-pg16-custom.dump");
    let mut executor = TimeoutExecutor {
        inner: PostgresStageExecutor::new(dump_path),
    };

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    assert_eq!(outcome.verdict, Verdict::timed_out(Stage::Restore, 1));
    assert!(outcome.cleanup_status.is_success());
    assert!(!temp_dir.join("postgres").exists());
    let _ = fs::remove_dir_all(&temp_dir);
}
