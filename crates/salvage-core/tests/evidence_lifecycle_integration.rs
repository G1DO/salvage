use std::fs;
use std::path::PathBuf;

use salvage_core::lifecycle::{
    DefaultStageExecutor, RunConfig, RunEngine, RunId, RunTelemetry, Stage, StageContext,
    StageExecutionError, StageExecutor, Verdict,
};
use salvage_core::manifest::parse_manifest;
use salvage_evidence::{EvidenceCompleteness, VerdictClassification, parse_evidence_bundle};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("salvage-evidence-test-{prefix}-{nanos}"));
    fs::create_dir_all(&dir).expect("create test temp dir");
    dir
}

struct MockTelemetryExecutor {
    observed_server: String,
    observed_client: String,
    verified_tables: Vec<String>,
    fail_in_verification: bool,
}

impl StageExecutor for MockTelemetryExecutor {
    fn execute_validation(
        &mut self,
        ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        ctx.telemetry.observed_client_version = Some(self.observed_client.clone());
        ctx.telemetry.command_identity = Some("/usr/bin/pg_restore".to_owned());
        Ok(())
    }

    fn execute_restore(&mut self, ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        ctx.telemetry.observed_server_version = Some(self.observed_server.clone());
        ctx.telemetry.target_dbname = Some("mock_db".to_owned());
        ctx.telemetry.verified_tables = self.verified_tables.clone();
        Ok(())
    }

    fn execute_verification(
        &mut self,
        _ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        if self.fail_in_verification {
            Err(StageExecutionError::failed(
                "restore/structural-verification-failed",
                "missing required table 'expected_orders'",
            ))
        } else {
            Ok(())
        }
    }

    fn telemetry(&self) -> Option<RunTelemetry> {
        Some(RunTelemetry {
            observed_server_version: Some(self.observed_server.clone()),
            observed_client_version: Some(self.observed_client.clone()),
            command_identity: Some("/usr/bin/pg_restore".to_owned()),
            target_dbname: Some("mock_db".to_owned()),
            observed_app_version: None,
            observed_artifact_digest: None,
            declared_artifact_digest: None,
            artifact_repository: None,
            artifact_resolved_image_id: None,
            boot_seconds: None,
            verified_tables: self.verified_tables.clone(),
            extra: Default::default(),
        })
    }
}

#[test]
fn test_evidence_bundle_and_report_generated_on_successful_run() {
    let manifest_text =
        fs::read_to_string(fixture_path("manifest-valid-v1.json")).expect("read manifest fixture");
    let manifest = parse_manifest(&manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("happy-evidence");
    let run_id = RunId::new("test-evidence-happy").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let mut executor = MockTelemetryExecutor {
        observed_server: "PostgreSQL 16.4 on x86_64-pc-linux-gnu".to_owned(),
        observed_client: "pg_restore (PostgreSQL) 16.4".to_owned(),
        verified_tables: vec!["users".to_owned(), "accounts".to_owned()],
        fail_in_verification: false,
    };

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    assert!(outcome.verdict.is_passed());
    assert!(outcome.cleanup_status.is_success());

    // 1. Assert evidence.json and report.html exist in run_dir
    let evidence_path = temp_dir.join("evidence.json");
    let report_path = temp_dir.join("report.html");
    assert!(evidence_path.exists(), "evidence.json must exist");
    assert!(report_path.exists(), "report.html must exist");

    // 2. Parse evidence.json and assert schema compliance
    let evidence_content = fs::read_to_string(&evidence_path).expect("read evidence.json");
    let bundle = parse_evidence_bundle(&evidence_content).expect("parse evidence bundle");

    assert_eq!(bundle.schema_version, "v1");
    assert_eq!(bundle.completeness, EvidenceCompleteness::Complete);
    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::Verified
    );
    assert_eq!(bundle.run.run_id, "test-evidence-happy");
    assert!(bundle.run.completed_at.is_some());
    assert!(bundle.run.total_duration_ms.is_some());

    // Assert versions captured
    assert_eq!(bundle.versions.declared_postgres, "16.4");
    assert_eq!(
        bundle.versions.observed_server.as_deref(),
        Some("PostgreSQL 16.4 on x86_64-pc-linux-gnu")
    );
    assert_eq!(
        bundle.versions.observed_client.as_deref(),
        Some("pg_restore (PostgreSQL) 16.4")
    );

    // Assert verified tables recorded
    assert_eq!(
        bundle.telemetry.verified_tables,
        vec!["users".to_string(), "accounts".to_string()]
    );

    // Assert stages recorded
    let stage_names: Vec<String> = bundle.stages.iter().map(|s| s.stage.clone()).collect();
    assert!(stage_names.contains(&"planning".to_string()));
    assert!(stage_names.contains(&"validation".to_string()));
    assert!(stage_names.contains(&"restore".to_string()));
    assert!(stage_names.contains(&"verification".to_string()));
    assert!(stage_names.contains(&"cleaning".to_string()));

    // Assert report.html contains key evidence
    let report_content = fs::read_to_string(&report_path).expect("read report.html");
    assert!(report_content.contains("test-evidence-happy"));
    assert!(report_content.contains("VERIFIED"));
    assert!(report_content.contains("accounts"));
    assert!(report_content.contains("users"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_evidence_distinguishes_failed_verification_from_failed_orchestration() {
    let manifest_text =
        fs::read_to_string(fixture_path("manifest-valid-v1.json")).expect("read manifest fixture");
    let manifest = parse_manifest(&manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("failed-verification");
    let run_id = RunId::new("test-evidence-fail-verify").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let mut executor = MockTelemetryExecutor {
        observed_server: "PostgreSQL 16.4".to_owned(),
        observed_client: "pg_restore 16.4".to_owned(),
        verified_tables: vec!["users".to_owned()],
        fail_in_verification: true,
    };

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    assert!(!outcome.verdict.is_passed());
    let evidence_path = temp_dir.join("evidence.json");
    let evidence_content = fs::read_to_string(&evidence_path).expect("read evidence.json");
    let bundle = parse_evidence_bundle(&evidence_content).expect("parse evidence bundle");

    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::VerificationFailed
    );
    let verdict = bundle.verdict.expect("verdict should be present");
    assert_eq!(verdict.stage.as_deref(), Some("verification"));
    assert_eq!(
        verdict.code.as_deref(),
        Some("restore/structural-verification-failed")
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_evidence_failure_changes_final_verdict_to_failed() {
    let manifest_text =
        fs::read_to_string(fixture_path("manifest-valid-v1.json")).expect("read manifest fixture");
    // Point evidence destination to an uncreatable/illegal filesystem path
    let bad_dest_manifest_text = manifest_text.replace(
        r#""destination": "file:///tmp/salvage-evidence""#,
        r#""destination": "file:///dev/null/illegal/destination/evidence""#,
    );
    let manifest = parse_manifest(&bad_dest_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("evidence-write-fail");
    let run_id = RunId::new("test-write-fail").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());
    let mut executor = DefaultStageExecutor;

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");

    // The primary verdict must be failed due to evidence write failure!
    match &outcome.verdict {
        Verdict::Failed {
            stage,
            code,
            message,
        } => {
            assert_eq!(*stage, Stage::Verification);
            assert_eq!(code, "evidence/write-failed");
            assert!(
                message.contains("failed to write recovery evidence"),
                "{message}"
            );
        }
        _ => panic!(
            "verdict should be Failed(evidence/write-failed), got {:?}",
            outcome.verdict
        ),
    }

    // Verify run_dir/evidence.json was updated to reflect the write failure
    let evidence_path = temp_dir.join("evidence.json");
    let evidence_content = fs::read_to_string(&evidence_path).expect("read run_dir evidence.json");
    let bundle = parse_evidence_bundle(&evidence_content).expect("parse evidence bundle");
    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::VerificationFailed
    );
    let v = bundle.verdict.expect("verdict must be present");
    assert_eq!(v.code.as_deref(), Some("evidence/write-failed"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_negative_secret_canary_eradicates_all_tokens_from_evidence() {
    let canary_password = "CANARY_SECRET_SUPER_PW_999888";
    let canary_token = "CANARY_TOKEN_BEARER_444555";

    unsafe {
        std::env::set_var("POSTGRES_PASSWORD", canary_password);
        std::env::set_var("SALVAGE_AUTH_TOKEN", canary_token);
    }

    let manifest_text =
        fs::read_to_string(fixture_path("manifest-valid-v1.json")).expect("read manifest fixture");
    // Inject canary into manifest owner
    let canary_manifest_text = manifest_text.replace(
        r#""owner": "recovery-drill""#,
        &format!(r#""owner": "recovery-drill-{}""#, canary_password),
    );
    let manifest = parse_manifest(&canary_manifest_text).expect("parse manifest");

    let temp_dir = unique_temp_dir("canary-leak-test");
    let run_id = RunId::new("test-canary-leak").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    let mut executor = MockTelemetryExecutor {
        observed_server: format!("PostgreSQL 16.4 password={canary_password}"),
        observed_client: format!("pg_restore Bearer {canary_token}"),
        verified_tables: vec!["users".to_owned()],
        fail_in_verification: false,
    };

    let outcome = RunEngine::start_run(config, manifest, &mut executor).expect("start run");
    assert!(outcome.verdict.is_passed());

    let evidence_path = temp_dir.join("evidence.json");
    let report_path = temp_dir.join("report.html");

    let json = fs::read_to_string(&evidence_path).expect("read evidence.json");
    let html = fs::read_to_string(&report_path).expect("read report.html");

    // Assert zero canary survivors in both JSON and HTML
    assert!(
        !json.contains(canary_password),
        "CRITICAL: canary password survived in evidence.json!"
    );
    assert!(
        !html.contains(canary_password),
        "CRITICAL: canary password survived in report.html!"
    );
    assert!(
        !json.contains(canary_token),
        "CRITICAL: canary token survived in evidence.json!"
    );
    assert!(
        !html.contains(canary_token),
        "CRITICAL: canary token survived in report.html!"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
