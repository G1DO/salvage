use std::fs;
use std::path::PathBuf;

use salvage_evidence::{
    EvidenceCompleteness, EvidenceError, VerdictClassification, parse_evidence_bundle,
    parse_evidence_bundle_bytes,
};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/evidence")
        .join(name)
}

#[test]
fn validates_verified_v1_golden_fixture() {
    let content = fs::read_to_string(fixture_path("evidence-valid-v1-verified.json"))
        .expect("read verified fixture");
    let bundle = parse_evidence_bundle(&content).expect("parse valid verified fixture");

    assert_eq!(bundle.schema_version, "v1");
    assert_eq!(bundle.completeness, EvidenceCompleteness::Complete);
    assert_eq!(bundle.run.run_id, "drill-20260908-001");
    assert_eq!(bundle.run.owner, "recovery-drill");
    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::Verified
    );
    assert!(bundle.verdict.is_some());
    assert_eq!(bundle.verdict.unwrap().verdict, "passed");
    assert!(bundle.cleanup.is_some());
    assert_eq!(bundle.cleanup.unwrap().status, "success");
    assert_eq!(bundle.stages.len(), 5);
    assert_eq!(bundle.telemetry.verified_tables.len(), 2);
}

#[test]
fn validates_failed_verification_v1_golden_fixture() {
    let content = fs::read_to_string(fixture_path("evidence-valid-v1-failed-verification.json"))
        .expect("read failed verification fixture");
    let bundle = parse_evidence_bundle(&content).expect("parse valid failed verification fixture");

    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::VerificationFailed
    );
    let verdict = bundle.verdict.expect("verdict present");
    assert_eq!(verdict.verdict, "failed");
    assert_eq!(verdict.stage.as_deref(), Some("verification"));
    assert_eq!(
        verdict.code.as_deref(),
        Some("restore/structural-verification-failed")
    );
}

#[test]
fn validates_failed_orchestration_v1_golden_fixture() {
    let content = fs::read_to_string(fixture_path("evidence-valid-v1-failed-orchestration.json"))
        .expect("read failed orchestration fixture");
    let bundle = parse_evidence_bundle(&content).expect("parse valid failed orchestration fixture");

    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::OrchestrationFailed
    );
    let verdict = bundle.verdict.expect("verdict present");
    assert_eq!(verdict.verdict, "failed");
    assert_eq!(verdict.stage.as_deref(), Some("validation"));
    assert_eq!(verdict.code.as_deref(), Some("restore/unsupported-version"));
}

#[test]
fn validates_failed_cleanup_v1_golden_fixture() {
    let content = fs::read_to_string(fixture_path("evidence-valid-v1-failed-cleanup.json"))
        .expect("read failed cleanup fixture");
    let bundle = parse_evidence_bundle(&content).expect("parse valid failed cleanup fixture");

    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::CleanupFailed
    );
    let cleanup = bundle.cleanup.expect("cleanup present");
    assert_eq!(cleanup.status, "failed");
    assert_eq!(cleanup.errors.len(), 1);
    assert!(cleanup.errors[0].contains("failed to unmount scratch directory"));
}

#[test]
fn validates_incomplete_v1_golden_fixture() {
    let content = fs::read_to_string(fixture_path("evidence-valid-v1-incomplete.json"))
        .expect("read incomplete fixture");
    let bundle = parse_evidence_bundle(&content).expect("parse incomplete fixture");

    assert_eq!(bundle.completeness, EvidenceCompleteness::Incomplete);
    assert_eq!(
        bundle.verdict_classification,
        VerdictClassification::Incomplete
    );
    assert!(bundle.verdict.is_none());
}

#[test]
fn rejects_unsupported_schema_version() {
    let content = fs::read_to_string(fixture_path("evidence-invalid-unsupported-version.json"))
        .expect("read unsupported version fixture");
    let err = parse_evidence_bundle(&content).expect_err("should reject unsupported version");

    match err {
        EvidenceError::UnsupportedVersion { found } => {
            assert_eq!(found, "v99");
        }
        _ => panic!("expected UnsupportedVersion error, got {:?}", err),
    }
}

#[test]
fn rejects_corrupt_truncated_file() {
    let content = fs::read_to_string(fixture_path("evidence-invalid-corrupt.json"))
        .expect("read corrupt fixture");
    let err = parse_evidence_bundle(&content).expect_err("should reject corrupt file");

    match err {
        EvidenceError::Corrupt { .. } | EvidenceError::Parse { .. } => {}
        _ => panic!("expected Corrupt or Parse error, got {:?}", err),
    }
}

#[test]
fn rejects_empty_file() {
    let err = parse_evidence_bundle_bytes(&[]).expect_err("should reject empty bytes");
    assert!(matches!(err, EvidenceError::Corrupt { .. }));
}

#[test]
fn v1_bundle_without_artifact_is_byte_identical() {
    let content =
        fs::read_to_string(fixture_path("evidence-valid-v1-verified.json")).expect("read");
    let bundle = parse_evidence_bundle(&content).expect("parse");
    assert!(bundle.artifact.is_none());
    assert!(bundle.limits.boot_seconds.is_none());
    let json = bundle.to_canonical_json().expect("ser");
    assert!(!json.contains("artifact"));
    assert!(!json.contains("boot_seconds"));
    let again = parse_evidence_bundle(&json).expect("reparse");
    assert_eq!(bundle, again);
}
