//! Evidence bundle construction, secret redaction, and persistence coordination.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use salvage_evidence::{
    ArtifactEvidence, BackupEvidence, CleanupEvidence, ContractEvidence, EvidenceBundle,
    EvidenceCompleteness, IsolationEvidence, LimitsEvidence, ManifestEvidence, RunEvidence,
    SUPPORTED_SCHEMA_VERSION, SecretRedactor, StageTimingEvidence, TelemetryEvidence, ToolEvidence,
    VerdictClassification, VerdictEvidence, VersionEvidence, render_html_report,
};

use super::journal::now_rfc3339;
use super::resource::RunId;
use super::state::{CleanupStatus, Stage, Verdict};
use crate::manifest::Manifest;

/// Operational telemetry collected during stage execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunTelemetry {
    /// Server version reported by the running database instance.
    pub observed_server_version: Option<String>,
    /// Client binary version string.
    pub observed_client_version: Option<String>,
    /// Command line identity of the restore tool.
    pub command_identity: Option<String>,
    /// Target database name.
    pub target_dbname: Option<String>,
    /// Application version observed by the boot stage (v2 manifests only).
    pub observed_app_version: Option<String>,
    /// OCI artifact digest observed by the boot stage (v2 manifests only).
    pub observed_artifact_digest: Option<String>,
    /// Declared OCI artifact digest from v2 manifest (None on v1).
    pub declared_artifact_digest: Option<String>,
    /// Declared OCI repository from v2 manifest (None on v1 or repository-less).
    pub artifact_repository: Option<String>,
    /// Resolved image ID after ensure_image (None until boot).
    pub artifact_resolved_image_id: Option<String>,
    /// Declared boot deadline seconds from v2 manifest (None on v1).
    pub boot_seconds: Option<i64>,
    /// App-owned contract results for v3 runs (`None` on v1/v2 where no
    /// contract stage exists; `Some` on v3, possibly empty on early failure).
    /// `None` preserves legacy `Verified` semantics; `Some` gates `Verified`
    /// on non-empty all-passed (O3-4, ADR 0005).
    pub contracts: Option<Vec<ContractEvidence>>,
    /// Boot isolation block for runs with isolation (`None` when isolation
    /// did not run, e.g. v1 or pre-boot failure).
    pub isolation: Option<IsolationEvidence>,
    /// Tables structurally verified in the target database.
    pub verified_tables: Vec<String>,
    /// Additional custom key-value telemetry.
    pub extra: BTreeMap<String, String>,
}

/// Recorded timing and status for a stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageTimingRecord {
    /// Lifecycle stage or phase name.
    pub stage: String,
    /// Outcome status string.
    pub status: String,
    /// Elapsed duration in milliseconds.
    pub duration_ms: Option<u64>,
}

/// Resolves an evidence destination string (e.g. `file:///tmp/salvage-evidence` or `/tmp/evidence`)
/// into a local filesystem PathBuf. Returns `None` for remote schemes (e.g. `s3://`).
pub fn resolve_destination_path(destination: &str) -> Option<PathBuf> {
    let trimmed = destination.trim();
    if let Some(stripped) = trimmed.strip_prefix("file://") {
        Some(PathBuf::from(stripped))
    } else if trimmed.contains("://") {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Classifies a run outcome into a high-level verdict category, distinguishing verification
/// from orchestration and cleanup failures.
///
/// O3-4 contract/isolation gating (ADR 0005):
/// - `contracts == None`: legacy v1/v2 path, no contract stage; `Verified`
///   preserves its old meaning (health/readiness passed).
/// - `contracts == Some(list)`: v3 path; `Verified` requires non-empty and
///   all `status == "passed"` with no `code`. Empty or any failure while the
///   stage verdict is `Passed` demotes to `VerificationFailed`; a stage
///   verdict already carrying `contract/...` also maps to
///   `VerificationFailed`. A green health/readiness endpoint alone can never
///   verify on v3.
/// - Any stage failure whose `code` starts with `isolation/` maps to the new
///   `IsolationFailed`, which takes precedence over contract gating and
///   `BootFailed`.
pub fn classify_verdict(
    verdict: Option<&Verdict>,
    cleanup: Option<&CleanupStatus>,
    completeness: EvidenceCompleteness,
    contracts: Option<&[ContractEvidence]>,
    isolation: Option<&IsolationEvidence>,
) -> VerdictClassification {
    if completeness == EvidenceCompleteness::Incomplete {
        return VerdictClassification::Incomplete;
    }

    // Isolation failures dominate: explicit block check plus verdict-code
    // check so hand-built bundles with `isolation/...` codes classify too.
    let verdict_is_isolation = matches!(
        verdict,
        Some(Verdict::Failed { code, .. }) if code.starts_with("isolation/")
    );
    let isolation_block_signals_failure = isolation.map(|iso| iso.egress.allowed).unwrap_or(false);
    if verdict_is_isolation || isolation_block_signals_failure {
        return VerdictClassification::IsolationFailed;
    }

    match verdict {
        Some(Verdict::Passed) => {
            if let Some(list) = contracts {
                let all_passed = !list.is_empty()
                    && list
                        .iter()
                        .all(|c| c.status == "passed" && c.code.is_none());
                if !all_passed {
                    return VerdictClassification::VerificationFailed;
                }
            }
            if let Some(CleanupStatus::Failed { .. }) = cleanup {
                VerdictClassification::CleanupFailed
            } else {
                VerdictClassification::Verified
            }
        }
        Some(Verdict::Failed { stage, code, .. }) => {
            if code.starts_with("contract/") {
                VerdictClassification::VerificationFailed
            } else if code.starts_with("isolation/") {
                VerdictClassification::IsolationFailed
            } else if *stage == Stage::Boot {
                VerdictClassification::BootFailed
            } else if *stage == Stage::Verification || *stage == Stage::Contracts {
                VerdictClassification::VerificationFailed
            } else {
                VerdictClassification::OrchestrationFailed
            }
        }
        Some(Verdict::TimedOut { .. }) => VerdictClassification::TimedOut,
        Some(Verdict::Cancelled { .. }) => VerdictClassification::Cancelled,
        None => VerdictClassification::Incomplete,
    }
}

fn build_artifact_evidence(telemetry: &RunTelemetry) -> Option<ArtifactEvidence> {
    let digest = telemetry
        .declared_artifact_digest
        .clone()
        .or_else(|| telemetry.observed_artifact_digest.clone())?;
    Some(ArtifactEvidence {
        digest,
        repository: telemetry.artifact_repository.clone(),
        resolved_image_id: telemetry.artifact_resolved_image_id.clone(),
        observed_version: telemetry.observed_app_version.clone(),
    })
}

/// Builds an EvidenceBundle from raw run components.
#[allow(clippy::too_many_arguments)]
pub fn build_evidence_bundle(
    run_id: &RunId,
    manifest: &Manifest,
    manifest_hash: &str,
    created_at: &str,
    completed_at: Option<String>,
    total_duration_ms: Option<u64>,
    stages: &[StageTimingRecord],
    verdict: Option<&Verdict>,
    cleanup: Option<&CleanupStatus>,
    events: Vec<serde_json::Value>,
    telemetry: &RunTelemetry,
    completeness: EvidenceCompleteness,
) -> EvidenceBundle {
    let stage_evidence = stages
        .iter()
        .map(|s| StageTimingEvidence {
            stage: s.stage.clone(),
            status: s.status.clone(),
            duration_ms: s.duration_ms,
        })
        .collect();

    let verdict_evidence = verdict.map(|v| match v {
        Verdict::Passed => VerdictEvidence {
            verdict: "passed".to_owned(),
            stage: None,
            code: None,
            message: None,
            timeout_seconds: None,
            signal: None,
        },
        Verdict::Failed {
            stage,
            code,
            message,
        } => VerdictEvidence {
            verdict: "failed".to_owned(),
            stage: Some(stage.to_string()),
            code: Some(code.clone()),
            message: Some(message.clone()),
            timeout_seconds: None,
            signal: None,
        },
        Verdict::TimedOut {
            stage,
            timeout_seconds,
        } => VerdictEvidence {
            verdict: "timed-out".to_owned(),
            stage: Some(stage.to_string()),
            code: None,
            message: None,
            timeout_seconds: Some(*timeout_seconds),
            signal: None,
        },
        Verdict::Cancelled {
            stage,
            signal,
            reason,
        } => VerdictEvidence {
            verdict: "cancelled".to_owned(),
            stage: Some(stage.to_string()),
            code: None,
            message: Some(reason.clone()),
            timeout_seconds: None,
            signal: signal.clone(),
        },
    });

    let cleanup_evidence = cleanup.map(|c| match c {
        CleanupStatus::Success => CleanupEvidence {
            status: "success".to_owned(),
            errors: Vec::new(),
        },
        CleanupStatus::Failed { errors } => CleanupEvidence {
            status: "failed".to_owned(),
            errors: errors.clone(),
        },
    });

    let verdict_classification = classify_verdict(
        verdict,
        cleanup,
        completeness,
        telemetry.contracts.as_deref(),
        telemetry.isolation.as_ref(),
    );

    let declared_manifest_value = serde_json::to_value(manifest).unwrap_or(serde_json::Value::Null);

    let restore_type_str = serde_json::to_string(&manifest.restore.restore_type)
        .unwrap_or_default()
        .trim_matches('"')
        .to_owned();

    let restore_source_str = serde_json::to_string(&manifest.restore.source)
        .unwrap_or_default()
        .trim_matches('"')
        .to_owned();

    let mut bundle = EvidenceBundle {
        schema_version: SUPPORTED_SCHEMA_VERSION.to_owned(),
        completeness,
        run: RunEvidence {
            run_id: run_id.to_string(),
            owner: manifest.run.owner.clone(),
            created_at: created_at.to_owned(),
            completed_at,
            total_duration_ms,
        },
        tool: ToolEvidence {
            name: "salvage".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        manifest: ManifestEvidence {
            canonical_hash: manifest_hash.to_owned(),
            declared: declared_manifest_value,
        },
        backup: BackupEvidence {
            digest: manifest.backup.digest.clone(),
            source: restore_source_str,
            restore_type: restore_type_str,
        },
        versions: VersionEvidence {
            declared_postgres: manifest.postgres.version.clone(),
            observed_server: telemetry.observed_server_version.clone(),
            observed_client: telemetry.observed_client_version.clone(),
        },
        limits: LimitsEvidence {
            cpu_millicores: manifest.limits.cpu_millicores,
            memory_mib: manifest.limits.memory_mib,
            disk_mib: manifest.limits.disk_mib,
            restore_seconds: manifest.deadlines.restore_seconds,
            verify_seconds: manifest.deadlines.verify_seconds,
            boot_seconds: telemetry.boot_seconds,
        },
        artifact: build_artifact_evidence(telemetry),
        stages: stage_evidence,
        contracts: telemetry.contracts.clone(),
        isolation: telemetry.isolation.clone(),
        verdict: verdict_evidence,
        verdict_classification,
        cleanup: cleanup_evidence,
        events,
        telemetry: TelemetryEvidence {
            target_dbname: telemetry.target_dbname.clone(),
            command_identity: telemetry.command_identity.clone(),
            observed_app_version: telemetry.observed_app_version.clone(),
            observed_artifact_digest: telemetry.observed_artifact_digest.clone(),
            verified_tables: telemetry.verified_tables.clone(),
            custom: telemetry.extra.clone(),
        },
    };

    // Apply secret redaction across the entire bundle
    let mut redactor = SecretRedactor::new();
    redactor.add_env_secrets();
    redactor.redact_bundle(&mut bundle);

    bundle
}

/// Atomically persists an evidence bundle and static report into a destination directory.
pub fn persist_evidence(bundle: &EvidenceBundle, destination_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destination_dir)?;

    let json_content = bundle.to_pretty_json().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to serialize evidence: {e}"),
        )
    })?;

    let html_content = render_html_report(bundle);

    // Write evidence.json atomically via temporary file
    let tmp_json_path = destination_dir.join(format!(
        ".evidence-{}-{}.json.tmp",
        bundle.run.run_id,
        std::process::id()
    ));
    let final_json_path = destination_dir.join("evidence.json");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_json_path)?;
        file.write_all(json_content.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(tmp_json_path, final_json_path)?;

    // Write report.html atomically via temporary file
    let tmp_html_path = destination_dir.join(format!(
        ".report-{}-{}.html.tmp",
        bundle.run.run_id,
        std::process::id()
    ));
    let final_html_path = destination_dir.join("report.html");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_html_path)?;
        file.write_all(html_content.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(tmp_html_path, final_html_path)?;

    Ok(())
}

/// Writes initial incomplete evidence at the beginning of a run.
pub fn write_initial_incomplete_evidence(
    run_id: &RunId,
    manifest: &Manifest,
    manifest_hash: &str,
    run_dir: &Path,
) -> std::io::Result<()> {
    let now = now_rfc3339();
    let stages = vec![StageTimingRecord {
        stage: "planning".to_owned(),
        status: "passed".to_owned(),
        duration_ms: None,
    }];

    let bundle = build_evidence_bundle(
        run_id,
        manifest,
        manifest_hash,
        &now,
        None,
        None,
        &stages,
        None,
        None,
        Vec::new(),
        &RunTelemetry::default(),
        EvidenceCompleteness::Incomplete,
    );

    persist_evidence(&bundle, run_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passed_contract(name: &str) -> ContractEvidence {
        ContractEvidence {
            name: name.to_owned(),
            kind: "sql".to_owned(),
            status: "passed".to_owned(),
            code: None,
            output: "1".to_owned(),
            truncated: false,
            duration_ms: Some(1),
            rows: 1,
        }
    }

    fn failed_contract(name: &str) -> ContractEvidence {
        ContractEvidence {
            name: name.to_owned(),
            kind: "http".to_owned(),
            status: "failed".to_owned(),
            code: Some("contract/assert-failed".to_owned()),
            output: "non-2xx".to_owned(),
            truncated: false,
            duration_ms: Some(1),
            rows: 0,
        }
    }

    #[test]
    fn legacy_none_preserves_verified() {
        let c = classify_verdict(
            Some(&Verdict::Passed),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            None,
            None,
        );
        assert_eq!(c, VerdictClassification::Verified);
    }

    #[test]
    fn health_pass_plus_contracts_fail_is_not_verified() {
        let contracts = vec![passed_contract("a"), failed_contract("b")];
        let c = classify_verdict(
            Some(&Verdict::Passed),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            Some(&contracts),
            None,
        );
        assert_eq!(c, VerdictClassification::VerificationFailed);
    }

    #[test]
    fn empty_contracts_is_not_verified() {
        let empty: Vec<ContractEvidence> = vec![];
        let c = classify_verdict(
            Some(&Verdict::Passed),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            Some(&empty),
            None,
        );
        assert_eq!(c, VerdictClassification::VerificationFailed);
    }

    #[test]
    fn all_passed_contracts_verify() {
        let contracts = vec![passed_contract("a"), passed_contract("b")];
        let c = classify_verdict(
            Some(&Verdict::Passed),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            Some(&contracts),
            None,
        );
        assert_eq!(c, VerdictClassification::Verified);
    }

    #[test]
    fn contract_code_maps_to_verification_failed() {
        let v = Verdict::failed(Stage::Contracts, "contract/timeout", "hung");
        let c = classify_verdict(
            Some(&v),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            Some(&[failed_contract("x")]),
            None,
        );
        assert_eq!(c, VerdictClassification::VerificationFailed);
    }

    #[test]
    fn isolation_code_maps_to_isolation_failed() {
        let v = Verdict::failed(Stage::Boot, "isolation/egress-allowed", "reachable");
        let c = classify_verdict(
            Some(&v),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            Some(&[passed_contract("a")]),
            None,
        );
        assert_eq!(c, VerdictClassification::IsolationFailed);

        let v2 = Verdict::failed(Stage::Boot, "isolation/policy-failed", "no docker");
        let c2 = classify_verdict(
            Some(&v2),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            None,
            None,
        );
        assert_eq!(c2, VerdictClassification::IsolationFailed);
    }

    #[test]
    fn isolation_allowed_block_forces_isolation_failed_even_on_pass() {
        let iso = IsolationEvidence {
            network: Some("salvage-net-x".to_owned()),
            allowlist: vec![],
            egress: salvage_evidence::EgressEvidence {
                host: "prod-forbidden.invalid".to_owned(),
                allowed: true,
                detail: "reachable".to_owned(),
            },
        };
        let c = classify_verdict(
            Some(&Verdict::Passed),
            Some(&CleanupStatus::Success),
            EvidenceCompleteness::Complete,
            Some(&[passed_contract("a")]),
            Some(&iso),
        );
        assert_eq!(c, VerdictClassification::IsolationFailed);
    }
}
