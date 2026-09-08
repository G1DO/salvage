//! Evidence bundle construction, secret redaction, and persistence coordination.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use salvage_evidence::{
    BackupEvidence, CleanupEvidence, EvidenceBundle, EvidenceCompleteness, LimitsEvidence,
    ManifestEvidence, RunEvidence, SUPPORTED_SCHEMA_VERSION, SecretRedactor, StageTimingEvidence,
    TelemetryEvidence, ToolEvidence, VerdictClassification, VerdictEvidence, VersionEvidence,
    render_html_report,
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
pub fn classify_verdict(
    verdict: Option<&Verdict>,
    cleanup: Option<&CleanupStatus>,
    completeness: EvidenceCompleteness,
) -> VerdictClassification {
    if completeness == EvidenceCompleteness::Incomplete {
        return VerdictClassification::Incomplete;
    }

    match verdict {
        Some(Verdict::Passed) => {
            if let Some(CleanupStatus::Failed { .. }) = cleanup {
                VerdictClassification::CleanupFailed
            } else {
                VerdictClassification::Verified
            }
        }
        Some(Verdict::Failed { stage, .. }) => {
            if *stage == Stage::Verification {
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

    let verdict_classification = classify_verdict(verdict, cleanup, completeness);

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
        },
        stages: stage_evidence,
        verdict: verdict_evidence,
        verdict_classification,
        cleanup: cleanup_evidence,
        events,
        telemetry: TelemetryEvidence {
            target_dbname: telemetry.target_dbname.clone(),
            command_identity: telemetry.command_identity.clone(),
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
