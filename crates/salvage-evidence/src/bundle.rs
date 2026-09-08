//! Versioned recovery evidence bundle (`v1`) schema and validation.
//!
//! An evidence bundle is the durable, machine-readable audit trail of a recovery run.
//! It records run identity, declared and observed versions, effective limits, stage
//! timings, structured events, primary verdict, cleanup result, and explicit completeness.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The only schema version this crate implements.
pub const SUPPORTED_SCHEMA_VERSION: &str = "v1";

/// Explicit completeness status of an evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceCompleteness {
    /// The run concluded all stages and cleanup, producing a final terminal bundle.
    Complete,
    /// The run was interrupted or is in-flight; terminal record may be absent.
    Incomplete,
}

impl std::fmt::Display for EvidenceCompleteness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Complete => write!(f, "complete"),
            Self::Incomplete => write!(f, "incomplete"),
        }
    }
}

/// High-level verdict classification distinguishing verification, orchestration, and cleanup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictClassification {
    /// All stages and structural verification passed, and resource cleanup succeeded.
    Verified,
    /// Restore succeeded, but structural verification failed (Stage::Verification).
    VerificationFailed,
    /// Orchestration or pre-conditions failed before verification (Planning/Validation/Restore).
    OrchestrationFailed,
    /// Verification passed, but one or more owned resources failed to clean up.
    CleanupFailed,
    /// A stage or global deadline timed out.
    TimedOut,
    /// The run was cancelled by a signal or operator.
    Cancelled,
    /// The run did not reach a terminal state (interrupted or in-progress).
    Incomplete,
}

impl std::fmt::Display for VerdictClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::VerificationFailed => write!(f, "verification-failed"),
            Self::OrchestrationFailed => write!(f, "orchestration-failed"),
            Self::CleanupFailed => write!(f, "cleanup-failed"),
            Self::TimedOut => write!(f, "timed-out"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Incomplete => write!(f, "incomplete"),
        }
    }
}

/// Identity and timing of the recovery run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEvidence {
    /// Owning run identifier.
    pub run_id: String,
    /// Identity of the operator or service account.
    pub owner: String,
    /// Timestamp when run started (RFC3339).
    pub created_at: String,
    /// Timestamp when run concluded (RFC3339), if completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Total duration in milliseconds, if completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_duration_ms: Option<u64>,
}

/// Salvage tool identity and build version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEvidence {
    /// Name of the recovery tool (`"salvage"`).
    pub name: String,
    /// Package version string.
    pub version: String,
}

/// Snapshot of the input manifest and its canonical digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEvidence {
    /// Canonical SHA-256 hash of the effective manifest.
    pub canonical_hash: String,
    /// Redacted declared manifest content.
    pub declared: serde_json::Value,
}

/// Declared backup identity and restore configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEvidence {
    /// Content digest of the backup archive (`sha256:...`).
    pub digest: String,
    /// Restore input source (e.g. "local", "s3").
    pub source: String,
    /// Restore kind (e.g. "full", "incremental", "pitr").
    pub restore_type: String,
}

/// Declared and observed engine/binary versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionEvidence {
    /// Declared PostgreSQL version in manifest.
    pub declared_postgres: String,
    /// Observed server version from `SELECT version()`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_server: Option<String>,
    /// Observed client version from `pg_restore --version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_client: Option<String>,
}

/// Effective resource limits and stage deadlines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsEvidence {
    /// CPU limit in millicores.
    pub cpu_millicores: i64,
    /// Memory limit in MiB.
    pub memory_mib: i64,
    /// Disk limit in MiB.
    pub disk_mib: i64,
    /// Restore stage timeout in seconds.
    pub restore_seconds: i64,
    /// Verify stage timeout in seconds.
    pub verify_seconds: i64,
}

/// Timing and status of an individual execution stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageTimingEvidence {
    /// Stage name (e.g. "planning", "validation", "restore", "verification", "cleaning").
    pub stage: String,
    /// Stage outcome status ("passed", "failed", "timed-out", "cancelled", "running").
    pub status: String,
    /// Duration of stage in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Primary stage verdict of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictEvidence {
    /// Verdict outcome: "passed", "failed", "timed-out", "cancelled".
    pub verdict: String,
    /// Stage in which failure, timeout, or cancellation occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// Stable diagnostic code if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Detailed diagnostic message if failed or cancelled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Timeout seconds if timed out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i64>,
    /// Signal name if cancelled by signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Outcome of resource cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupEvidence {
    /// Cleanup status ("success", "failed").
    pub status: String,
    /// List of cleanup error diagnostics, empty on success.
    pub errors: Vec<String>,
}

/// Operational telemetry recorded by the restore adapter.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEvidence {
    /// Target database name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_dbname: Option<String>,
    /// Command line identity of restore tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_identity: Option<String>,
    /// User tables structurally verified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_tables: Vec<String>,
    /// Custom key-value telemetry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
}

/// A versioned recovery evidence bundle (`v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    /// Schema version; must be `"v1"`.
    pub schema_version: String,
    /// Completeness status: "complete" or "incomplete".
    pub completeness: EvidenceCompleteness,
    /// Run identity and timing.
    pub run: RunEvidence,
    /// Tool identity.
    pub tool: ToolEvidence,
    /// Manifest identity and snapshot.
    pub manifest: ManifestEvidence,
    /// Backup input identity.
    pub backup: BackupEvidence,
    /// Declared vs observed engine versions.
    pub versions: VersionEvidence,
    /// Resource and deadline limits.
    pub limits: LimitsEvidence,
    /// Per-stage timings.
    pub stages: Vec<StageTimingEvidence>,
    /// Primary verdict; absent if run was interrupted before terminal state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictEvidence>,
    /// Distinct failure / success classification.
    pub verdict_classification: VerdictClassification,
    /// Resource cleanup status; absent if run was interrupted before cleanup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupEvidence>,
    /// Structured append-only event log.
    pub events: Vec<serde_json::Value>,
    /// Operational telemetry from restore adapter.
    pub telemetry: TelemetryEvidence,
}

impl EvidenceBundle {
    /// Serializes this evidence bundle as compact canonical JSON.
    pub fn to_canonical_json(&self) -> Result<String, EvidenceError> {
        serde_json::to_string(self).map_err(|e| EvidenceError::Schema {
            message: e.to_string(),
        })
    }

    /// Serializes this evidence bundle as formatted JSON.
    pub fn to_pretty_json(&self) -> Result<String, EvidenceError> {
        serde_json::to_string_pretty(self).map_err(|e| EvidenceError::Schema {
            message: e.to_string(),
        })
    }

    /// Validates internal consistency of the bundle.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(EvidenceError::UnsupportedVersion {
                found: self.schema_version.clone(),
            });
        }

        if self.run.run_id.trim().is_empty() {
            return Err(EvidenceError::Schema {
                message: "run_id must not be blank".to_owned(),
            });
        }

        if self.completeness == EvidenceCompleteness::Complete {
            if self.verdict.is_none() {
                return Err(EvidenceError::Incomplete {
                    message: "complete bundle must contain a terminal verdict".to_owned(),
                });
            }
            if self.cleanup.is_none() {
                return Err(EvidenceError::Incomplete {
                    message: "complete bundle must contain cleanup status".to_owned(),
                });
            }
            if self.verdict_classification == VerdictClassification::Incomplete {
                return Err(EvidenceError::Incomplete {
                    message: "complete bundle cannot have incomplete classification".to_owned(),
                });
            }
        }

        Ok(())
    }
}

/// Errors occurring during evidence parsing, validation, or schema verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// Input is not well-formed JSON.
    Parse {
        /// Diagnostic message.
        message: String,
    },
    /// Well-formed JSON with the wrong schema or missing required fields.
    Schema {
        /// Diagnostic message.
        message: String,
    },
    /// Unsupported schema version.
    UnsupportedVersion {
        /// The version found in the document.
        found: String,
    },
    /// Bundle is incomplete or missing required terminal records.
    Incomplete {
        /// Diagnostic message.
        message: String,
    },
    /// Truncated or corrupted file.
    Corrupt {
        /// Diagnostic message.
        message: String,
    },
}

impl EvidenceError {
    /// Returns the stable diagnostic code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Parse { .. } => "evidence/parse",
            Self::Schema { .. } => "evidence/schema",
            Self::UnsupportedVersion { .. } => "evidence/unsupported-version",
            Self::Incomplete { .. } => "evidence/incomplete",
            Self::Corrupt { .. } => "evidence/corrupt",
        }
    }

    /// Returns human-readable error detail.
    pub fn message(&self) -> String {
        match self {
            Self::Parse { message }
            | Self::Schema { message }
            | Self::Incomplete { message }
            | Self::Corrupt { message } => message.clone(),
            Self::UnsupportedVersion { found } => {
                format!(
                    "unsupported schema_version {found:?}; expected {SUPPORTED_SCHEMA_VERSION:?}"
                )
            }
        }
    }
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for EvidenceError {}

/// Parses and validates an evidence bundle from a JSON string.
pub fn parse_evidence_bundle(json: &str) -> Result<EvidenceBundle, EvidenceError> {
    parse_evidence_bundle_bytes(json.as_bytes())
}

/// Parses and validates an evidence bundle from raw bytes.
pub fn parse_evidence_bundle_bytes(bytes: &[u8]) -> Result<EvidenceBundle, EvidenceError> {
    if bytes.is_empty() {
        return Err(EvidenceError::Corrupt {
            message: "evidence file is empty (0 bytes)".to_owned(),
        });
    }

    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => {
            return Err(EvidenceError::Parse {
                message: format!("evidence contains non-UTF-8 bytes: {e}"),
            });
        }
    };

    // First check version without full decode
    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: Option<String>,
    }

    if let Ok(probe) = serde_json::from_str::<VersionProbe>(text)
        && let Some(ver) = probe.schema_version
        && ver != SUPPORTED_SCHEMA_VERSION
    {
        return Err(EvidenceError::UnsupportedVersion { found: ver });
    }

    let bundle: EvidenceBundle = serde_json::from_str(text).map_err(|e| {
        if e.is_eof() {
            EvidenceError::Corrupt {
                message: format!("premature end of file: {e}"),
            }
        } else if e.is_syntax() {
            EvidenceError::Parse {
                message: format!("JSON syntax error: {e}"),
            }
        } else {
            EvidenceError::Schema {
                message: format!("schema error: {e}"),
            }
        }
    })?;

    bundle.validate()?;
    Ok(bundle)
}
