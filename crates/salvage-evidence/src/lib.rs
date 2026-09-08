//! Types, redaction, serialization, and report rendering for recovery evidence.
//!
//! Evidence is the durable, machine-readable audit trail of a recovery run.
//! JSON (`evidence.json`) is the canonical source of truth; HTML (`report.html`)
//! and text projections are generated deterministically from that source.

pub mod bundle;
pub mod redact;
pub mod report;

pub use bundle::{
    BackupEvidence, CleanupEvidence, EvidenceBundle, EvidenceCompleteness, EvidenceError,
    LimitsEvidence, ManifestEvidence, RunEvidence, SUPPORTED_SCHEMA_VERSION, StageTimingEvidence,
    TelemetryEvidence, ToolEvidence, VerdictClassification, VerdictEvidence, VersionEvidence,
    parse_evidence_bundle, parse_evidence_bundle_bytes,
};
pub use redact::{REDACTED_PLACEHOLDER, SecretRedactor};
pub use report::{render_html_report, render_text_report};

/// The result emitted by the workspace bootstrap check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckResult {
    status: &'static str,
    component: &'static str,
    postgres_adapter: &'static str,
}

impl CheckResult {
    /// Creates evidence for the workspace-level bootstrap check.
    pub const fn workspace(postgres_adapter: &'static str) -> Self {
        Self {
            status: "ok",
            component: "workspace",
            postgres_adapter,
        }
    }

    /// Serializes this fixed-schema result as one JSON object.
    pub fn to_json(self) -> String {
        format!(
            r#"{{"status":"{}","component":"{}","postgres_adapter":"{}"}}"#,
            self.status, self.component, self.postgres_adapter
        )
    }
}

#[cfg(test)]
mod tests {
    use super::CheckResult;

    #[test]
    fn serializes_the_workspace_schema() {
        assert_eq!(
            CheckResult::workspace("postgres").to_json(),
            r#"{"status":"ok","component":"workspace","postgres_adapter":"postgres"}"#
        );
    }
}
