//! Stable result taxonomy for recovery contracts.
//!
//! A `ContractResult` is per-contract: `Passed` carries no code, anything else
//! carries exactly one `contract/*` code so callers can match without parsing
//! text. Aggregation (counts of passed/failed/timed-out/classified) is left to
//! the future evidence slice; this crate only classifies.

/// Contract timed out (hung fixture exceeds its `timeout_ms`).
pub const CODE_TIMEOUT: &str = "contract/timeout";
/// Contract spec is malformed (schema error, never a panic).
pub const CODE_MALFORMED: &str = "contract/malformed";
/// Contract output exceeded caps (truncated, see `ContractResult::truncated`).
pub const CODE_OVERSIZED: &str = "contract/oversized";
/// Contract backend crashed (panic, signal death, non-zero exec exit).
pub const CODE_CRASH: &str = "contract/crash";
/// Contract ran but its assertion failed (0 rows, non-2xx, output mismatch).
pub const CODE_ASSERT_FAILED: &str = "contract/assert-failed";

/// Pass/fail/timeout status for a single contract.
///
/// `Failed` always pairs with a `contract/*` code on the owning
/// [`ContractResult`]; `TimedOut` always pairs with [`CODE_TIMEOUT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractStatus {
    /// Contract assertion held within budget and caps.
    Passed,
    /// Contract ran (or was rejected) with a classified failure code.
    Failed,
    /// Contract exceeded its deadline and was terminated.
    TimedOut,
}

impl ContractStatus {
    /// Stable lowercase name (`passed` | `failed` | `timed-out`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::TimedOut => "timed-out",
        }
    }

    /// Returns true for [`ContractStatus::Passed`].
    #[must_use]
    pub const fn is_passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

impl std::fmt::Display for ContractStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-contract execution result.
///
/// `code` is `None` for passes and `Some(contract/*)` otherwise (`classified`).
/// `output` is redacted (via `SecretRedactor`) and truncated to caps before it
/// is stored here, so it is safe to assert on or persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractResult {
    /// Declared contract name.
    pub name: String,
    /// Contract kind (`sql` | `http` | `exec`).
    pub kind: &'static str,
    /// Pass/fail/timeout status.
    pub status: ContractStatus,
    /// Stable classification code (`contract/*`) when not passed.
    pub code: Option<String>,
    /// Redacted, cap-truncated captured output.
    pub output: String,
    /// True when `output` was cut to fit [`crate::ContractCaps`].
    pub truncated: bool,
    /// Wall-clock execution time in milliseconds.
    pub duration_ms: u64,
    /// Row count for `sql` contracts; otherwise 0.
    pub rows: usize,
    /// Spawned `exec` pid (`== pgid`) when a child was created.
    ///
    /// `None` for `sql`/`http` and for `exec` results rejected before spawn.
    /// Present on `exec` pass/fail/timeout so tests can assert the
    /// process group is gone after a timeout kill.
    pub pid: Option<u32>,
}

impl ContractResult {
    /// Builds a passing result.
    #[must_use]
    pub fn passed(
        name: impl Into<String>,
        kind: &'static str,
        output: String,
        duration_ms: u64,
        rows: usize,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            status: ContractStatus::Passed,
            code: None,
            output,
            truncated: false,
            duration_ms,
            rows,
            pid: None,
        }
    }

    /// Builds a classified failure result.
    #[must_use]
    pub fn failed(
        name: impl Into<String>,
        kind: &'static str,
        code: impl Into<String>,
        output: String,
        truncated: bool,
        duration_ms: u64,
        rows: usize,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            status: ContractStatus::Failed,
            code: Some(code.into()),
            output,
            truncated,
            duration_ms,
            rows,
            pid: None,
        }
    }

    /// Builds a timeout result (always [`CODE_TIMEOUT`]).
    #[must_use]
    pub fn timed_out(name: impl Into<String>, kind: &'static str, duration_ms: u64) -> Self {
        Self {
            name: name.into(),
            kind,
            status: ContractStatus::TimedOut,
            code: Some(CODE_TIMEOUT.to_owned()),
            output: String::new(),
            truncated: false,
            duration_ms,
            rows: 0,
            pid: None,
        }
    }

    /// Returns true when a `contract/*` classification code is present.
    #[must_use]
    pub fn is_classified(&self) -> bool {
        self.code.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_names_match_issue_taxonomy() {
        assert_eq!(ContractStatus::Passed.as_str(), "passed");
        assert_eq!(ContractStatus::Failed.as_str(), "failed");
        assert_eq!(ContractStatus::TimedOut.as_str(), "timed-out");
    }

    #[test]
    fn timeout_result_is_classified() {
        let result = ContractResult::timed_out("hang", "sql", 200);
        assert_eq!(result.status, ContractStatus::TimedOut);
        assert_eq!(result.code.as_deref(), Some(CODE_TIMEOUT));
        assert!(result.is_classified());
        assert!(!ContractResult::passed("ok", "sql", String::new(), 1, 0).is_classified());
    }
}
