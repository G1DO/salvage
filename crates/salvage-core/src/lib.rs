//! Core domain and lifecycle entry points.

pub mod lifecycle;
pub mod manifest;

use salvage_evidence::CheckResult;

/// Runs the non-invasive workspace bootstrap check.
pub fn workspace_check() -> CheckResult {
    CheckResult::workspace("postgres")
}

#[cfg(test)]
mod tests {
    use super::workspace_check;

    #[test]
    fn reports_the_bootstrap_boundaries() {
        assert_eq!(
            workspace_check().to_json(),
            r#"{"status":"ok","component":"workspace","postgres_adapter":"postgres"}"#
        );
    }
}
