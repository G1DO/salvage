//! Types and serialization for machine-readable bootstrap evidence.

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
