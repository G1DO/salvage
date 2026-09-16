//! Resource caps for contract execution.
//!
//! Contract code is attacker-influenced: every execution enforces an output
//! byte cap, a row cap, a per-contract duration (from `timeout_ms`), an argv
//! allowlist, and no-shell spawning.

use std::collections::BTreeSet;

/// Default ceiling for captured output per contract (64 KiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// Default ceiling for rows per `sql` contract.
pub const DEFAULT_MAX_ROWS: usize = 1000;

/// Hermetic default argv0 allowlist for `exec` contracts.
///
/// Basename-matched, so both `sleep` and `/bin/sleep` are accepted. `sh`,
/// `bash`, `powershell`, and other shells are deliberately absent: spawning
/// never uses a shell.
pub fn default_allowed_argv0() -> BTreeSet<String> {
    [
        "true",
        "false",
        "echo",
        "sleep",
        "pg_isready",
        "psql",
        "cat",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Bounded-execution caps shared by all contract kinds.
#[derive(Debug, Clone)]
pub struct ContractCaps {
    /// Maximum captured output bytes kept per contract.
    pub max_output_bytes: usize,
    /// Maximum rows kept per `sql` contract.
    pub max_rows: usize,
    /// Allowed `argv[0]` entries (matched by full string or basename).
    pub allowed_exec_argv0: BTreeSet<String>,
}

impl Default for ContractCaps {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_rows: DEFAULT_MAX_ROWS,
            allowed_exec_argv0: default_allowed_argv0(),
        }
    }
}

impl ContractCaps {
    /// Creates caps with explicit bounds and the default argv allowlist.
    #[must_use]
    pub fn with_bounds(max_output_bytes: usize, max_rows: usize) -> Self {
        Self {
            max_output_bytes,
            max_rows,
            allowed_exec_argv0: default_allowed_argv0(),
        }
    }

    /// Returns true when `argv0` (or its basename) is allowlisted.
    #[must_use]
    pub fn is_exec_allowed(&self, argv0: &str) -> bool {
        if self.allowed_exec_argv0.contains(argv0) {
            return true;
        }
        let basename = argv0.rsplit('/').next().unwrap_or(argv0);
        let basename = basename.rsplit('\\').next().unwrap_or(basename);
        self.allowed_exec_argv0.contains(basename)
    }

    /// Truncates `text` to [`Self::max_output_bytes`] bytes on a char boundary.
    ///
    /// Returns the (possibly truncated) text plus whether truncation happened.
    #[must_use]
    pub fn truncate_output(&self, text: &str) -> (String, bool) {
        if text.len() <= self.max_output_bytes {
            return (text.to_owned(), false);
        }
        let mut end = self.max_output_bytes;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        (text[..end].to_owned(), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allowlist_has_no_shell() {
        let caps = ContractCaps::default();
        assert!(caps.is_exec_allowed("sleep"));
        assert!(caps.is_exec_allowed("/bin/sleep"));
        assert!(!caps.is_exec_allowed("sh"));
        assert!(!caps.is_exec_allowed("bash"));
        assert!(!caps.is_exec_allowed("rm"));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let caps = ContractCaps::with_bounds(4, 10);
        let (text, truncated) = caps.truncate_output("abcdef");
        assert_eq!(text, "abcd");
        assert!(truncated);
        let (emoji, truncated) = ContractCaps::with_bounds(3, 10).truncate_output("éclair");
        assert!(truncated);
        assert!(emoji.len() <= 3);
    }
}
