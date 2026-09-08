//! Secret redaction engine for recovery evidence and diagnostic logs.
//!
//! Redacts sensitive tokens, passwords, private keys, authorization headers,
//! and known canary strings from manifests, command lines, environment,
//! database errors, and rendered reports before persistence.

use serde_json::Value;
use std::collections::BTreeSet;

use crate::bundle::EvidenceBundle;

/// Redaction placeholder replacement string.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Engine for detecting and masking secrets in evidence and logs.
#[derive(Debug, Clone, Default)]
pub struct SecretRedactor {
    /// Exact secret strings to search and replace.
    exact_secrets: BTreeSet<String>,
}

impl SecretRedactor {
    /// Creates a new redactor with default rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a known secret or canary string for redaction.
    /// Secrets shorter than 3 characters are ignored to prevent false positives.
    pub fn add_secret(&mut self, secret: impl Into<String>) -> &mut Self {
        let s = secret.into();
        let trimmed = s.trim();
        if trimmed.len() >= 3 {
            self.exact_secrets.insert(trimmed.to_owned());
        }
        self
    }

    /// Automatically scans the process environment for secret-like variable names
    /// and registers their values for redaction.
    pub fn add_env_secrets(&mut self) -> &mut Self {
        for (key, val) in std::env::vars() {
            let upper = key.to_uppercase();
            if upper.contains("PASS")
                || upper.contains("SECRET")
                || upper.contains("TOKEN")
                || upper.contains("KEY")
                || upper.contains("AUTH")
                || upper.contains("CREDENTIAL")
            {
                self.add_secret(val);
            }
        }
        self
    }

    /// Redacts all recognized secrets from a string slice.
    pub fn redact_text(&self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }

        let mut out = input.to_owned();

        // 1. Redact exact registered secrets first (e.g. canaries, env values)
        for secret in &self.exact_secrets {
            if out.contains(secret) {
                out = out.replace(secret, REDACTED_PLACEHOLDER);
            }
        }

        // 2. Redact URI passwords: scheme://user:PASSWORD@host
        out = redact_uri_passwords(&out);

        // 3. Redact key-value secrets in text (e.g. password=..., secret: ...)
        out = redact_key_value_secrets(&out);

        // 4. Redact Bearer / Basic tokens
        out = redact_auth_headers(&out);

        // 5. Redact PEM private keys
        out = redact_pem_keys(&out);

        // 6. Redact AWS access keys
        out = redact_aws_keys(&out);

        // 7. Second pass for registered secrets in case regex replacements exposed them
        for secret in &self.exact_secrets {
            if out.contains(secret) {
                out = out.replace(secret, REDACTED_PLACEHOLDER);
            }
        }

        out
    }

    /// Recursively redacts secrets from a serde_json::Value in-place.
    pub fn redact_value(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                *s = self.redact_text(s);
            }
            Value::Array(arr) => {
                for item in arr {
                    self.redact_value(item);
                }
            }
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    let key_lower = key.to_lowercase();
                    if is_sensitive_key(&key_lower) {
                        match val {
                            Value::String(_) => {
                                *val = Value::String(REDACTED_PLACEHOLDER.to_owned());
                            }
                            Value::Object(_) | Value::Array(_) => {
                                self.redact_value(val);
                            }
                            _ => {
                                *val = Value::String(REDACTED_PLACEHOLDER.to_owned());
                            }
                        }
                    } else {
                        self.redact_value(val);
                    }
                }
            }
            _ => {}
        }
    }

    /// Redacts all components of an evidence bundle in-place.
    pub fn redact_bundle(&self, bundle: &mut EvidenceBundle) {
        // Redact manifest declared JSON
        self.redact_value(&mut bundle.manifest.declared);

        // Redact run identity
        bundle.run.owner = self.redact_text(&bundle.run.owner);

        // Redact backup source
        bundle.backup.source = self.redact_text(&bundle.backup.source);

        // Redact versions
        if let Some(ref mut server) = bundle.versions.observed_server {
            *server = self.redact_text(server);
        }
        if let Some(ref mut client) = bundle.versions.observed_client {
            *client = self.redact_text(client);
        }

        // Redact verdict details
        if let Some(ref mut v) = bundle.verdict {
            if let Some(ref mut msg) = v.message {
                *msg = self.redact_text(msg);
            }
            if let Some(ref mut code) = v.code {
                *code = self.redact_text(code);
            }
        }

        // Redact cleanup errors
        if let Some(ref mut cleanup) = bundle.cleanup {
            for err in &mut cleanup.errors {
                *err = self.redact_text(err);
            }
        }

        // Redact events
        for event in &mut bundle.events {
            self.redact_value(event);
        }

        // Redact telemetry
        if let Some(ref mut cmd) = bundle.telemetry.command_identity {
            *cmd = self.redact_text(cmd);
        }
        if let Some(ref mut db) = bundle.telemetry.target_dbname {
            *db = self.redact_text(db);
        }
        for table in &mut bundle.telemetry.verified_tables {
            *table = self.redact_text(table);
        }
        for (_, val) in bundle.telemetry.custom.iter_mut() {
            *val = self.redact_text(val);
        }
    }
}

fn is_sensitive_key(key: &str) -> bool {
    key.contains("password")
        || key.contains("passwd")
        || key.contains("secret")
        || key.contains("token")
        || key.contains("api_key")
        || key.contains("access_key")
        || key.contains("auth")
        || key.contains("credential")
        || key.contains("private_key")
}

fn redact_uri_passwords(text: &str) -> String {
    // Looks for `://<user>:<pass>@`
    let mut result = String::with_capacity(text.len());
    let mut remainder = text;

    while let Some(proto_idx) = remainder.find("://") {
        let after_proto = proto_idx + 3;
        result.push_str(&remainder[..after_proto]);
        let search_area = &remainder[after_proto..];

        if let Some(at_idx) = search_area.find('@') {
            let authority = &search_area[..at_idx];
            // Don't cross spaces, line breaks, paths, or queries
            if !authority.contains(' ')
                && !authority.contains('\n')
                && !authority.contains('/')
                && !authority.contains('?')
                && let Some(colon_idx) = authority.find(':')
            {
                let user = &authority[..colon_idx];
                result.push_str(user);
                result.push(':');
                result.push_str(REDACTED_PLACEHOLDER);
                result.push('@');
                remainder = &search_area[at_idx + 1..];
                continue;
            }
        }

        // If not a matching user:pass authority, just advance past `://`
        remainder = &remainder[after_proto..];
    }

    result.push_str(remainder);
    result
}

fn redact_key_value_secrets(text: &str) -> String {
    let sensitive_keys = [
        "password",
        "passwd",
        "secret",
        "secret_key",
        "token",
        "api_key",
        "access_key",
        "pgpassword",
    ];

    let mut result = text.to_owned();

    for key in sensitive_keys {
        // Match patterns like: key=VALUE, key: VALUE, key = "VALUE"
        // Case-insensitive search
        let mut search_from = 0;
        while search_from < result.len() {
            let slice = &result[search_from..];
            let found_offset = match find_case_insensitive(slice, key) {
                Some(idx) => idx,
                None => break,
            };

            let key_start = search_from + found_offset;
            let after_key = key_start + key.len();

            // Ensure word boundary before key
            if key_start > 0 {
                let prev = result[..key_start].chars().next_back().unwrap();
                if prev.is_alphanumeric() || prev == '_' {
                    search_from = after_key;
                    continue;
                }
            }

            // Look for delimiter: =, :, or whitespace followed by = or :
            let rest = &result[after_key..];
            let trimmed_rest = rest.trim_start();
            let leading_ws = rest.len() - trimmed_rest.len();

            if trimmed_rest.starts_with('=') || trimmed_rest.starts_with(':') {
                let delim_char_len = 1;
                let val_start_relative = after_key + leading_ws + delim_char_len;
                let val_area = &result[val_start_relative..];
                let val_trimmed = val_area.trim_start();
                let ws_after_delim = val_area.len() - val_trimmed.len();
                let actual_val_start = val_start_relative + ws_after_delim;

                // Value could be quoted ("...", '...') or bare word
                let (val_end, is_quoted) = if let Some(q) = val_trimmed.chars().next()
                    && (q == '"' || q == '\'')
                {
                    let inner = &val_trimmed[1..];
                    if let Some(close_q) = inner.find(q) {
                        (actual_val_start + 1 + close_q + 1, true)
                    } else {
                        (actual_val_start + val_trimmed.len(), false)
                    }
                } else {
                    let end = val_trimmed
                        .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '&')
                        .unwrap_or(val_trimmed.len());
                    (actual_val_start + end, false)
                };

                let replacement = if is_quoted {
                    format!("\"{REDACTED_PLACEHOLDER}\"")
                } else {
                    REDACTED_PLACEHOLDER.to_owned()
                };

                let prefix = &result[..actual_val_start];
                let suffix = &result[val_end..];
                let new_result = format!("{prefix}{replacement}{suffix}");
                search_from = prefix.len() + replacement.len();
                result = new_result;
            } else {
                search_from = after_key;
            }
        }
    }

    result
}

fn redact_auth_headers(text: &str) -> String {
    let mut result = text.to_owned();

    for auth_type in ["Bearer", "Basic"] {
        let mut search_from = 0;
        while search_from < result.len() {
            let slice = &result[search_from..];
            let found_idx = match find_case_insensitive(slice, auth_type) {
                Some(idx) => idx,
                None => break,
            };

            let auth_start = search_from + found_idx;
            let after_auth = auth_start + auth_type.len();

            let rest = &result[after_auth..];
            if rest.starts_with(' ') {
                let val_area = rest.trim_start();
                let ws_len = rest.len() - val_area.len();
                let actual_val_start = after_auth + ws_len;

                let end = val_area
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .unwrap_or(val_area.len());

                if end > 0 {
                    let val_end = actual_val_start + end;
                    let prefix = &result[..actual_val_start];
                    let suffix = &result[val_end..];
                    let new_result = format!("{prefix}{REDACTED_PLACEHOLDER}{suffix}");
                    search_from = prefix.len() + REDACTED_PLACEHOLDER.len();
                    result = new_result;
                    continue;
                }
            }

            search_from = after_auth;
        }
    }

    result
}

fn redact_pem_keys(text: &str) -> String {
    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";

    let mut result = String::with_capacity(text.len());
    let mut remainder = text;

    while let Some(start_idx) = remainder.find(begin_marker) {
        result.push_str(&remainder[..start_idx]);
        let after_start = &remainder[start_idx..];

        if let Some(end_idx) = after_start.find(end_marker) {
            let after_end = &after_start[end_idx..];
            if let Some(hyphen_idx) = after_end[9..].find("-----") {
                let full_end = end_idx + 9 + hyphen_idx + 5;
                result.push_str("[REDACTED PRIVATE KEY]");
                remainder = &after_start[full_end..];
                continue;
            }
        }

        result.push_str(begin_marker);
        remainder = &after_start[begin_marker.len()..];
    }

    result.push_str(remainder);
    result
}

fn redact_aws_keys(text: &str) -> String {
    let mut result = text.to_owned();
    let mut search_from = 0;

    while search_from < result.len() {
        let slice = &result[search_from..];
        if let Some(akia_idx) = slice.find("AKIA") {
            let abs_start = search_from + akia_idx;
            let candidate = &result[abs_start..];
            if candidate.len() >= 20 {
                let key_candidate = &candidate[..20];
                if key_candidate[4..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() && c.is_ascii_uppercase())
                {
                    let prefix = result[..abs_start].to_owned();
                    let suffix = result[abs_start + 20..].to_owned();
                    let new_prefix_len = prefix.len() + REDACTED_PLACEHOLDER.len();
                    result = format!("{prefix}{REDACTED_PLACEHOLDER}{suffix}");
                    search_from = new_prefix_len;
                    continue;
                }
            }
            search_from = abs_start + 4;
        } else {
            break;
        }
    }

    result
}

fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.to_lowercase().find(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_uri_passwords() {
        let redactor = SecretRedactor::new();
        let uri = "postgres://salvage_user:super_secret_pw123@localhost:5432/my_db";
        assert_eq!(
            redactor.redact_text(uri),
            "postgres://salvage_user:[REDACTED]@localhost:5432/my_db"
        );
    }

    #[test]
    fn redacts_key_value_secrets() {
        let redactor = SecretRedactor::new();
        let log = "Connecting with password=secret_token_abc and token: 'my-bearer-secret'";
        let redacted = redactor.redact_text(log);
        assert!(!redacted.contains("secret_token_abc"));
        assert!(!redacted.contains("my-bearer-secret"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_auth_headers() {
        let redactor = SecretRedactor::new();
        let header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        assert_eq!(
            redactor.redact_text(header),
            "Authorization: Bearer [REDACTED]"
        );
    }

    #[test]
    fn redacts_custom_canary_tokens() {
        let mut redactor = SecretRedactor::new();
        redactor.add_secret("CANARY_SPECIAL_TOKEN_XYZ");

        let text = "Output contains CANARY_SPECIAL_TOKEN_XYZ within error details";
        assert_eq!(
            redactor.redact_text(text),
            "Output contains [REDACTED] within error details"
        );
    }
}
