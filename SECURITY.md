# Security Policy

## Reporting

Do not open a public GitHub Issue for a suspected vulnerability.

Report privately to the maintainers with: affected commit/version, manifest/fixture or steps to reproduce (redact secrets), impact (data loss, escape from isolation, secret leak, supply-chain), and any logs/evidence bundles with secrets already redacted.

We will triage severity and exposure, contain when necessary, remediate, verify with security tests, then coordinate release/advisory/disclosure. Corrective engineering becomes normal tracked Issues once safe to disclose.

## Scope

Salvage restores untrusted backups and boots OCI images in isolation. Of particular interest: escape from ephemeral PG/socket/process-group isolation, container leak or cross-run interference, digest bypass, `SecretRedactor` bypass, dependency or CI/release-chain integrity.
