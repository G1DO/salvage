# Security

## Trust boundaries

- Manifest (untrusted input) → validator (fail-closed, `manifest/...`) → isolated runners (PG + OCI) → redacted evidence.
- Recovery drills never contact production: ephemeral `initdb` cluster, Unix socket only (`listen_addresses = ''`), scratch dirs owned per `RunId`.
- Supply chain: `--locked` everywhere, pinned toolchain `1.92.0`, pinned GitHub Actions + Dependabot for cargo/actions. Secrets never in manifests/fixtures/evidence.

## Controls

- Backup: SHA-256 must equal `manifest.backup.digest` + `PGDMP` magic before any spawn; else `restore/digest-mismatch` / `corrupt-backup`.
- OCI: pull by `sha256:` digest only; mutable `latest` rejected; `--artifact` override must match manifest digest.
- Evidence: `SecretRedactor` removes credentials, connection strings, private keys, auth headers, env secrets before `evidence.json` persistence and `report.html` projection (see `redaction_canary` test).
- Processes: isolated groups, `SIGTERM→SIGKILL` + reap; cleanup scoped to owned resources only.

## Reporting

See root `SECURITY.md`. Do not file public Issues for undisclosed vulnerabilities. Corrective work becomes normal tracked Issues once safe.
