# Salvage

Salvage is a recovery-verification tool for proving that a specific PostgreSQL backup and application release can reconstruct a valid service in an isolated environment.

## Goals

- Restore declared PostgreSQL backups reproducibly.
- Verify exact backup and application artifact identities.
- Produce typed, machine-readable recovery results.
- Test failure, timeout, cancellation, and cleanup behavior.
- Prevent recovery drills from contacting production systems.
- Retain redacted evidence for every run.

## Status

Salvage is in early development. Current engineering work is tracked in [GitHub Issues](https://github.com/G1DO/salvage/issues).

## Workspace

The Rust workspace keeps the executable boundary in `crates/salvage-cli`, lifecycle/domain code in `crates/salvage-core`, the PostgreSQL adapter boundary in `crates/salvage-postgres`, and machine-readable evidence in `crates/salvage-evidence`.

The bootstrap CLI is intentionally non-invasive. `salvage check` emits one JSON object and exits `0`; unsupported arguments emit a JSON usage error on stderr and exit `2`. The command does not connect to PostgreSQL.

`salvage manifest check <path>` validates a versioned (`v1`) recovery-run manifest without performing a restore: exit `0` prints the canonical `manifest_hash` (`sha256:<hex>` over the normalized manifest), exit `1` emits a typed `manifest/...` diagnostic, and exit `2` reports unreadable input or usage. Surrounding whitespace in value fields is trimmed before hashing, so padding variants share one hash; non-UTF-8 bytes report `manifest/parse` (exit `1`), while a missing file reports `io` (exit `2`). Golden valid/invalid fixtures live in `tests/fixtures/manifest-*.json` with expected codes in `tests/fixtures/manifest-diagnostics.json`. Manifest schema, compatibility, and hashing rules are documented in `crates/salvage-core/src/manifest.rs`.

The recovery run lifecycle state machine in `crates/salvage-core/src/lifecycle/` drives bounded recovery runs through explicit states (`planning`, `validating`, `restoring`, `verifying`, `terminal`, `cleaning`, `cleaned`), tracks resource ownership with isolated process groups and safe child reaping, bounds stages with deadlines and signal cancellation, maintains atomic state persistence and append-only event journaling, and prevents stale resource reuse on re-entry.

The PostgreSQL adapter in `crates/salvage-postgres/` restores a declared logical backup (`pg_dump -Fc` custom archive) into a fresh, completely isolated ephemeral PostgreSQL target. Before spawning target resources, it validates the backup SHA-256 digest and archive magic bytes (`PGDMP`), failing closed with typed diagnostics (`restore/digest-mismatch`, `restore/corrupt-backup`). It initializes an ephemeral cluster with `initdb` in a scratch directory managed by `ResourceManager`, binds exclusively to a local Unix domain socket (`listen_addresses = ''`), supervises `postgres` and `pg_restore` inside isolated process groups, runs structural table and row verification, and classifies failures into machine-readable diagnostics (`restore/unsupported-version`, `restore/missing-prerequisite`, `restore/structural-verification-failed`, `restore/target-connection-failed`). All resources are reaped and cleaned up in reverse order upon success, failure, timeout, or cancellation.

The evidence engine in `crates/salvage-evidence/` defines the versioned (`v1`) canonical recovery evidence schema (`evidence.json`) and deterministic static report projection (`report.html`). It records run and tool identity, manifest hash, declared and observed versions, stage timings, structured events, primary verdict, and explicit completeness status (`complete` vs `incomplete`). The multi-pattern `SecretRedactor` eliminates credentials, connection strings, private keys, auth headers, and environment secrets before persistence or projection. `salvage evidence check <path>` validates an evidence bundle against supported schema versions and completeness criteria; `salvage evidence report <path>` generates a self-contained HTML report.

`salvage run <path> [--backup <path>] [--expected-table <table>] [--run-id <id>] [--run-dir <dir>]` executes an end-to-end recovery run from manifest to terminal verdict against an ephemeral, isolated PostgreSQL target: exit `0` outputs a machine-readable JSON verdict confirming `verified` status and successful cleanup; exit `1` outputs a typed error verdict (`restore/digest-mismatch`, `restore/corrupt-backup`, `restore/unsupported-version`, `restore/missing-prerequisite`, `restore/structural-verification-failed`, `restore/target-connection-failed`, `timeout`, `cancelled`) while guaranteeing zero leaked child processes, temporary directories, or unix sockets; exit `2` reports unreadable input or CLI usage errors. If `--backup` is omitted, the command automatically discovers a backup file in the manifest's directory or current working directory whose SHA-256 digest matches `manifest.backup.digest`. Signal cancellation (`SIGINT`/`SIGTERM`) triggers graceful cancellation, reaps descendant process groups, cleans up scratch directories, and records a terminal `cancelled` evidence bundle.


## Verification

Install `cargo-audit` once with `cargo install cargo-audit --locked`, then run the complete local verification path with:

```sh
./scripts/verify.sh
```

The script checks formatting, clippy warnings, workspace tests, the locked dependency graph, and the intentional compile-fail fixture in `tests/fixtures/invalid.rs`. CI runs the same command.


## V2 boot artifact drill

V2 manifests add app plus readiness and deadlines boot seconds. The boot stage pulls by digest, probes readiness, re-verifies tables post-boot, and records artifact plus boot seconds in evidence. V1 bundles stay byte identical.

Tiny drill commands:

- Build tiny images from crates salvage-oci tests fixtures images tiny-http and tests fixtures images tiny-crash and tiny-hang
- Run v2 happy with valid v2 boot tcp manifest plus backup dump plus run dir, replacing app digest with built image ID
- Wrong digest fails closed with app digest-mismatch and boot failed and no container leaked
- Crash CMD false maps to app crash, hang sleep with boot seconds 5 maps to timed out, SIGINT mid-boot maps to cancelled
- All runs guarantee zero leaked containers via docker ps filter and postgres directory removed
- Evidence includes artifact digest repository resolved image and observed version plus limits boot seconds when present, report shows conditional Artifact rows and BOOT FAILED badge
