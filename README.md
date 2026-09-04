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

## Verification

Install `cargo-audit` once with `cargo install cargo-audit --locked`, then run the complete local verification path with:

```sh
./scripts/verify.sh
```

The script checks formatting, clippy warnings, workspace tests, the locked dependency graph, and the intentional compile-fail fixture in `tests/fixtures/invalid.rs`. CI runs the same command.
