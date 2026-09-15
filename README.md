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

## Quickstart

Install `cargo-audit` once with `cargo install cargo-audit --locked`, then run the full local gate:

```sh
./scripts/verify.sh
```

Run a recovery drill (requires PostgreSQL 16 binaries; set `POSTGRES_BIN_DIR` if needed):

```sh
cargo run -p salvage-cli --locked -- run tests/fixtures/manifest-valid-pg16-restore.json \
  --backup tests/fixtures/valid-pg16-custom.dump \
  --run-dir target/recovery-evidence
```

## Docs

- Contributing and local workflow: `CONTRIBUTING.md`
- Architecture (lifecycle, isolation, boot, evidence): `docs/architecture.md`
- CLI, manifest, and evidence reference: `docs/reference/cli-manifest-evidence.md`
- Drills and runbooks: `docs/operations/runbooks.md`
- Security model and reporting: `docs/security.md`, `SECURITY.md`
- Architecture decisions: `docs/decisions/`
