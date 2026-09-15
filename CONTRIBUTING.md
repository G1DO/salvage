# Contributing to Salvage

Repository-specific workflow. General engineering model lives in Notion `Workflow`; do not duplicate it here.

## Setup

- Pinned toolchain `1.92.0` in `rust-toolchain.toml`. `rustup` picks it automatically.
- Install once: `cargo install cargo-audit --locked`
- PostgreSQL 16 binaries required for restore drills (`initdb`, `postgres`, `pg_restore`, `psql`, `pg_isready`). Set `POSTGRES_BIN_DIR` to prioritize a directory. CI installs `postgresql-16` if `initdb` is missing.
- Docker required only for boot E2E (`SALVAGE_TEST_DOCKER=1`).

## Checks

Run the full local gate before every PR:

```sh
./scripts/verify.sh
```

What it runs (`scripts/verify.sh` is canonical):
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo test --workspace --all-targets --locked`
4. `cargo audit`
5. Negative fixture: `tests/fixtures/invalid.rs` must fail to compile

Plus, when touched:

```sh
# PG16 black-box drill + evidence artifact
cargo run -p salvage-cli --locked -- run tests/fixtures/manifest-valid-pg16-restore.json --backup tests/fixtures/valid-pg16-custom.dump --run-dir target/recovery-evidence

# Docker boot E2E (OCI/boot touched)
SALVAGE_TEST_DOCKER=1 cargo test --test e2e_boot --locked -- --ignored
SALVAGE_TEST_DOCKER=1 cargo test -p salvage-oci --test boot_integration --locked -- --ignored
```

## Manifest authoring

- Start from `tests/fixtures/manifest-valid-v1.json` (frozen v1) or `tests/fixtures/manifest-valid-v2-boot-tcp.json` (v2 + `app` + `deadlines.boot_seconds`).
- Expected diagnostic codes live in `tests/fixtures/manifest-diagnostics.json`.
- Schema truth is `crates/salvage-core/src/manifest.rs`. `v1` is frozen byte-identical; new fields require a new `schema_version`. Unknown fields are rejected (`manifest/schema`).
- Validate without restoring: `salvage manifest check <path>` → exit `0` + `sha256:<hex>`, exit `1` typed `manifest/...`, exit `2` `io`/usage.

## PR rules

- One coherent change per PR. Fill `.github/PULL_REQUEST_TEMPLATE.md`.
- Update `README.md` / `docs/` in the same PR as the code when behavior changes.
- ADR for architecturally significant decisions in `docs/decisions/`; preserve old records, add superseding ADR on change.
- Keep `main` releasable. CI must pass; self-review is enough for ordinary solo work, request peer review for auth/trust-boundary/data-loss/migration/release-pipeline changes.
