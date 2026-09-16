# Architecture

Current implemented truth. Code is canonical; this file links it.

## Workspace boundary

- `crates/salvage-cli`: executable boundary. `USAGE` in `crates/salvage-cli/src/main.rs:13`. No PostgreSQL contact in `check` / `manifest check` / `evidence check|report`.
- `crates/salvage-core`: manifest + lifecycle/domain. Manifest spec `crates/salvage-core/src/manifest.rs:1-79`. Lifecycle spec `crates/salvage-core/src/lifecycle/mod.rs:1-52`.
- `crates/salvage-postgres`: PostgreSQL adapter boundary. Preflight + restore `crates/salvage-postgres/src/restore.rs:20-60`.
- `crates/salvage-evidence`: canonical evidence schema + deterministic projections. `crates/salvage-evidence/src/lib.rs:1-6`, `bundle.rs`.
- `crates/salvage-oci`: OCI boot executor (v2 only).
- `crates/salvage-contracts`: recovery contract executor core (O3-2, bounded + classified, not yet wired to CLI/evidence). Types `crates/salvage-contracts/src/outcome.rs`, caps `crates/salvage-contracts/src/caps.rs`, runners `crates/salvage-contracts/src/executor.rs`.

## Run lifecycle

`Planning → Validating → Restoring → Verifying → (Booting →) Terminal(Verdict) → Cleaning → Cleaned`

- v1 short-circuits `Verifying → Terminal`. v2 runs `Booting` after verification via `RunEngine::start_run_v2` with `deadlines.boot_seconds`.
- `RunOutcome` keeps primary `Verdict` separate from `CleanupStatus`; cleanup failure never masks root cause.
- Resources (`OwnedResource` + `RunId`) are scoped per-run; cleanup is reverse-order, idempotent. Safe re-entry via `StaleResources` / `AlreadyExists`.
- Processes run in isolated groups (`PGID == PID`); `SIGTERM → SIGKILL` broadcast + reap on timeout/cancel.
- `journal.jsonl` (append-only) + atomic `state.json` per state change; `diagnose_run` for post-mortem. Run dir preserves `evidence.json`, `report.html`, `journal.jsonl`, `state.json`.

## Postgres isolation

1. `verify_backup_preflight`: file exists → SHA-256 equals `manifest.backup.digest` → `PGDMP` magic (`PG_DUMP_CUSTOM_MAGIC`). Fail-closed: `restore/missing-prerequisite`, `restore/digest-mismatch`, `restore/corrupt-backup`.
2. `initdb` ephemeral cluster in scratch dir owned by `ResourceManager`.
3. Binds Unix socket only (`listen_addresses = ''`); no TCP, no prod contact.
4. Supervises `postgres` + `pg_restore` in process groups; structural table/row verification (`--expected-table`, default `salvage_records`); typed `restore/...` diagnostics; `pg_restore` major version must match manifest.
5. Cleanup reaps groups and removes data/socket dirs on success/failure/timeout/cancel.

## v2 boot

- `ManifestV2.app`: `digest: sha256:<64hex>` required; `repository`, `tag` optional (`latest`/ `@`/`:` rejected as `app-tag`); `readiness`: `tcp{host?,port}` | `http{host?,port,path}` | `exec{command[]}`.
- `salvage run --artifact <repo@sha256:...>` requires v2; digest part after last `@` must equal `manifest.app.digest` or `app/digest-mismatch` (exit 1).
- Boot pulls by digest, probes readiness within `boot_seconds`, re-verifies tables post-boot, records `artifact` + `boot` evidence. Wrong digest → `boot-failed`, no container leaked. Crash (`false`) → `app/crash`, hang → `timed-out`, SIGINT/SIGTERM → `cancelled`.

## Evidence

- `evidence.json` (v1) is canonical; `report.html`/text are deterministic projections. Non-deterministic fields excluded from golden comparison (run_id, timestamps, durations).
- `Verdict`: `verified` | `verification-failed` | `boot-failed` | `orchestration-failed` | `cleanup-failed` | `timed-out` | `cancelled` | `incomplete`. `completeness`: `complete` vs `incomplete`.
- `SecretRedactor` strips credentials/connection strings/keys/headers before persistence/projection.

## Recovery contracts (O3-2 core, unwired)

- Declared in `v3` manifests (`contracts[]`, see `crates/salvage-core/src/manifest.rs:80-96`); executed by `ContractExecutor` against the booted artifact with per-contract `timeout_ms` budgets.
- Result taxonomy: `passed` | `failed` | `timed-out` plus one `contract/*` code (`contract/timeout`, `contract/malformed`, `contract/oversized`, `contract/crash`, `contract/assert-failed`).
- Caps: output bytes (default 64 KiB), rows (default 1000), duration (`timeout_ms`), argv allowlist, no shell. `sql` handles are Unix-socket-only (no TCP param). Output is truncated to caps and passed through `SecretRedactor` before assert/persist.
- `sql`/`http` run through injected backends (unit fakes; no Docker, no PG, no real sockets in tests). `exec` spawns real children in isolated groups; timeout kills the group (`SIGTERM → SIGKILL` + reap, pid reported for leak asserts).
- Out of scope here: network policy, evidence schema change, CLI wiring, Docker E2E (later O3 slices).
