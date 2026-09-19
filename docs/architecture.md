# Architecture

Current implemented truth. Code is canonical; this file links it.

## Workspace boundary

- `crates/salvage-cli`: executable boundary. `USAGE` in `crates/salvage-cli/src/main.rs:13`. No PostgreSQL contact in `check` / `manifest check` / `evidence check|report`.
- `crates/salvage-core`: manifest + lifecycle/domain. Manifest spec `crates/salvage-core/src/manifest.rs:1-79`. Lifecycle spec `crates/salvage-core/src/lifecycle/mod.rs:1-52`.
- `crates/salvage-postgres`: PostgreSQL adapter boundary. Preflight + restore `crates/salvage-postgres/src/restore.rs:20-60`.
- `crates/salvage-evidence`: canonical evidence schema + deterministic projections. `crates/salvage-evidence/src/lib.rs:1-6`, `bundle.rs`.
- `crates/salvage-oci`: OCI boot executor (v2/v3) with default-deny isolation (O3-3). Policy `crates/salvage-oci/src/isolation.rs`, decision `docs/decisions/0004-boot-isolation-default-deny.md`.
- `crates/salvage-contracts`: recovery contract executor (O3-2 core, O3-4 wired to CLI/evidence). Types `crates/salvage-contracts/src/outcome.rs`, caps `crates/salvage-contracts/src/caps.rs`, runners `crates/salvage-contracts/src/executor.rs`, production backends `crates/salvage-cli/src/main.rs:261-412` (`V3Executor`).

## Run lifecycle

`Planning → Validating → Restoring → Verifying → (Booting → Contracts →) Terminal(Verdict) → Cleaning → Cleaned`

- v1 short-circuits `Verifying → Terminal`. v2 runs `Booting` after verification via `RunEngine::start_run_v2` with `deadlines.boot_seconds`. v3 runs `Booting` then `Contracts` via `RunEngine::start_run_v3` (`Stage::Contracts`, journaled + `contracts` stage timing); health/readiness alone can never verify.
- `RunOutcome` keeps primary `Verdict` separate from `CleanupStatus`; cleanup failure never masks root cause.
- Resources (`OwnedResource` + `RunId`) are scoped per-run; cleanup is reverse-order, idempotent. Order: containers, then isolated networks (`Network{name}`, `docker network rm`), then process groups, files, dirs. Safe re-entry via `StaleResources` / `AlreadyExists`.
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
- Boot pulls by digest, starts on per-run `--internal` network (`salvage-net-<run-id>`, default-deny, `-P` retained as no-op), probes forbidden egress (`prod-forbidden.invalid` → `allowed:false`, reachable → `isolation/egress-allowed`), probes readiness within `boot_seconds` (host mapped-port first, then in-container `nc`/`wget` fallback for `--internal`), re-verifies tables post-boot, records `artifact` + `boot` + `isolation_*` evidence. Wrong digest → `boot-failed`, no container/network leaked. Crash (`false`) → `app/crash`, hang → `timed-out`, SIGINT/SIGTERM → `cancelled`. Policy error → `isolation/policy-failed` fail-closed, never `bridge`.

## Evidence

- `evidence.json` (v1) is canonical; `report.html`/text are deterministic projections. Non-deterministic fields excluded from golden comparison (run_id, timestamps, durations, `contracts[].duration_ms`).
- `Verdict`: `verified` | `verification-failed` | `boot-failed` | `isolation-failed` | `orchestration-failed` | `cleanup-failed` | `timed-out` | `cancelled` | `incomplete`. `completeness`: `complete` vs `incomplete`.
- `Verified` requires: stage `Passed` AND (`contracts == None` legacy v1/v2 OR `Some` non-empty all `passed` with no `code`) AND no isolation failure. Contract `contract/...` failures map to `verification-failed`; `isolation/...` maps to `isolation-failed` (dominates). See `docs/decisions/0005-evidence-contracts-isolation-verdict.md`.
- `SecretRedactor` strips credentials/connection strings/keys/headers before persistence/projection, including `contracts[].{name,kind,output,code}` and `isolation.{network,allowlist,egress.*}`.

## Recovery contracts (v3, wired O3-4, proven O3-5)

| Kind | Protocol | Limits | Failure codes |
|---|---|---|---|
| `sql` | `psql -h <unix-socket> -U postgres -d <restored>` with declared `query`; socket-only, no TCP param | per-contract `timeout_ms` `1..=300000`, output 64 KiB, rows 1000 | `contract/timeout`, `contract/malformed` (blank/spec mismatch), `contract/crash` (spawn/panic), `contract/oversized`, `contract/assert-failed` (0 rows) |
| `http` | minimal blocking HTTP/1.0 over `TcpStream`, no redirects; `http://` only — `https://` fails closed as `contract/crash` (no TLS deps) | same `timeout_ms` + 64 KiB body cap | `contract/timeout`, `contract/malformed` (non-`http(s)`/bad host), `contract/crash` (DNS/connect/read, incl. https), `contract/oversized`, `contract/assert-failed` (non-2xx) |
| `exec` | real child, no shell (`Command::new(argv0)`), isolated process group, `SIGTERM → SIGKILL` + reap on timeout | same `timeout_ms` + 64 KiB cap, argv allowlist (`true,false,echo,sleep,pg_isready,psql,cat`, basename-matched, shells absent) | `contract/timeout` (group killed, pid reported), `contract/malformed` (empty/blank/not-allowlisted, no spawn), `contract/crash` (spawn fail/non-zero exit), `contract/oversized`, `contract/assert-failed` |

- Declared in `v3` manifests (`contracts[]` 1..=32, unique names, `crates/salvage-core/src/manifest.rs`); executed by `ContractExecutor` (`crates/salvage-contracts/src/executor.rs`) after boot via `V3Executor::execute_contracts` (`crates/salvage-cli/src/main.rs:457-496`). Output is truncated to caps and passed through `SecretRedactor` (with env secrets) before assert/persist/display.
- Isolation default-deny: per-run `salvage-net-<run-id>` `--internal` (no egress, allowlist validated but still denied); forbidden probe `prod-forbidden.invalid` (`.invalid` RFC 2606, no external net) blocked → `allowed:false`, reachable → `isolation/egress-allowed`, missing tools/spawn failure → `isolation/policy-failed` fail-closed, never `bridge`. Block recorded as `isolation{network,allowlist,egress}` in evidence; `docker ps` + `docker network ls` clean on every verdict.
- E2E matrix (O3-5, `crates/salvage-cli/tests/e2e_contracts.rs`, `#[ignore]` + `SALVAGE_TEST_DOCKER=1`): happy-verified (PG16 dump + tiny-http + SQL + local-HTTP + exec), forbidden-egress, hang/crash, redaction canary. Fixture `tests/fixtures/manifest-valid-v3-e2e.json` (local `http://127.0.0.1:8000/` + `egress_allow ["127.0.0.1"]`). CI runs unit + opt-in Docker matrix and uploads `recovery-evidence` (v1) + `recovery-evidence-v3` (contracts + isolation). See `docs/decisions/0006-e2e-matrix-contracts-isolation.md`.

## Fault matrix (O4, `crates/salvage-cli/tests/e2e_faults.rs`)

- Full-slice v3 runs (restore → boot → contracts → evidence → cleanup) under one injected fault, `#[ignore]` + `SALVAGE_TEST_DOCKER=1`, `SALVAGE_FAULT_MATRIX_REPEATS=N` (CI uses 2, run ids carry pid + nanos so leaks cannot be masked). See `docs/decisions/0007-fault-matrix.md`, `0008-missing-role-extension.md`.
- Rows: truncated backup (`restore/corrupt-backup`), declared `postgres.version 99.0` (`restore/unsupported-version`), zeroed `app.digest` (`app/digest-mismatch` → `boot-failed`), missing role/extension (`restore/missing-role` / `restore/missing-extension` via `pg_restore` stderr classification), contract `malformed` (`rm` never spawned) / `crash` (allowlisted `false`) / `timeout` (`sleep 30` with 1 s budget, group killed) / `oversized` (70 KiB HTTP vs 64 KiB cap), evidence-write failure (`file:///dev/full` ENOSPC-class + `chmod 555` EACCES variant + tiny-tmpfs true-ENOSPC attempt with loud skip → `evidence/write-failed`), `SIGTERM` mid-contracts + `SIGINT` mid-boot (journal-synced, → `cancelled`), global deadline (`SALVAGE_TEST_GLOBAL_TIMEOUT_MS` + one-shot `SALVAGE_TEST_RESTORE_DELAY_MS`) + restore/verify stage-timeout hangs (→ `timed-out`).
- Every row asserts expected code, bounded wall-clock, parsed `evidence.json` classification, green `evidence check` with `cleanup success`, retained `evidence.json`/`report.html`/`journal.jsonl`/`state.json`, and zero leak (containers, `salvage-net-<run-id>`, ephemeral `postgres/` dir). Crash/timeout contract rows additionally assert `isolation.egress.allowed:false`, proving default-deny holds even on contract failure (reachable egress stays unit-double-only: `--internal` cannot route outside; blocked covered full-slice O3, reachable covered by `salvage-oci` fake-docker units).
