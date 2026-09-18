# Reference: CLI, manifest, evidence

Lookup material. Schemas in code are canonical.

## CLI

`salvage check | salvage manifest check <path> | salvage evidence check <path> | salvage evidence report <path> | salvage run <path> [--backup <path>] [--artifact <repo@sha256:...>]`

Full flag parsing: `crates/salvage-cli/src/main.rs:147-219`.

| Command | Success | Typed error | Usage/IO error |
|---|---|---|---|
| `salvage check` | exit 0, one JSON `{"status":"ok",...}` | — | exit 2 JSON usage on stderr |
| `manifest check <path>` | exit 0 `manifest_hash: sha256:<hex>` over normalized manifest | exit 1 `manifest/...` | exit 2 `io` (missing/unreadable) or usage; non-UTF8 → `manifest/parse` exit 1 |
| `evidence check <path>` | exit 0 (complete) | exit 1 `evidence/...` incl. `evidence/incomplete` | exit 2 `io`/usage |
| `evidence report <path>` | exit 0 HTML to stdout | exit 1 `evidence/...` | exit 2 `io`/usage |
| `run <path> [--backup] [--expected-table] [--run-id] [--run-dir] [--artifact]` | exit 0 JSON `verified` + cleanup ok | exit 1 typed verdict (`restore/...`, `app/...`, `contract/...`, `isolation/...`, `timed-out`, `cancelled`, run-state) | exit 2 `io`/usage; `--artifact` on v1 → `usage` |

Notes:
- Whitespace in value fields trimmed before hashing; padding variants share one hash. `schema_version` must match exactly.
- `--backup` omitted → search manifest dir + cwd for file whose SHA-256 matches `manifest.backup.digest`; fallback `<manifest-stem>.dump`, then `backup.dump`.
- `--expected-table` default `salvage_records`. `--run-dir` default per-run system-temp subdir. `POSTGRES_BIN_DIR` prioritizes PG binaries.
- Signal `SIGINT`/`SIGTERM` → terminal `cancelled` + cleanup.

## Manifest

Canonical: `crates/salvage-core/src/manifest.rs`. Fixtures: `tests/fixtures/manifest-valid-*.json`, codes: `tests/fixtures/manifest-diagnostics.json`.

- `v1` frozen byte-identical. Top order: `schema_version, backup, postgres, restore, limits, deadlines, evidence, run`.
- `v2` strict superset. Top order: `schema_version, backup, postgres, restore, app, limits, deadlines, evidence, run`. Requires `app{digest, readiness}` + `deadlines.boot_seconds` (positive).
- `v3` strict superset of `v2` (O3-1 declared, O3-4 wired, O3-5 proven). Top order: `schema_version, backup, postgres, restore, app, contracts, limits, deadlines, evidence, run`. Requires `contracts[]` (1..=32, unique non-blank `name`s). Per-contract `timeout_ms` `1..=300000` (no central `verify_contracts_seconds`; see ADR 0003). `spec` shape must match `kind`: `sql{query non-blank, socket-only}` | `http{url http(s)://, method?}` | `exec{command[] non-empty, no blanks}`. Production: `sql` via `psql -h <socket>`; `http` minimal TCP `http://` only (`https://` fails closed as `contract/crash`, no TLS deps); `exec` no-shell, argv allowlist (`true,false,echo,sleep,pg_isready,psql,cat`), output 64 KiB / rows 1000. Egress default-deny: absent `egress_allow` = deny; `http` contracts must list their host in `egress_allow` (hosts, no `://`). Mutable `latest` URL path segments → `manifest/semantic/contract-mutable-ref` (same policy as O2 `latest` tag rule). `salvage run` on `v3` executes boot then contracts via `StageExecutor::execute_contracts` (`crates/salvage-cli/src/main.rs` `V3Executor`: psql-over-socket SQL, minimal TCP HTTP with https fail-closed as `contract/crash`, real exec); no new flags, contracts come from the manifest. `manifest check` accepts `v3`. E2E fixture `tests/fixtures/manifest-valid-v3-e2e.json` (local `http://127.0.0.1:8000/` + `egress_allow ["127.0.0.1"]`, digest placeholder replaced per-run). See ADR 0005 + 0006.
- `app.digest`: `sha256:<64hex>` required. `app.repository`, `app.tag` optional; explicit `null` is schema error. `latest` (any case) or tag with `@`/`:` → `manifest/semantic/app-tag`.
- `readiness`: `tcp{port 1-65535, host?}` | `http{port, path must start with /, host?}` | `exec{command non-empty, no blanks}`. On isolated `--internal` boot networks, `tcp`/`http` try host mapped-port first, then in-container `nc`/`wget` fallback (`127.0.0.1:<port>`); see ADR 0004.
- Isolation (O3-3, `crates/salvage-oci/src/isolation.rs`): per-run `salvage-net-<run-id>` `--internal` (default-deny, allowlist validated but still denied); forbidden probe `prod-forbidden.invalid` (blocked → `allowed:false`, reachable → `isolation/egress-allowed`); policy error → `isolation/policy-failed` fail-closed.
- Errors: `manifest/parse` (bad JSON / non-UTF8), `manifest/schema` (shape/unknown fields/enum), `manifest/unsupported-version`, `manifest/semantic/*` (digest/version/limits/deadlines/owner/destination/restore combo/app-*/contract-*).

## Evidence

Canonical: `crates/salvage-evidence/src/bundle.rs`. Golden: `tests/fixtures/evidence/evidence-*.json`.

- `evidence.json` schema `v1`. Fields: run/tool identity, manifest hash, declared/observed versions, stage timings, events, verdict, completeness, plus O3-4 additive `contracts[]` (`None` on v1/v2, `Some` on v3) and `isolation{network, allowlist, egress}` (`None` when isolation did not run). `Verified` requires contracts non-empty all-passed when present; empty/failed `Some` can never verify. New `IsolationFailed` (`isolation-failed`) for `isolation/...` codes; contract failures (`contract/...`, `Stage::contracts`) map to `VerificationFailed`. See ADR 0005.
- `evidence check` enforces supported version + completeness, and rejects `Verified` with empty/failed contracts (`evidence/incomplete`). `evidence report` renders self-contained HTML; Artifact rows + `BOOT FAILED` / `ISOLATION FAILED` badges conditional on v2/v3 presence/failure; Contracts + Isolation cards from redacted bundle.
- Deterministic projection: `run_id`, `created_at`, `completed_at`, `total_duration_ms`, `stages[].duration_ms`, `contracts[].duration_ms`, `events[].timestamp/run_id/duration_ms` excluded from golden diff. Contract `output` is redacted + truncated before persist, deterministic for fixed inputs.
- E2E matrix (O3-5): `crates/salvage-cli/tests/e2e_contracts.rs` (`#[ignore]`, `SALVAGE_TEST_DOCKER=1`) — happy-verified, forbidden-egress, hang/crash, redaction canary. CI runs `cargo test --test e2e_contracts --locked -- --ignored` plus v3 drill uploading `recovery-evidence-v3` with contracts + isolation blocks. See ADR 0006.
- Fault matrix (O4-1 + O4-2 + O4-3): `crates/salvage-cli/tests/e2e_faults.rs` (`#[ignore]`, `SALVAGE_TEST_DOCKER=1`) — full-slice corrupt-backup, wrong DB/app version, missing role (`restore/missing-role`, O4-2), malformed/oversized contracts, evidence-write failure (`/dev/full` ENOSPC-class rep + `chmod 555` EACCES variant + tiny-tmpfs true-ENOSPC attempt with loud skip), SIGTERM, global deadline, restore stage-timeout hang (`restore_seconds` < `SALVAGE_TEST_RESTORE_DELAY_MS`); every row asserts expected verdict, bound, green `evidence check`, cleanup success, zero leak. Test-only env: `SALVAGE_TEST_GLOBAL_TIMEOUT_MS` (global deadline injector, mirrors the `SALVAGE_TEST_RESTORE_DELAY_MS` restore hook; never set in production) and `SALVAGE_FAULT_MATRIX_REPEATS=N` (CI uses 2). Contracts honor cancellation and the global deadline at every boundary; hung `exec` preempts mid-contract, hung `sql`/`http` cancel at the boundary within `timeout_ms`. Taxonomy intentionally maps every `persist` I/O error to `evidence/write-failed` (no errno distinction). See ADR 0007.
