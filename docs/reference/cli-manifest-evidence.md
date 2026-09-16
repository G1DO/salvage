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
| `run <path> [--backup] [--expected-table] [--run-id] [--run-dir] [--artifact]` | exit 0 JSON `verified` + cleanup ok | exit 1 typed verdict (`restore/...`, `app/...`, `timed-out`, `cancelled`, run-state) | exit 2 `io`/usage; `--artifact` on v1 → `usage` |

Notes:
- Whitespace in value fields trimmed before hashing; padding variants share one hash. `schema_version` must match exactly.
- `--backup` omitted → search manifest dir + cwd for file whose SHA-256 matches `manifest.backup.digest`; fallback `<manifest-stem>.dump`, then `backup.dump`.
- `--expected-table` default `salvage_records`. `--run-dir` default per-run system-temp subdir. `POSTGRES_BIN_DIR` prioritizes PG binaries.
- Signal `SIGINT`/`SIGTERM` → terminal `cancelled` + cleanup.

## Manifest

Canonical: `crates/salvage-core/src/manifest.rs`. Fixtures: `tests/fixtures/manifest-valid-*.json`, codes: `tests/fixtures/manifest-diagnostics.json`.

- `v1` frozen byte-identical. Top order: `schema_version, backup, postgres, restore, limits, deadlines, evidence, run`.
- `v2` strict superset. Top order: `schema_version, backup, postgres, restore, app, limits, deadlines, evidence, run`. Requires `app{digest, readiness}` + `deadlines.boot_seconds` (positive).
- `v3` strict superset of `v2` (O3-1, declare-only). Top order: `schema_version, backup, postgres, restore, app, contracts, limits, deadlines, evidence, run`. Requires `contracts[]` (1..=32, unique non-blank `name`s). Per-contract `timeout_ms` `1..=300000` (no central `verify_contracts_seconds`; see ADR 0003). `spec` shape must match `kind`: `sql{query}` | `http{url http(s)://, method?}` | `exec{command[] non-empty}`. Egress default-deny: absent `egress_allow` = deny; `http` contracts must list their host in `egress_allow` (hosts, no `://`). Mutable `latest` URL path segments → `manifest/semantic/contract-mutable-ref` (same policy as O2 `latest` tag rule). `salvage run` on `v3` exits `usage` until a later O3 slice wires up execution; the O3-2 executor core (`crates/salvage-contracts`) is implemented and unit-tested but not yet CLI/evidence-wired; `manifest check` accepts `v3`.
- `app.digest`: `sha256:<64hex>` required. `app.repository`, `app.tag` optional; explicit `null` is schema error. `latest` (any case) or tag with `@`/`:` → `manifest/semantic/app-tag`.
- `readiness`: `tcp{port 1-65535, host?}` | `http{port, path must start with /, host?}` | `exec{command non-empty, no blanks}`.
- Errors: `manifest/parse` (bad JSON / non-UTF8), `manifest/schema` (shape/unknown fields/enum), `manifest/unsupported-version`, `manifest/semantic/*` (digest/version/limits/deadlines/owner/destination/restore combo/app-*/contract-*).

## Evidence

Canonical: `crates/salvage-evidence/src/bundle.rs`. Golden: `tests/fixtures/evidence/evidence-*.json`.

- `evidence.json` schema `v1`. Fields: run/tool identity, manifest hash, declared/observed versions, stage timings, events, verdict, completeness.
- `evidence check` enforces supported version + completeness. `evidence report` renders self-contained HTML; Artifact rows + `BOOT FAILED` badge conditional on v2 boot presence/failure.
- Deterministic projection: `run_id`, `created_at`, `completed_at`, `total_duration_ms`, `stages[].duration_ms`, `events[].timestamp/run_id/duration_ms` excluded from golden diff.
