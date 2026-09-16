# ADR 0006: E2E matrix plus docs plus CI job (O3-5)

Status: accepted
Date: 2026-09-16

## Context

O3-1 declares v3 `contracts[]` (ADR 0003). O3-2 implements the bounded
executor core. O3-3 enforces boot isolation on per-run `--internal` networks
(ADR 0004). O3-4 wires v3 through CLI/evidence with `Verified` gating and
`IsolationFailed` (ADR 0005).

O3-5 must demonstrate the O3 exit gate end-to-end in CI without flaky prod
contact: versioned contracts pass, forbidden egress is detected, secrets are
safe. Issue #38 scopes: `e2e_contracts.rs` (ignored, `SALVAGE_TEST_DOCKER=1`
precedent from O2 `e2e_boot.rs`), `docs/architecture.md` + `docs/reference/`
update, CI job running unit + opt-in Docker matrix, ADR, zero-leak check.
Out: backup creation, scheduler, broad DB support.

Issue #38 names the ADR `0003-contracts-isolation`; `0003`/`0004`/`0005`
already exist, so this record is `0006` preserving the intent.

## Decision

- Matrix `crates/salvage-cli/tests/e2e_contracts.rs`, all `#[ignore]` +
  `SALVAGE_TEST_DOCKER=1` (default `cargo test` green for non-Docker devs):
  - `happy_verified_with_contracts`: PG16 dump + `tiny-http` + SQL
    (`SELECT count(*) FROM salvage_records`) + HTTP (`http://127.0.0.1:<ephemeral>/`)
    + exec (`echo`) ⇒ `verified`, `contracts[]` 3×`passed`, `isolation`
    `allowed:false`, `evidence check` + `report` (VERIFIED + Contracts +
    Isolation cards) green.
  - `forbidden_egress_blocked_on_isolated_network`: same happy shape,
    asserts `network == salvage-net-<run-id>`, allowlist retains
    `127.0.0.1`, `egress.host == prod-forbidden.invalid`,
    `detail` non-empty, no `isolation/egress-allowed`, `docker network ls`
    clean.
  - `hang_and_crash_contracts_fail_closed`: exec `sleep 30`/`timeout 200ms`
    ⇒ `contract/timeout` plus `false` ⇒ `contract/crash` in one run;
    verdict `verification-failed` (health green alone never verifies),
    `evidence check` still passes (failed bundle validates).
  - `redaction_canary_never_survives_evidence`: canary via SQL
    (`SELECT '<canary>'`), HTTP (local server body), exec (`echo <canary>`)
    with `SALVAGE_E2E_SECRET_CANARY_XYZ` (SECRET name ⇒ `add_env_secrets`);
    redacted before assert so still `verified`, but raw canary absent from
    `evidence.json`/`report.html`/`journal.jsonl`/`state.json`,
    `[REDACTED]` present in JSON + HTML.
- Local-only fakes, no external network: PG Unix-socket-only, HTTP via
  test-spawned `127.0.0.1` `TcpListener` (ephemeral port, 90s/20-req cap),
  egress probe `.invalid` RFC 2606. `https://` stays fail-closed as
  `contract/crash` (no TLS deps); E2E therefore uses `http://` with
  `egress_allow ["127.0.0.1"]` (fixture
  `tests/fixtures/manifest-valid-v3-e2e.json`).
- Zero-leak per test: filtered `docker ps -a`, `docker network ls`,
  `!run_dir/postgres`, `evidence.json`/`report.html`/`journal.jsonl`/`state.json`
  kept.
- Docs: `docs/architecture.md` gains contract protocol table + limits +
  isolation default-deny + health-alone-cannot-verify (replaces O3-2
  "unwired"); `docs/reference/cli-manifest-evidence.md` gains production
  protocol notes + E2E fixture/CI pointer; `docs/operations/runbooks.md`
  gains v3 drill + matrix commands.
- CI (`.github/workflows/ci.yml`): keep v1 `recovery-evidence` drill
  (compat), add `SALVAGE_TEST_DOCKER=1 cargo test --test e2e_contracts
  --locked -- --ignored` step plus v3 drill (`tiny-http` build + digest
  `sed` + `python3 -m http.server 8000` + `salvage run
  manifest-valid-v3-e2e.json`) uploading `target/recovery-evidence-v3/*`
  alongside v1. `recovery-evidence` artifact thus carries contracts +
  isolation blocks.

## Consequences

- O3 closes when matrix green locally + CI green with Docker tests ignored
  by default.
- CI cost bounded: 4 extra Docker runs (~2 min), 30-min job timeout intact.
- Future: allowlist proxy, `https` TLS, broad DB support need new ADRs;
  this record is preserved.
