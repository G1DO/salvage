# ADR 0005: Evidence contracts + isolation and Verified gating (O3-4)

Status: accepted
Date: 2026-09-16

## Context

O3-1 declares v3 `contracts[]` with default-deny `egress_allow` (ADR 0003).
O3-2 implements the bounded executor core (`salvage-contracts`, `contract/*`
codes, redaction before assert/persist). O3-3 enforces boot isolation on a
per-run `--internal` network with a forbidden-egress probe
(`isolation/egress-allowed`, `isolation/policy-failed`, ADR 0004).

O3-4 must make `Verified` prove application validity: a green
health/readiness endpoint alone can never verify. Contract/isolation output is
attacker-influenced and must be redacted before persist AND before display.
Evidence change must stay additive-only with v1 reader compat.

Issue #37 offers two classifications for isolation: new `IsolationFailed` or
`VerificationFailed + isolation/...`.

## Decision

- Evidence `v1` gains additive `contracts?: ContractEvidence[]` and
  `isolation?: IsolationEvidence` (`crates/salvage-evidence/src/bundle.rs`):
  - `ContractEvidence{name, kind, status, code?, output, truncated,
    duration_ms?, rows}`. `output` is redacted + cap-truncated; `duration_ms`
    is non-deterministic and excluded from golden diff (like
    `stages[].duration_ms`).
  - `IsolationEvidence{network?, allowlist[], egress{host, allowed, detail}}`.
    `allowed` is always `false` on success; reachable is a verdict failure,
    never `true` in persisted evidence.
  - `None` = not applicable (v1/v2, pre-isolation). `None` preserves legacy
    `Verified` and byte-identical v1 JSON (no `contracts`/`isolation` keys).
    `Some` = v3 contract stage ran.
- New `VerdictClassification::IsolationFailed` (`isolation-failed`, badge
  `ISOLATION FAILED`), chosen over `VerificationFailed + isolation/...`:
  - Contract failures (`contract/...`, `Stage::Contracts`) map to
    `VerificationFailed`.
  - Isolation failures (`isolation/egress-allowed`,
    `isolation/policy-failed`, `Stage::Boot`, or `egress.allowed==true`) map
    to `IsolationFailed`, which dominates contract gating and `BootFailed`.
  - `Verified` requires: stage verdict `Passed` AND (`contracts == None`
    legacy OR `Some` non-empty all `passed` with no `code`) AND no isolation
    failure. Empty/partial/failed contracts while `Passed` demotes to
    `VerificationFailed`. `evidence check` (`validate()`) rejects `Verified`
    with empty/failed `Some(contracts)`.
- `SecretRedactor::redact_bundle` covers `contracts[].{name,kind,output,code}`
  and `isolation.{network,allowlist,egress.*}`; `render_html_report` /
  `render_text_report` render deterministic Contracts + Isolation sections
  from the already-redacted bundle with HTML escaping.
- Engine `start_run_v3` runs boot then `Stage::Contracts` (new `Stage`
  variant, journaled + `contracts` stage timing) via
  `StageExecutor::execute_contracts` (default noop `Ok(vec![])` so v1/v2 keep
  working). Empty/partial results fail closed with `contract/empty`.
  Isolation block is built from run-id network + allowlist union + boot probe
  extras, redacted before persist.
- CLI `run` on v3 threads manifest contracts through (no new flags;
  contracts come from the manifest): real psql-over-socket SQL backend,
  minimal TCP HTTP backend (https fails closed as `contract/crash`), real
  exec via `ContractExecutor`. Exit `1` with `contract/...` or
  `isolation/...` code on failure (existing verdict-code propagation).

## Consequences

- v1/v2 goldens still validate; v1 without contracts serializes without new
  keys. New golden exclusion: `contracts[].duration_ms`.
- Negative tests enforce: canary in SQL/HTTP/exec output never survives
  `evidence.json`/`report.html`; `health-pass + contracts-fail => not
  Verified`; `evidence check` rejects bad `Verified`.
- E2E matrix + docs overhaul deferred to O3-5.
