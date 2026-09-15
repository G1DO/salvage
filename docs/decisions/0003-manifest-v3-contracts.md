# ADR 0003: Manifest v3 declared recovery contracts (O3-1)

Status: accepted
Date: 2026-09-16

## Context

O3 needs versioned SQL / HTTP / executable contracts to prove application
validity. O3-1 declares them without executing so O3-2+ (executor,
isolation, evidence) has a stable schema. ADR 0001 requires new
capabilities to arrive as a new `schema_version` with older versions frozen.

## Decision

- `v3` is a strict superset of `v2`: every `v2` field keeps meaning,
  position, and validation. `v3` additionally requires `contracts[]`,
  ordered after `app`: `schema_version, backup, postgres, restore, app,
  contracts, limits, deadlines, evidence, run`.
- Contract shape: `{name, kind: sql|http|exec, spec, timeout_ms,
  egress_allow?}` with `deny_unknown_fields` everywhere. `spec` must match
  `kind`: `sql{query}` | `http{url, method?}` | `exec{command[]}`.
- Deadlines are per-contract `timeout_ms` (`1..=300000`), not a central
  `deadlines.verify_contracts_seconds`: heterogeneous SQL/HTTP/exec probes
  need per-probe budgets, consistent with the existing per-stage deadline
  pattern. At most 32 contracts.
- Egress is default-deny: absent `egress_allow` means no network. `http`
  contracts must list their URL host in `egress_allow` (hosts, no `://`);
  unlisted hosts are rejected as `manifest/semantic/contract-egress`.
- Mutable refs rejected where applicable, same policy as the O2 `latest`
  rule: `http` URLs with a `latest` path segment (any case) are rejected as
  `manifest/semantic/contract-mutable-ref`; `app.tag` keeps the v2 rule.
- Diagnostics: `manifest/semantic/contract-name`, `contract-duplicate`,
  `contract-deadline`, `contract-egress`, `contract-spec`,
  `contract-mutable-ref`. Shape errors (unknown fields/kinds, explicit
  `null`) stay `manifest/schema`. Truth lives in
  `crates/salvage-core/src/manifest.rs`; docs link to it.
- `salvage run` on `v3` exits `usage` until O3-2+ implements execution;
  `manifest check` accepts `v3`. No executor, isolation, evidence, or E2E
  change in this slice.

## Consequences

- `v1`/`v2` documents and hashes are unchanged; readers dispatch on
  `schema_version` first.
- O3-2+ can assume at least one well-formed, uniquely named, budgeted,
  egress-declared contract per `v3` manifest.
- A future schema change requires `v4` and a new ADR.
