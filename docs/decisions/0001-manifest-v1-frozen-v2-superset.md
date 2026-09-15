# ADR 0001: Manifest v1 frozen, v2 strict superset

Status: accepted
Date: 2026-09-15

## Context

Recovery manifests are durable contracts. Drills, evidence bundles, and hashes reference exact manifests; silent reinterpretation would break verifiability.

## Decision

- `v1` is frozen byte-identical forever.
- Schema changes require a new `schema_version`. `v2` is a strict superset: every `v1` field keeps meaning/position/validation, plus required `app{digest, readiness}` and `deadlines.boot_seconds`.
- Readers dispatch on `schema_version` first, reject unknown versions as `manifest/unsupported-version`, reject unknown fields as `manifest/schema` (no silent misspelling).
- Canonical hash is `sha256:<hex>` over compact JSON in declaration order; whitespace-trimmed value fields share one hash (except `schema_version`).

## Consequences

- Old drills replay exactly; new capabilities are additive and explicitly versioned.
- Writers must emit exactly one known version; multi-version readers stay explicit.
- Superseded only by a new ADR adding `v3` or changing hashing.
