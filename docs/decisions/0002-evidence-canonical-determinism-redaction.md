# ADR 0002: Evidence JSON canonical, deterministic projections, mandatory redaction

Status: accepted
Date: 2026-09-15

## Context

Evidence must be machine-verifiable, diffable in goldens, and safe to retain/upload from CI. Timestamps/durations and secrets would break determinism or leak credentials.

## Decision

- `evidence.json` (v1) is the canonical source of truth; `report.html`/text are deterministic projections.
- Golden comparison excludes `run_id`, `created_at`, `completed_at`, `total_duration_ms`, `stages[].duration_ms`, `events[].timestamp/run_id/duration_ms`.
- `Verdict` kept separate from `CleanupStatus`; cleanup failure never masks primary verdict. `completeness`: `complete` vs `incomplete`.
- `SecretRedactor` runs before persistence and projection (credentials, connection strings, keys, auth headers, env secrets). Enforced by `redaction_canary` + `report_determinism` tests.

## Consequences

- Bundles are comparable, auditable, and safe to upload as CI artifacts.
- New verdict kinds or redaction patterns require schema/test updates in the same PR.
