# ADR 0007: Fault taxonomy plus full-slice harness (O4-1)

Status: accepted
Date: 2026-09-17

## Context

O4 requires the recovery runner to stay correct under faults and
cancellation across the full restore → boot → contracts slice, each fault
with an expected verdict, bounded completion, retained safe evidence, and
verified cleanup. Per-slice coverage exists (O2 `e2e_boot.rs`, O3
`e2e_contracts.rs`, restore integration, contract units), but no test runs
the whole v3 pipeline under fault, and two gaps were found while designing
the matrix:

1. A signal (`SIGINT`/`SIGTERM`) arriving mid-contracts was silently
   ignored: `V3Executor::execute_contracts` never consulted the
   cancellation token, and the exec poll loop only watched the contract
   timeout. A 30 s `sleep` contract would run to completion and the run
   could still verify.
2. No global-deadline plumbing reached the CLI: `RunConfig::global_timeout`
   existed but `salvage run` always left it `None`, so global expiry was
   untestable end-to-end.

Issue #46 scopes O4-1: taxonomy + harness with faults injectable without
changing the manifest schema or CLI flags. Out: missing role/extension
distinct codes (needs `pg_restore` stderr classification, O4-2), true
filesystem-`ENOSPC` (O4-3), reachable-egress E2E (O4-4). See #45.

## Decision

- Matrix `crates/salvage-cli/tests/e2e_faults.rs`, all `#[ignore]` +
  `SALVAGE_TEST_DOCKER=1` (O3-5 precedent). Each row runs the full v3
  slice and asserts exit code, expected `code` on stderr, bounded
  wall-clock, parsed `evidence.json` classification, green
  `evidence check` with `cleanup_status success`, and zero leak
  (containers, `salvage-net-<run-id>`, `!run_dir/postgres`, 4 evidence
  files kept):
  - truncated backup (`corrupt-truncated.dump` + its own digest so the
    magic-byte check fires) ⇒ `restore/corrupt-backup`,
    `orchestration-failed`;
  - declared `postgres.version 99.0` ⇒ `restore/unsupported-version`,
    `orchestration-failed`;
  - zeroed `app.digest` pin ⇒ `app/digest-mismatch`, `boot-failed`;
  - disallowed `argv[0]` (`rm`, passes manifest shape checks, rejected by
    the exec allowlist before spawn) ⇒ `contract/malformed`,
    `verification-failed`;
  - 70 KiB HTTP body vs 64 KiB cap ⇒ `contract/oversized` + `truncated`,
    `verification-failed` (HTTP, not exec: a >64 KiB `echo` fills the pipe
    with nobody draining and deadlocks into `contract/timeout`);
  - `evidence.destination file:///dev/full` (Linux-only row; every write
    fails `ENOSPC`-class) ⇒ `evidence/write-failed`,
    `verification-failed`, run-dir bundle still persisted;
  - `SIGTERM` while an `exec sleep 60` contract runs ⇒ `cancelled`;
    the signal lands deterministically by polling `journal.jsonl` for
    `"stage":"contracts"` (`stage-started`, kebab-case as persisted);
  - `SALVAGE_TEST_GLOBAL_TIMEOUT_MS=3000` + `SALVAGE_TEST_RESTORE_DELAY_MS=15000`
    ⇒ `timed-out` inside restore.
- Product changes (all covered by the matrix):
  - `cancellation::interrupt_requested()` exposes the process-wide signal
    flag; the exec poll loop preempts a hung child on interrupt (kill +
    wait, ~10 ms poll). The timeout-shaped result is discarded: the caller
    maps interrupted runs to `Cancelled` via the token, so no taxonomy
    change was needed. Hung `sql`/`http` stay bounded by their
    `timeout_ms` and cancel at the contract boundary.
  - `V3Executor::execute_contracts` honors the token and the stage
    deadline at every contract boundary (pre- and post-contract), returning
    `Cancelled`/`TimedOut` instead of running to a stale `Passed`.
  - Test-only `SALVAGE_TEST_GLOBAL_TIMEOUT_MS` env hook in `salvage run`
    (mirrors the `SALVAGE_TEST_RESTORE_DELAY_MS` precedent; never set in
    production, no manifest/flag change).
- Repeats: `SALVAGE_FAULT_MATRIX_REPEATS=N` (default 1); CI runs 2, and run
  ids carry pid + nanos so a leak from an earlier iteration cannot be
  masked.
- CI (`.github/workflows/ci.yml`): `SALVAGE_TEST_DOCKER=1
  SALVAGE_FAULT_MATRIX_REPEATS=2 cargo test --test e2e_faults --locked --
  --ignored` after the contracts matrix step.
- Docs: runbook gains the matrix command; reference gains the new env hook
  and matrix pointer.

## Consequences

- O4-1 closes when the matrix is green locally (8/8 at O4-1 merge, ~25 s;
  9/9 with O4-2's missing-role row) + CI green with Docker tests ignored
  by default.
- CI cost: ~1 min extra (8 rows × ~25 s ÷ 2 threads × 2 repeats at O4-1
  merge; grows by one row in O4-2).
- Known limitation: cancellation during a hung `sql`/`http` contract takes
  effect at the contract boundary (bounded by `timeout_ms`); only `exec`
  preempts mid-contract today.
- Follow-ups stay in #45 slices O4-2..O4-4; allowlist proxy, `https` TLS,
  broad DB support still need new ADRs.
