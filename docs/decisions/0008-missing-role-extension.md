# ADR 0008: Missing role and extension get distinct restore verdicts (O4-2)

Status: accepted
Date: 2026-09-17

## Context

O4-1 built the full-slice fault harness (ADR 0007). Its matrix showed every
`pg_restore` non-zero exit collapsing into `restore/corrupt-backup`:
`classify_restore_exit_status` looked only at the exit code while the
piped stderr was never drained. A missing role or extension is an
environment mismatch, not a corrupt backup — probed live, a role-owned
dump restores its table and data fine and only the `OWNER TO` reassignment
fails — and operators need the difference to act (create the role /
install the extension vs distrust the artifact).

Issue #48 scopes O4-2: capture stderr, classify, fixtures, matrix row.
Out: observed-vs-declared PG skew (needs a multi-version toolchain),
true-ENOSPC (O4-3), reachable-egress E2E (O4-4).

## Decision

- `ProcessHandle::take_stderr()` exposes the piped stderr handle;
  `execute_restore` drains it after a non-zero exit and classifies on
  (code, stderr). Post-exit read adds no new failure mode: error volumes
  are a handful of lines, and if output ever filled the pipe the child
  would already be stuck and the stage would time out exactly as before.
- New codes (both `OrchestrationFailed`, restore stage, bounded, safe
  evidence, verified cleanup via the existing stage machinery):
  - `restore/missing-role`: one stderr line contains `role "` and
    `" does not exist` (same-line requirement defeats wrapped-output
    false positives).
  - `restore/missing-extension`: one line contains `could not open
    extension control file`, or `extension "` plus `" does not exist`.
  - Anything else keeps `restore/corrupt-backup` (behavior preserved).
- Fragments are the real server message shapes, verified live against
  PostgreSQL 16 during design (role via a scratch restore of the new
  fixture; extension via `CREATE/ALTER EXTENSION postgis` on a scratch
  server). The surfaced message carries the first matching line
  (300-char cap) so the role/extension name reaches the operator.
- Fixture `tests/fixtures/missing-role.dump` (+sha256 in the matrix row):
  generated once via `initdb` scratch cluster, `CREATE ROLE
  phantom_salvage`, table owned by it, `pg_dump -Fc` (see generation
  script notes in #48). The pipeline passes no `--no-owner`, so the
  `OWNER TO` failure surfaces by design.
- No deterministic missing-extension fixture exists in this toolchain:
  the committed dumps carry no extension entries (pinned `plpgsql` is
  skipped by `pg_dump`), dump and restore share one machine so nothing
  can be present-at-dump yet absent-at-restore, and mutating the system
  extension directory inside a test is unacceptable. The classifier is
  unit-tested with the real message shapes instead; a fixture needs a
  multi-extension toolchain (future, same class as PG-skew).
- Matrix: `missing_role_full_slice` row in `e2e_faults.rs` (digest-pinned
  fixture, expects `restore/missing-role` + `orchestration-failed` +
  bound + green `evidence check` + cleanup success + zero leak + role
  name on stderr). No CI change: the row joins the existing `e2e_faults`
  job (CI repeats=2 covers it).
- Docs: runbook + reference fault-table lines.

## Consequences

- O4-2 closes when the classifier units + matrix are green locally and CI
  is green.
- New taxonomy is additive: no existing code changes meaning, and the
  fallback line is byte-identical to the old message.
- Follow-ups stay in #45: O4-3 (true-ENOSPC, slow child), O4-4
  (SIGINT full-slice, verify-deadline, closeout).

## Addendum 2026-09-18: missing-extension E2E fixture (issue #53)

- Fixture `tests/fixtures/missing-extension.dump` (+sha256 in the
  `missing_extension_full_slice` row) closes the deferred gap above with no
  system-dir mutation inside the test and no multi-package toolchain at
  test time.
- Generation (one-time, build-time only): scratch `initdb` cluster,
  `CREATE EXTENSION citext`, `salvage_records` table + 2 rows,
  `pg_dump -Fc --no-comments`, then same-length `citext` (6) → `phantm`
  (6) byte-patch of the 3 plaintext TOC occurrences (`EXTENSION` name,
  `CREATE EXTENSION`, `DROP EXTENSION`). `plpgsql` cannot be the patch
  source because pinned `plpgsql` is skipped by `pg_dump` (no entry to
  patch); `citext` is dumped as a real extension entry. `phantm` never
  exists on any machine, so the asymmetry (present-at-build via `citext`,
  absent-at-restore via `phantm`) is deterministic on the single PG16
  toolchain.
- Restore shape (verified live, PG 16.2): exit 1,
  `extension "phantm" is not available` +
  `DETAIL: Could not open extension control file
  ".../phantm.control": No such file or directory` +
  `Command was: CREATE EXTENSION IF NOT EXISTS phantm WITH SCHEMA public;`
  → classifier `restore/missing-extension` (same path as the existing
  `postgis` unit shape). The matrix row mirrors `missing_role_full_slice`
  (digest pin, `orchestration-failed`, 180 s bound, green
  `evidence check`, cleanup success, zero leak, `phantm` on stderr).
- No CI change: the row joins the existing `e2e_faults` job
  (CI repeats=2 covers it).
