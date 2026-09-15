# Runbooks

Action-oriented procedures. Evidence systems own what actually happened; link bundles, don't copy them.

## PG16 black-box drill

```sh
cargo run -p salvage-cli --locked -- run tests/fixtures/manifest-valid-pg16-restore.json \
  --backup tests/fixtures/valid-pg16-custom.dump \
  --run-dir target/recovery-evidence
ls -la target/recovery-evidence/
# expect evidence.json, report.html, journal.jsonl, state.json
salvage evidence check target/recovery-evidence/evidence.json
```

If `initdb` missing: CI shims `/usr/lib/postgresql/16/bin` or `apt install postgresql-16`. Locally set `POSTGRES_BIN_DIR` to your PG16 `bin/`.
Failure map: `restore/digest-mismatch` (wrong file), `restore/corrupt-backup` (use `tests/fixtures/corrupt-truncated.dump`), `restore/unsupported-version` (version skew), `restore/missing-prerequisite` (no binaries/file).

## v2 boot drill

```sh
# build (paths mirrored in tests/fixtures/images/)
docker build -t salvage-tiny-http crates/salvage-oci/tests/fixtures/images/tiny-http
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' salvage-tiny-http | cut -d@ -f2)
# happy path (tcp:8080)
cargo run -p salvage-cli --locked -- run tests/fixtures/manifest-valid-v2-boot-tcp.json \
  --backup tests/fixtures/valid-pg16-custom.dump \
  --artifact "salvage-tiny-http@$DIGEST" --run-dir target/boot-evidence
# wrong digest → app/digest-mismatch + boot-failed, no leak
# crash image (CMD false) → app/crash; hang image + boot_seconds 5 → timed-out; SIGINT mid-boot → cancelled
docker ps --filter 'name=salvage' --filter 'ancestor=salvage-tiny-http' -q | wc -l
# expect 0; postgres data/socket dirs removed, evidence preserved
```

## Leak / cleanup check

- `docker ps` filtered by run: must be empty after every verdict (verified, failed, timed-out, cancelled).
- Run dir keeps `evidence.json`, `report.html`, `journal.jsonl`, `state.json`; managed PG data/socket dirs gone.
- Interrupted run: inspect `journal.jsonl` + `state.json` via `diagnose_run`; re-enter via `cleanup_stale` (safe, idempotent). Never delete outside owned `RunId` scope.

## Incident sketch

Detect → triage → mitigate → verify recovery → postmortem when learning warrants it → corrective Issues. Keep one record with severity, owner, times, timeline, decisions, recovery evidence. Break-glass: prioritize safe recovery, keep audit trail, complete review/docs after.
