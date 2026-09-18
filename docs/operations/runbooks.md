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

## v3 contracts drill (O3-5)

```sh
# E2E matrix (opt-in Docker, ignored by default):
SALVAGE_TEST_DOCKER=1 cargo test --test e2e_contracts --locked -- --ignored
# happy: PG16 dump + tiny-http + SQL + local-HTTP + exec => verified
# egress: prod-forbidden.invalid blocked, allowed:false, network cleaned
# hang/crash: contract/timeout + contract/crash => verification-failed, no leak
# canary: secret in SQL/HTTP/exec output => [REDACTED], never raw

# manual v3 drill (fixture uses local http://127.0.0.1:8000/, digest placeholder):
docker build -t salvage-tiny-http:test tests/fixtures/images/tiny-http
DIGEST=$(docker image inspect salvage-tiny-http:test --format '{{.Id}}')
sed "s/e22a313ea41b0ce4bc1919997a651a41fc0ae71eaf7d605bc2cbfd03e0a32cb8/${DIGEST#sha256:}/" \
  tests/fixtures/manifest-valid-v3-e2e.json > /tmp/manifest-v3-e2e.json
python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 &
HTTP_PID=$!
cargo run -p salvage-cli --locked -- run /tmp/manifest-v3-e2e.json \
  --backup tests/fixtures/valid-pg16-custom.dump \
  --run-dir target/recovery-evidence-v3
kill $HTTP_PID
ls -la target/recovery-evidence-v3/
# expect evidence.json (contracts[] all passed + isolation allowed:false),
# report.html (Recovery Contracts + Boot Isolation), journal.jsonl, state.json
salvage evidence check target/recovery-evidence-v3/evidence.json
```

## O4 fault matrix (O4-1 + O4-2 + O4-3 + O4-4)

```sh
# Full-slice faults with expected verdicts (opt-in Docker, ignored by default):
SALVAGE_TEST_DOCKER=1 cargo test --test e2e_faults --locked -- --ignored
# corrupt backup => restore/corrupt-backup; wrong DB version => restore/unsupported-version
# missing role (phantom owner) => restore/missing-role
# missing extension (phantm, citext-patched fixture) => restore/missing-extension
# wrong app digest => app/digest-mismatch + boot-failed
# disallowed argv0 => contract/malformed; 70 KiB HTTP body => contract/oversized
# destination file:///dev/full => evidence/write-failed (Linux, ENOSPC-class rep)
# destination under chmod 555 dir => evidence/write-failed (EACCES variant, same path)
# tiny tmpfs pre-filled => evidence/write-failed (true ENOSPC attempt; loud skip without mount priv, see #49)
# restore_seconds < SALVAGE_TEST_RESTORE_DELAY_MS => timeout in restore (stage-timeout variant)
# verify_seconds < SALVAGE_TEST_VERIFY_DELAY_MS => timeout in verification (stage-timeout variant, O4-4)
# SIGTERM mid-contracts => cancelled (code; verdict cancelled); SIGINT mid-boot => cancelled (O4-4 signal pair)
# global deadline => timeout (code; verdict timed-out)
# reachable egress stays unit-double-only: --internal cannot route outside by construction (see #50);
#   blocked case covered full-slice (O3); reachable covered by salvage-oci fake-docker units
# every row: bounded wall-clock, evidence check green, cleanup success, zero leak
# repeat determinism: SALVAGE_FAULT_MATRIX_REPEATS=2 (CI uses 2)
```

Contracts are versioned: `sql` socket-only `psql`, `http` `http://` only (`https` → `contract/crash`), `exec` no-shell allowlist (`true,echo,sleep,false,pg_isready,psql,cat`). Per-contract `timeout_ms` `1..=300000`, output 64 KiB / rows 1000. Health-alone-cannot-verify: boot green + contracts fail ⇒ `verification-failed`, never `verified`.

## Leak / cleanup check

- `docker ps` filtered by run: must be empty after every verdict (verified, failed, timed-out, cancelled).
- Run dir keeps `evidence.json`, `report.html`, `journal.jsonl`, `state.json`; managed PG data/socket dirs gone.
- Interrupted run: inspect `journal.jsonl` + `state.json` via `diagnose_run`; re-enter via `cleanup_stale` (safe, idempotent). Never delete outside owned `RunId` scope.

## Incident sketch

Detect → triage → mitigate → verify recovery → postmortem when learning warrants it → corrective Issues. Keep one record with severity, owner, times, timeline, decisions, recovery evidence. Break-glass: prioritize safe recovery, keep audit trail, complete review/docs after.
