## What / Why

<!-- What changed, why. Link parent Outcome/Issue when one exists. -->

Closes: #

## How verified

<!-- Cheapest trustworthy evidence for the claim. Check all that apply. -->

- [ ] `./scripts/verify.sh` (fmt, clippy `-D warnings`, tests `--locked`, audit, negative fixture)
- [ ] PG16 black-box drill: `cargo run -p salvage-cli --locked -- run tests/fixtures/manifest-valid-pg16-restore.json --backup tests/fixtures/valid-pg16-custom.dump --run-dir target/recovery-evidence`
- [ ] Docker boot E2E (when OCI/boot touched): `SALVAGE_TEST_DOCKER=1 cargo test --test e2e_boot --locked -- --ignored` + `cargo test -p salvage-oci --test boot_integration --locked -- --ignored`
- [ ] Zero-leak check: `docker ps` filter clean, postgres data/socket dirs removed, `evidence.json`/`report.html`/`journal.jsonl`/`state.json` preserved

## Risk checklist

- [ ] No auth / trust boundary / secrets / external input / dependency / persistent-state change — or risk noted below
- [ ] Failure behavior considered (digest-mismatch, corrupt-backup, timeout, cancel, cleanup-failed)
- [ ] Rollback / disable / migrate / recover path noted if operationally risky
- [ ] Public/durable contract impact (manifest v1/v2, evidence v1, CLI exits) considered

Risk notes:

## Docs

- [ ] `README.md` / `docs/` updated in this PR where behavior changed
- [ ] ADR added/updated where an architecturally significant decision changed (preserve old record, add superseding ADR)

## Delivery notes

<!-- Rollout / recovery expectations. N/A for docs-only changes. -->
