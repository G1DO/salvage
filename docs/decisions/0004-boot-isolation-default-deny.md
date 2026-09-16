# ADR 0004: Boot isolation default-deny via per-run internal network (O3-3)

Status: accepted
Date: 2026-09-16

## Context

O2 boot runs app containers on `bridge -P` (`crates/salvage-oci/src/container.rs`),
which leaves container-to-outside egress open. O3 needs undeclared production
dependencies unreachable, with any forbidden attempt recorded as safe evidence
instead of a silent pass. Manifest v3 already declares default-deny
(`egress_allow` absent means deny; HTTP must list its host, ADR 0003), but
nothing enforces it at runtime. PG precedent is socket-only
(`listen_addresses = ''`).

Issue #36 offers two drivers: `none` / no-egress + allowlist, or
loopback + PG-socket only.

## Decision

- Per-run isolated bridge network with `--internal`:
  `docker network create --internal --label salvage-run=<run-id>
  --label salvage-isolation=default-deny salvage-net-<run-id>`,
  then `docker run --network <isolated> -P ...`. `-P` is retained but is a
  no-op on `--internal` (Docker ignores publishing on internal networks);
  readiness does not rely on it.
- Why not `none`: `none` also breaks host-to-container readiness (`-P` is
  ignored, `tcp`/`http` probes from the host never connect). `--internal`
  was chosen over `none` because it still denies container-to-outside
  egress while keeping a real bridge for DNS/loopback semantics; host
  publishing is still ineffective, so readiness uses an in-container
  fallback (next point).
- Readiness fallback (`crates/salvage-oci/src/probe.rs`): `tcp`/`http`
  first try the host mapped-port probe (O2 behavior); on failure they retry
  inside the container via `docker exec` (`nc -z -w2 127.0.0.1 <port>` for
  TCP, `wget -qO- --timeout=2 http://127.0.0.1:<port><path>` for HTTP,
  both BusyBox-friendly). Missing tools are `Ok(false)` so bridge images
  without `nc`/`wget` still pass via the host path. `exec` readiness is
  unchanged (already `docker exec`).
- Allowlist derived from v3 `contracts[].egress_allow`, validated
  (hosts, no `://`, no whitespace). O3-3 still denies everything: no egress
  rule is added. The list is retained for evidence and a future allowlist
  proxy.
- Forbidden-egress probe after start, before readiness:
  `docker exec <id> wget -qO- --timeout=2 http://prod-forbidden.invalid/`
  with `curl --max-time 2` fallback. `.invalid` (RFC 2606) never leaves the
  lab; no external network dependency.
  - Blocked (non-zero) → `Ok{allowed:false}`.
  - Reachable (exit 0) → `Failed{Boot, isolation/egress-allowed}`.
  - Missing tools / `docker exec` spawn failure →
    `Failed{Boot, isolation/policy-failed}` (fail-closed, no silent pass).
  - Detail redacted via `SecretRedactor` before evidence.
- Fail-closed everywhere: any `network create` / policy validation error
  returns `isolation/policy-failed` and aborts boot; never falls back to
  `bridge`. `TimedOut`/`Cancelled` propagate unchanged.
- Cleanup: network registered in `ResourceManager` as `Network{name}`.
  Release order is containers first, then networks, then process groups /
  files / dirs. Engine `release_all` therefore removes container + network
  on both pass and fail paths; no network object exists for `none`, so
  `internal` also satisfies the `docker ps` + `docker network ls` clean
  acceptance check.

## Consequences

- Boot is deny-by-default; undeclared prod contact is unreachable.
- Reachable-despite-deny becomes `Failed{Boot, isolation/egress-allowed}`
  (`BootFailed` classification), never `Verified`.
- `ResourceManager` gains `Network` kind + `remove_network` (`network rm`,
  `No such network` idempotent).
- A future schema change (allowlist proxy, egress rules) needs a new ADR;
  this record is preserved.
