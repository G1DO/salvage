# Salvage

Salvage is a recovery-verification tool for proving that a specific PostgreSQL backup and application release can reconstruct a valid service in an isolated environment.

## Goals

- Restore declared PostgreSQL backups reproducibly.
- Verify exact backup and application artifact identities.
- Produce typed, machine-readable recovery results.
- Test failure, timeout, cancellation, and cleanup behavior.
- Prevent recovery drills from contacting production systems.
- Retain redacted evidence for every run.

## Status

Salvage is in early development. Current engineering work is tracked in [GitHub Issues](https://github.com/G1DO/salvage/issues).
