# Salvage

Salvage is an evidence-producing recovery-verification system.

Given an immutable backup identity and an exact released application artifact, it reconstructs the declared service in an isolated environment, runs application-owned recovery contracts, emits a typed verdict with redacted evidence, and proves cleanup.

> Status: greenfield. No recovery capability or portfolio claim is implemented yet.

## Current outcome

Build the first independently verifiable vertical slice:

- validate a versioned run manifest;
- restore one supported PostgreSQL logical backup into an isolated target;
- supervise lifecycle, cancellation, deadlines, and cleanup;
- distinguish infrastructure, restore, verification, timeout, cancellation, and cleanup failures;
- emit machine-readable evidence tied to immutable inputs;
- prove zero owned resources remain after success and failure.

The canonical outcome definition and exit gate live in [Notion](https://app.notion.com/p/3d10a821b3cc816aa790f11c5077828b). Accepted engineering work lives in [GitHub Issues](https://github.com/G1DO/salvage/issues).

## Scope

The first release is intentionally narrow:

- Rust owns the CLI, state machine, process/container lifecycle, PostgreSQL restore orchestration, failure taxonomy, evidence, and cleanup.
- Python may later provide a versioned out-of-process recovery-contract SDK for applications such as Ahoy.
- Initial support is one PostgreSQL logical-backup path and one local isolated execution model.

Not in the first release: backup creation, scheduling, Kubernetes, a hosted control plane, multi-cloud failover, arbitrary workflow scripting, or broad database support.

## Correctness principles

A run cannot be marked verified unless:

1. backup identity and declared versions match the manifest;
2. restoration and required structural checks succeed;
3. mandatory application contracts pass;
4. forbidden production access does not occur;
5. evidence is complete and redacted;
6. every owned resource is removed.

A health endpoint alone is never recovery proof.

## Source of truth

- [Salvage project hub](https://app.notion.com/p/3d10a821b3cc81ff9201e9ef47eaa463)
- [Detailed blueprint](https://app.notion.com/p/3cf0a821b3cc81f98815e1d7f7f1b235)
- [Engineering workflow](https://app.notion.com/p/3bb0a821b3cc817394cdf93a936a3612)
- [GitHub execution](https://github.com/G1DO/salvage/issues)

Notion owns product intent, durable requirements, outcomes, decisions, risks, and verified conclusions. GitHub Issues and pull requests own executable work. Repository documentation owns implemented technical truth.

## Working method

Use small issues, short-lived branches, focused pull requests, CI evidence tied to the exact commit, and system-level outcome verification. Do not call an outcome complete because its issues are closed; verify its Notion exit gate with durable evidence.
