//! Recovery contract executor core: bounded plus classified.
//!
//! Runs `sql` / `http` / `exec` contracts declared by `v3` manifests
//! (`crates/salvage-core/src/manifest.rs`, O3-1 schema) against the booted
//! artifact with bounded deadlines and a stable error taxonomy.
//!
//! Scope (O3-2): executor core only. No network policy, no evidence schema
//! change, no CLI wiring, no Docker E2E. `sql` / `http` backends are injected
//! traits so unit tests run as in-memory fakes (no Docker, no PG, no real
//! sockets); `exec` spawns real children directly (no shell) in isolated
//! process groups (`crates/salvage-core/src/lifecycle/process.rs`) so the
//! timeout path can be proven to reap the group.
//!
//! Captured output is passed through `SecretRedactor` before assert/persist.
//! SQL handles are socket-only (`socket_dir: &Path`); there is deliberately no
//! TCP host/port parameter.

pub mod caps;
pub mod executor;
pub mod outcome;

pub use caps::ContractCaps;
pub use executor::{
    BackendError, ContractExecutor, ExecOptions, HttpBackend, HttpResponse, SqlBackend,
};
pub use outcome::{
    CODE_ASSERT_FAILED, CODE_CRASH, CODE_MALFORMED, CODE_OVERSIZED, CODE_TIMEOUT, ContractResult,
    ContractStatus,
};
