//! Bounded run lifecycle, state machine, and resource ownership model.
//!
//! This module defines the state machine, ownership model, stage execution,
//! deadline and cancellation handling, process management, and durable event
//! journaling that make recovery runs bounded, diagnosable, and cleanable.
//!
//! # States and Transitions
//!
//! The lifecycle flows through defined states:
//! `Planning` -> `Validating` -> `Restoring` -> `Verifying` -> `Terminal(Verdict)` -> `Cleaning` -> `Cleaned(RunOutcome)`
//!
//! Any illegal transition returns [`StateError::IllegalTransition`].
//!
//! # Primary Verdict vs Cleanup Separation
//!
//! The final [`RunOutcome`] keeps the primary stage [`Verdict`] separate from
//! [`CleanupStatus`]. A cleanup failure will never erase or mask the root
//! cause of a run failure.
//!
//! # Resource Ownership & Scoped Cleanup
//!
//! Resources (directories, files, process groups) are registered as
//! [`OwnedResource`] with an explicit [`RunId`]. Cleanup is strictly scoped to
//! resources owned by the run, preventing collateral deletion and ensuring
//! idempotent release.
//!
//! # Process Groups & Descendant Reaping
//!
//! Child processes are spawned in isolated process groups (`PGID == PID`).
//! Upon termination, timeout, or cancellation, signals are broadcast to the
//! process group (`-pgid`), escalating from `SIGTERM` to `SIGKILL`, followed
//! by reaping the direct child to prevent orphaned processes and zombies.
//!
//! # Durable Journal & Interrupted Run Diagnosis
//!
//! State transitions, resource acquisitions, and stage events are appended to
//! `journal.jsonl`, while `state.json` is updated atomically on every state
//! change. An interrupted run can be diagnosed post-mortem by inspecting the
//! journal and state files via [`diagnose_run`].
//!
//! # Safe Re-entry
//!
//! Starting a run over an existing state directory fails safely if uncleaned
//! or completed state is detected ([`RunError::StaleResources`] or
//! [`RunError::AlreadyExists`]). Re-entering via [`RunEngine::cleanup_stale`]
//! provides a safe, idempotent recovery cleanup point.

pub mod cancellation;
pub mod engine;
pub mod evidence;
pub mod journal;
pub mod process;
pub mod resource;
pub mod state;

pub use cancellation::{
    CancellationToken, StageDeadline, install_signal_handler, reset_signal_state,
};
pub use engine::{
    DefaultStageExecutor, RunConfig, RunEngine, RunError, StageContext, StageExecutionError,
    StageExecutor,
};
pub use evidence::RunTelemetry;
pub use journal::{EventPayload, Journal, JournalEvent, PersistedState, diagnose_run};
pub use process::{ProcessHandle, terminate_and_reap_child, terminate_process_group};
pub use resource::{OwnedResource, ResourceError, ResourceKind, ResourceManager, RunId};
pub use state::{CleanupStatus, RunOutcome, Stage, State, StateError, Verdict};
