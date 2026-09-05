//! Run lifecycle engine, stage execution, and safe re-entry coordination.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::manifest::{Manifest, manifest_hash};

use super::cancellation::{CancellationToken, StageDeadline};
use super::journal::{EventPayload, Journal, PersistedState, now_rfc3339};
use super::resource::{ResourceError, ResourceManager, RunId};
use super::state::{CleanupStatus, RunOutcome, Stage, State, StateError, Verdict};

/// Context provided to stage handlers during execution.
pub struct StageContext<'a> {
    /// Owning run identity.
    pub run_id: &'a RunId,
    /// Recovery manifest.
    pub manifest: &'a Manifest,
    /// Canonical hash of the manifest.
    pub manifest_hash: &'a str,
    /// Resource manager scoped to the run.
    pub resource_manager: &'a mut ResourceManager,
    /// Stage deadline tracker.
    pub deadline: &'a StageDeadline,
    /// Token for propagating cancellation.
    pub cancellation_token: &'a CancellationToken,
    /// Journal for recording custom stage events.
    pub journal: &'a Journal,
}

/// Errors returned by stage execution handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageExecutionError {
    /// The stage failed with a typed error code.
    Failed {
        /// Stable diagnostic error code.
        code: String,
        /// Detailed failure message.
        message: String,
    },
    /// The stage timed out.
    TimedOut,
    /// The stage was cancelled.
    Cancelled {
        /// Optional signal name.
        signal: Option<String>,
        /// Cancellation reason.
        reason: String,
    },
}

impl StageExecutionError {
    /// Creates a failed stage error.
    pub fn failed(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Failed {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Creates a cancelled stage error.
    pub fn cancelled(signal: Option<String>, reason: impl Into<String>) -> Self {
        Self::Cancelled {
            signal,
            reason: reason.into(),
        }
    }
}

/// Trait implemented by stage executors (e.g. restore handlers, verification checks).
pub trait StageExecutor {
    /// Executes the validation stage.
    fn execute_validation(
        &mut self,
        _ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        Ok(())
    }

    /// Executes the restore stage.
    fn execute_restore(&mut self, _ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        Ok(())
    }

    /// Executes the verification stage placeholder.
    fn execute_verification(
        &mut self,
        _ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        Ok(())
    }
}

/// Default no-op stage executor.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStageExecutor;

impl StageExecutor for DefaultStageExecutor {}

/// Configuration for running a recovery lifecycle.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Unique run identifier.
    pub run_id: RunId,
    /// Working directory for run state, scratch, and evidence.
    pub run_dir: PathBuf,
    /// Optional global deadline limit for the entire run.
    pub global_timeout: Option<Duration>,
    /// Cancellation token.
    pub cancellation_token: CancellationToken,
}

impl RunConfig {
    /// Creates a new run configuration.
    pub fn new(run_id: RunId, run_dir: PathBuf) -> Self {
        Self {
            run_id,
            run_dir,
            global_timeout: None,
            cancellation_token: CancellationToken::new(),
        }
    }
}

/// Errors occurring during run execution or safe re-entry.
#[derive(Debug)]
pub enum RunError {
    /// State machine transition error.
    State(StateError),
    /// Resource management error.
    Resource(ResourceError),
    /// I/O error persisting state or journal.
    Io(std::io::Error),
    /// Attempted to start a run over a run that has already completed.
    AlreadyExists {
        /// The conflicting run ID.
        run_id: RunId,
    },
    /// Attempted to start a run over uncleaned/stale state from a prior interrupted run.
    StaleResources {
        /// The conflicting run ID.
        run_id: RunId,
        /// State in which the prior run was interrupted.
        state: String,
    },
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(err) => write!(f, "lifecycle state error: {err}"),
            Self::Resource(err) => write!(f, "resource error: {err}"),
            Self::Io(err) => write!(f, "i/o error: {err}"),
            Self::AlreadyExists { run_id } => {
                write!(f, "run `{run_id}` already completed in this directory")
            }
            Self::StaleResources { run_id, state } => {
                write!(
                    f,
                    "run `{run_id}` has stale uncleaned resources from interrupted state `{state}`"
                )
            }
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(err) => Some(err),
            Self::Resource(err) => Some(err),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<StateError> for RunError {
    fn from(err: StateError) -> Self {
        Self::State(err)
    }
}

impl From<ResourceError> for RunError {
    fn from(err: ResourceError) -> Self {
        Self::Resource(err)
    }
}

impl From<std::io::Error> for RunError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// The engine that drives the recovery run lifecycle through its states and stages.
pub struct RunEngine;

impl RunEngine {
    /// Executes a bounded recovery run from planning through cleanup.
    pub fn start_run(
        config: RunConfig,
        manifest: Manifest,
        executor: &mut impl StageExecutor,
    ) -> Result<RunOutcome, RunError> {
        let run_id = config.run_id;
        let run_dir = config.run_dir;
        let journal = Journal::new(run_id.clone(), run_dir.clone());
        let hash = manifest_hash(&manifest);

        // 1. Safe re-entry check: ensure no prior stale or completed run state exists
        if journal.state_path().exists()
            && let Ok(existing) = journal.load_state()
        {
            if existing.state.is_cleaned() {
                return Err(RunError::AlreadyExists { run_id });
            } else {
                return Err(RunError::StaleResources {
                    run_id,
                    state: existing.state.name().to_owned(),
                });
            }
        }

        std::fs::create_dir_all(&run_dir)?;
        let mut resource_manager = ResourceManager::new(run_id.clone(), run_dir.clone());

        let mut current_state = State::Planning;
        let created_at = now_rfc3339();
        let mut persisted_state = PersistedState {
            run_id: run_id.clone(),
            manifest_hash: hash.clone(),
            state: current_state.clone(),
            created_at_rfc3339: created_at.clone(),
            updated_at_rfc3339: created_at.clone(),
        };

        journal.save_state(&persisted_state)?;
        journal.record_event(EventPayload::StateTransition {
            from: "init".to_owned(),
            to: current_state.name().to_owned(),
            details: Some(format!("manifest_hash={hash}")),
        })?;

        let global_deadline = config.global_timeout.map(|t| Instant::now() + t);

        // Helper to update state safely and persist
        let transition_to = |next: State,
                             journal: &Journal,
                             persisted_state: &mut PersistedState,
                             current_state: &mut State|
         -> Result<(), RunError> {
            let from_name = current_state.name().to_owned();
            let to_name = next.name().to_owned();
            current_state.transition_to(next)?;
            persisted_state.state = current_state.clone();
            persisted_state.updated_at_rfc3339 = now_rfc3339();
            journal.save_state(persisted_state)?;
            journal.record_event(EventPayload::StateTransition {
                from: from_name,
                to: to_name,
                details: None,
            })?;
            Ok(())
        };

        // Execution Stages
        let mut final_verdict: Option<Verdict> = None;

        // Stage 1: Validation
        transition_to(
            State::Validating,
            &journal,
            &mut persisted_state,
            &mut current_state,
        )?;
        let validation_deadline = StageDeadline::new(Duration::from_secs(60), global_deadline);

        journal.record_event(EventPayload::StageStarted {
            stage: Stage::Validation,
            deadline_seconds: 60,
        })?;

        if config.cancellation_token.is_cancelled() {
            final_verdict = Some(Verdict::cancelled(
                Stage::Validation,
                None,
                "cancelled before validation",
            ));
        } else if validation_deadline.is_expired() {
            final_verdict = Some(Verdict::timed_out(Stage::Validation, 60));
        } else {
            let mut ctx = StageContext {
                run_id: &run_id,
                manifest: &manifest,
                manifest_hash: &hash,
                resource_manager: &mut resource_manager,
                deadline: &validation_deadline,
                cancellation_token: &config.cancellation_token,
                journal: &journal,
            };

            let start = Instant::now();
            match executor.execute_validation(&mut ctx) {
                Ok(()) => {
                    journal.record_event(EventPayload::StageCompleted {
                        stage: Stage::Validation,
                        duration_ms: start.elapsed().as_millis() as u64,
                    })?;
                }
                Err(StageExecutionError::Failed { code, message }) => {
                    journal.record_event(EventPayload::StageFailed {
                        stage: Stage::Validation,
                        code: code.clone(),
                        message: message.clone(),
                    })?;
                    final_verdict = Some(Verdict::failed(Stage::Validation, code, message));
                }
                Err(StageExecutionError::TimedOut) => {
                    journal.record_event(EventPayload::StageTimedOut {
                        stage: Stage::Validation,
                        timeout_seconds: 60,
                    })?;
                    final_verdict = Some(Verdict::timed_out(Stage::Validation, 60));
                }
                Err(StageExecutionError::Cancelled { signal, reason }) => {
                    journal.record_event(EventPayload::StageCancelled {
                        stage: Stage::Validation,
                        signal: signal.clone(),
                        reason: reason.clone(),
                    })?;
                    final_verdict = Some(Verdict::cancelled(Stage::Validation, signal, reason));
                }
            }
        }

        // Stage 2: Restore
        if final_verdict.is_none() {
            transition_to(
                State::Restoring,
                &journal,
                &mut persisted_state,
                &mut current_state,
            )?;
            let restore_timeout_secs = manifest.deadlines.restore_seconds;
            let restore_deadline = StageDeadline::new(
                Duration::from_secs(restore_timeout_secs as u64),
                global_deadline,
            );

            journal.record_event(EventPayload::StageStarted {
                stage: Stage::Restore,
                deadline_seconds: restore_timeout_secs,
            })?;

            if config.cancellation_token.is_cancelled() {
                final_verdict = Some(Verdict::cancelled(
                    Stage::Restore,
                    None,
                    "cancelled before restore",
                ));
            } else if restore_deadline.is_expired() {
                final_verdict = Some(Verdict::timed_out(Stage::Restore, restore_timeout_secs));
            } else {
                let mut ctx = StageContext {
                    run_id: &run_id,
                    manifest: &manifest,
                    manifest_hash: &hash,
                    resource_manager: &mut resource_manager,
                    deadline: &restore_deadline,
                    cancellation_token: &config.cancellation_token,
                    journal: &journal,
                };

                let start = Instant::now();
                match executor.execute_restore(&mut ctx) {
                    Ok(()) => {
                        journal.record_event(EventPayload::StageCompleted {
                            stage: Stage::Restore,
                            duration_ms: start.elapsed().as_millis() as u64,
                        })?;
                    }
                    Err(StageExecutionError::Failed { code, message }) => {
                        journal.record_event(EventPayload::StageFailed {
                            stage: Stage::Restore,
                            code: code.clone(),
                            message: message.clone(),
                        })?;
                        final_verdict = Some(Verdict::failed(Stage::Restore, code, message));
                    }
                    Err(StageExecutionError::TimedOut) => {
                        journal.record_event(EventPayload::StageTimedOut {
                            stage: Stage::Restore,
                            timeout_seconds: restore_timeout_secs,
                        })?;
                        final_verdict =
                            Some(Verdict::timed_out(Stage::Restore, restore_timeout_secs));
                    }
                    Err(StageExecutionError::Cancelled { signal, reason }) => {
                        journal.record_event(EventPayload::StageCancelled {
                            stage: Stage::Restore,
                            signal: signal.clone(),
                            reason: reason.clone(),
                        })?;
                        final_verdict = Some(Verdict::cancelled(Stage::Restore, signal, reason));
                    }
                }
            }
        }

        // Stage 3: Verification
        if final_verdict.is_none() {
            transition_to(
                State::Verifying,
                &journal,
                &mut persisted_state,
                &mut current_state,
            )?;
            let verify_timeout_secs = manifest.deadlines.verify_seconds;
            let verify_deadline = StageDeadline::new(
                Duration::from_secs(verify_timeout_secs as u64),
                global_deadline,
            );

            journal.record_event(EventPayload::StageStarted {
                stage: Stage::Verification,
                deadline_seconds: verify_timeout_secs,
            })?;

            if config.cancellation_token.is_cancelled() {
                final_verdict = Some(Verdict::cancelled(
                    Stage::Verification,
                    None,
                    "cancelled before verification",
                ));
            } else if verify_deadline.is_expired() {
                final_verdict = Some(Verdict::timed_out(Stage::Verification, verify_timeout_secs));
            } else {
                let mut ctx = StageContext {
                    run_id: &run_id,
                    manifest: &manifest,
                    manifest_hash: &hash,
                    resource_manager: &mut resource_manager,
                    deadline: &verify_deadline,
                    cancellation_token: &config.cancellation_token,
                    journal: &journal,
                };

                let start = Instant::now();
                match executor.execute_verification(&mut ctx) {
                    Ok(()) => {
                        journal.record_event(EventPayload::StageCompleted {
                            stage: Stage::Verification,
                            duration_ms: start.elapsed().as_millis() as u64,
                        })?;
                        final_verdict = Some(Verdict::Passed);
                    }
                    Err(StageExecutionError::Failed { code, message }) => {
                        journal.record_event(EventPayload::StageFailed {
                            stage: Stage::Verification,
                            code: code.clone(),
                            message: message.clone(),
                        })?;
                        final_verdict = Some(Verdict::failed(Stage::Verification, code, message));
                    }
                    Err(StageExecutionError::TimedOut) => {
                        journal.record_event(EventPayload::StageTimedOut {
                            stage: Stage::Verification,
                            timeout_seconds: verify_timeout_secs,
                        })?;
                        final_verdict =
                            Some(Verdict::timed_out(Stage::Verification, verify_timeout_secs));
                    }
                    Err(StageExecutionError::Cancelled { signal, reason }) => {
                        journal.record_event(EventPayload::StageCancelled {
                            stage: Stage::Verification,
                            signal: signal.clone(),
                            reason: reason.clone(),
                        })?;
                        final_verdict =
                            Some(Verdict::cancelled(Stage::Verification, signal, reason));
                    }
                }
            }
        }

        let verdict = final_verdict.unwrap_or(Verdict::Passed);

        // Terminal transition
        transition_to(
            State::Terminal(verdict.clone()),
            &journal,
            &mut persisted_state,
            &mut current_state,
        )?;

        // Cleanup phase
        transition_to(
            State::Cleaning(verdict.clone()),
            &journal,
            &mut persisted_state,
            &mut current_state,
        )?;
        journal.record_event(EventPayload::CleanupStarted)?;

        let cleanup_status = match resource_manager.release_all() {
            Ok(()) => {
                journal.record_event(EventPayload::CleanupFinished {
                    success: true,
                    errors: Vec::new(),
                })?;
                CleanupStatus::Success
            }
            Err(errors) => {
                journal.record_event(EventPayload::CleanupFinished {
                    success: false,
                    errors: errors.clone(),
                })?;
                CleanupStatus::failed(errors)
            }
        };

        let outcome = RunOutcome::new(verdict, cleanup_status);
        transition_to(
            State::Cleaned(outcome.clone()),
            &journal,
            &mut persisted_state,
            &mut current_state,
        )?;

        Ok(outcome)
    }

    /// Safely re-enters an interrupted or completed run directory to perform idempotent cleanup.
    pub fn cleanup_stale(run_dir: &Path, run_id: Option<&RunId>) -> Result<RunOutcome, RunError> {
        let state_path = run_dir.join("state.json");
        if !state_path.exists() {
            return Err(RunError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no run state found at {}", state_path.display()),
            )));
        }

        let content = std::fs::read_to_string(&state_path)?;
        let mut persisted: PersistedState = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if let Some(expected_id) = run_id
            && &persisted.run_id != expected_id
        {
            return Err(RunError::Resource(ResourceError::InvalidRunId(format!(
                "state belongs to run `{}`, but `{expected_id}` was specified",
                persisted.run_id
            ))));
        }

        if let State::Cleaned(ref outcome) = persisted.state {
            return Ok(outcome.clone());
        }

        let journal = Journal::new(persisted.run_id.clone(), run_dir.to_path_buf());
        let mut resource_manager =
            ResourceManager::new(persisted.run_id.clone(), run_dir.to_path_buf());

        // Extract or construct a safe terminal verdict for the interrupted run
        let verdict = match &persisted.state {
            State::Terminal(v) | State::Cleaning(v) => v.clone(),
            _ => Verdict::cancelled(
                Stage::Planning,
                None,
                format!(
                    "interrupted in state `{}` and recovered during cleanup",
                    persisted.state.name()
                ),
            ),
        };

        let _ = journal.record_event(EventPayload::CleanupStarted);

        let cleanup_status = match resource_manager.release_all() {
            Ok(()) => {
                let _ = journal.record_event(EventPayload::CleanupFinished {
                    success: true,
                    errors: Vec::new(),
                });
                CleanupStatus::Success
            }
            Err(errors) => {
                let _ = journal.record_event(EventPayload::CleanupFinished {
                    success: false,
                    errors: errors.clone(),
                });
                CleanupStatus::failed(errors)
            }
        };

        let outcome = RunOutcome::new(verdict, cleanup_status);
        persisted.state = State::Cleaned(outcome.clone());
        persisted.updated_at_rfc3339 = now_rfc3339();
        journal.save_state(&persisted)?;

        let _ = journal.record_event(EventPayload::StateTransition {
            from: "recovery_cleanup".to_owned(),
            to: "cleaned".to_owned(),
            details: None,
        });

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::manifest::parse_manifest;

    const VALID_MANIFEST: &str = r#"{
        "schema_version": "v1",
        "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "postgres": {"version": "16.4"},
        "restore": {"source": "s3", "type": "full"},
        "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120},
        "deadlines": {"restore_seconds": 600, "verify_seconds": 300},
        "evidence": {"destination": "file:///tmp/salvage-evidence"},
        "run": {"owner": "recovery-drill"}
    }"#;

    #[test]
    fn engine_executes_successful_run() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-success-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        let run_id = RunId::new("test-success-run").unwrap();
        let config = RunConfig::new(run_id.clone(), temp_dir.clone());
        let mut executor = DefaultStageExecutor;

        let outcome = RunEngine::start_run(config, manifest, &mut executor).unwrap();
        assert!(outcome.verdict.is_passed());
        assert!(outcome.cleanup_status.is_success());

        let journal = Journal::new(run_id, temp_dir.clone());
        let state = journal.load_state().unwrap();
        assert!(state.state.is_cleaned());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn engine_rejects_reentry_over_existing_run() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-reentry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        let run_id = RunId::new("test-reentry-run").unwrap();
        let config = RunConfig::new(run_id.clone(), temp_dir.clone());
        let mut executor = DefaultStageExecutor;

        let outcome =
            RunEngine::start_run(config.clone(), manifest.clone(), &mut executor).unwrap();
        assert!(outcome.verdict.is_passed());

        // Re-entry must fail safely
        let err = RunEngine::start_run(config, manifest, &mut executor).unwrap_err();
        assert!(matches!(err, RunError::AlreadyExists { .. }));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    struct FailingRestoreExecutor;
    impl StageExecutor for FailingRestoreExecutor {
        fn execute_restore(
            &mut self,
            _ctx: &mut StageContext<'_>,
        ) -> Result<(), StageExecutionError> {
            Err(StageExecutionError::failed(
                "restore/corrupt",
                "corrupted segment detected",
            ))
        }
    }

    #[test]
    fn engine_handles_stage_failure_and_performs_cleanup() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        let run_id = RunId::new("test-fail-run").unwrap();
        let config = RunConfig::new(run_id, temp_dir.clone());
        let mut executor = FailingRestoreExecutor;

        let outcome = RunEngine::start_run(config, manifest, &mut executor).unwrap();
        assert_eq!(
            outcome.verdict,
            Verdict::failed(
                Stage::Restore,
                "restore/corrupt",
                "corrupted segment detected"
            )
        );
        assert!(outcome.cleanup_status.is_success());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
