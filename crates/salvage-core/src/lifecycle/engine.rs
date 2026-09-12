//! Run lifecycle engine, stage execution, and safe re-entry coordination.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::manifest::{Manifest, ManifestV2, manifest_hash, manifest_hash_v2};

use super::cancellation::{CancellationToken, StageDeadline};
use super::evidence::{
    RunTelemetry, StageTimingRecord, build_evidence_bundle, persist_evidence,
    resolve_destination_path,
};
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
    /// Operational telemetry collector.
    pub telemetry: &'a mut RunTelemetry,
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

    /// Executes the application boot stage (v2 manifests only).
    ///
    /// The default is a no-op so existing executors keep working; Slice 2+
    /// overrides this to boot the declared OCI artifact and probe readiness.
    fn execute_boot(&mut self, _ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        Ok(())
    }

    /// Returns captured telemetry if provided by the executor.
    fn telemetry(&self) -> Option<RunTelemetry> {
        None
    }
}

/// Default no-op stage executor.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStageExecutor;

impl StageExecutor for DefaultStageExecutor {}

/// Boot execution policy: the engine runs its boot block if and only if a
/// policy is present (`start_run_v2` always supplies one from
/// `ManifestV2.deadlines.boot_seconds`; `start_run` supplies none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootPolicy {
    /// Seconds allowed for the boot stage; must be positive (v2 manifests
    /// guarantee this via `manifest/semantic/deadlines` validation).
    pub boot_seconds: i64,
}

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

/// Applies the declared-manifest snapshot to a freshly built bundle.
///
/// The snapshot is assigned *after* `build_evidence_bundle` (which redacts
/// the core-declared value), so it must be redacted explicitly here: without
/// this, secrets in `owner`/`destination` would leak back into evidence via
/// the unredacted override (caught by the canary tests).
fn apply_declared_snapshot(
    bundle: &mut salvage_evidence::EvidenceBundle,
    declared_manifest: &serde_json::Value,
) {
    bundle.manifest.declared = declared_manifest.clone();
    let mut redactor = salvage_evidence::SecretRedactor::new();
    redactor.add_env_secrets();
    redactor.redact_value(&mut bundle.manifest.declared);
}

/// The engine that drives the recovery run lifecycle through its states and stages.
pub struct RunEngine;

impl RunEngine {
    /// Executes a bounded recovery run from planning through cleanup (v1).
    ///
    /// v1 manifests declare no boot stage, so the boot block never runs and
    /// the evidence contains no `boot` timing: v1 behavior is unchanged.
    pub fn start_run(
        config: RunConfig,
        manifest: Manifest,
        executor: &mut impl StageExecutor,
    ) -> Result<RunOutcome, RunError> {
        Self::start_run_with_boot(config, manifest, None, executor)
    }

    /// Executes a bounded run with an optional boot stage.
    ///
    /// `Some(boot)` runs the boot block after successful verification,
    /// emitting `Boot` stage events and a `boot` stage timing; `None` skips
    /// it entirely. Shared implementation behind `RunEngine::start_run`
    /// (v1, `None`) and `RunEngine::start_run_v2` (v2, always `Some`).
    pub fn start_run_with_boot(
        config: RunConfig,
        manifest: Manifest,
        boot: Option<BootPolicy>,
        executor: &mut impl StageExecutor,
    ) -> Result<RunOutcome, RunError> {
        let hash = manifest_hash(&manifest);
        let declared = serde_json::to_value(&manifest).unwrap_or(serde_json::Value::Null);
        Self::run_inner(config, manifest, hash, declared, boot, executor)
    }

    /// Executes a bounded recovery run for a v2 manifest (with boot stage).
    ///
    /// Design choice (Slice 1): `StageContext` still carries the v1 core
    /// manifest; the v2 hash and the full declared v2 snapshot travel
    /// alongside it into state, journal details, and evidence. Slice 2
    /// extends the context with the full `AppArtifact`
    /// (digest/repository/tag/readiness) so the boot executor can pull and
    /// probe the declared artifact.
    pub fn start_run_v2(
        config: RunConfig,
        manifest: ManifestV2,
        executor: &mut impl StageExecutor,
    ) -> Result<RunOutcome, RunError> {
        let hash = manifest_hash_v2(&manifest);
        let declared = serde_json::to_value(&manifest).unwrap_or(serde_json::Value::Null);
        let boot = Some(BootPolicy {
            boot_seconds: manifest.deadlines.boot_seconds,
        });
        Self::run_inner(
            config,
            manifest.core_manifest(),
            hash,
            declared,
            boot,
            executor,
        )
    }

    fn run_inner(
        config: RunConfig,
        manifest: Manifest,
        hash: String,
        declared_manifest: serde_json::Value,
        boot: Option<BootPolicy>,
        executor: &mut impl StageExecutor,
    ) -> Result<RunOutcome, RunError> {
        let run_id = config.run_id;
        let run_dir = config.run_dir;
        let journal = Journal::new(run_id.clone(), run_dir.clone());

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

        let run_start_instant = Instant::now();
        let mut stage_timings: Vec<StageTimingRecord> = Vec::new();
        let mut telemetry = RunTelemetry {
            boot_seconds: boot.map(|b| b.boot_seconds),
            ..Default::default()
        };

        // Write initial incomplete evidence bundle (with the declared
        // snapshot so v2 runs reference the full v2 manifest from the start).
        {
            let now = now_rfc3339();
            let stages = vec![StageTimingRecord {
                stage: "planning".to_owned(),
                status: "passed".to_owned(),
                duration_ms: None,
            }];
            let mut initial = build_evidence_bundle(
                &run_id,
                &manifest,
                &hash,
                &now,
                None,
                None,
                &stages,
                None,
                None,
                Vec::new(),
                &telemetry,
                salvage_evidence::EvidenceCompleteness::Incomplete,
            );
            apply_declared_snapshot(&mut initial, &declared_manifest);
            let _ = persist_evidence(&initial, &run_dir);
        }

        stage_timings.push(StageTimingRecord {
            stage: "planning".to_owned(),
            status: "passed".to_owned(),
            duration_ms: Some(run_start_instant.elapsed().as_millis() as u64),
        });

        // Execution Stages
        let mut final_verdict: Option<Verdict> = None;

        // Stage 1: Validation
        transition_to(
            State::Validating,
            &journal,
            &mut persisted_state,
            &mut current_state,
        )?;
        let val_start = Instant::now();
        let validation_deadline = StageDeadline::new(Duration::from_secs(60), global_deadline);

        journal.record_event(EventPayload::StageStarted {
            stage: Stage::Validation,
            deadline_seconds: 60,
        })?;

        if config.cancellation_token.is_cancelled() {
            let sig = config.cancellation_token.cancellation_signal();
            final_verdict = Some(Verdict::cancelled(
                Stage::Validation,
                sig,
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
                telemetry: &mut telemetry,
            };

            match executor.execute_validation(&mut ctx) {
                Ok(()) => {
                    journal.record_event(EventPayload::StageCompleted {
                        stage: Stage::Validation,
                        duration_ms: val_start.elapsed().as_millis() as u64,
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

        stage_timings.push(StageTimingRecord {
            stage: "validation".to_owned(),
            status: match &final_verdict {
                None => "passed".to_owned(),
                Some(Verdict::Failed { .. }) => "failed".to_owned(),
                Some(Verdict::TimedOut { .. }) => "timed-out".to_owned(),
                Some(Verdict::Cancelled { .. }) => "cancelled".to_owned(),
                Some(Verdict::Passed) => "passed".to_owned(),
            },
            duration_ms: Some(val_start.elapsed().as_millis() as u64),
        });

        // Stage 2: Restore
        if final_verdict.is_none() {
            transition_to(
                State::Restoring,
                &journal,
                &mut persisted_state,
                &mut current_state,
            )?;
            let restore_start = Instant::now();
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
                let sig = config.cancellation_token.cancellation_signal();
                final_verdict = Some(Verdict::cancelled(
                    Stage::Restore,
                    sig,
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
                    telemetry: &mut telemetry,
                };

                match executor.execute_restore(&mut ctx) {
                    Ok(()) => {
                        journal.record_event(EventPayload::StageCompleted {
                            stage: Stage::Restore,
                            duration_ms: restore_start.elapsed().as_millis() as u64,
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

            stage_timings.push(StageTimingRecord {
                stage: "restore".to_owned(),
                status: match &final_verdict {
                    None => "passed".to_owned(),
                    Some(Verdict::Failed { .. }) => "failed".to_owned(),
                    Some(Verdict::TimedOut { .. }) => "timed-out".to_owned(),
                    Some(Verdict::Cancelled { .. }) => "cancelled".to_owned(),
                    Some(Verdict::Passed) => "passed".to_owned(),
                },
                duration_ms: Some(restore_start.elapsed().as_millis() as u64),
            });
        }

        // Stage 3: Verification
        if final_verdict.is_none() {
            transition_to(
                State::Verifying,
                &journal,
                &mut persisted_state,
                &mut current_state,
            )?;
            let verify_start = Instant::now();
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
                let sig = config.cancellation_token.cancellation_signal();
                final_verdict = Some(Verdict::cancelled(
                    Stage::Verification,
                    sig,
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
                    telemetry: &mut telemetry,
                };

                match executor.execute_verification(&mut ctx) {
                    Ok(()) => {
                        journal.record_event(EventPayload::StageCompleted {
                            stage: Stage::Verification,
                            duration_ms: verify_start.elapsed().as_millis() as u64,
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

            stage_timings.push(StageTimingRecord {
                stage: "verification".to_owned(),
                status: match &final_verdict {
                    None | Some(Verdict::Passed) => "passed".to_owned(),
                    Some(Verdict::Failed { .. }) => "failed".to_owned(),
                    Some(Verdict::TimedOut { .. }) => "timed-out".to_owned(),
                    Some(Verdict::Cancelled { .. }) => "cancelled".to_owned(),
                },
                duration_ms: Some(verify_start.elapsed().as_millis() as u64),
            });
        }

        // Stage 4: Boot (gated on the boot policy: v2 manifests only).
        //
        // v1 runs (`boot == None`) skip this block entirely: no `Boot`
        // journal events and no `boot` timing, so v1 evidence is unchanged.
        if let Some(boot_policy) = boot
            && final_verdict.as_ref().is_some_and(Verdict::is_passed)
        {
            transition_to(
                State::Booting,
                &journal,
                &mut persisted_state,
                &mut current_state,
            )?;
            let boot_start = Instant::now();
            let boot_timeout_secs = boot_policy.boot_seconds;
            let boot_deadline = StageDeadline::new(
                Duration::from_secs(boot_timeout_secs as u64),
                global_deadline,
            );

            journal.record_event(EventPayload::StageStarted {
                stage: Stage::Boot,
                deadline_seconds: boot_timeout_secs,
            })?;

            if config.cancellation_token.is_cancelled() {
                let sig = config.cancellation_token.cancellation_signal();
                final_verdict = Some(Verdict::cancelled(
                    Stage::Boot,
                    sig,
                    "cancelled before boot",
                ));
            } else if boot_deadline.is_expired() {
                final_verdict = Some(Verdict::timed_out(Stage::Boot, boot_timeout_secs));
            } else {
                let mut ctx = StageContext {
                    run_id: &run_id,
                    manifest: &manifest,
                    manifest_hash: &hash,
                    resource_manager: &mut resource_manager,
                    deadline: &boot_deadline,
                    cancellation_token: &config.cancellation_token,
                    journal: &journal,
                    telemetry: &mut telemetry,
                };

                match executor.execute_boot(&mut ctx) {
                    Ok(()) => {
                        journal.record_event(EventPayload::StageCompleted {
                            stage: Stage::Boot,
                            duration_ms: boot_start.elapsed().as_millis() as u64,
                        })?;
                    }
                    Err(StageExecutionError::Failed { code, message }) => {
                        journal.record_event(EventPayload::StageFailed {
                            stage: Stage::Boot,
                            code: code.clone(),
                            message: message.clone(),
                        })?;
                        final_verdict = Some(Verdict::failed(Stage::Boot, code, message));
                    }
                    Err(StageExecutionError::TimedOut) => {
                        journal.record_event(EventPayload::StageTimedOut {
                            stage: Stage::Boot,
                            timeout_seconds: boot_timeout_secs,
                        })?;
                        final_verdict = Some(Verdict::timed_out(Stage::Boot, boot_timeout_secs));
                    }
                    Err(StageExecutionError::Cancelled { signal, reason }) => {
                        journal.record_event(EventPayload::StageCancelled {
                            stage: Stage::Boot,
                            signal: signal.clone(),
                            reason: reason.clone(),
                        })?;
                        final_verdict = Some(Verdict::cancelled(Stage::Boot, signal, reason));
                    }
                }
            }

            stage_timings.push(StageTimingRecord {
                stage: "boot".to_owned(),
                status: match &final_verdict {
                    None | Some(Verdict::Passed) => "passed".to_owned(),
                    Some(Verdict::Failed { .. }) => "failed".to_owned(),
                    Some(Verdict::TimedOut { .. }) => "timed-out".to_owned(),
                    Some(Verdict::Cancelled { .. }) => "cancelled".to_owned(),
                },
                duration_ms: Some(boot_start.elapsed().as_millis() as u64),
            });
        }

        let mut verdict = final_verdict.unwrap_or(Verdict::Passed);

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
        let clean_start = Instant::now();

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

        stage_timings.push(StageTimingRecord {
            stage: "cleaning".to_owned(),
            status: if cleanup_status.is_success() {
                "passed".to_owned()
            } else {
                "failed".to_owned()
            },
            duration_ms: Some(clean_start.elapsed().as_millis() as u64),
        });

        // Collect executor telemetry if provided
        if let Some(exec_telem) = executor.telemetry() {
            if telemetry.observed_server_version.is_none() {
                telemetry.observed_server_version = exec_telem.observed_server_version;
            }
            if telemetry.observed_client_version.is_none() {
                telemetry.observed_client_version = exec_telem.observed_client_version;
            }
            if telemetry.command_identity.is_none() {
                telemetry.command_identity = exec_telem.command_identity;
            }
            if telemetry.target_dbname.is_none() {
                telemetry.target_dbname = exec_telem.target_dbname;
            }
            if telemetry.observed_app_version.is_none() {
                telemetry.observed_app_version = exec_telem.observed_app_version;
            }
            if telemetry.observed_artifact_digest.is_none() {
                telemetry.observed_artifact_digest = exec_telem.observed_artifact_digest;
            }
            if telemetry.declared_artifact_digest.is_none() {
                telemetry.declared_artifact_digest = exec_telem.declared_artifact_digest;
            }
            if telemetry.artifact_repository.is_none() {
                telemetry.artifact_repository = exec_telem.artifact_repository;
            }
            if telemetry.artifact_resolved_image_id.is_none() {
                telemetry.artifact_resolved_image_id = exec_telem.artifact_resolved_image_id;
            }
            if telemetry.boot_seconds.is_none() {
                telemetry.boot_seconds = exec_telem.boot_seconds;
            }
            if telemetry.verified_tables.is_empty() {
                telemetry.verified_tables = exec_telem.verified_tables;
            }
            telemetry.extra.extend(exec_telem.extra);
        }

        // Build and persist evidence bundle
        let completed_at = now_rfc3339();
        let total_duration_ms = run_start_instant.elapsed().as_millis() as u64;
        let raw_events = journal.load_events().unwrap_or_default();
        let json_events: Vec<serde_json::Value> = raw_events
            .into_iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        let mut bundle = build_evidence_bundle(
            &run_id,
            &manifest,
            &hash,
            &created_at,
            Some(completed_at.clone()),
            Some(total_duration_ms),
            &stage_timings,
            Some(&verdict),
            Some(&cleanup_status),
            json_events.clone(),
            &telemetry,
            salvage_evidence::EvidenceCompleteness::Complete,
        );
        apply_declared_snapshot(&mut bundle, &declared_manifest);

        let mut evidence_write_error: Option<std::io::Error> = None;

        if let Err(e) = persist_evidence(&bundle, &run_dir) {
            evidence_write_error = Some(e);
        }

        if let Some(dest_path) = resolve_destination_path(&manifest.evidence.destination)
            && dest_path != run_dir
            && let Err(e) = persist_evidence(&bundle, &dest_path)
        {
            evidence_write_error.get_or_insert(e);
        }

        if let Some(write_err) = evidence_write_error {
            let err_msg = format!("failed to write recovery evidence: {write_err}");
            let _ = journal.record_event(EventPayload::StageFailed {
                stage: Stage::Verification,
                code: "evidence/write-failed".to_owned(),
                message: err_msg.clone(),
            });
            verdict = Verdict::failed(Stage::Verification, "evidence/write-failed", err_msg);

            let mut updated_bundle = build_evidence_bundle(
                &run_id,
                &manifest,
                &hash,
                &created_at,
                Some(completed_at),
                Some(total_duration_ms),
                &stage_timings,
                Some(&verdict),
                Some(&cleanup_status),
                json_events,
                &telemetry,
                salvage_evidence::EvidenceCompleteness::Complete,
            );
            apply_declared_snapshot(&mut updated_bundle, &declared_manifest);
            let _ = persist_evidence(&updated_bundle, &run_dir);
        }

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
    use crate::manifest::{parse_manifest, parse_manifest_v2};

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
    const VALID_V2_MANIFEST: &str = r#"{
        "schema_version": "v2",
        "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "postgres": {"version": "16.4"},
        "restore": {"source": "s3", "type": "full"},
        "app": {
            "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "tag": "v1.2.3",
            "readiness": {"type": "tcp", "port": 8080}
        },
        "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120},
        "deadlines": {"restore_seconds": 600, "verify_seconds": 300, "boot_seconds": 120},
        "evidence": {"destination": "file:///tmp/salvage-evidence"},
        "run": {"owner": "recovery-drill"}
    }"#;

    #[test]
    fn v2_run_executes_boot_stage_with_noop_executor() {
        let temp_dir = std::env::temp_dir().join(format!(
            "salvage-engine-boot-success-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest_v2(VALID_V2_MANIFEST).unwrap();
        let run_id = RunId::new("test-boot-success-run").unwrap();
        let config = RunConfig::new(run_id.clone(), temp_dir.clone());
        let mut executor = DefaultStageExecutor;

        let outcome = RunEngine::start_run_v2(config, manifest, &mut executor).unwrap();
        assert!(outcome.verdict.is_passed());
        assert!(outcome.cleanup_status.is_success());

        let journal = Journal::new(run_id, temp_dir.clone());
        let events = journal.load_events().unwrap();
        assert!(
            events.iter().any(|e| matches!(
                &e.payload,
                EventPayload::StageStarted { stage, .. } if *stage == Stage::Boot
            )),
            "boot StageStarted must be journaled"
        );
        assert!(
            events.iter().any(|e| matches!(
                &e.payload,
                EventPayload::StageCompleted { stage, .. } if *stage == Stage::Boot
            )),
            "boot StageCompleted must be journaled"
        );

        let evidence = std::fs::read_to_string(temp_dir.join("evidence.json")).unwrap();
        let bundle: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        let stages = bundle["stages"].as_array().unwrap();
        let boot = stages
            .iter()
            .find(|s| s["stage"] == "boot")
            .expect("boot timing");
        assert_eq!(boot["status"], "passed");
        assert_eq!(bundle["manifest"]["declared"]["schema_version"], "v2");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    struct FailingBootExecutor;

    impl StageExecutor for FailingBootExecutor {
        fn execute_boot(&mut self, _ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
            Err(StageExecutionError::failed(
                "boot/readiness",
                "readiness probe failed",
            ))
        }
    }

    #[test]
    fn v2_run_maps_boot_failure_to_boot_failed_classification() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-boot-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest_v2(VALID_V2_MANIFEST).unwrap();
        let run_id = RunId::new("test-boot-fail-run").unwrap();
        let config = RunConfig::new(run_id, temp_dir.clone());
        let mut executor = FailingBootExecutor;

        let outcome = RunEngine::start_run_v2(config, manifest, &mut executor).unwrap();
        assert_eq!(
            outcome.verdict,
            Verdict::failed(Stage::Boot, "boot/readiness", "readiness probe failed")
        );
        assert!(outcome.cleanup_status.is_success());

        let evidence = std::fs::read_to_string(temp_dir.join("evidence.json")).unwrap();
        let bundle = salvage_evidence::parse_evidence_bundle(&evidence).unwrap();
        assert_eq!(
            bundle.verdict_classification,
            salvage_evidence::VerdictClassification::BootFailed
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn start_run_with_boot_runs_boot_for_core_manifests() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-boot-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        let run_id = RunId::new("test-boot-policy-run").unwrap();
        let config = RunConfig::new(run_id, temp_dir.clone());
        let mut executor = DefaultStageExecutor;

        let outcome = RunEngine::start_run_with_boot(
            config,
            manifest,
            Some(BootPolicy { boot_seconds: 60 }),
            &mut executor,
        )
        .unwrap();
        assert!(outcome.verdict.is_passed());

        let evidence = std::fs::read_to_string(temp_dir.join("evidence.json")).unwrap();
        let bundle: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        let stages = bundle["stages"].as_array().unwrap();
        assert!(
            stages
                .iter()
                .any(|s| s["stage"] == "boot" && s["status"] == "passed"),
            "boot timing must be recorded when a boot policy is present"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn v1_run_records_no_boot_timing() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-no-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        let run_id = RunId::new("test-no-boot-run").unwrap();
        let config = RunConfig::new(run_id, temp_dir.clone());
        let mut executor = DefaultStageExecutor;

        let outcome = RunEngine::start_run(config, manifest, &mut executor).unwrap();
        assert!(outcome.verdict.is_passed());

        let evidence = std::fs::read_to_string(temp_dir.join("evidence.json")).unwrap();
        let bundle: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        let stages = bundle["stages"].as_array().unwrap();
        assert!(
            stages.iter().all(|s| s["stage"] != "boot"),
            "v1 evidence must not contain a boot timing"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    #[test]
    fn v2_run_redacts_declared_snapshot() {
        // Regression test: the v2 declared override must be redacted exactly
        // like the rest of the bundle (owner canary must not survive).
        let canary = "CANARY_V2_OWNER_SECRET_31337";
        unsafe {
            std::env::set_var("SALVAGE_V2_OWNER_SECRET", canary);
        }

        let temp_dir =
            std::env::temp_dir().join(format!("salvage-engine-v2-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let text = VALID_V2_MANIFEST.replace(
            r#""owner": "recovery-drill""#,
            &format!(r#""owner": "recovery-drill-{canary}""#),
        );
        let manifest = parse_manifest_v2(&text).unwrap();
        let run_id = RunId::new("test-v2-canary-run").unwrap();
        let config = RunConfig::new(run_id, temp_dir.clone());
        let mut executor = DefaultStageExecutor;

        let outcome = RunEngine::start_run_v2(config, manifest, &mut executor).unwrap();
        assert!(outcome.verdict.is_passed());

        let evidence = std::fs::read_to_string(temp_dir.join("evidence.json")).unwrap();
        assert!(
            !evidence.contains(canary),
            "v2 canary owner must not survive in evidence.json"
        );
        let bundle: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        assert_eq!(bundle["manifest"]["declared"]["schema_version"], "v2");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
