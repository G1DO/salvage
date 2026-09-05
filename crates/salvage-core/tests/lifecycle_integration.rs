//! Integration tests for bounded run lifecycle, ownership, process reaping,
//! deadlines, cancellation, journaling, and safe re-entry.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use salvage_core::lifecycle::{
    CancellationToken, CleanupStatus, DefaultStageExecutor, EventPayload, Journal, ProcessHandle,
    ResourceManager, RunConfig, RunEngine, RunError, RunId, RunOutcome, Stage, StageContext,
    StageExecutionError, StageExecutor, State, Verdict, diagnose_run,
};
use salvage_core::manifest::parse_manifest;

const TEST_MANIFEST: &str = r#"{
    "schema_version": "v1",
    "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    "postgres": {"version": "16.4"},
    "restore": {"source": "s3", "type": "full"},
    "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120},
    "deadlines": {"restore_seconds": 1, "verify_seconds": 1},
    "evidence": {"destination": "file:///tmp/salvage-evidence"},
    "run": {"owner": "recovery-drill"}
}"#;

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "salvage-lifecycle-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_all_legal_and_illegal_state_transitions() {
    let verdict_passed = Verdict::Passed;
    let verdict_failed = Verdict::failed(Stage::Restore, "restore/error", "error");
    let outcome_passed = RunOutcome::new(verdict_passed.clone(), CleanupStatus::Success);
    let outcome_failed = RunOutcome::new(verdict_failed.clone(), CleanupStatus::Success);

    // 1. From Planning
    let mut state = State::Planning;
    assert!(state.transition_to(State::Validating).is_ok());

    let mut state = State::Planning;
    assert!(
        state
            .transition_to(State::Terminal(verdict_passed.clone()))
            .is_ok()
    );

    let mut state = State::Planning;
    assert!(state.transition_to(State::Restoring).is_err());
    assert!(state.transition_to(State::Verifying).is_err());
    assert!(
        state
            .transition_to(State::Cleaning(verdict_passed.clone()))
            .is_err()
    );
    assert!(
        state
            .transition_to(State::Cleaned(outcome_passed.clone()))
            .is_err()
    );

    // 2. From Validating
    let mut state = State::Validating;
    assert!(state.transition_to(State::Restoring).is_ok());

    let mut state = State::Validating;
    assert!(
        state
            .transition_to(State::Terminal(verdict_failed.clone()))
            .is_ok()
    );

    let mut state = State::Validating;
    assert!(state.transition_to(State::Planning).is_err());
    assert!(state.transition_to(State::Verifying).is_err());
    assert!(
        state
            .transition_to(State::Cleaning(verdict_passed.clone()))
            .is_err()
    );
    assert!(
        state
            .transition_to(State::Cleaned(outcome_passed.clone()))
            .is_err()
    );

    // 3. From Restoring
    let mut state = State::Restoring;
    assert!(state.transition_to(State::Verifying).is_ok());

    let mut state = State::Restoring;
    assert!(
        state
            .transition_to(State::Terminal(verdict_failed.clone()))
            .is_ok()
    );

    let mut state = State::Restoring;
    assert!(state.transition_to(State::Planning).is_err());
    assert!(state.transition_to(State::Validating).is_err());
    assert!(
        state
            .transition_to(State::Cleaning(verdict_passed.clone()))
            .is_err()
    );
    assert!(
        state
            .transition_to(State::Cleaned(outcome_passed.clone()))
            .is_err()
    );

    // 4. From Verifying
    let mut state = State::Verifying;
    assert!(
        state
            .transition_to(State::Terminal(verdict_passed.clone()))
            .is_ok()
    );

    let mut state = State::Verifying;
    assert!(state.transition_to(State::Planning).is_err());
    assert!(state.transition_to(State::Validating).is_err());
    assert!(state.transition_to(State::Restoring).is_err());
    assert!(
        state
            .transition_to(State::Cleaning(verdict_passed.clone()))
            .is_err()
    );
    assert!(
        state
            .transition_to(State::Cleaned(outcome_passed.clone()))
            .is_err()
    );

    // 5. From Terminal
    let mut state = State::Terminal(verdict_passed.clone());
    assert!(
        state
            .transition_to(State::Cleaning(verdict_passed.clone()))
            .is_ok()
    );

    let mut state = State::Terminal(verdict_passed.clone());
    // Mismatched verdict to Cleaning
    assert!(
        state
            .transition_to(State::Cleaning(verdict_failed.clone()))
            .is_err()
    );
    assert!(state.transition_to(State::Planning).is_err());
    assert!(state.transition_to(State::Validating).is_err());
    assert!(state.transition_to(State::Restoring).is_err());
    assert!(state.transition_to(State::Verifying).is_err());
    assert!(
        state
            .transition_to(State::Cleaned(outcome_passed.clone()))
            .is_err()
    );

    // 6. From Cleaning
    let mut state = State::Cleaning(verdict_passed.clone());
    assert!(
        state
            .transition_to(State::Cleaned(outcome_passed.clone()))
            .is_ok()
    );

    let mut state = State::Cleaning(verdict_passed.clone());
    // Mismatched verdict in outcome
    assert!(state.transition_to(State::Cleaned(outcome_failed)).is_err());
    assert!(state.transition_to(State::Planning).is_err());
    assert!(state.transition_to(State::Validating).is_err());
    assert!(state.transition_to(State::Restoring).is_err());
    assert!(state.transition_to(State::Verifying).is_err());
    assert!(
        state
            .transition_to(State::Terminal(verdict_passed.clone()))
            .is_err()
    );

    // 7. From Cleaned
    let mut state = State::Cleaned(outcome_passed);
    assert!(state.transition_to(State::Planning).is_err());
    assert!(state.transition_to(State::Validating).is_err());
    assert!(state.transition_to(State::Restoring).is_err());
    assert!(state.transition_to(State::Verifying).is_err());
    assert!(
        state
            .transition_to(State::Terminal(verdict_passed.clone()))
            .is_err()
    );
    assert!(
        state
            .transition_to(State::Cleaning(verdict_passed))
            .is_err()
    );
}

#[test]
fn test_primary_verdict_preserved_on_cleanup_failure() {
    let temp_dir = unique_temp_dir("verdict-preserved");
    let manifest = parse_manifest(TEST_MANIFEST).unwrap();
    let run_id = RunId::new("run-fail-cleanup").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    struct FailingStageWithCleanupError {
        scratch_dir: PathBuf,
    }

    impl StageExecutor for FailingStageWithCleanupError {
        fn execute_restore(
            &mut self,
            ctx: &mut StageContext<'_>,
        ) -> Result<(), StageExecutionError> {
            // Acquire a subdirectory and file
            let dir = ctx
                .resource_manager
                .acquire_directory(Path::new("locked-scratch"))
                .unwrap();
            let file = ctx
                .resource_manager
                .acquire_file(Path::new("locked-scratch/locked.txt"))
                .unwrap();
            fs::write(&file, b"important").unwrap();
            self.scratch_dir = dir;

            // Make the scratch directory read-only so removing its contents during cleanup fails
            let mut perms = fs::metadata(&self.scratch_dir).unwrap().permissions();
            perms.set_readonly(true);
            fs::set_permissions(&self.scratch_dir, perms).unwrap();

            Err(StageExecutionError::failed(
                "restore/segment-checksum",
                "checksum mismatch on segment 0001",
            ))
        }
    }

    let mut executor = FailingStageWithCleanupError {
        scratch_dir: PathBuf::new(),
    };
    let outcome = RunEngine::start_run(config, manifest, &mut executor).unwrap();

    // Restore permissions so test cleanup can remove temp_dir
    if executor.scratch_dir.exists() {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&executor.scratch_dir).unwrap().permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(&executor.scratch_dir, perms);
    }

    // Primary verdict MUST remain the original restore failure
    assert_eq!(
        outcome.verdict,
        Verdict::failed(
            Stage::Restore,
            "restore/segment-checksum",
            "checksum mismatch on segment 0001"
        )
    );

    // Cleanup status reflects failure
    assert!(!outcome.cleanup_status.is_success());
    if let CleanupStatus::Failed { errors } = &outcome.cleanup_status {
        assert!(!errors.is_empty());
    } else {
        panic!("expected cleanup status to be Failed");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_resource_ownership_scoped_isolation() {
    let temp_dir = unique_temp_dir("scoped-isolation");
    let run_id = RunId::new("run-isolation").unwrap();
    let mut rm = ResourceManager::new(run_id, temp_dir.clone());

    // Create a sibling unowned file in the parent directory
    let unowned_file = temp_dir.join("unowned-user-file.txt");
    fs::write(&unowned_file, b"do not delete").unwrap();

    // Acquire run-owned directory and file
    let owned_dir = rm.acquire_directory(Path::new("owned-scratch")).unwrap();
    let owned_file = rm
        .acquire_file(Path::new("owned-scratch/owned.txt"))
        .unwrap();
    fs::write(&owned_file, b"run data").unwrap();

    assert!(owned_dir.exists());
    assert!(owned_file.exists());
    assert!(unowned_file.exists());

    // Release all run resources
    rm.release_all().unwrap();

    // Owned resources should be deleted, unowned file must remain intact!
    assert!(!owned_file.exists());
    assert!(!owned_dir.exists());
    assert!(
        unowned_file.exists(),
        "unowned file must NOT be deleted by run cleanup"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stage_timeout_and_process_cleanup() {
    let temp_dir = unique_temp_dir("stage-timeout");
    let manifest = parse_manifest(TEST_MANIFEST).unwrap();
    let run_id = RunId::new("run-timeout").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());

    struct TimingOutExecutor;
    impl StageExecutor for TimingOutExecutor {
        fn execute_restore(
            &mut self,
            ctx: &mut StageContext<'_>,
        ) -> Result<(), StageExecutionError> {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("sleep 60 & sleep 60");
            let handle = ProcessHandle::spawn(cmd).unwrap();
            let pgid = handle.pgid;
            ctx.resource_manager
                .register_process_group(handle.pid, pgid);

            // Wait until deadline expires
            while !ctx.deadline.is_expired() {
                std::thread::sleep(Duration::from_millis(10));
            }

            Err(StageExecutionError::TimedOut)
        }
    }

    let mut executor = TimingOutExecutor;
    let outcome = RunEngine::start_run(config, manifest, &mut executor).unwrap();

    assert_eq!(outcome.verdict, Verdict::timed_out(Stage::Restore, 1));
    assert!(outcome.cleanup_status.is_success());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cancellation_token_cancels_stage_and_cleans_up() {
    let temp_dir = unique_temp_dir("cancellation");
    let manifest = parse_manifest(TEST_MANIFEST).unwrap();
    let run_id = RunId::new("run-cancel").unwrap();
    let config = RunConfig::new(run_id, temp_dir.clone());
    let token = config.cancellation_token.clone();

    struct CancellableExecutor {
        token: CancellationToken,
    }

    impl StageExecutor for CancellableExecutor {
        fn execute_restore(
            &mut self,
            ctx: &mut StageContext<'_>,
        ) -> Result<(), StageExecutionError> {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("sleep 60");
            let handle = ProcessHandle::spawn(cmd).unwrap();
            ctx.resource_manager
                .register_process_group(handle.pid, handle.pgid);

            // Trigger cancellation from background thread
            let token = self.token.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                token.cancel();
            });

            while !ctx.cancellation_token.is_cancelled() {
                std::thread::sleep(Duration::from_millis(5));
            }

            Err(StageExecutionError::cancelled(
                Some("SIGINT".to_owned()),
                "interrupted by user signal",
            ))
        }
    }

    let mut executor = CancellableExecutor { token };
    let outcome = RunEngine::start_run(config, manifest, &mut executor).unwrap();

    assert_eq!(
        outcome.verdict,
        Verdict::cancelled(
            Stage::Restore,
            Some("SIGINT".to_owned()),
            "interrupted by user signal"
        )
    );
    assert!(outcome.cleanup_status.is_success());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_interrupted_run_diagnosis_and_safe_recovery() {
    let temp_dir = unique_temp_dir("interrupted-diagnosis");
    let run_id = RunId::new("run-interrupted").unwrap();
    let journal = Journal::new(run_id.clone(), temp_dir.clone());

    // Simulate an interrupted run in Restoring state
    let state = salvage_core::lifecycle::PersistedState {
        run_id: run_id.clone(),
        manifest_hash: "sha256:11223344556677889900aabbccddeeff".to_owned(),
        state: State::Restoring,
        created_at_rfc3339: "2026-09-05T00:00:00Z".to_owned(),
        updated_at_rfc3339: "2026-09-05T00:01:00Z".to_owned(),
    };
    journal.save_state(&state).unwrap();
    journal
        .record_event(EventPayload::StateTransition {
            from: "validating".to_owned(),
            to: "restoring".to_owned(),
            details: None,
        })
        .unwrap();

    // Diagnose the interrupted run from disk
    let diagnosed = diagnose_run(&temp_dir).unwrap();
    assert_eq!(diagnosed.run_id, run_id);
    assert_eq!(diagnosed.state, State::Restoring);

    // Starting a new run on the stale directory MUST fail safely
    let manifest = parse_manifest(TEST_MANIFEST).unwrap();
    let config = RunConfig::new(run_id.clone(), temp_dir.clone());
    let mut executor = DefaultStageExecutor;
    let err = RunEngine::start_run(config, manifest, &mut executor).unwrap_err();
    assert!(matches!(err, RunError::StaleResources { .. }));

    // Re-entry for recovery cleanup MUST succeed
    let outcome = RunEngine::cleanup_stale(&temp_dir, Some(&run_id)).unwrap();
    assert!(outcome.cleanup_status.is_success());

    // After cleanup, the persisted state must now be Cleaned
    let final_state = journal.load_state().unwrap();
    assert!(final_state.state.is_cleaned());

    // Repeated cleanup calls are idempotent
    let second_cleanup = RunEngine::cleanup_stale(&temp_dir, Some(&run_id)).unwrap();
    assert_eq!(outcome, second_cleanup);

    let _ = fs::remove_dir_all(&temp_dir);
}
