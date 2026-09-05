//! Lifecycle states, stages, verdicts, and transitions.

use serde::{Deserialize, Serialize};

/// The major execution stages of a recovery run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Initial preparation and setup.
    Planning,
    /// Manifest and precondition validation.
    Validation,
    /// PostgreSQL restore execution.
    Restore,
    /// Recovery verification placeholder.
    Verification,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planning => write!(f, "planning"),
            Self::Validation => write!(f, "validation"),
            Self::Restore => write!(f, "restore"),
            Self::Verification => write!(f, "verification"),
        }
    }
}

/// The primary verdict of a recovery run, independent of cleanup status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum Verdict {
    /// All stages completed successfully.
    Passed,
    /// A stage failed with a typed diagnostic error code.
    Failed {
        /// Stage in which the failure occurred.
        stage: Stage,
        /// Stable machine-readable error code.
        code: String,
        /// Human-readable message detailing the failure.
        message: String,
    },
    /// A stage or global deadline timed out.
    TimedOut {
        /// Stage in which timeout occurred.
        stage: Stage,
        /// Timeout limit in seconds.
        timeout_seconds: i64,
    },
    /// The run was interrupted or cancelled (e.g. SIGINT/SIGTERM).
    Cancelled {
        /// Stage in which cancellation was received.
        stage: Stage,
        /// Optional signal name (e.g. "SIGINT", "SIGTERM").
        signal: Option<String>,
        /// Reason for cancellation.
        reason: String,
    },
}

impl Verdict {
    /// Returns true if the verdict is [`Verdict::Passed`].
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Creates a [`Verdict::Failed`] outcome.
    pub fn failed(stage: Stage, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Failed {
            stage,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Creates a [`Verdict::TimedOut`] outcome.
    pub const fn timed_out(stage: Stage, timeout_seconds: i64) -> Self {
        Self::TimedOut {
            stage,
            timeout_seconds,
        }
    }

    /// Creates a [`Verdict::Cancelled`] outcome.
    pub fn cancelled(stage: Stage, signal: Option<String>, reason: impl Into<String>) -> Self {
        Self::Cancelled {
            stage,
            signal,
            reason: reason.into(),
        }
    }
}

/// The status of resource cleanup for a recovery run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CleanupStatus {
    /// All owned resources were cleanly released and reaped.
    Success,
    /// One or more resources failed to clean up.
    Failed {
        /// Diagnostic error messages describing each cleanup error.
        errors: Vec<String>,
    },
}

impl CleanupStatus {
    /// Returns true if cleanup succeeded completely.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Creates a failed cleanup status.
    pub const fn failed(errors: Vec<String>) -> Self {
        Self::Failed { errors }
    }
}

/// The final outcome of a recovery run, pairing the primary verdict with cleanup status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOutcome {
    /// The primary verdict of the run stages.
    pub verdict: Verdict,
    /// The status of resource cleanup.
    pub cleanup_status: CleanupStatus,
}

impl RunOutcome {
    /// Creates a run outcome.
    pub const fn new(verdict: Verdict, cleanup_status: CleanupStatus) -> Self {
        Self {
            verdict,
            cleanup_status,
        }
    }
}

/// Lifecycle states of a recovery run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "payload", rename_all = "kebab-case")]
pub enum State {
    /// Initial preparation and setup.
    Planning,
    /// Manifest and precondition validation.
    Validating,
    /// Restoring PostgreSQL data.
    Restoring,
    /// Verifying restore integrity.
    Verifying,
    /// Stage execution concluded with a primary verdict.
    Terminal(Verdict),
    /// Active resource cleanup.
    Cleaning(Verdict),
    /// All cleanup completed; final terminal state.
    Cleaned(RunOutcome),
}

impl State {
    /// Returns true if the state is in an active execution stage.
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Planning | Self::Validating | Self::Restoring | Self::Verifying
        )
    }

    /// Returns true if the state is [`State::Terminal`].
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }

    /// Returns true if the state is [`State::Cleaning`].
    pub const fn is_cleaning(&self) -> bool {
        matches!(self, Self::Cleaning(_))
    }

    /// Returns true if the state is [`State::Cleaned`].
    pub const fn is_cleaned(&self) -> bool {
        matches!(self, Self::Cleaned(_))
    }

    /// Returns the name of the state.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Planning => "planning",
            Self::Validating => "validating",
            Self::Restoring => "restoring",
            Self::Verifying => "verifying",
            Self::Terminal(_) => "terminal",
            Self::Cleaning(_) => "cleaning",
            Self::Cleaned(_) => "cleaned",
        }
    }

    /// Validates and applies a transition from `self` to `next`.
    pub fn transition_to(&mut self, next: Self) -> Result<(), StateError> {
        let legal = match (&*self, &next) {
            (Self::Planning, Self::Validating) => true,
            (Self::Planning, Self::Terminal(_)) => true,

            (Self::Validating, Self::Restoring) => true,
            (Self::Validating, Self::Terminal(_)) => true,

            (Self::Restoring, Self::Verifying) => true,
            (Self::Restoring, Self::Terminal(_)) => true,

            (Self::Verifying, Self::Terminal(_)) => true,

            (Self::Terminal(v1), Self::Cleaning(v2)) if v1 == v2 => true,

            (Self::Cleaning(v), Self::Cleaned(outcome)) if &outcome.verdict == v => true,

            _ => false,
        };

        if legal {
            *self = next;
            Ok(())
        } else {
            Err(StateError::IllegalTransition {
                from: self.name().to_owned(),
                to: next.name().to_owned(),
            })
        }
    }
}

/// Errors occurring during state machine transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// An invalid state transition was attempted.
    IllegalTransition {
        /// Source state.
        from: String,
        /// Target state.
        to: String,
    },
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal state transition from `{from}` to `{to}`")
            }
        }
    }
}

impl std::error::Error for StateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_transitions_succeed() {
        let mut state = State::Planning;
        assert!(state.is_active());

        state.transition_to(State::Validating).unwrap();
        assert_eq!(state, State::Validating);

        state.transition_to(State::Restoring).unwrap();
        assert_eq!(state, State::Restoring);

        state.transition_to(State::Verifying).unwrap();
        assert_eq!(state, State::Verifying);

        state
            .transition_to(State::Terminal(Verdict::Passed))
            .unwrap();
        assert!(state.is_terminal());

        state
            .transition_to(State::Cleaning(Verdict::Passed))
            .unwrap();
        assert!(state.is_cleaning());

        state
            .transition_to(State::Cleaned(RunOutcome::new(
                Verdict::Passed,
                CleanupStatus::Success,
            )))
            .unwrap();
        assert!(state.is_cleaned());
    }

    #[test]
    fn stage_failure_transitions_directly_to_terminal() {
        let mut state = State::Restoring;
        let verdict = Verdict::failed(Stage::Restore, "restore/checksum", "digest mismatch");
        state
            .transition_to(State::Terminal(verdict.clone()))
            .unwrap();
        state
            .transition_to(State::Cleaning(verdict.clone()))
            .unwrap();
        state
            .transition_to(State::Cleaned(RunOutcome::new(
                verdict,
                CleanupStatus::Success,
            )))
            .unwrap();
        assert!(state.is_cleaned());
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        let mut state = State::Planning;
        assert_eq!(
            state.transition_to(State::Restoring).unwrap_err(),
            StateError::IllegalTransition {
                from: "planning".to_owned(),
                to: "restoring".to_owned(),
            }
        );

        let mut cleaned = State::Cleaned(RunOutcome::new(Verdict::Passed, CleanupStatus::Success));
        assert_eq!(
            cleaned.transition_to(State::Planning).unwrap_err(),
            StateError::IllegalTransition {
                from: "cleaned".to_owned(),
                to: "planning".to_owned(),
            }
        );

        let mut terminal = State::Terminal(Verdict::Passed);
        let mismatched = State::Cleaning(Verdict::timed_out(Stage::Restore, 300));
        assert_eq!(
            terminal.transition_to(mismatched).unwrap_err(),
            StateError::IllegalTransition {
                from: "terminal".to_owned(),
                to: "cleaning".to_owned(),
            }
        );
    }

    #[test]
    fn primary_verdict_is_preserved_despite_cleanup_failure() {
        let verdict = Verdict::failed(Stage::Restore, "restore/io", "disk full");
        let cleanup = CleanupStatus::failed(vec!["failed to unmount scratch".to_owned()]);
        let outcome = RunOutcome::new(verdict.clone(), cleanup.clone());

        assert_eq!(outcome.verdict, verdict);
        assert_eq!(outcome.cleanup_status, cleanup);
        assert!(!outcome.verdict.is_passed());
        assert!(!outcome.cleanup_status.is_success());
    }
}
