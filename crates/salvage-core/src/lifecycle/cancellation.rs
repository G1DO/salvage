//! Cancellation token and deadline propagation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A thread-safe token for propagating cancellation across stages and background tasks.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    /// Creates a new uncancelled token.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signals cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Returns true if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Tracks the deadline budget for a single execution stage alongside an optional global deadline.
#[derive(Debug, Clone)]
pub struct StageDeadline {
    stage_start: Instant,
    stage_timeout: Duration,
    global_deadline: Option<Instant>,
}

impl StageDeadline {
    /// Creates a new stage deadline.
    pub fn new(stage_timeout: Duration, global_deadline: Option<Instant>) -> Self {
        Self {
            stage_start: Instant::now(),
            stage_timeout,
            global_deadline,
        }
    }

    /// Returns true if either the stage timeout or global deadline has expired.
    pub fn is_expired(&self) -> bool {
        if self.stage_start.elapsed() >= self.stage_timeout {
            return true;
        }
        if let Some(global) = self.global_deadline
            && Instant::now() >= global
        {
            return true;
        }
        false
    }

    /// Returns the remaining duration before expiration.
    pub fn remaining(&self) -> Duration {
        let stage_elapsed = self.stage_start.elapsed();
        let stage_remaining = self.stage_timeout.saturating_sub(stage_elapsed);
        if let Some(global) = self.global_deadline {
            let now = Instant::now();
            if now >= global {
                Duration::ZERO
            } else {
                let global_remaining = global.duration_since(now);
                stage_remaining.min(global_remaining)
            }
        } else {
            stage_remaining
        }
    }

    /// Returns the elapsed duration since the stage started.
    pub fn elapsed(&self) -> Duration {
        self.stage_start.elapsed()
    }

    /// Returns the configured stage timeout.
    pub fn timeout(&self) -> Duration {
        self.stage_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_token_behavior() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());

        let clone = token.clone();
        clone.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn stage_deadline_expiration() {
        let deadline = StageDeadline::new(Duration::from_millis(20), None);
        assert!(!deadline.is_expired());
        std::thread::sleep(Duration::from_millis(30));
        assert!(deadline.is_expired());
    }

    #[test]
    fn global_deadline_preempts_stage_deadline() {
        let global = Instant::now() + Duration::from_millis(20);
        let deadline = StageDeadline::new(Duration::from_secs(100), Some(global));
        assert!(!deadline.is_expired());
        std::thread::sleep(Duration::from_millis(30));
        assert!(deadline.is_expired());
    }
}
