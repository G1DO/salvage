//! Cancellation token and deadline propagation.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static GLOBAL_SIGNAL_FLAG: AtomicBool = AtomicBool::new(false);
static GLOBAL_SIGNAL_NUM: AtomicI32 = AtomicI32::new(0);

extern "C" fn signal_handler(signum: libc::c_int) {
    GLOBAL_SIGNAL_FLAG.store(true, Ordering::SeqCst);
    GLOBAL_SIGNAL_NUM.store(signum, Ordering::SeqCst);
}

/// Installs process-wide signal handlers for `SIGINT` and `SIGTERM` to safely trigger cancellation.
pub fn install_signal_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// Resets global signal state (primarily for test environments).
pub fn reset_signal_state() {
    GLOBAL_SIGNAL_FLAG.store(false, Ordering::SeqCst);
    GLOBAL_SIGNAL_NUM.store(0, Ordering::SeqCst);
}

/// A thread-safe token for propagating cancellation across stages and background tasks.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    signal: Arc<Mutex<Option<String>>>,
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
            signal: Arc::new(Mutex::new(None)),
        }
    }

    /// Signals cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Signals cancellation with an associated signal name.
    pub fn cancel_with_signal(&self, signal: Option<String>) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut sig_lock) = self.signal.lock() {
            *sig_lock = signal;
        }
    }

    /// Returns true if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst) || GLOBAL_SIGNAL_FLAG.load(Ordering::SeqCst)
    }

    /// Returns the cancellation signal name if cancellation was triggered by a signal.
    pub fn cancellation_signal(&self) -> Option<String> {
        if let Ok(sig_lock) = self.signal.lock()
            && let Some(ref s) = *sig_lock
        {
            return Some(s.clone());
        }
        if GLOBAL_SIGNAL_FLAG.load(Ordering::SeqCst) {
            match GLOBAL_SIGNAL_NUM.load(Ordering::SeqCst) {
                libc::SIGINT => Some("SIGINT".to_owned()),
                libc::SIGTERM => Some("SIGTERM".to_owned()),
                _ => Some("SIGNAL".to_owned()),
            }
        } else {
            None
        }
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
