//! Structured event journaling and atomic state persistence.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::resource::{ResourceKind, RunId};
use super::state::{Stage, State};

/// Payload variants for structured diagnostic events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum EventPayload {
    /// A transition between lifecycle states.
    StateTransition {
        /// Source state.
        from: String,
        /// Destination state.
        to: String,
        /// Optional context.
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },
    /// A system resource was acquired and registered under the run.
    ResourceAcquired {
        /// Unique resource identifier.
        resource_id: String,
        /// Kind of resource acquired.
        kind: ResourceKind,
    },
    /// A system resource was released.
    ResourceReleased {
        /// Unique resource identifier.
        resource_id: String,
        /// Whether release succeeded.
        success: bool,
        /// Error message if release failed.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// A stage execution started.
    StageStarted {
        /// The stage that began.
        stage: Stage,
        /// Configured timeout in seconds.
        deadline_seconds: i64,
    },
    /// A stage completed successfully.
    StageCompleted {
        /// The stage that finished.
        stage: Stage,
        /// Elapsed time in milliseconds.
        duration_ms: u64,
    },
    /// A stage failed.
    StageFailed {
        /// The failing stage.
        stage: Stage,
        /// Stable error diagnostic code.
        code: String,
        /// Detailed failure message.
        message: String,
    },
    /// A stage timed out.
    StageTimedOut {
        /// The stage that timed out.
        stage: Stage,
        /// Timeout limit in seconds.
        timeout_seconds: i64,
    },
    /// A stage was cancelled.
    StageCancelled {
        /// The stage that was cancelled.
        stage: Stage,
        /// Signal name if triggered by OS signal.
        #[serde(skip_serializing_if = "Option::is_none")]
        signal: Option<String>,
        /// Reason for cancellation.
        reason: String,
    },
    /// Cleanup phase began.
    CleanupStarted,
    /// Cleanup phase concluded.
    CleanupFinished {
        /// Whether all cleanups succeeded.
        success: bool,
        /// Diagnostic error messages if cleanup failed.
        errors: Vec<String>,
    },
}

/// A timestamped, structured event recorded in the append-only journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEvent {
    /// RFC3339 timestamp.
    pub timestamp_rfc3339: String,
    /// Owning run identity.
    pub run_id: RunId,
    /// Detailed event payload.
    #[serde(flatten)]
    pub payload: EventPayload,
}

/// Durable run state stored on disk in `state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    /// Owning run identity.
    pub run_id: RunId,
    /// Canonical hash of the effective manifest.
    pub manifest_hash: String,
    /// Current state machine state.
    pub state: State,
    /// Creation timestamp in RFC3339.
    pub created_at_rfc3339: String,
    /// Last update timestamp in RFC3339.
    pub updated_at_rfc3339: String,
}

/// Manages durable state files and the append-only event journal.
#[derive(Debug)]
pub struct Journal {
    run_id: RunId,
    run_dir: PathBuf,
}

impl Journal {
    /// Creates a journal manager for the specified run directory.
    pub fn new(run_id: RunId, run_dir: PathBuf) -> Self {
        Self { run_id, run_dir }
    }

    /// Returns the path to `state.json`.
    pub fn state_path(&self) -> PathBuf {
        self.run_dir.join("state.json")
    }

    /// Returns the path to `journal.jsonl`.
    pub fn journal_path(&self) -> PathBuf {
        self.run_dir.join("journal.jsonl")
    }

    /// Appends a structured event to `journal.jsonl`.
    pub fn record_event(&self, payload: EventPayload) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.run_dir)?;
        let event = JournalEvent {
            timestamp_rfc3339: now_rfc3339(),
            run_id: self.run_id.clone(),
            payload,
        };

        let json_line = serde_json::to_string(&event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.journal_path())?;

        writeln!(file, "{json_line}")?;
        file.sync_data()?;
        Ok(())
    }

    /// Atomically persists state to `state.json` via a temporary file and rename.
    pub fn save_state(&self, state: &PersistedState) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.run_dir)?;
        let tmp_path = self.run_dir.join("state.json.tmp");
        let final_path = self.state_path();

        let json = serde_json::to_string_pretty(state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        std::fs::rename(tmp_path, final_path)?;
        Ok(())
    }

    /// Reads and parses the durable state from `state.json`.
    pub fn load_state(&self) -> std::io::Result<PersistedState> {
        let content = std::fs::read_to_string(self.state_path())?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Reads and parses all events from `journal.jsonl`.
    pub fn load_events(&self) -> std::io::Result<Vec<JournalEvent>> {
        let path = self.journal_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: JournalEvent = serde_json::from_str(trimmed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            events.push(event);
        }

        Ok(events)
    }
}

/// Diagnoses an interrupted or completed run by inspecting its on-disk state.
pub fn diagnose_run(run_dir: &Path) -> Result<PersistedState, std::io::Error> {
    let state_file = run_dir.join("state.json");
    let content = std::fs::read_to_string(state_file)?;
    serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub(crate) fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    let mut year = 1970;
    let mut day_of_year = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if day_of_year < days_in_year {
            break;
        }
        day_of_year -= days_in_year;
        year += 1;
    }

    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1;
    let mut day = day_of_year + 1;
    for &dim in &days_in_months {
        if day <= dim {
            break;
        }
        day -= dim;
        month += 1;
    }

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_event_and_state_persistence() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-journal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let run_id = RunId::new("journal-test-run").unwrap();
        let journal = Journal::new(run_id.clone(), temp_dir.clone());

        journal
            .record_event(EventPayload::StateTransition {
                from: "planning".to_owned(),
                to: "validating".to_owned(),
                details: None,
            })
            .unwrap();

        journal
            .record_event(EventPayload::StageStarted {
                stage: Stage::Validation,
                deadline_seconds: 60,
            })
            .unwrap();

        let state = PersistedState {
            run_id: run_id.clone(),
            manifest_hash: "sha256:abcd".to_owned(),
            state: State::Validating,
            created_at_rfc3339: now_rfc3339(),
            updated_at_rfc3339: now_rfc3339(),
        };

        journal.save_state(&state).unwrap();

        let loaded_state = journal.load_state().unwrap();
        assert_eq!(loaded_state.run_id, run_id);
        assert_eq!(loaded_state.state, State::Validating);

        let events = journal.load_events().unwrap();
        assert_eq!(events.len(), 2);

        let diagnosed = diagnose_run(&temp_dir).unwrap();
        assert_eq!(diagnosed.state, State::Validating);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
