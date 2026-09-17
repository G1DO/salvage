//! Backup verification, restore execution, and structural integrity checks.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use salvage_core::lifecycle::{
    CancellationToken, ProcessHandle, ResourceManager, StageDeadline, StageExecutionError,
};
use sha2::{Digest, Sha256};

use crate::target::EphemeralPostgresTarget;

/// Magic bytes at the start of a PostgreSQL custom format archive (`pg_dump -Fc`).
pub const PG_DUMP_CUSTOM_MAGIC: &[u8; 5] = b"PGDMP";

/// Verifies that the backup file exists, matches the manifest digest, and has valid archive magic bytes.
pub fn verify_backup_preflight(
    path: &Path,
    expected_digest: &str,
) -> Result<(), StageExecutionError> {
    if !path.exists() {
        return Err(StageExecutionError::failed(
            "restore/missing-prerequisite",
            format!("backup file not found at `{}`", path.display()),
        ));
    }

    let mut file = File::open(path).map_err(|e| {
        StageExecutionError::failed(
            "restore/missing-prerequisite",
            format!("failed to open backup file `{}`: {e}", path.display()),
        )
    })?;

    // 1. Verify SHA-256 digest
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| {
            StageExecutionError::failed(
                "restore/corrupt-backup",
                format!("failed to read backup file for checksum: {e}"),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let digest_result = hasher.finalize();
    let mut computed_digest = String::with_capacity("sha256:".len() + 64);
    computed_digest.push_str("sha256:");
    for byte in digest_result {
        computed_digest.push_str(&format!("{byte:02x}"));
    }

    if computed_digest != expected_digest {
        return Err(StageExecutionError::failed(
            "restore/digest-mismatch",
            format!(
                "checksum mismatch: manifest declared `{expected_digest}`, backup has `{computed_digest}`"
            ),
        ));
    }

    // 2. Verify archive header magic bytes
    let mut header_file = File::open(path).map_err(|e| {
        StageExecutionError::failed(
            "restore/missing-prerequisite",
            format!("failed to reopen backup file: {e}"),
        )
    })?;

    let mut magic = [0u8; 5];
    let bytes_read = header_file.read(&mut magic).map_err(|e| {
        StageExecutionError::failed(
            "restore/corrupt-backup",
            format!("failed to read archive header: {e}"),
        )
    })?;

    if bytes_read < 5 || &magic != PG_DUMP_CUSTOM_MAGIC {
        return Err(StageExecutionError::failed(
            "restore/corrupt-backup",
            format!(
                "backup file `{}` does not have valid PostgreSQL custom archive magic bytes",
                path.display()
            ),
        ));
    }

    Ok(())
}

/// Executes `pg_restore` into the ephemeral target database.
pub fn execute_restore(
    target: &EphemeralPostgresTarget,
    backup_path: &Path,
    target_dbname: &str,
    resource_manager: &mut ResourceManager,
    deadline: &StageDeadline,
    cancellation_token: &CancellationToken,
) -> Result<Duration, StageExecutionError> {
    if cancellation_token.is_cancelled() {
        return Err(StageExecutionError::cancelled(
            cancellation_token.cancellation_signal(),
            "cancelled before starting pg_restore",
        ));
    }
    if deadline.is_expired() {
        return Err(StageExecutionError::TimedOut);
    }

    // Create the target restore database
    target.create_database(target_dbname)?;

    // Spawn pg_restore in an isolated process group
    let mut cmd = Command::new(&target.binaries.pg_restore);
    cmd.arg("-h")
        .arg(&target.socket_dir)
        .arg("-U")
        .arg(&target.superuser)
        .arg("-d")
        .arg(target_dbname)
        .arg("--clean")
        .arg("--if-exists")
        .arg(backup_path);

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut handle = ProcessHandle::spawn(cmd).map_err(|e| {
        StageExecutionError::failed(
            "restore/missing-prerequisite",
            format!("failed to spawn pg_restore: {e}"),
        )
    })?;

    let _ = resource_manager.register_process_group(handle.pid, handle.pgid);

    // Wait for pg_restore to complete with cancellation/deadline supervision
    let poll_interval = Duration::from_millis(20);
    let start = Instant::now();

    loop {
        if cancellation_token.is_cancelled() {
            let _ = handle.terminate(Duration::from_millis(100));
            return Err(StageExecutionError::cancelled(
                cancellation_token.cancellation_signal(),
                "pg_restore cancelled by user signal",
            ));
        }
        if deadline.is_expired() {
            let _ = handle.terminate(Duration::from_millis(100));
            return Err(StageExecutionError::TimedOut);
        }

        if let Ok(delay_str) = std::env::var("SALVAGE_TEST_RESTORE_DELAY_MS")
            && let Ok(delay_ms) = delay_str.parse::<u64>()
        {
            let sleep_chunk = Duration::from_millis(50);
            let mut elapsed = Duration::ZERO;
            while elapsed < Duration::from_millis(delay_ms) {
                if cancellation_token.is_cancelled() {
                    let _ = handle.terminate(Duration::from_millis(100));
                    return Err(StageExecutionError::cancelled(
                        cancellation_token.cancellation_signal(),
                        "pg_restore cancelled by user signal",
                    ));
                }
                if deadline.is_expired() {
                    let _ = handle.terminate(Duration::from_millis(100));
                    return Err(StageExecutionError::TimedOut);
                }
                std::thread::sleep(sleep_chunk);
                elapsed += sleep_chunk;
            }
        }

        match handle.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(start.elapsed());
                } else {
                    // O4-2: drain stderr after exit so the failure can be
                    // classified (missing role/extension vs corrupt backup).
                    // Volumes are small (a handful of error lines); if output
                    // ever filled the pipe the child would already be stuck
                    // and this stage would time out, so post-exit read adds
                    // no new failure mode.
                    let mut stderr_text = String::new();
                    if let Some(mut stderr) = handle.take_stderr() {
                        let _ = stderr.read_to_string(&mut stderr_text);
                    }
                    // Extract diagnostic from pg_restore exit status + stderr
                    return Err(classify_restore_exit_status(status.code(), &stderr_text));
                }
            }
            Ok(None) => {
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(StageExecutionError::failed(
                    "restore/corrupt-backup",
                    format!("error waiting on pg_restore: {e}"),
                ));
            }
        }
    }
}

/// Classifies a non-zero `pg_restore` exit using its captured stderr.
///
/// O4-2: a missing role or extension is an environment mismatch, not a
/// corrupt backup, and operators need the difference to act (create the
/// role / install the extension vs distrust the artifact). Anything else
/// keeps the historical `restore/corrupt-backup` code. Fragments below are
/// the real server message shapes, verified against PostgreSQL 16
/// (`role "x" does not exist` from `ALTER ... OWNER TO`; `could not open
/// extension control file` from `CREATE EXTENSION` with absent files;
/// `extension "x" does not exist` from `ALTER EXTENSION`).
fn classify_restore_exit_status(code: Option<i32>, stderr: &str) -> StageExecutionError {
    const MAX_EXCERPT_CHARS: usize = 300;
    let excerpt = |line: &str| {
        let short: String = line.chars().take(MAX_EXCERPT_CHARS).collect();
        if line.chars().count() > MAX_EXCERPT_CHARS {
            format!("{short}…")
        } else {
            short
        }
    };
    let role_line = stderr.lines().map(str::trim).find(|line| {
        let lowered = line.to_lowercase();
        lowered.contains("role \"") && lowered.contains("\" does not exist")
    });
    if let Some(line) = role_line {
        return StageExecutionError::failed(
            "restore/missing-role",
            format!(
                "pg_restore failed: environment role is missing ({}); pg_restore exit code: {code:?}",
                excerpt(line),
            ),
        );
    }
    let extension_line = stderr.lines().map(str::trim).find(|line| {
        let lowered = line.to_lowercase();
        lowered.contains("could not open extension control file")
            || (lowered.contains("extension \"") && lowered.contains("\" does not exist"))
    });
    if let Some(line) = extension_line {
        return StageExecutionError::failed(
            "restore/missing-extension",
            format!(
                "pg_restore failed: environment extension is missing ({}); pg_restore exit code: {code:?}",
                excerpt(line),
            ),
        );
    }
    StageExecutionError::failed(
        "restore/corrupt-backup",
        format!("pg_restore terminated with non-zero exit code: {code:?}"),
    )
}

/// Runs structural verification checks against the restored database.
pub fn verify_structural_integrity(
    target: &EphemeralPostgresTarget,
    dbname: &str,
    expected_table: Option<&str>,
) -> Result<Vec<String>, StageExecutionError> {
    // 1. Query public tables
    let query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;";
    let tables_output = target.run_psql(dbname, query)?;
    let tables: Vec<String> = tables_output
        .lines()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    if tables.is_empty() {
        return Err(StageExecutionError::failed(
            "restore/structural-verification-failed",
            "restored database contains no user tables in public schema",
        ));
    }

    // 2. If an expected table is specified, check existence and row count
    if let Some(table) = expected_table {
        if !tables.iter().any(|t| t == table) {
            return Err(StageExecutionError::failed(
                "restore/structural-verification-failed",
                format!(
                    "expected table `{table}` not found in restored tables: {:?}",
                    tables
                ),
            ));
        }

        let escaped_table = table.replace('"', "\"\"");
        let count_query = format!("SELECT count(*) FROM \"{escaped_table}\";");
        let count_output = target.run_psql(dbname, &count_query)?;
        let row_count: i64 = count_output
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .parse()
            .map_err(|e| {
                StageExecutionError::failed(
                    "restore/structural-verification-failed",
                    format!("failed to parse row count from `{count_output}`: {e}"),
                )
            })?;

        if row_count == 0 {
            return Err(StageExecutionError::failed(
                "restore/structural-verification-failed",
                format!("expected table `{table}` contains 0 rows after restore"),
            ));
        }
    }

    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_code(err: &StageExecutionError) -> &str {
        match err {
            StageExecutionError::Failed { code, .. } => code,
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn missing_role_from_owner_reassignment() {
        // Real pg_restore shape (PostgreSQL 16, verified live in O4-2).
        let stderr = "pg_restore: error: could not execute query: ERROR:  role \"phantom_salvage\" does not exist\n\
             Command was: ALTER TABLE public.salvage_records OWNER TO phantom_salvage;\n\
             pg_restore: warning: errors ignored on restore: 2\n";
        let err = classify_restore_exit_status(Some(1), stderr);
        assert_eq!(failed_code(&err), "restore/missing-role");
        assert!(format!("{err:?}").contains("phantom_salvage"));
    }

    #[test]
    fn missing_extension_from_absent_control_file() {
        // Real server shape for CREATE EXTENSION with missing files.
        let stderr = "pg_restore: error: could not execute query: ERROR:  extension \"postgis\" is not available\n\
             DETAIL:  Could not open extension control file \"/usr/share/postgresql/16/extension/postgis.control\": No such file or directory.\n";
        let err = classify_restore_exit_status(Some(1), stderr);
        assert_eq!(failed_code(&err), "restore/missing-extension");
    }

    #[test]
    fn missing_extension_from_alter_unknown_name() {
        let stderr = "pg_restore: error: could not execute query: ERROR:  extension \"postgis\" does not exist\n";
        let err = classify_restore_exit_status(Some(1), stderr);
        assert_eq!(failed_code(&err), "restore/missing-extension");
    }

    #[test]
    fn unrelated_failure_keeps_corrupt_backup() {
        // Historical behavior preserved: anything else stays corrupt-backup.
        let stderr = "pg_restore: error: unrecognized data block type (42) in archive\n";
        let err = classify_restore_exit_status(Some(1), stderr);
        assert_eq!(failed_code(&err), "restore/corrupt-backup");
    }

    #[test]
    fn empty_stderr_and_killed_process_stay_corrupt_backup() {
        assert_eq!(
            failed_code(&classify_restore_exit_status(Some(1), "")),
            "restore/corrupt-backup"
        );
        assert_eq!(
            failed_code(&classify_restore_exit_status(None, "")),
            "restore/corrupt-backup"
        );
    }

    #[test]
    fn role_match_requires_both_fragments_on_one_line() {
        // `role "` on one line and `" does not exist` on another must not
        // match: prevents cross-line false positives from wrapped output.
        let stderr = "pg_restore: note: role \"app\" owns objects\n\
             pg_restore: error: something \"important\" does not exist\n";
        let err = classify_restore_exit_status(Some(1), stderr);
        assert_eq!(failed_code(&err), "restore/corrupt-backup");
    }
}
