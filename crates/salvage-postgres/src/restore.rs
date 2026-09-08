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
    let computed_digest = format!("sha256:{digest_result:x}");

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
                    // Extract diagnostic from pg_restore exit status
                    return Err(classify_restore_exit_status(status.code()));
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

fn classify_restore_exit_status(code: Option<i32>) -> StageExecutionError {
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
