//! Ephemeral isolated PostgreSQL target provisioning.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use salvage_core::lifecycle::{
    CancellationToken, ProcessHandle, ResourceManager, StageDeadline, StageExecutionError,
};

use crate::tools::PostgresBinaries;

/// An isolated, ephemeral PostgreSQL cluster instance managed within a run.
#[derive(Debug)]
pub struct EphemeralPostgresTarget {
    /// Directory containing the isolated Unix domain socket.
    pub socket_dir: PathBuf,
    /// Data directory of the cluster.
    pub data_dir: PathBuf,
    /// Configured superuser name.
    pub superuser: String,
    /// Resolved PostgreSQL binaries used by this target.
    pub binaries: PostgresBinaries,
}

impl EphemeralPostgresTarget {
    /// Creates and starts an isolated PostgreSQL cluster using the run's resource manager.
    pub fn start(
        binaries: &PostgresBinaries,
        resource_manager: &mut ResourceManager,
        deadline: &StageDeadline,
        cancellation_token: &CancellationToken,
        superuser: &str,
    ) -> Result<Self, StageExecutionError> {
        // Check cancellation & deadline upfront
        if cancellation_token.is_cancelled() {
            return Err(StageExecutionError::cancelled(
                None,
                "cancelled before starting PostgreSQL target",
            ));
        }
        if deadline.is_expired() {
            return Err(StageExecutionError::TimedOut);
        }

        // 1. Acquire directories owned by the run
        let _ = resource_manager
            .acquire_directory(Path::new("postgres"))
            .map_err(|e| {
                StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("failed to allocate target postgres directory: {e}"),
                )
            })?;

        let data_dir = resource_manager
            .acquire_directory(Path::new("postgres/data"))
            .map_err(|e| {
                StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("failed to allocate target data directory: {e}"),
                )
            })?;

        let socket_dir = resource_manager
            .acquire_directory(Path::new("postgres/socket"))
            .map_err(|e| {
                StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("failed to allocate target socket directory: {e}"),
                )
            })?;

        // initdb requires directory permissions to be strictly 0700
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("failed to set permissions on data directory: {e}"),
                )
            },
        )?;

        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("failed to set permissions on socket directory: {e}"),
                )
            },
        )?;

        // 2. Initialize the cluster with initdb
        let mut init_cmd = Command::new(&binaries.initdb);
        init_cmd
            .arg("-D")
            .arg(&data_dir)
            .arg("-U")
            .arg(superuser)
            .arg("-A")
            .arg("trust")
            .arg("--no-locale")
            .arg("--encoding=UTF8");

        let init_output = init_cmd.output().map_err(|e| {
            StageExecutionError::failed(
                "restore/target-connection-failed",
                format!("failed to execute initdb: {e}"),
            )
        })?;

        if !init_output.status.success() {
            let stderr = String::from_utf8_lossy(&init_output.stderr);
            return Err(StageExecutionError::failed(
                "restore/target-connection-failed",
                format!("initdb initialization failed: {stderr}"),
            ));
        }

        // 3. Configure postgresql.conf for complete network isolation
        let conf_path = data_dir.join("postgresql.conf");
        let mut conf_file = OpenOptions::new()
            .append(true)
            .open(&conf_path)
            .map_err(|e| {
                StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("failed to open postgresql.conf: {e}"),
                )
            })?;

        let conf_content = format!(
            "\n# Salvage isolated configuration\n\
             listen_addresses = ''\n\
             unix_socket_directories = '{}'\n\
             fsync = off\n\
             synchronous_commit = off\n\
             full_page_writes = off\n\
             max_connections = 30\n\
             shared_buffers = 32MB\n",
            socket_dir.display()
        );

        conf_file.write_all(conf_content.as_bytes()).map_err(|e| {
            StageExecutionError::failed(
                "restore/target-connection-failed",
                format!("failed to write postgresql.conf: {e}"),
            )
        })?;

        // 4. Spawn postgres in an isolated process group
        let mut pg_cmd = Command::new(&binaries.postgres);
        pg_cmd.arg("-D").arg(&data_dir);
        pg_cmd.stdout(std::process::Stdio::null());
        pg_cmd.stderr(std::process::Stdio::null());

        let mut handle = ProcessHandle::spawn(pg_cmd).map_err(|e| {
            StageExecutionError::failed(
                "restore/target-connection-failed",
                format!("failed to spawn postgres server: {e}"),
            )
        })?;

        // Register process group with resource manager for guaranteed cleanup
        let _ = resource_manager.register_process_group(handle.pid, handle.pgid);

        // 5. Poll pg_isready until the cluster accepts connections
        let poll_interval = Duration::from_millis(50);
        let start_time = Instant::now();

        loop {
            if cancellation_token.is_cancelled() {
                return Err(StageExecutionError::cancelled(
                    None,
                    "cancelled while waiting for postgres target readiness",
                ));
            }
            if deadline.is_expired() {
                return Err(StageExecutionError::TimedOut);
            }

            // Check if postgres process exited prematurely
            if let Ok(Some(status)) = handle.try_wait() {
                return Err(StageExecutionError::failed(
                    "restore/target-connection-failed",
                    format!("postgres server exited prematurely with status: {status}"),
                ));
            }

            // Test readiness via pg_isready
            let mut ready_cmd = Command::new(&binaries.pg_isready);
            ready_cmd
                .arg("-h")
                .arg(&socket_dir)
                .arg("-U")
                .arg(superuser);

            if let Ok(ready_output) = ready_cmd.output()
                && ready_output.status.success()
            {
                break;
            }

            // Guard against unbounded local loop in case deadline is very long
            if start_time.elapsed() > Duration::from_secs(30) {
                return Err(StageExecutionError::failed(
                    "restore/target-connection-failed",
                    "postgres server failed to become ready within 30 seconds",
                ));
            }

            std::thread::sleep(poll_interval);
        }

        Ok(Self {
            socket_dir,
            data_dir,
            superuser: superuser.to_owned(),
            binaries: binaries.clone(),
        })
    }

    /// Executes a SQL query via `psql` over the isolated Unix domain socket.
    pub fn run_psql(&self, dbname: &str, query: &str) -> Result<String, StageExecutionError> {
        let mut cmd = Command::new(&self.binaries.psql);
        cmd.arg("-h")
            .arg(&self.socket_dir)
            .arg("-U")
            .arg(&self.superuser)
            .arg("-d")
            .arg(dbname)
            .arg("-A")
            .arg("-t")
            .arg("-c")
            .arg(query);

        let output = cmd.output().map_err(|e| {
            StageExecutionError::failed(
                "restore/target-connection-failed",
                format!("failed to execute psql query: {e}"),
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StageExecutionError::failed(
                "restore/target-connection-failed",
                format!("psql query failed: {stderr}"),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Creates an empty database inside the target cluster.
    pub fn create_database(&self, dbname: &str) -> Result<(), StageExecutionError> {
        let escaped = dbname.replace('"', "\"\"");
        let query = format!("CREATE DATABASE \"{escaped}\";");
        self.run_psql("postgres", &query)?;
        Ok(())
    }

    /// Queries the server version from the running cluster.
    pub fn server_version(&self) -> Result<String, StageExecutionError> {
        self.run_psql("postgres", "SELECT version();")
    }
}
