//! The PostgreSQL adapter boundary.

pub mod restore;
pub mod target;
pub mod tools;

use std::path::PathBuf;
use std::time::Duration;

use salvage_core::lifecycle::{StageContext, StageExecutionError, StageExecutor};

pub use restore::{execute_restore, verify_backup_preflight, verify_structural_integrity};
pub use target::EphemeralPostgresTarget;
pub use tools::PostgresBinaries;

/// Identifies the PostgreSQL adapter used by the bootstrap check.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Adapter;

impl Adapter {
    /// Creates the adapter boundary without connecting to a database.
    pub const fn new() -> Self {
        Self
    }

    /// Returns the stable adapter identifier used in machine-readable output.
    pub const fn name(self) -> &'static str {
        "postgres"
    }
}

/// Operational and diagnostic telemetry captured during recovery stages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreTelemetry {
    /// PostgreSQL server version reported by `SELECT version()`.
    pub server_version: Option<String>,
    /// Client binary version string reported by `pg_restore`.
    pub client_version: Option<String>,
    /// Restored database name.
    pub target_dbname: Option<String>,
    /// Command line identity of the restore executable.
    pub restore_command: Option<String>,
    /// Elapsed duration of the `pg_restore` execution.
    pub restore_duration: Option<Duration>,
    /// List of user tables verified in the restored database.
    pub verified_tables: Vec<String>,
}

/// Stage executor for restoring PostgreSQL backups into an isolated target.
#[derive(Debug)]
pub struct PostgresStageExecutor {
    /// Path to the declared backup archive file.
    backup_path: PathBuf,
    /// Name of the restore database.
    target_dbname: String,
    /// Optional expected table to verify during structural verification.
    expected_table: Option<String>,
    /// Superuser username for the target cluster (default: "postgres").
    superuser: String,
    /// Discovered PostgreSQL binaries.
    binaries: Option<PostgresBinaries>,
    /// Captured telemetry.
    pub telemetry: RestoreTelemetry,
    /// Socket directory of the ephemeral target, if started.
    socket_dir: Option<PathBuf>,
}

impl PostgresStageExecutor {
    /// Creates a new executor for a given backup archive path.
    pub fn new(backup_path: impl Into<PathBuf>) -> Self {
        Self {
            backup_path: backup_path.into(),
            target_dbname: "salvage_restore".to_owned(),
            expected_table: None,
            superuser: "postgres".to_owned(),
            binaries: None,
            telemetry: RestoreTelemetry::default(),
            socket_dir: None,
        }
    }

    /// Sets the expected table name to verify post-restore.
    pub fn with_expected_table(mut self, table: impl Into<String>) -> Self {
        self.expected_table = Some(table.into());
        self
    }

    /// Sets a custom target database name.
    pub fn with_target_dbname(mut self, dbname: impl Into<String>) -> Self {
        self.target_dbname = dbname.into();
        self
    }

    /// Sets the superuser name for the ephemeral cluster.
    pub fn with_superuser(mut self, superuser: impl Into<String>) -> Self {
        self.superuser = superuser.into();
        self
    }

    /// Returns the socket directory of the ephemeral target, if started.
    pub fn socket_dir(&self) -> Option<&std::path::Path> {
        self.socket_dir.as_deref()
    }

    /// Returns a reference to the captured stage telemetry.
    pub fn telemetry(&self) -> &RestoreTelemetry {
        &self.telemetry
    }
}

impl StageExecutor for PostgresStageExecutor {
    fn execute_validation(
        &mut self,
        ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        // 1. Discover binaries and check declared PostgreSQL version compatibility
        let binaries = PostgresBinaries::discover(Some(&ctx.manifest.postgres.version))?;

        // 2. Pre-flight verification of backup file: existence, SHA-256 digest, and magic bytes
        verify_backup_preflight(&self.backup_path, &ctx.manifest.backup.digest)?;

        self.telemetry.client_version = Some(binaries.version_str.clone());
        self.telemetry.restore_command = Some(binaries.pg_restore.display().to_string());
        ctx.telemetry.observed_client_version = Some(binaries.version_str.clone());
        ctx.telemetry.command_identity = Some(binaries.pg_restore.display().to_string());
        self.binaries = Some(binaries);
        Ok(())
    }

    fn execute_restore(&mut self, ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        let binaries = match &self.binaries {
            Some(b) => b,
            None => {
                let b = PostgresBinaries::discover(Some(&ctx.manifest.postgres.version))?;
                self.binaries = Some(b);
                self.binaries.as_ref().unwrap()
            }
        };

        // 1. Start ephemeral isolated PostgreSQL cluster
        let target = EphemeralPostgresTarget::start(
            binaries,
            ctx.resource_manager,
            ctx.deadline,
            ctx.cancellation_token,
            &self.superuser,
        )?;

        self.socket_dir = Some(target.socket_dir.clone());

        // Query server version
        let server_version = target.server_version()?;
        self.telemetry.server_version = Some(server_version.clone());
        self.telemetry.target_dbname = Some(self.target_dbname.clone());
        ctx.telemetry.observed_server_version = Some(server_version);
        ctx.telemetry.target_dbname = Some(self.target_dbname.clone());

        // 2. Execute pg_restore
        let duration = execute_restore(
            &target,
            &self.backup_path,
            &self.target_dbname,
            ctx.resource_manager,
            ctx.deadline,
            ctx.cancellation_token,
        )?;
        self.telemetry.restore_duration = Some(duration);

        // 3. Perform structural verification checks
        let verified_tables = verify_structural_integrity(
            &target,
            &self.target_dbname,
            self.expected_table.as_deref(),
        )?;
        self.telemetry.verified_tables = verified_tables.clone();
        ctx.telemetry.verified_tables = verified_tables;

        Ok(())
    }

    fn telemetry(&self) -> Option<salvage_core::lifecycle::RunTelemetry> {
        Some(salvage_core::lifecycle::RunTelemetry {
            observed_server_version: self.telemetry.server_version.clone(),
            observed_client_version: self.telemetry.client_version.clone(),
            command_identity: self.telemetry.restore_command.clone(),
            target_dbname: self.telemetry.target_dbname.clone(),
            observed_app_version: None,
            observed_artifact_digest: None,
            declared_artifact_digest: None,
            artifact_repository: None,
            artifact_resolved_image_id: None,
            boot_seconds: None,
            verified_tables: self.telemetry.verified_tables.clone(),
            extra: Default::default(),
        })
    }
}
