use std::path::PathBuf;

use salvage_core::lifecycle::{RunTelemetry, StageContext, StageExecutionError, StageExecutor};
use std::time::Instant;

use salvage_core::manifest::{AppArtifact, Limits};

pub mod compat;
pub mod container;
pub mod image;
pub mod probe;
pub mod runtime;

pub use compat::{check_compat, reverify_post_boot};
pub use container::{ContainerHandle, parse_docker_port, start_app_container};
pub use image::{ImageIdentity, ensure_image};
pub use probe::{http_probe_once, tcp_probe_once, wait_ready};
pub use runtime::{ContainerRuntime, MIN_DOCKER_MAJOR};

#[derive(Debug, Clone)]
pub struct OciBootExecutor {
    pub app: AppArtifact,
    pub limits: Limits,
    pub pg_socket_dir: Option<PathBuf>,
    pub postgres_version: Option<String>,
    pub observed_app_version: Option<String>,
    pub observed_artifact_digest: Option<String>,
    pub observed_resolved_image_id: Option<String>,
    pub observed_container_id_short: Option<String>,
    pub boot_duration_ms: Option<u64>,
}

impl OciBootExecutor {
    pub fn new(app: AppArtifact, limits: Limits) -> Self {
        Self {
            app,
            limits,
            pg_socket_dir: None,
            postgres_version: None,
            observed_app_version: None,
            observed_artifact_digest: None,
            observed_resolved_image_id: None,
            observed_container_id_short: None,
            boot_duration_ms: None,
        }
    }

    pub fn with_pg_socket_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.pg_socket_dir = Some(dir.into());
        self
    }

    pub fn with_postgres_version(mut self, v: impl Into<String>) -> Self {
        self.postgres_version = Some(v.into());
        self
    }

    pub fn with_pg_socket_dir_opt(mut self, dir: Option<PathBuf>) -> Self {
        self.pg_socket_dir = dir;
        self
    }
}

impl StageExecutor for OciBootExecutor {
    fn execute_boot(&mut self, ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        let boot_start = Instant::now();
        let runtime = ContainerRuntime::discover().map_err(|e| match e {
            StageExecutionError::Failed { code, message } => {
                StageExecutionError::failed(code, message)
            }
            other => other,
        })?;
        let identity = ensure_image(
            &runtime,
            &self.app,
            ctx.resource_manager,
            ctx.deadline,
            ctx.cancellation_token,
        )?;
        let handle = start_app_container(
            &runtime,
            &identity,
            &self.app,
            ctx.run_id,
            &self.limits,
            self.pg_socket_dir.as_deref(),
            ctx.resource_manager,
            ctx.deadline,
            ctx.cancellation_token,
        )?;
        wait_ready(
            &runtime,
            &handle,
            &self.app.readiness,
            ctx.deadline,
            ctx.cancellation_token,
        )?;
        let pg_ver = self
            .postgres_version
            .clone()
            .or_else(|| Some(ctx.manifest.postgres.version.clone()));
        check_compat(
            &runtime,
            &handle,
            &self.app,
            pg_ver.as_deref(),
            ctx.resource_manager,
            ctx.deadline,
            ctx.cancellation_token,
        )?;
        reverify_post_boot(
            self.pg_socket_dir.as_deref(),
            ctx.telemetry.target_dbname.as_deref(),
            &ctx.telemetry.verified_tables.clone(),
            pg_ver.as_deref(),
            ctx.resource_manager,
            ctx.deadline,
            ctx.cancellation_token,
        )?;
        let observed_digest = identity.declared_digest.clone();
        let observed_version = self
            .app
            .tag
            .clone()
            .or_else(|| Some(identity.image_id.clone()));
        let resolved = identity.image_id.clone();
        let short: String = handle.id.chars().take(12).collect();
        let elapsed: u64 = boot_start.elapsed().as_millis() as u64;
        self.observed_artifact_digest = Some(observed_digest.clone());
        self.observed_app_version = observed_version.clone();
        self.observed_resolved_image_id = Some(resolved.clone());
        self.observed_container_id_short = Some(short.clone());
        self.boot_duration_ms = Some(elapsed);
        ctx.telemetry.observed_artifact_digest = Some(observed_digest.clone());
        ctx.telemetry.observed_app_version = observed_version.clone();
        ctx.telemetry.declared_artifact_digest = Some(self.app.digest.clone());
        ctx.telemetry.artifact_repository = self.app.repository.clone();
        ctx.telemetry.artifact_resolved_image_id = Some(resolved.clone());
        ctx.telemetry
            .extra
            .insert("container_id_short".to_owned(), short);
        ctx.telemetry
            .extra
            .insert("artifact_digest".to_owned(), observed_digest);
        ctx.telemetry
            .extra
            .insert("boot_duration_ms".to_owned(), elapsed.to_string());
        Ok(())
    }

    fn telemetry(&self) -> Option<RunTelemetry> {
        Some(RunTelemetry {
            observed_server_version: None,
            observed_client_version: None,
            command_identity: None,
            target_dbname: None,
            observed_app_version: self.observed_app_version.clone(),
            observed_artifact_digest: self.observed_artifact_digest.clone(),
            declared_artifact_digest: Some(self.app.digest.clone()),
            artifact_repository: self.app.repository.clone(),
            artifact_resolved_image_id: self.observed_resolved_image_id.clone(),
            boot_seconds: None,
            verified_tables: Vec::new(),
            extra: Default::default(),
        })
    }
}

#[derive(Debug)]
pub struct CompositeBootExecutor {
    pub postgres: salvage_postgres::PostgresStageExecutor,
    pub oci: OciBootExecutor,
}

impl CompositeBootExecutor {
    pub fn new(postgres: salvage_postgres::PostgresStageExecutor, oci: OciBootExecutor) -> Self {
        Self { postgres, oci }
    }
}

impl StageExecutor for CompositeBootExecutor {
    fn execute_validation(
        &mut self,
        ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        self.postgres.execute_validation(ctx)
    }

    fn execute_restore(&mut self, ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        self.postgres.execute_restore(ctx)?;
        if let Some(sock) = self.postgres.socket_dir() {
            self.oci.pg_socket_dir = Some(sock.to_path_buf());
        }
        Ok(())
    }

    fn execute_verification(
        &mut self,
        ctx: &mut StageContext<'_>,
    ) -> Result<(), StageExecutionError> {
        self.postgres.execute_verification(ctx)
    }

    fn execute_boot(&mut self, ctx: &mut StageContext<'_>) -> Result<(), StageExecutionError> {
        self.oci.execute_boot(ctx)
    }

    fn telemetry(&self) -> Option<RunTelemetry> {
        let pg_telem = &self.postgres.telemetry;
        let oci_telem = &self.oci;
        let merged = RunTelemetry {
            observed_server_version: pg_telem.server_version.clone(),
            observed_client_version: pg_telem.client_version.clone(),
            command_identity: pg_telem.restore_command.clone(),
            target_dbname: pg_telem.target_dbname.clone(),
            observed_app_version: oci_telem.observed_app_version.clone(),
            observed_artifact_digest: oci_telem.observed_artifact_digest.clone(),
            declared_artifact_digest: Some(oci_telem.app.digest.clone()),
            artifact_repository: oci_telem.app.repository.clone(),
            artifact_resolved_image_id: oci_telem.observed_resolved_image_id.clone(),
            boot_seconds: None,
            verified_tables: pg_telem.verified_tables.clone(),
            extra: Default::default(),
        };
        let _ = (pg_telem, oci_telem);
        // placeholder to keep structure, real merge below
        let pg = Some(merged);
        let oci: Option<RunTelemetry> = self.oci.telemetry();
        match (pg, oci) {
            (Some(mut p), Some(o)) => {
                if p.observed_app_version.is_none() {
                    p.observed_app_version = o.observed_app_version;
                }
                if p.observed_artifact_digest.is_none() {
                    p.observed_artifact_digest = o.observed_artifact_digest;
                }
                if p.declared_artifact_digest.is_none() {
                    p.declared_artifact_digest = o.declared_artifact_digest;
                }
                if p.artifact_repository.is_none() {
                    p.artifact_repository = o.artifact_repository;
                }
                if p.artifact_resolved_image_id.is_none() {
                    p.artifact_resolved_image_id = o.artifact_resolved_image_id;
                }
                p.extra.extend(o.extra);
                Some(p)
            }
            (Some(p), None) => Some(p),
            (None, Some(o)) => Some(o),
            (None, None) => None,
        }
    }
}
