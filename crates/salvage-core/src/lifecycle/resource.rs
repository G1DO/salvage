//! Explicit run ownership and resource management.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::journal::now_rfc3339;
use super::process::terminate_process_group;

/// Unique identifier for a recovery run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(String);

impl RunId {
    /// Creates a validated [`RunId`].
    pub fn new(id: impl Into<String>) -> Result<Self, ResourceError> {
        let s = id.into().trim().to_owned();
        if s.is_empty() {
            return Err(ResourceError::InvalidRunId(
                "run identity cannot be empty".to_owned(),
            ));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(ResourceError::InvalidRunId(format!(
                "run identity {s:?} contains invalid characters; expected alphanumeric, '-', '_', or '.'"
            )));
        }
        Ok(Self(s))
    }

    /// Returns the string representation of this run identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The kind of system resource owned by a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ResourceKind {
    /// A managed directory on disk.
    Directory {
        /// Absolute path to the directory.
        path: PathBuf,
    },
    /// A managed file on disk.
    File {
        /// Absolute path to the file.
        path: PathBuf,
    },
    /// An isolated process group.
    ProcessGroup {
        /// Process leader PID.
        pid: u32,
        /// Process group ID.
        pgid: u32,
    },
}

/// A system resource tagged with an explicit run ownership identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedResource {
    /// Unique resource identifier within the run.
    pub resource_id: String,
    /// The owning run's identity.
    pub run_id: RunId,
    /// The kind of resource.
    pub kind: ResourceKind,
    /// Acquisition timestamp in RFC3339 format.
    pub acquired_at_rfc3339: String,
    /// Whether this resource has already been released.
    pub released: bool,
}

/// Tracks and manages lifecycle cleanup for resources owned by a run.
#[derive(Debug)]
pub struct ResourceManager {
    run_id: RunId,
    root_dir: PathBuf,
    resources: Vec<OwnedResource>,
}

impl ResourceManager {
    /// Creates a new resource manager scoped to `run_id` and `root_dir`.
    pub fn new(run_id: RunId, root_dir: PathBuf) -> Self {
        Self {
            run_id,
            root_dir,
            resources: Vec::new(),
        }
    }

    /// Returns the owning run ID.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the root directory scoped to this run.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns a slice of all tracked resources.
    pub fn resources(&self) -> &[OwnedResource] {
        &self.resources
    }

    /// Acquires and creates a directory owned by this run.
    pub fn acquire_directory(&mut self, path: &Path) -> Result<PathBuf, ResourceError> {
        let abs_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root_dir.join(path)
        };

        if !abs_path.starts_with(&self.root_dir) {
            return Err(ResourceError::OutOfScope {
                path: abs_path,
                root: self.root_dir.clone(),
            });
        }

        std::fs::create_dir_all(&abs_path).map_err(|err| ResourceError::Io {
            path: abs_path.clone(),
            source: err,
        })?;

        let resource_id = format!("dir:{}", abs_path.display());
        if !self.resources.iter().any(|r| r.resource_id == resource_id) {
            self.resources.push(OwnedResource {
                resource_id,
                run_id: self.run_id.clone(),
                kind: ResourceKind::Directory {
                    path: abs_path.clone(),
                },
                acquired_at_rfc3339: now_rfc3339(),
                released: false,
            });
        }

        Ok(abs_path)
    }

    /// Acquires a file owned by this run.
    pub fn acquire_file(&mut self, path: &Path) -> Result<PathBuf, ResourceError> {
        let abs_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root_dir.join(path)
        };

        if !abs_path.starts_with(&self.root_dir) {
            return Err(ResourceError::OutOfScope {
                path: abs_path,
                root: self.root_dir.clone(),
            });
        }

        if let Some(parent) = abs_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| ResourceError::Io {
                path: parent.to_path_buf(),
                source: err,
            })?;
        }

        let resource_id = format!("file:{}", abs_path.display());
        if !self.resources.iter().any(|r| r.resource_id == resource_id) {
            self.resources.push(OwnedResource {
                resource_id,
                run_id: self.run_id.clone(),
                kind: ResourceKind::File {
                    path: abs_path.clone(),
                },
                acquired_at_rfc3339: now_rfc3339(),
                released: false,
            });
        }

        Ok(abs_path)
    }

    /// Registers an isolated process group as owned by this run.
    pub fn register_process_group(&mut self, pid: u32, pgid: u32) -> String {
        let resource_id = format!("pgid:{pgid}");
        self.resources.push(OwnedResource {
            resource_id: resource_id.clone(),
            run_id: self.run_id.clone(),
            kind: ResourceKind::ProcessGroup { pid, pgid },
            acquired_at_rfc3339: now_rfc3339(),
            released: false,
        });
        resource_id
    }

    /// Releases a single resource by its ID. Idempotent.
    pub fn release_resource(&mut self, resource_id: &str) -> Result<(), ResourceError> {
        if let Some(res) = self
            .resources
            .iter_mut()
            .find(|r| r.resource_id == resource_id)
        {
            if res.released {
                return Ok(());
            }

            match &res.kind {
                ResourceKind::ProcessGroup { pgid, .. } => {
                    let _ = terminate_process_group(*pgid, Duration::from_millis(100));
                }
                ResourceKind::File { path } => {
                    if path.exists() {
                        std::fs::remove_file(path).map_err(|err| ResourceError::Io {
                            path: path.clone(),
                            source: err,
                        })?;
                    }
                }
                ResourceKind::Directory { path } => {
                    if path.exists() {
                        std::fs::remove_dir_all(path).map_err(|err| ResourceError::Io {
                            path: path.clone(),
                            source: err,
                        })?;
                    }
                }
            }

            res.released = true;
        }
        Ok(())
    }

    /// Idempotently releases and cleans up all owned resources in reverse acquisition order.
    pub fn release_all(&mut self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // 1. Terminate all process groups first
        for res in self.resources.iter_mut().rev() {
            if !res.released
                && let ResourceKind::ProcessGroup { pgid, .. } = &res.kind
            {
                if let Err(err) = terminate_process_group(*pgid, Duration::from_millis(100)) {
                    errors.push(format!("failed to terminate process group {pgid}: {err}"));
                }
                res.released = true;
            }
        }

        // 2. Remove files
        for res in self.resources.iter_mut().rev() {
            if !res.released
                && let ResourceKind::File { path } = &res.kind
            {
                if path.exists()
                    && let Err(err) = std::fs::remove_file(path)
                {
                    errors.push(format!("failed to remove file {}: {err}", path.display()));
                }
                res.released = true;
            }
        }

        // 3. Remove directories
        for res in self.resources.iter_mut().rev() {
            if !res.released
                && let ResourceKind::Directory { path } = &res.kind
            {
                if path.exists()
                    && let Err(err) = std::fs::remove_dir_all(path)
                {
                    errors.push(format!(
                        "failed to remove directory {}: {err}",
                        path.display()
                    ));
                }
                res.released = true;
            }
        }

        // 4. Finally remove root dir if empty or owned
        if self.root_dir.exists()
            && let Ok(mut entries) = std::fs::read_dir(&self.root_dir)
            && entries.next().is_none()
        {
            let _ = std::fs::remove_dir(&self.root_dir);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Errors occurring during resource operations.

#[derive(Debug)]
pub enum ResourceError {
    /// Invalid run ID string.
    InvalidRunId(String),
    /// Attempted to acquire a resource outside the run root.
    OutOfScope {
        /// The invalid path.
        path: PathBuf,
        /// The allowed root directory.
        root: PathBuf,
    },
    /// I/O error during resource creation/deletion.
    Io {
        /// Target path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRunId(msg) => write!(f, "invalid run id: {msg}"),
            Self::OutOfScope { path, root } => {
                write!(
                    f,
                    "path `{}` is outside run ownership root `{}`",
                    path.display(),
                    root.display()
                )
            }
            Self::Io { path, source } => {
                write!(f, "i/o error for `{}`: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ResourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_validation() {
        assert!(RunId::new("run-123").is_ok());
        assert!(RunId::new("run_test.01").is_ok());
        assert!(RunId::new("").is_err());
        assert!(RunId::new("   ").is_err());
        assert!(RunId::new("run/slash").is_err());
        assert!(RunId::new("run space").is_err());
    }

    #[test]
    fn resource_manager_directory_and_file_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-res-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let run_id = RunId::new("test-run-1").unwrap();
        let mut rm = ResourceManager::new(run_id, temp_dir.clone());

        let scratch = rm.acquire_directory(Path::new("scratch")).unwrap();
        assert!(scratch.exists());

        let file = rm.acquire_file(Path::new("scratch/data.txt")).unwrap();
        std::fs::write(&file, b"test content").unwrap();
        assert!(file.exists());

        assert_eq!(rm.resources().len(), 2);

        // Idempotent release
        rm.release_all().unwrap();
        assert!(!file.exists());
        assert!(!scratch.exists());

        // Repeated release succeeds
        assert!(rm.release_all().is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resource_manager_rejects_out_of_scope_paths() {
        let temp_dir =
            std::env::temp_dir().join(format!("salvage-scope-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let run_id = RunId::new("test-run-scope").unwrap();
        let mut rm = ResourceManager::new(run_id, temp_dir.clone());

        let outside = std::env::temp_dir().join("outside-salvage-run");
        assert!(rm.acquire_directory(&outside).is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
