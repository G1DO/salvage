//! PostgreSQL tool resolution and version compatibility checking.

use std::path::{Path, PathBuf};
use std::process::Command;

use salvage_core::lifecycle::StageExecutionError;

/// Resolved paths to all required PostgreSQL binaries.
#[derive(Debug, Clone)]
pub struct PostgresBinaries {
    /// Path to `initdb`.
    pub initdb: PathBuf,
    /// Path to `postgres`.
    pub postgres: PathBuf,
    /// Path to `pg_restore`.
    pub pg_restore: PathBuf,
    /// Path to `psql`.
    pub psql: PathBuf,
    /// Path to `pg_isready`.
    pub pg_isready: PathBuf,
    /// Full version string reported by the binaries.
    pub version_str: String,
    /// Major version number (e.g. 16).
    pub major_version: u32,
}

impl PostgresBinaries {
    /// Discovers PostgreSQL binaries, prioritizing the declared version if specified.
    pub fn discover(declared_version: Option<&str>) -> Result<Self, StageExecutionError> {
        let declared_major = match declared_version {
            Some(v) => parse_major_version(v)?,
            None => None,
        };

        // Candidate search directories
        let mut candidate_dirs: Vec<PathBuf> = Vec::new();

        // 1. Explicit override via POSTGRES_BIN_DIR
        if let Ok(dir) = std::env::var("POSTGRES_BIN_DIR") {
            let p = PathBuf::from(dir);
            if p.is_dir() {
                candidate_dirs.push(p);
            }
        }

        // 2. If declared major version is given, try `/usr/lib/postgresql/<major>/bin`
        if let Some(major) = declared_major {
            let p = PathBuf::from(format!("/usr/lib/postgresql/{major}/bin"));
            if p.is_dir() {
                candidate_dirs.push(p);
            }
        }

        // 3. System directories under /usr/lib/postgresql/
        if let Ok(entries) = std::fs::read_dir("/usr/lib/postgresql") {
            let mut dirs: Vec<PathBuf> = Vec::new();
            for entry in entries.flatten() {
                let bin_dir = entry.path().join("bin");
                if bin_dir.is_dir() {
                    dirs.push(bin_dir);
                }
            }
            // Sort descending so newer versions are checked first
            dirs.sort_by(|a, b| b.cmp(a));
            candidate_dirs.extend(dirs);
        }

        // 4. PATH entries
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                if dir.is_dir() && !candidate_dirs.contains(&dir) {
                    candidate_dirs.push(dir);
                }
            }
        }

        // Find binaries
        let mut found_initdb: Option<PathBuf> = None;
        let mut found_postgres: Option<PathBuf> = None;
        let mut found_pg_restore: Option<PathBuf> = None;
        let mut found_psql: Option<PathBuf> = None;
        let mut found_pg_isready: Option<PathBuf> = None;

        for dir in &candidate_dirs {
            if found_initdb.is_none() && is_executable(&dir.join("initdb")) {
                found_initdb = Some(dir.join("initdb"));
            }
            if found_postgres.is_none() && is_executable(&dir.join("postgres")) {
                found_postgres = Some(dir.join("postgres"));
            }
            if found_pg_restore.is_none() && is_executable(&dir.join("pg_restore")) {
                found_pg_restore = Some(dir.join("pg_restore"));
            }
            if found_psql.is_none() && is_executable(&dir.join("psql")) {
                found_psql = Some(dir.join("psql"));
            }
            if found_pg_isready.is_none() && is_executable(&dir.join("pg_isready")) {
                found_pg_isready = Some(dir.join("pg_isready"));
            }
        }

        let initdb = found_initdb.ok_or_else(|| {
            StageExecutionError::failed(
                "restore/missing-prerequisite",
                "missing required PostgreSQL binary `initdb`",
            )
        })?;
        let postgres = found_postgres.ok_or_else(|| {
            StageExecutionError::failed(
                "restore/missing-prerequisite",
                "missing required PostgreSQL binary `postgres`",
            )
        })?;
        let pg_restore = found_pg_restore.ok_or_else(|| {
            StageExecutionError::failed(
                "restore/missing-prerequisite",
                "missing required PostgreSQL binary `pg_restore`",
            )
        })?;
        let psql = found_psql.ok_or_else(|| {
            StageExecutionError::failed(
                "restore/missing-prerequisite",
                "missing required PostgreSQL binary `psql`",
            )
        })?;
        let pg_isready = found_pg_isready.ok_or_else(|| {
            StageExecutionError::failed(
                "restore/missing-prerequisite",
                "missing required PostgreSQL binary `pg_isready`",
            )
        })?;

        // Extract version from pg_restore
        let output = Command::new(&pg_restore)
            .arg("--version")
            .output()
            .map_err(|e| {
                StageExecutionError::failed(
                    "restore/missing-prerequisite",
                    format!("failed to execute pg_restore --version: {e}"),
                )
            })?;

        let version_str = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let major = extract_major_from_version_string(&version_str).ok_or_else(|| {
            StageExecutionError::failed(
                "restore/unsupported-version",
                format!("unable to parse PostgreSQL major version from {version_str:?}"),
            )
        })?;

        // Version compatibility check
        if let Some(expected_major) = declared_major
            && major != expected_major
        {
            return Err(StageExecutionError::failed(
                "restore/unsupported-version",
                format!(
                    "manifest declares PostgreSQL major version {expected_major}, but found PostgreSQL version {major} ({version_str})"
                ),
            ));
        }

        Ok(Self {
            initdb,
            postgres,
            pg_restore,
            psql,
            pg_isready,
            version_str,
            major_version: major,
        })
    }
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            return meta.permissions().mode() & 0o111 != 0;
        }
    }
    false
}

fn parse_major_version(version_str: &str) -> Result<Option<u32>, StageExecutionError> {
    let first = version_str.split('.').next().unwrap_or("").trim();
    if first.is_empty() {
        return Ok(None);
    }
    let major = first.parse::<u32>().map_err(|_| {
        StageExecutionError::failed(
            "restore/unsupported-version",
            format!("invalid major version in {version_str:?}"),
        )
    })?;
    Ok(Some(major))
}

fn extract_major_from_version_string(text: &str) -> Option<u32> {
    for part in text.split_whitespace() {
        if let Some(first_num) = part.split('.').next()
            && let Ok(major) = first_num.parse::<u32>()
            && (9..=50).contains(&major)
        {
            return Some(major);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_major_from_various_strings() {
        assert_eq!(
            extract_major_from_version_string("initdb (PostgreSQL) 16.2 (Ubuntu 16.2-1ubuntu4)"),
            Some(16)
        );
        assert_eq!(
            extract_major_from_version_string(
                "pg_restore (PostgreSQL) 16.2 (Ubuntu 16.2-1ubuntu4)"
            ),
            Some(16)
        );
        assert_eq!(
            extract_major_from_version_string("postgres (PostgreSQL) 14.22"),
            Some(14)
        );
        assert_eq!(extract_major_from_version_string("random text"), None);
    }

    #[test]
    fn discovers_installed_postgresql_on_system() {
        let binaries = PostgresBinaries::discover(Some("16.4")).expect("find PG 16 binaries");
        assert_eq!(binaries.major_version, 16);
        assert!(binaries.initdb.exists());
        assert!(binaries.postgres.exists());
        assert!(binaries.pg_restore.exists());
        assert!(binaries.psql.exists());
        assert!(binaries.pg_isready.exists());
    }

    #[test]
    fn rejects_unsupported_version() {
        let err = PostgresBinaries::discover(Some("99.0")).expect_err("PG 99 not installed");
        match err {
            StageExecutionError::Failed { code, message } => {
                assert_eq!(code, "restore/unsupported-version");
                assert!(message.contains(
                    "manifest declares PostgreSQL major version 99, but found PostgreSQL version 16"
                ));
            }
            other => panic!("expected StageExecutionError::Failed, got {other:?}"),
        }
    }
}
