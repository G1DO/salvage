//! Versioned recovery-run manifest (`v1`).
//!
//! The manifest is the declarative input to a recovery run. It identifies
//! every recovery input immutably (backup digest, PostgreSQL version,
//! restore source/type) plus the safety envelope (resource limits, stage
//! deadlines, evidence destination, run ownership).
//!
//! # Schema version
//!
//! The first supported schema version is `"v1"`, carried in the required
//! `schema_version` field. Unknown `schema_version` values are rejected with
//! a dedicated `manifest/unsupported-version` diagnostic.
//!
//! # Compatibility
//!
//! - Readers accept only schema versions they implement and reject anything
//!   else as `manifest/unsupported-version`; they never guess across versions.
//! - Writers emit exactly one `schema_version` and must not add fields the
//!   declared version does not define. Unknown fields are rejected on read
//!   (`manifest/schema`) so misspelled safety settings cannot be ignored.
//! - Before any tagged release the draft version may be superseded explicitly
//!   (replace the schema and document the break). After a tagged release,
//!   schema changes require a new `schema_version`; `v1` documents are then
//!   frozen and keep validating exactly as before.
//! - No defaulting: a new version must not silently reinterpret `v1`
//!   documents. Multi-version readers dispatch on `schema_version` first.
//!
//! # Canonical form and hashing
//!
//! The canonical form is the compact JSON serialization of [`Manifest`] with
//! fields in declaration order (top level: `schema_version`, `backup`,
//! `postgres`, `restore`, `limits`, `deadlines`, `evidence`, `run`; nested
//! structs in their own declaration order), no whitespace, no trailing
//! newline. [`manifest_hash`] returns `sha256:<hex>` over those exact bytes.
//!
//! Before validation, parsing normalizes the effective manifest by trimming
//! surrounding whitespace from every free-text/value field (`backup.digest`,
//! `postgres.version`, `restore.recovery_target`,
//! `restore.base_backup_digest`, `evidence.destination`, `run.owner`).
//! Surrounding whitespace is never significant in these fields, so padding
//! variants of the same manifest share one canonical form and one hash —
//! the hash identifies the exact *effective* manifest the evidence bundle
//! must reference. (`schema_version` is the version-dispatch key and must
//! match exactly; it is not trimmed.)
//!
//! # Error taxonomy
//!
//! Failures are split so callers can tell them apart without parsing text:
//!
//! - `manifest/parse`: the input is not well-formed JSON, including input
//!   that is not valid UTF-8 (manifests are UTF-8 JSON, so undecodable
//!   bytes are malformed input, not an I/O problem).
//! - `manifest/schema`: well-formed JSON with the wrong shape (missing or
//!   mistyped required fields, unknown fields, unknown enum variants).
//! - `manifest/unsupported-version`: recognized shape but an unimplemented
//!   `schema_version`.
//! - `manifest/semantic/<subject>`: schema-valid but violates a semantic
//!   rule (bad digest/version format, non-positive limits or deadlines,
//!   blank ownership/destination, incompatible restore combination).
//!
//! Configuration is declarative: the manifest carries no scripts and no
//! generic workflow DSL, and `v1` carries no application OCI boot or
//! contract configuration.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

/// The only schema version this crate implements.
pub const SUPPORTED_SCHEMA_VERSION: &str = "v1";

/// Prefix for canonical manifest hashes.
pub const HASH_PREFIX: &str = "sha256:";

/// A validated recovery-run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema version; must be `"v1"`.
    pub schema_version: String,
    /// Immutable backup identity.
    pub backup: Backup,
    /// PostgreSQL version the backup belongs to.
    pub postgres: Postgres,
    /// Where the restore reads from and which restore kind to perform.
    pub restore: Restore,
    /// Resource limits for the isolated restore.
    pub limits: Limits,
    /// Per-stage deadlines in seconds.
    pub deadlines: Deadlines,
    /// Where machine-readable evidence is written.
    pub evidence: Evidence,
    /// Run ownership identity.
    pub run: Run,
}

/// Immutable backup identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    /// Content digest, `sha256:<64 hex>`.
    pub digest: String,
}

/// PostgreSQL version the backup belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Postgres {
    /// Version string, `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` (numeric parts).
    pub version: String,
}

/// Restore source and kind, plus kind-specific inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restore {
    /// Where the restore reads the backup from.
    pub source: RestoreSource,
    /// Which restore kind to perform.
    #[serde(rename = "type")]
    pub restore_type: RestoreType,
    /// Point-in-time recovery target; required for `pitr`, forbidden otherwise.
    /// Explicit `null` is a schema error, not an absent value.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_target: Option<String>,
    /// Base backup digest for incremental restores; required for
    /// `incremental`, forbidden otherwise. Explicit `null` is a schema
    /// error, not an absent value.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub base_backup_digest: Option<String>,
}

/// Supported restore input locations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreSource {
    /// Object storage (S3-compatible).
    S3,
    /// Object storage (GCS).
    Gcs,
    /// Object storage (Azure Blob).
    AzureBlob,
    /// Local filesystem path inside the isolated environment.
    Local,
}

/// Supported restore kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreType {
    /// Restore a full backup.
    Full,
    /// Restore an incremental chain on top of a base backup.
    Incremental,
    /// Point-in-time recovery to `recovery_target`.
    Pitr,
}

/// Resource limits for the isolated restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// CPU limit in millicores; must be positive.
    pub cpu_millicores: i64,
    /// Memory limit in MiB; must be positive.
    pub memory_mib: i64,
    /// Scratch disk limit in MiB; must be positive.
    pub disk_mib: i64,
}

/// Per-stage deadlines in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deadlines {
    /// Seconds allowed for the restore stage; must be positive.
    pub restore_seconds: i64,
    /// Seconds allowed for the verify stage; must be positive.
    pub verify_seconds: i64,
}

/// Where machine-readable evidence is written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Destination URI or path; must be non-blank.
    pub destination: String,
}

/// Run ownership identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// Owner identity (user or service account); must be non-blank.
    pub owner: String,
}

/// Typed manifest failure with a stable diagnostic code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Input is not well-formed JSON.
    Parse {
        /// Human-readable detail (never parsed for control flow).
        message: String,
    },
    /// Well-formed JSON with the wrong shape.
    Schema {
        /// Human-readable detail (never parsed for control flow).
        message: String,
    },
    /// Recognized shape but an unimplemented schema version.
    UnsupportedVersion {
        /// The `schema_version` that was found.
        found: String,
    },
    /// Schema-valid input that violates a semantic rule.
    Semantic {
        /// Stable subject code, e.g. `manifest/semantic/limits`.
        code: &'static str,
        /// Human-readable detail (never parsed for control flow).
        message: String,
    },
}

impl ManifestError {
    /// Returns the stable diagnostic code for this failure.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Parse { .. } => "manifest/parse",
            Self::Schema { .. } => "manifest/schema",
            Self::UnsupportedVersion { .. } => "manifest/unsupported-version",
            Self::Semantic { code, .. } => code,
        }
    }

    /// Returns the human-readable detail for this failure.
    pub fn message(&self) -> String {
        match self {
            Self::Parse { message } | Self::Schema { message } => message.clone(),
            Self::UnsupportedVersion { found } => {
                format!(
                    "unsupported schema_version {found:?}; expected {SUPPORTED_SCHEMA_VERSION:?}"
                )
            }
            Self::Semantic { message, .. } => message.clone(),
        }
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for ManifestError {}

fn semantic(code: &'static str, message: impl Into<String>) -> ManifestError {
    ManifestError::Semantic {
        code,
        message: message.into(),
    }
}

/// Rejects explicit `null` for optional string fields: `None` means the key
/// was absent, anything else (including `null`) must be a string.
fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct NoNull;

    impl<'de> serde::de::Visitor<'de> for NoNull {
        type Value = Option<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a string")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Err(E::custom(
                "explicit null is not allowed; omit the field instead",
            ))
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Err(E::custom(
                "explicit null is not allowed; omit the field instead",
            ))
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            String::deserialize(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(NoNull)
}
fn is_hex_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_digest(field: &str, code: &'static str, value: &str) -> Result<(), ManifestError> {
    match value.strip_prefix("sha256:") {
        Some(hex) if is_hex_digest(hex) => Ok(()),
        _ => Err(semantic(
            code,
            format!("{field} must be `sha256:<64 hex>`, got {value:?}"),
        )),
    }
}

fn validate_postgres_version(value: &str) -> Result<(), ManifestError> {
    let parts: Vec<&str> = value.split('.').collect();
    let numeric = (parts.len() == 2 || parts.len() == 3)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if numeric {
        Ok(())
    } else {
        Err(semantic(
            "manifest/semantic/postgres-version",
            format!(
                "postgres.version must be MAJOR.MINOR[.PATCH] with numeric parts, got {value:?}"
            ),
        ))
    }
}

fn validate_manifest(manifest: &mut Manifest) -> Result<(), ManifestError> {
    // Normalize the effective manifest: surrounding whitespace in free-text
    // value fields is never significant (padding variants must share one
    // canonical form and one hash). `schema_version` is the version-dispatch
    // key and must match exactly, so it is not trimmed.
    manifest.backup.digest = manifest.backup.digest.trim().to_owned();
    manifest.postgres.version = manifest.postgres.version.trim().to_owned();
    if let Some(target) = manifest.restore.recovery_target.take() {
        manifest.restore.recovery_target = Some(target.trim().to_owned());
    }
    if let Some(digest) = manifest.restore.base_backup_digest.take() {
        manifest.restore.base_backup_digest = Some(digest.trim().to_owned());
    }
    manifest.evidence.destination = manifest.evidence.destination.trim().to_owned();
    manifest.run.owner = manifest.run.owner.trim().to_owned();

    validate_digest(
        "backup.digest",
        "manifest/semantic/backup-digest",
        &manifest.backup.digest,
    )?;
    validate_postgres_version(&manifest.postgres.version)?;

    match manifest.restore.restore_type {
        RestoreType::Full => {
            if manifest.restore.recovery_target.is_some() {
                return Err(semantic(
                    "manifest/semantic/restore-combination",
                    "restore.recovery_target is only allowed with type `pitr`",
                ));
            }
            if manifest.restore.base_backup_digest.is_some() {
                return Err(semantic(
                    "manifest/semantic/restore-combination",
                    "restore.base_backup_digest is only allowed with type `incremental`",
                ));
            }
        }
        RestoreType::Pitr => {
            match &manifest.restore.recovery_target {
                Some(target) if !target.is_empty() => {}
                _ => {
                    return Err(semantic(
                        "manifest/semantic/restore-combination",
                        "restore.recovery_target is required and must be non-blank with type `pitr`",
                    ));
                }
            }
            if manifest.restore.base_backup_digest.is_some() {
                return Err(semantic(
                    "manifest/semantic/restore-combination",
                    "restore.base_backup_digest is only allowed with type `incremental`",
                ));
            }
        }
        RestoreType::Incremental => {
            match &manifest.restore.base_backup_digest {
                Some(digest) => validate_digest(
                    "restore.base_backup_digest",
                    "manifest/semantic/base-backup-digest",
                    digest,
                )?,
                None => {
                    return Err(semantic(
                        "manifest/semantic/restore-combination",
                        "restore.base_backup_digest is required with type `incremental`",
                    ));
                }
            }
            if manifest.restore.recovery_target.is_some() {
                return Err(semantic(
                    "manifest/semantic/restore-combination",
                    "restore.recovery_target is only allowed with type `pitr`",
                ));
            }
        }
    }

    if manifest.limits.cpu_millicores <= 0
        || manifest.limits.memory_mib <= 0
        || manifest.limits.disk_mib <= 0
    {
        return Err(semantic(
            "manifest/semantic/limits",
            "limits.cpu_millicores, limits.memory_mib, and limits.disk_mib must all be positive",
        ));
    }

    if manifest.deadlines.restore_seconds <= 0 || manifest.deadlines.verify_seconds <= 0 {
        return Err(semantic(
            "manifest/semantic/deadlines",
            "deadlines.restore_seconds and deadlines.verify_seconds must both be positive",
        ));
    }

    if manifest.evidence.destination.is_empty() {
        return Err(semantic(
            "manifest/semantic/evidence-destination",
            "evidence.destination must be non-blank",
        ));
    }

    if manifest.run.owner.is_empty() {
        return Err(semantic(
            "manifest/semantic/run-owner",
            "run.owner must be non-blank",
        ));
    }

    Ok(())
}

/// Parses and validates a manifest document.
///
/// Stage order is fixed: JSON parsing, then the `schema_version` gate, then
/// shape (schema) checks, then normalization plus semantic validation. Each
/// stage has its own diagnostic code family so callers can distinguish the
/// failure kind. Version dispatch happens before shape checks so a document
/// declaring an unimplemented version always reports
/// `manifest/unsupported-version`, even if its fields also differ from the
/// supported schema.
///
/// Surrounding whitespace in free-text value fields is trimmed during
/// validation, so padding variants share one canonical form and one hash.
pub fn parse_manifest(text: &str) -> Result<Manifest, ManifestError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| ManifestError::Parse {
            message: format!("invalid JSON: {error}"),
        })?;
    parse_manifest_value(value)
}

/// Parses and validates a manifest from raw bytes.
///
/// Manifests are UTF-8 JSON: undecodable bytes report `manifest/parse`
/// (malformed input), not an I/O error. Decodable input follows the same
/// stages as [`parse_manifest`].
pub fn parse_manifest_bytes(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|error| ManifestError::Parse {
        message: format!("invalid UTF-8: {error}"),
    })?;
    parse_manifest(text)
}

fn parse_manifest_value(value: serde_json::Value) -> Result<Manifest, ManifestError> {
    let version = match value.get("schema_version") {
        Some(serde_json::Value::String(version)) => version.clone(),
        _ => {
            return Err(ManifestError::Schema {
                message: "schema violation: missing or non-string `schema_version`".to_owned(),
            });
        }
    };
    if version != SUPPORTED_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedVersion { found: version });
    }
    let mut manifest: Manifest =
        serde_json::from_value(value).map_err(|error| ManifestError::Schema {
            message: format!("schema violation: {error}"),
        })?;
    validate_manifest(&mut manifest)?;
    Ok(manifest)
}

/// Serializes the manifest in canonical form (compact JSON, declaration
/// field order, no trailing newline).
pub fn normalized_json(manifest: &Manifest) -> String {
    serde_json::to_string(manifest).expect("manifest serialization is infallible")
}

/// Returns the canonical content hash identifying the exact effective
/// manifest: `sha256:<hex>` over [`normalized_json`] bytes.
pub fn manifest_hash(manifest: &Manifest) -> String {
    let digest = Sha256::digest(normalized_json(manifest).as_bytes());
    let mut hex = String::with_capacity(HASH_PREFIX.len() + 64);
    hex.push_str(HASH_PREFIX);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

