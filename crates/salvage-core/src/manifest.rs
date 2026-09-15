//! Versioned recovery-run manifest (`v1` frozen, `v2` with boot artifact).
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
//!
//! # Schema v2 (O2 Slice 1)
//!
//! `v2` is a strict superset of `v1`: every `v1` field keeps its meaning,
//! position, and validation, and `v2` additionally requires `app`
//! (immutable OCI artifact identity plus readiness probe) and
//! `deadlines.boot_seconds` (positive deadline for the `boot` lifecycle
//! stage). `v1` documents stay frozen byte-identical; multi-version readers
//! dispatch on `schema_version` first via `parse_any_manifest`. The
//! canonical v2 form orders top-level fields as `schema_version`, `backup`,
//! `postgres`, `restore`, `app`, `limits`, `deadlines`, `evidence`, `run`.
//!
//! `v2` adds `manifest/semantic/app-digest`, `app-repository`, `app-tag`,
//! and `app-readiness` diagnostics. Mutable tags (`latest`, case-insensitive,
//! or any tag containing `@` or `:`) are rejected as `app-tag`.
//!
//! # Schema v3 (O3 Slice 1)
//!
//! `v3` is a strict superset of `v2`: every `v2` field keeps its meaning,
//! position, and validation, and `v3` additionally requires `contracts`
//! (declared recovery contracts without executing them). Each contract has a
//! unique non-blank `name`, a `kind` (`sql` | `http` | `exec`), a kind-shaped
//! `spec`, a per-contract `timeout_ms` (`1..=MAX_CONTRACT_TIMEOUT_MS`), and
//! optional `egress_allow` (absent means deny; HTTP contracts must declare
//! their host). The canonical v3 form orders top-level fields as
//! `schema_version`, `backup`, `postgres`, `restore`, `app`, `contracts`,
//! `limits`, `deadlines`, `evidence`, `run`.
//!
//! `v3` adds `manifest/semantic/contract-name`, `contract-duplicate`,
//! `contract-deadline`, `contract-egress`, `contract-spec`, and
//! `contract-mutable-ref` diagnostics. Mutable URL refs (`latest` path
//! segment, case-insensitive) are rejected like the O2 `latest` tag rule.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

/// The original schema version, frozen byte-identical (`v1` readers keep
/// working exactly as before).
pub const SUPPORTED_SCHEMA_VERSION: &str = "v1";

/// The latest schema version implemented by this crate.
pub const LATEST_SCHEMA_VERSION: &str = "v3";

/// Every schema version this crate can read via `parse_any_manifest`.
pub const SUPPORTED_SCHEMA_VERSIONS: [&str; 3] =
    [SUPPORTED_SCHEMA_VERSION, "v2", LATEST_SCHEMA_VERSION];

/// Upper bound for a single contract `timeout_ms` (oversized values rejected).
pub const MAX_CONTRACT_TIMEOUT_MS: i64 = 300_000;

/// Upper bound for the number of declared contracts.
pub const MAX_CONTRACTS: usize = 32;

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
                    "unsupported schema_version {found:?}; expected one of {SUPPORTED_SCHEMA_VERSIONS:?}"
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

/// Rejects explicit `null` for optional string-list fields: `None` means the
/// key was absent, anything else (including `null`) must be a string array.
fn deserialize_optional_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct NoNullList;

    impl<'de> serde::de::Visitor<'de> for NoNullList {
        type Value = Option<Vec<String>>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an array of strings")
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
            Vec::<String>::deserialize(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(NoNullList)
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

// ===========================================================================
// Schema v2: application boot artifact + boot deadline (O2 Slice 1).
// ===========================================================================
//
// v2 keeps `Manifest` (v1) frozen and adds `ManifestV2` alongside it: the
// simplest shape that preserves the v1 API byte-identically. `AnyManifest`
// dispatches on `schema_version` for multi-version readers.

/// Immutable OCI application artifact identity plus readiness probe (v2 only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppArtifact {
    /// Content digest, `sha256:<64 hex>`.
    pub digest: String,
    /// Optional OCI repository (e.g. `registry.example.com/team/app`).
    /// Explicit `null` is a schema error, not an absent value.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub repository: Option<String>,
    /// Optional immutable tag. `latest` (any case) and any tag containing
    /// `@` or `:` are rejected. Explicit `null` is a schema error.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub tag: Option<String>,
    /// Readiness probe interpreted by the boot executor (Slice 2+).
    pub readiness: AppReadiness,
}

/// Readiness probe for the application artifact (v2 only).
///
/// Slice 1 implements all three probe kinds so later slices need no schema
/// rework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AppReadiness {
    /// TCP connect probe against `host:port` (host defaults to loopback).
    Tcp {
        /// Probe host. Explicit `null` is a schema error.
        #[serde(
            default,
            deserialize_with = "deserialize_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        host: Option<String>,
        /// TCP port, `1..=65535`.
        port: i64,
    },
    /// HTTP GET probe against `host:port` plus `path`.
    Http {
        /// Probe host. Explicit `null` is a schema error.
        #[serde(
            default,
            deserialize_with = "deserialize_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        host: Option<String>,
        /// TCP port, `1..=65535`.
        port: i64,
        /// HTTP path, must start with `/`. Explicit `null` is a schema error.
        #[serde(
            default,
            deserialize_with = "deserialize_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        path: Option<String>,
    },
    /// Exec probe running `command` in the boot environment.
    Exec {
        /// Command plus arguments; non-empty, no blank entries.
        command: Vec<String>,
    },
}

/// Per-stage deadlines in seconds (v2 adds `boot_seconds`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlinesV2 {
    /// Seconds allowed for the restore stage; must be positive.
    pub restore_seconds: i64,
    /// Seconds allowed for the verify stage; must be positive.
    pub verify_seconds: i64,
    /// Seconds allowed for the boot stage; must be positive.
    pub boot_seconds: i64,
}

/// A validated recovery-run manifest with application boot artifact (`v2`).
///
/// Field order is the canonical v2 order: `schema_version`, `backup`,
/// `postgres`, `restore`, `app`, `limits`, `deadlines`, `evidence`, `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestV2 {
    /// Schema version; must be `"v2"`.
    pub schema_version: String,
    /// Immutable backup identity.
    pub backup: Backup,
    /// PostgreSQL version the backup belongs to.
    pub postgres: Postgres,
    /// Where the restore reads from and which restore kind to perform.
    pub restore: Restore,
    /// Immutable application artifact identity and readiness probe.
    pub app: AppArtifact,
    /// Resource limits for the isolated restore.
    pub limits: Limits,
    /// Per-stage deadlines in seconds (including boot).
    pub deadlines: DeadlinesV2,
    /// Where machine-readable evidence is written.
    pub evidence: Evidence,
    /// Run ownership identity.
    pub run: Run,
}

/// Either supported manifest version, dispatched on `schema_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyManifest {
    /// Frozen v1 manifest (no boot stage).
    V1(Manifest),
    /// v2 manifest with application boot artifact.
    V2(ManifestV2),
    /// v3 manifest with application boot artifact plus declared contracts.
    V3(ManifestV3),
}

impl AnyManifest {
    /// Returns the declared `schema_version` (`"v1"`, `"v2"`, or `"v3"`).
    pub fn schema_version(&self) -> &str {
        match self {
            Self::V1(manifest) => manifest.schema_version.as_str(),
            Self::V2(manifest) => manifest.schema_version.as_str(),
            Self::V3(manifest) => manifest.schema_version.as_str(),
        }
    }

    /// Returns the boot deadline in seconds, if declared.
    ///
    /// `None` for v1 (the engine runs no boot stage); `Some(boot_seconds)`
    /// for v2/v3. The lifecycle engine gates its boot block on this value.
    pub fn boot_seconds(&self) -> Option<i64> {
        match self {
            Self::V1(_) => None,
            Self::V2(manifest) => Some(manifest.deadlines.boot_seconds),
            Self::V3(manifest) => Some(manifest.deadlines.boot_seconds),
        }
    }

    /// Returns the canonical content hash of the exact effective manifest.
    pub fn manifest_hash_any(&self) -> String {
        match self {
            Self::V1(manifest) => manifest_hash(manifest),
            Self::V2(manifest) => manifest_hash_v2(manifest),
            Self::V3(manifest) => manifest_hash_v3(manifest),
        }
    }

    /// Returns the v1 core of this manifest for stage contexts.
    ///
    /// v1 clones as-is; v2/v3 drop `app` (and `contracts`) and narrow
    /// deadlines to restore/verify seconds. Slice 2 extends stage contexts
    /// with the full `AppArtifact`; until then the engine carries the core
    /// plus the versioned hash and declared snapshot.
    pub fn core_manifest(&self) -> Manifest {
        match self {
            Self::V1(manifest) => manifest.clone(),
            Self::V2(manifest) => manifest.core_manifest(),
            Self::V3(manifest) => manifest.core_manifest(),
        }
    }

    /// Returns the declared contracts, if any.
    ///
    /// `None` for v1/v2 (no contract stage); `Some(contracts)` for v3.
    /// The contract executor (O3-2+) consumes this list.
    pub fn contracts(&self) -> Option<&[Contract]> {
        match self {
            Self::V1(_) | Self::V2(_) => None,
            Self::V3(manifest) => Some(manifest.contracts.as_slice()),
        }
    }
}

impl ManifestV2 {
    /// Returns the v1 core of this v2 manifest (schema `"v1"`, `app`
    /// dropped, deadlines narrowed). See `AnyManifest::core_manifest`.
    pub fn core_manifest(&self) -> Manifest {
        Manifest {
            schema_version: SUPPORTED_SCHEMA_VERSION.to_owned(),
            backup: self.backup.clone(),
            postgres: self.postgres.clone(),
            restore: self.restore.clone(),
            limits: self.limits.clone(),
            deadlines: Deadlines {
                restore_seconds: self.deadlines.restore_seconds,
                verify_seconds: self.deadlines.verify_seconds,
            },
            evidence: self.evidence.clone(),
            run: self.run.clone(),
        }
    }
}

fn validate_readiness_port(port: i64) -> Result<(), ManifestError> {
    if (1..=65535).contains(&port) {
        Ok(())
    } else {
        Err(semantic(
            "manifest/semantic/app-readiness",
            format!("app.readiness.port must be 1..=65535, got {port}"),
        ))
    }
}

fn validate_readiness_host(host: &mut Option<String>) -> Result<(), ManifestError> {
    if let Some(value) = host.take() {
        let trimmed = value.trim().to_owned();
        if trimmed.is_empty() {
            return Err(semantic(
                "manifest/semantic/app-readiness",
                "app.readiness.host must be non-blank when present",
            ));
        }
        *host = Some(trimmed);
    }
    Ok(())
}

fn validate_app(app: &mut AppArtifact) -> Result<(), ManifestError> {
    app.digest = app.digest.trim().to_owned();
    validate_digest("app.digest", "manifest/semantic/app-digest", &app.digest)?;

    if let Some(repository) = app.repository.take() {
        let trimmed = repository.trim().to_owned();
        if trimmed.is_empty() {
            return Err(semantic(
                "manifest/semantic/app-repository",
                "app.repository must be non-blank when present",
            ));
        }
        if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(semantic(
                "manifest/semantic/app-repository",
                format!("app.repository must not contain whitespace, got {trimmed:?}"),
            ));
        }
        app.repository = Some(trimmed);
    }

    if let Some(tag) = app.tag.take() {
        let trimmed = tag.trim().to_owned();
        if trimmed.is_empty() {
            return Err(semantic(
                "manifest/semantic/app-tag",
                "app.tag must be non-blank when present",
            ));
        }
        if trimmed.eq_ignore_ascii_case("latest") {
            return Err(semantic(
                "manifest/semantic/app-tag",
                format!("app.tag {trimmed:?} is mutable (`latest`); pin an immutable tag"),
            ));
        }
        if trimmed.contains('@') || trimmed.contains(':') {
            return Err(semantic(
                "manifest/semantic/app-tag",
                format!(
                    "app.tag {trimmed:?} must not contain `@` or `:`; pin a plain immutable tag"
                ),
            ));
        }
        if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(semantic(
                "manifest/semantic/app-tag",
                format!("app.tag must not contain whitespace, got {trimmed:?}"),
            ));
        }
        app.tag = Some(trimmed);
    }

    match &mut app.readiness {
        AppReadiness::Tcp { host, port } => {
            validate_readiness_port(*port)?;
            validate_readiness_host(host)?;
        }
        AppReadiness::Http { host, port, path } => {
            validate_readiness_port(*port)?;
            validate_readiness_host(host)?;
            if let Some(value) = path.take() {
                let trimmed = value.trim().to_owned();
                if trimmed.is_empty() || !trimmed.starts_with('/') {
                    return Err(semantic(
                        "manifest/semantic/app-readiness",
                        format!("app.readiness.path must start with `/`, got {trimmed:?}"),
                    ));
                }
                *path = Some(trimmed);
            }
        }
        AppReadiness::Exec { command } => {
            if command.is_empty() {
                return Err(semantic(
                    "manifest/semantic/app-readiness",
                    "app.readiness.command must be non-empty",
                ));
            }
            let mut normalized = Vec::with_capacity(command.len());
            for entry in command.iter() {
                let trimmed = entry.trim().to_owned();
                if trimmed.is_empty() {
                    return Err(semantic(
                        "manifest/semantic/app-readiness",
                        "app.readiness.command entries must be non-blank",
                    ));
                }
                normalized.push(trimmed);
            }
            *command = normalized;
        }
    }

    Ok(())
}

fn validate_manifest_v2(manifest: &mut ManifestV2) -> Result<(), ManifestError> {
    // Same normalization as v1: surrounding whitespace in free-text value
    // fields is never significant. `schema_version` must match exactly.
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

    validate_app(&mut manifest.app)?;

    if manifest.limits.cpu_millicores <= 0
        || manifest.limits.memory_mib <= 0
        || manifest.limits.disk_mib <= 0
    {
        return Err(semantic(
            "manifest/semantic/limits",
            "limits.cpu_millicores, limits.memory_mib, and limits.disk_mib must all be positive",
        ));
    }

    if manifest.deadlines.restore_seconds <= 0
        || manifest.deadlines.verify_seconds <= 0
        || manifest.deadlines.boot_seconds <= 0
    {
        return Err(semantic(
            "manifest/semantic/deadlines",
            "deadlines.restore_seconds, deadlines.verify_seconds, and deadlines.boot_seconds must all be positive",
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

/// Parses and validates a `v2` manifest document.
///
/// Same stage order as `parse_manifest`: JSON parsing, then the
/// `schema_version` gate (`"v2"` only), then shape checks, then
/// normalization plus semantic validation.
pub fn parse_manifest_v2(text: &str) -> Result<ManifestV2, ManifestError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| ManifestError::Parse {
            message: format!("invalid JSON: {error}"),
        })?;
    parse_manifest_v2_value(value)
}

/// Parses and validates a `v2` manifest from raw bytes.
///
/// Undecodable bytes report `manifest/parse`, exactly like
/// `parse_manifest_bytes`.
pub fn parse_manifest_v2_bytes(bytes: &[u8]) -> Result<ManifestV2, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|error| ManifestError::Parse {
        message: format!("invalid UTF-8: {error}"),
    })?;
    parse_manifest_v2(text)
}

fn parse_manifest_v2_value(value: serde_json::Value) -> Result<ManifestV2, ManifestError> {
    let version = match value.get("schema_version") {
        Some(serde_json::Value::String(version)) => version.clone(),
        _ => {
            return Err(ManifestError::Schema {
                message: "schema violation: missing or non-string `schema_version`".to_owned(),
            });
        }
    };
    if version != "v2" {
        return Err(ManifestError::UnsupportedVersion { found: version });
    }
    let mut manifest: ManifestV2 =
        serde_json::from_value(value).map_err(|error| ManifestError::Schema {
            message: format!("schema violation: {error}"),
        })?;
    validate_manifest_v2(&mut manifest)?;
    Ok(manifest)
}

/// Parses and validates a manifest of any supported version.
///
/// Dispatches on `schema_version` before shape checks: `"v1"` parses as
/// `Manifest`, `"v2"` as `ManifestV2`, `"v3"` as `ManifestV3`; anything else
/// reports `manifest/unsupported-version`.
pub fn parse_any_manifest(text: &str) -> Result<AnyManifest, ManifestError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| ManifestError::Parse {
            message: format!("invalid JSON: {error}"),
        })?;
    parse_any_manifest_value(value)
}

/// Parses and validates a manifest of any supported version from raw bytes.
pub fn parse_any_manifest_bytes(bytes: &[u8]) -> Result<AnyManifest, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|error| ManifestError::Parse {
        message: format!("invalid UTF-8: {error}"),
    })?;
    parse_any_manifest(text)
}

fn parse_any_manifest_value(value: serde_json::Value) -> Result<AnyManifest, ManifestError> {
    let version = match value.get("schema_version") {
        Some(serde_json::Value::String(version)) => version.clone(),
        _ => {
            return Err(ManifestError::Schema {
                message: "schema violation: missing or non-string `schema_version`".to_owned(),
            });
        }
    };
    if version == SUPPORTED_SCHEMA_VERSION {
        parse_manifest_value(value).map(AnyManifest::V1)
    } else if version == "v2" {
        parse_manifest_v2_value(value).map(AnyManifest::V2)
    } else if version == LATEST_SCHEMA_VERSION {
        parse_manifest_v3_value(value).map(AnyManifest::V3)
    } else {
        Err(ManifestError::UnsupportedVersion { found: version })
    }
}

/// Serializes the v2 manifest in canonical form (compact JSON, declaration
/// field order, no trailing newline).
pub fn normalized_json_v2(manifest: &ManifestV2) -> String {
    serde_json::to_string(manifest).expect("manifest serialization is infallible")
}

/// Returns the canonical content hash identifying the exact effective v2
/// manifest: `sha256:<hex>` over `normalized_json_v2` bytes.
pub fn manifest_hash_v2(manifest: &ManifestV2) -> String {
    let digest = Sha256::digest(normalized_json_v2(manifest).as_bytes());
    let mut hex = String::with_capacity(HASH_PREFIX.len() + 64);
    hex.push_str(HASH_PREFIX);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// ===========================================================================
// Schema v3: declared recovery contracts (O3 Slice 1).
// ===========================================================================
//
// v3 keeps `Manifest` (v1) and `ManifestV2` (v2) frozen and adds `ManifestV3`
// alongside them. Contracts are declared only: no executor, no isolation
// enforcement, no evidence change here. O3-2+ builds the executor on this
// schema. Per-contract `timeout_ms` is the deadline model (central
// `verify_contracts_seconds` rejected: heterogeneous SQL/HTTP/exec probes
// need per-probe budgets; see ADR 0003).

/// Contract kind (v3 only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContractKind {
    /// SQL probe with a `query` spec.
    Sql,
    /// HTTP probe with a `url` (+ optional `method`) spec.
    Http,
    /// Executable probe with a `command` spec.
    Exec,
}

/// SQL contract spec (v3 only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlSpec {
    /// SQL query text; must be non-blank.
    pub query: String,
}

/// HTTP contract spec (v3 only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSpec {
    /// Absolute URL, `http://` or `https://`; must be non-blank.
    pub url: String,
    /// Optional HTTP method (`GET`, `POST`, ...). Explicit `null` is a
    /// schema error, not an absent value.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub method: Option<String>,
}

/// Exec contract spec (v3 only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSpec {
    /// Command plus arguments; non-empty, no blank entries.
    pub command: Vec<String>,
}

/// Kind-shaped contract spec (v3 only).
///
/// Untagged so the JSON stays `{kind, spec{...}}`: the `kind` field selects
/// the expected shape and `validate_contract` cross-checks them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContractSpec {
    /// SQL shape: `{query}`.
    Sql(SqlSpec),
    /// HTTP shape: `{url, method?}`.
    Http(HttpSpec),
    /// Exec shape: `{command[]}`.
    Exec(ExecSpec),
}

/// A declared recovery contract (v3 only).
///
/// Field order is canonical: `name`, `kind`, `spec`, `timeout_ms`,
/// `egress_allow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Unique contract name; must be non-blank.
    pub name: String,
    /// Contract kind selecting the expected `spec` shape.
    pub kind: ContractKind,
    /// Kind-shaped spec.
    pub spec: ContractSpec,
    /// Per-contract deadline in milliseconds, `1..=MAX_CONTRACT_TIMEOUT_MS`.
    pub timeout_ms: i64,
    /// Optional egress allowlist. Absent means deny-all; HTTP contracts must
    /// declare their host here. Explicit `null` is a schema error.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub egress_allow: Option<Vec<String>>,
}

/// A validated recovery-run manifest with boot artifact + contracts (`v3`).
///
/// Field order is the canonical v3 order: `schema_version`, `backup`,
/// `postgres`, `restore`, `app`, `contracts`, `limits`, `deadlines`,
/// `evidence`, `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestV3 {
    /// Schema version; must be `"v3"`.
    pub schema_version: String,
    /// Immutable backup identity.
    pub backup: Backup,
    /// PostgreSQL version the backup belongs to.
    pub postgres: Postgres,
    /// Where the restore reads from and which restore kind to perform.
    pub restore: Restore,
    /// Immutable application artifact identity and readiness probe.
    pub app: AppArtifact,
    /// Declared recovery contracts (non-empty, unique names).
    pub contracts: Vec<Contract>,
    /// Resource limits for the isolated restore.
    pub limits: Limits,
    /// Per-stage deadlines in seconds (including boot).
    pub deadlines: DeadlinesV2,
    /// Where machine-readable evidence is written.
    pub evidence: Evidence,
    /// Run ownership identity.
    pub run: Run,
}

impl ManifestV3 {
    /// Returns the v1 core of this v3 manifest (schema `"v1"`, `app` and
    /// `contracts` dropped, deadlines narrowed). See
    /// `AnyManifest::core_manifest`.
    pub fn core_manifest(&self) -> Manifest {
        Manifest {
            schema_version: SUPPORTED_SCHEMA_VERSION.to_owned(),
            backup: self.backup.clone(),
            postgres: self.postgres.clone(),
            restore: self.restore.clone(),
            limits: self.limits.clone(),
            deadlines: Deadlines {
                restore_seconds: self.deadlines.restore_seconds,
                verify_seconds: self.deadlines.verify_seconds,
            },
            evidence: self.evidence.clone(),
            run: self.run.clone(),
        }
    }
}

/// Allowed HTTP methods for `http` contract specs.
const ALLOWED_HTTP_METHODS: [&str; 7] =
    ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

fn http_url_host(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host_port = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_port
        .split('@')
        .next_back()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

fn egress_entry_host(entry: &str) -> String {
    entry
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn validate_egress_allow(allow: &mut Option<Vec<String>>) -> Result<Vec<String>, ManifestError> {
    match allow.take() {
        None => Ok(Vec::new()),
        Some(entries) => {
            let mut normalized = Vec::with_capacity(entries.len());
            for entry in entries {
                let trimmed = entry.trim().to_owned();
                if trimmed.is_empty() {
                    return Err(semantic(
                        "manifest/semantic/contract-egress",
                        "contracts[].egress_allow entries must be non-blank when present",
                    ));
                }
                if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
                    return Err(semantic(
                        "manifest/semantic/contract-egress",
                        format!(
                            "contracts[].egress_allow entries must not contain whitespace, got {trimmed:?}"
                        ),
                    ));
                }
                if trimmed.contains("://") {
                    return Err(semantic(
                        "manifest/semantic/contract-egress",
                        format!(
                            "contracts[].egress_allow entries must be hosts, not URLs (no `://`), got {trimmed:?}"
                        ),
                    ));
                }
                normalized.push(trimmed);
            }
            *allow = Some(normalized.clone());
            Ok(normalized)
        }
    }
}

fn validate_contract(contract: &mut Contract) -> Result<(), ManifestError> {
    contract.name = contract.name.trim().to_owned();
    if contract.name.is_empty() {
        return Err(semantic(
            "manifest/semantic/contract-name",
            "contracts[].name must be non-blank",
        ));
    }

    if contract.timeout_ms <= 0 || contract.timeout_ms > MAX_CONTRACT_TIMEOUT_MS {
        return Err(semantic(
            "manifest/semantic/contract-deadline",
            format!(
                "contracts[{}].timeout_ms must be 1..={MAX_CONTRACT_TIMEOUT_MS}, got {}",
                contract.name, contract.timeout_ms
            ),
        ));
    }

    let egress = validate_egress_allow(&mut contract.egress_allow)?;

    match (&contract.kind, &mut contract.spec) {
        (ContractKind::Sql, ContractSpec::Sql(spec)) => {
            spec.query = spec.query.trim().to_owned();
            if spec.query.is_empty() {
                return Err(semantic(
                    "manifest/semantic/contract-spec",
                    format!("contracts[{}].spec.query must be non-blank", contract.name),
                ));
            }
        }
        (ContractKind::Http, ContractSpec::Http(spec)) => {
            spec.url = spec.url.trim().to_owned();
            if spec.url.is_empty()
                || !(spec.url.starts_with("http://") || spec.url.starts_with("https://"))
            {
                return Err(semantic(
                    "manifest/semantic/contract-spec",
                    format!(
                        "contracts[{}].spec.url must be an `http(s)://` URL, got {:?}",
                        contract.name, spec.url
                    ),
                ));
            }
            if spec.url.bytes().any(|b| b.is_ascii_whitespace()) {
                return Err(semantic(
                    "manifest/semantic/contract-spec",
                    format!(
                        "contracts[{}].spec.url must not contain whitespace, got {:?}",
                        contract.name, spec.url
                    ),
                ));
            }
            let Some(host) = http_url_host(&spec.url) else {
                return Err(semantic(
                    "manifest/semantic/contract-spec",
                    format!(
                        "contracts[{}].spec.url must include a host, got {:?}",
                        contract.name, spec.url
                    ),
                ));
            };
            // Mutable-ref rule (same policy as O2 `latest`): URL path
            // segments pinned, never `latest`.
            let path_start = spec.url.find("://").map(|i| i + 3).unwrap_or(0);
            let after_host = spec.url[path_start..]
                .find('/')
                .map(|i| &spec.url[path_start + i..])
                .unwrap_or("");
            let path = after_host.split(['?', '#']).next().unwrap_or("");
            if path
                .split('/')
                .any(|segment| segment.eq_ignore_ascii_case("latest"))
            {
                return Err(semantic(
                    "manifest/semantic/contract-mutable-ref",
                    format!(
                        "contracts[{}].spec.url {:?} is mutable (`latest`); pin an immutable reference",
                        contract.name, spec.url
                    ),
                ));
            }
            if let Some(method) = spec.method.take() {
                let trimmed = method.trim().to_owned();
                if trimmed.is_empty() {
                    return Err(semantic(
                        "manifest/semantic/contract-spec",
                        format!(
                            "contracts[{}].spec.method must be non-blank when present",
                            contract.name
                        ),
                    ));
                }
                let upper = trimmed.to_ascii_uppercase();
                if !ALLOWED_HTTP_METHODS.contains(&upper.as_str()) {
                    return Err(semantic(
                        "manifest/semantic/contract-spec",
                        format!(
                            "contracts[{}].spec.method must be one of {ALLOWED_HTTP_METHODS:?}, got {trimmed:?}",
                            contract.name
                        ),
                    ));
                }
                spec.method = Some(upper);
            }
            // Default-deny egress: HTTP contracts must declare their host.
            if egress.is_empty() {
                return Err(semantic(
                    "manifest/semantic/contract-egress",
                    format!(
                        "contracts[{}] needs egress for its HTTP host {host:?} but declares no `egress_allow` (default-deny)",
                        contract.name
                    ),
                ));
            }
            let host_lower = host.to_ascii_lowercase();
            if !egress
                .iter()
                .map(|e| egress_entry_host(e))
                .any(|e| e == host_lower)
            {
                return Err(semantic(
                    "manifest/semantic/contract-egress",
                    format!(
                        "contracts[{}].spec.url host {host:?} is not in `egress_allow` {egress:?} (default-deny)",
                        contract.name
                    ),
                ));
            }
        }
        (ContractKind::Exec, ContractSpec::Exec(spec)) => {
            if spec.command.is_empty() {
                return Err(semantic(
                    "manifest/semantic/contract-spec",
                    format!(
                        "contracts[{}].spec.command must be non-empty",
                        contract.name
                    ),
                ));
            }
            let mut normalized = Vec::with_capacity(spec.command.len());
            for entry in spec.command.iter() {
                let trimmed = entry.trim().to_owned();
                if trimmed.is_empty() {
                    return Err(semantic(
                        "manifest/semantic/contract-spec",
                        format!(
                            "contracts[{}].spec.command entries must be non-blank",
                            contract.name
                        ),
                    ));
                }
                normalized.push(trimmed);
            }
            spec.command = normalized;
        }
        _ => {
            return Err(semantic(
                "manifest/semantic/contract-spec",
                format!(
                    "contracts[{}].spec shape does not match kind {:?}; use query for sql, url for http, command for exec",
                    contract.name, contract.kind
                ),
            ));
        }
    }

    Ok(())
}

fn validate_contracts(contracts: &mut [Contract]) -> Result<(), ManifestError> {
    if contracts.is_empty() {
        return Err(semantic(
            "manifest/semantic/contract-spec",
            "contracts must declare at least one contract",
        ));
    }
    if contracts.len() > MAX_CONTRACTS {
        return Err(semantic(
            "manifest/semantic/contract-spec",
            format!(
                "contracts must declare at most {MAX_CONTRACTS} contracts, got {}",
                contracts.len()
            ),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for contract in contracts.iter_mut() {
        validate_contract(contract)?;
        if !seen.insert(contract.name.clone()) {
            return Err(semantic(
                "manifest/semantic/contract-duplicate",
                format!("duplicate contract name {:?}", contract.name),
            ));
        }
    }
    Ok(())
}

fn validate_manifest_v3(manifest: &mut ManifestV3) -> Result<(), ManifestError> {
    // Same normalization as v1/v2: surrounding whitespace in free-text value
    // fields is never significant. `schema_version` must match exactly.
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

    validate_app(&mut manifest.app)?;

    validate_contracts(&mut manifest.contracts)?;

    if manifest.limits.cpu_millicores <= 0
        || manifest.limits.memory_mib <= 0
        || manifest.limits.disk_mib <= 0
    {
        return Err(semantic(
            "manifest/semantic/limits",
            "limits.cpu_millicores, limits.memory_mib, and limits.disk_mib must all be positive",
        ));
    }

    if manifest.deadlines.restore_seconds <= 0
        || manifest.deadlines.verify_seconds <= 0
        || manifest.deadlines.boot_seconds <= 0
    {
        return Err(semantic(
            "manifest/semantic/deadlines",
            "deadlines.restore_seconds, deadlines.verify_seconds, and deadlines.boot_seconds must all be positive",
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

/// Parses and validates a `v3` manifest document.
///
/// Same stage order as `parse_manifest`: JSON parsing, then the
/// `schema_version` gate (`"v3"` only), then shape checks, then
/// normalization plus semantic validation.
pub fn parse_manifest_v3(text: &str) -> Result<ManifestV3, ManifestError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| ManifestError::Parse {
            message: format!("invalid JSON: {error}"),
        })?;
    parse_manifest_v3_value(value)
}

/// Parses and validates a `v3` manifest from raw bytes.
///
/// Undecodable bytes report `manifest/parse`, exactly like
/// `parse_manifest_bytes`.
pub fn parse_manifest_v3_bytes(bytes: &[u8]) -> Result<ManifestV3, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|error| ManifestError::Parse {
        message: format!("invalid UTF-8: {error}"),
    })?;
    parse_manifest_v3(text)
}

fn parse_manifest_v3_value(value: serde_json::Value) -> Result<ManifestV3, ManifestError> {
    let version = match value.get("schema_version") {
        Some(serde_json::Value::String(version)) => version.clone(),
        _ => {
            return Err(ManifestError::Schema {
                message: "schema violation: missing or non-string `schema_version`".to_owned(),
            });
        }
    };
    if version != LATEST_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedVersion { found: version });
    }
    let mut manifest: ManifestV3 =
        serde_json::from_value(value).map_err(|error| ManifestError::Schema {
            message: format!("schema violation: {error}"),
        })?;
    validate_manifest_v3(&mut manifest)?;
    Ok(manifest)
}

/// Serializes the v3 manifest in canonical form (compact JSON, declaration
/// field order, no trailing newline).
pub fn normalized_json_v3(manifest: &ManifestV3) -> String {
    serde_json::to_string(manifest).expect("manifest serialization is infallible")
}

/// Returns the canonical content hash identifying the exact effective v3
/// manifest: `sha256:<hex>` over `normalized_json_v3` bytes.
pub fn manifest_hash_v3(manifest: &ManifestV3) -> String {
    let digest = Sha256::digest(normalized_json_v3(manifest).as_bytes());
    let mut hex = String::with_capacity(HASH_PREFIX.len() + 64);
    hex.push_str(HASH_PREFIX);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::{
        AnyManifest, AppReadiness, ManifestError, manifest_hash, manifest_hash_v2,
        manifest_hash_v3, normalized_json, normalized_json_v2, normalized_json_v3,
        parse_any_manifest, parse_manifest, parse_manifest_bytes, parse_manifest_v2,
        parse_manifest_v3,
    };

    const VALID: &str = r#"{
        "schema_version": "v1",
        "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "postgres": {"version": "16.4"},
        "restore": {"source": "s3", "type": "full"},
        "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120},
        "deadlines": {"restore_seconds": 600, "verify_seconds": 300},
        "evidence": {"destination": "file:///tmp/salvage-evidence"},
        "run": {"owner": "recovery-drill"}
    }"#;

    #[test]
    fn accepts_a_valid_manifest() {
        let manifest = parse_manifest(VALID).expect("valid manifest must parse");
        assert_eq!(manifest.schema_version, "v1");
        assert!(manifest_hash(&manifest).starts_with("sha256:"));
    }

    #[test]
    fn canonical_form_is_stable_and_ordered() {
        let pretty = VALID;
        let reordered = r#"{"run": {"owner": "recovery-drill"}, "evidence": {"destination": "file:///tmp/salvage-evidence"}, "deadlines": {"verify_seconds": 300, "restore_seconds": 600}, "limits": {"disk_mib": 5120, "memory_mib": 1024, "cpu_millicores": 500}, "restore": {"type": "full", "source": "s3"}, "postgres": {"version": "16.4"}, "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, "schema_version": "v1"}"#;
        let first = parse_manifest(pretty).expect("valid");
        let second = parse_manifest(reordered).expect("valid");
        assert_eq!(normalized_json(&first), normalized_json(&second));
        assert_eq!(manifest_hash(&first), manifest_hash(&second));
        assert!(
            normalized_json(&first).starts_with(r#"{"schema_version":"v1","backup":"#),
            "canonical form must keep declaration order"
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = VALID.replace(
            r#""run": {"owner": "recovery-drill"}"#,
            r#""run": {"owner": "recovery-drill"}, "scripts": ["echo hi"]"#,
        );
        assert_eq!(
            parse_manifest(&text).expect_err("unknown field").code(),
            "manifest/schema"
        );
    }

    #[test]
    fn distinguishes_error_kinds() {
        assert_eq!(
            parse_manifest("{oops").expect_err("parse").code(),
            "manifest/parse"
        );
        assert_eq!(
            parse_manifest(r#"{"schema_version": "v1"}"#)
                .expect_err("schema")
                .code(),
            "manifest/schema"
        );
        assert_eq!(
            parse_manifest(&VALID.replace(r#""v1""#, r#""v2""#))
                .expect_err("version")
                .code(),
            "manifest/unsupported-version"
        );
        // A divergent future version reports unsupported-version even though
        // its shape also differs from v1.
        assert_eq!(
            parse_manifest(r#"{"schema_version": "v2", "future_field": 1}"#)
                .expect_err("divergent version")
                .code(),
            "manifest/unsupported-version"
        );
        let zero_limits = VALID.replace(r#""cpu_millicores": 500"#, r#""cpu_millicores": 0"#);
        let error = parse_manifest(&zero_limits).expect_err("semantic");
        assert!(matches!(error, ManifestError::Semantic { .. }));
        assert_eq!(error.code(), "manifest/semantic/limits");
    }

    #[test]
    fn padding_whitespace_shares_one_canonical_hash() {
        let padded = VALID
            .replace(
                r#""owner": "recovery-drill""#,
                r#""owner": "  recovery-drill  ""#,
            )
            .replace(
                r#""destination": "file:///tmp/salvage-evidence""#,
                r#""destination": "  file:///tmp/salvage-evidence  ""#,
            );
        let base = parse_manifest(VALID).expect("valid");
        let normalized = parse_manifest(&padded).expect("padded");
        assert_eq!(normalized.run.owner, "recovery-drill");
        assert_eq!(
            normalized.evidence.destination,
            "file:///tmp/salvage-evidence"
        );
        assert_eq!(normalized_json(&base), normalized_json(&normalized));
        assert_eq!(manifest_hash(&base), manifest_hash(&normalized));
    }

    #[test]
    fn non_utf8_bytes_report_parse_not_schema() {
        let bytes = b"\xff\xfe{\"schema_version\": \"v1\"}";
        assert_eq!(
            parse_manifest_bytes(bytes).expect_err("non-UTF-8").code(),
            "manifest/parse"
        );
    }

    #[test]
    fn rejects_explicit_null_for_optional_fields() {
        let text = VALID.replace(
            r#""restore": {"source": "s3", "type": "full"}"#,
            r#""restore": {"source": "s3", "type": "full", "recovery_target": null}"#,
        );
        assert_eq!(
            parse_manifest(&text).expect_err("null target").code(),
            "manifest/schema"
        );
    }

    #[test]
    fn requires_pitr_target_and_incremental_base() {
        let pitr = VALID.replace(r#""type": "full""#, r#""type": "pitr""#);
        assert_eq!(
            parse_manifest(&pitr).expect_err("pitr target").code(),
            "manifest/semantic/restore-combination"
        );
        let incremental = VALID.replace(r#""type": "full""#, r#""type": "incremental""#);
        assert_eq!(
            parse_manifest(&incremental)
                .expect_err("incremental base")
                .code(),
            "manifest/semantic/restore-combination"
        );
    }
    const VALID_V2: &str = r#"{
        "schema_version": "v2",
        "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "postgres": {"version": "16.4"},
        "restore": {"source": "s3", "type": "full"},
        "app": {
            "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "repository": "registry.example.com/team/app",
            "tag": "v1.2.3",
            "readiness": {"type": "tcp", "port": 8080}
        },
        "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120},
        "deadlines": {"restore_seconds": 600, "verify_seconds": 300, "boot_seconds": 120},
        "evidence": {"destination": "file:///tmp/salvage-evidence"},
        "run": {"owner": "recovery-drill"}
    }"#;

    #[test]
    fn accepts_a_valid_v2_manifest() {
        let manifest = parse_manifest_v2(VALID_V2).expect("valid v2 manifest must parse");
        assert_eq!(manifest.schema_version, "v2");
        assert_eq!(manifest.deadlines.boot_seconds, 120);
        assert!(manifest_hash_v2(&manifest).starts_with("sha256:"));
        assert!(matches!(
            manifest.app.readiness,
            AppReadiness::Tcp { port: 8080, .. }
        ));
    }

    #[test]
    fn v2_canonical_form_orders_app_before_limits() {
        let manifest = parse_manifest_v2(VALID_V2).expect("valid");
        let canonical = normalized_json_v2(&manifest);
        assert!(
            canonical.starts_with(r#"{"schema_version":"v2","backup":"#),
            "v2 canonical form must keep declaration order"
        );
        let app_pos = canonical.find(r#""app":"#).expect("app present");
        let limits_pos = canonical.find(r#""limits":"#).expect("limits present");
        let deadlines_pos = canonical
            .find(r#""deadlines":"#)
            .expect("deadlines present");
        assert!(app_pos < limits_pos && limits_pos < deadlines_pos);
        assert!(canonical.contains(r#""boot_seconds":120"#));
    }

    #[test]
    fn v2_accepts_all_readiness_kinds() {
        let http = VALID_V2.replace(
            r#""readiness": {"type": "tcp", "port": 8080}"#,
            r#""readiness": {"type": "http", "port": 8080, "path": "/healthz"}"#,
        );
        assert!(matches!(
            parse_manifest_v2(&http).expect("http").app.readiness,
            AppReadiness::Http { .. }
        ));
        let exec = VALID_V2.replace(
            r#""readiness": {"type": "tcp", "port": 8080}"#,
            r#""readiness": {"type": "exec", "command": ["pg_isready", "-U", "postgres"]}"#,
        );
        assert!(matches!(
            parse_manifest_v2(&exec).expect("exec").app.readiness,
            AppReadiness::Exec { .. }
        ));
    }

    #[test]
    fn rejects_mutable_latest_tag_in_any_case() {
        for tag in ["latest", "Latest", "LATEST", "  latest  "] {
            let text = VALID_V2.replace(r#""tag": "v1.2.3""#, &format!(r#""tag": "{tag}""#));
            assert_eq!(
                parse_manifest_v2(&text).expect_err("latest tag").code(),
                "manifest/semantic/app-tag",
                "tag {tag:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_tag_containing_digest_or_port_markers() {
        for tag in ["v1@sha256:abc", "v1:8080", "a@b", "a:b"] {
            let text = VALID_V2.replace(r#""tag": "v1.2.3""#, &format!(r#""tag": "{tag}""#));
            assert_eq!(
                parse_manifest_v2(&text).expect_err("marker tag").code(),
                "manifest/semantic/app-tag",
                "tag {tag:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_app_digest() {
        let text = VALID_V2.replace(
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "not-a-digest",
        );
        assert_eq!(
            parse_manifest_v2(&text).expect_err("app digest").code(),
            "manifest/semantic/app-digest"
        );
    }

    #[test]
    fn rejects_missing_boot_deadline_as_schema_error() {
        let text = VALID_V2.replace(r#", "boot_seconds": 120"#, "");
        assert_eq!(
            parse_manifest_v2(&text).expect_err("missing boot").code(),
            "manifest/schema"
        );
    }

    #[test]
    fn rejects_nonpositive_boot_deadline() {
        let text = VALID_V2.replace(r#""boot_seconds": 120"#, r#""boot_seconds": 0"#);
        assert_eq!(
            parse_manifest_v2(&text).expect_err("boot deadline").code(),
            "manifest/semantic/deadlines"
        );
    }

    #[test]
    fn rejects_semantically_bad_readiness() {
        let bad_port = VALID_V2.replace(r#""port": 8080"#, r#""port": 0"#);
        assert_eq!(
            parse_manifest_v2(&bad_port).expect_err("port").code(),
            "manifest/semantic/app-readiness"
        );
        let bad_path = VALID_V2.replace(
            r#""readiness": {"type": "tcp", "port": 8080}"#,
            r#""readiness": {"type": "http", "port": 8080, "path": "no-slash"}"#,
        );
        assert_eq!(
            parse_manifest_v2(&bad_path).expect_err("path").code(),
            "manifest/semantic/app-readiness"
        );
        let empty_command = VALID_V2.replace(
            r#""readiness": {"type": "tcp", "port": 8080}"#,
            r#""readiness": {"type": "exec", "command": []}"#,
        );
        assert_eq!(
            parse_manifest_v2(&empty_command)
                .expect_err("command")
                .code(),
            "manifest/semantic/app-readiness"
        );
    }

    #[test]
    fn v1_canonical_form_and_hash_are_frozen() {
        let manifest = parse_manifest(VALID).expect("valid");
        let expected = r#"{"schema_version":"v1","backup":{"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"postgres":{"version":"16.4"},"restore":{"source":"s3","type":"full"},"limits":{"cpu_millicores":500,"memory_mib":1024,"disk_mib":5120},"deadlines":{"restore_seconds":600,"verify_seconds":300},"evidence":{"destination":"file:///tmp/salvage-evidence"},"run":{"owner":"recovery-drill"}}"#;
        assert_eq!(normalized_json(&manifest), expected);
        assert_eq!(manifest_hash(&manifest).len(), "sha256:".len() + 64);
        // The v1-only entry point still rejects v2 documents.
        assert_eq!(
            parse_manifest(VALID_V2).expect_err("v1 rejects v2").code(),
            "manifest/unsupported-version"
        );
    }

    #[test]
    fn any_manifest_dispatches_both_versions() {
        assert!(matches!(
            parse_any_manifest(VALID).expect("v1"),
            AnyManifest::V1(_)
        ));
        assert_eq!(parse_any_manifest(VALID).expect("v1").boot_seconds(), None);
        let any = parse_any_manifest(VALID_V2).expect("v2");
        assert_eq!(any.schema_version(), "v2");
        assert_eq!(any.boot_seconds(), Some(120));
        assert!(any.manifest_hash_any().starts_with("sha256:"));
        assert_eq!(
            parse_any_manifest(r#"{"schema_version": "v9"}"#)
                .expect_err("v9")
                .code(),
            "manifest/unsupported-version"
        );
    }

    #[test]
    fn v2_padding_whitespace_shares_one_canonical_hash() {
        let padded = VALID_V2.replace(
            r#""owner": "recovery-drill""#,
            r#""owner": "  recovery-drill  ""#,
        );
        let base = parse_manifest_v2(VALID_V2).expect("valid");
        let normalized = parse_manifest_v2(&padded).expect("padded");
        assert_eq!(normalized_json_v2(&base), normalized_json_v2(&normalized));
        assert_eq!(manifest_hash_v2(&base), manifest_hash_v2(&normalized));
    }

    const VALID_V3: &str = r#"{
        "schema_version": "v3",
        "backup": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "postgres": {"version": "16.4"},
        "restore": {"source": "s3", "type": "full"},
        "app": {
            "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "repository": "registry.example.com/team/app",
            "tag": "v1.2.3",
            "readiness": {"type": "tcp", "port": 8080}
        },
        "contracts": [
            {"name": "users-count", "kind": "sql", "spec": {"query": "SELECT count(*) FROM salvage_records"}, "timeout_ms": 5000},
            {"name": "health", "kind": "http", "spec": {"url": "https://api.example.com/healthz", "method": "GET"}, "timeout_ms": 5000, "egress_allow": ["api.example.com"]},
            {"name": "check-db", "kind": "exec", "spec": {"command": ["pg_isready", "-U", "postgres"]}, "timeout_ms": 5000}
        ],
        "limits": {"cpu_millicores": 500, "memory_mib": 1024, "disk_mib": 5120},
        "deadlines": {"restore_seconds": 600, "verify_seconds": 300, "boot_seconds": 120},
        "evidence": {"destination": "file:///tmp/salvage-evidence"},
        "run": {"owner": "recovery-drill"}
    }"#;

    #[test]
    fn accepts_a_valid_v3_manifest() {
        let manifest = parse_manifest_v3(VALID_V3).expect("valid v3 manifest must parse");
        assert_eq!(manifest.schema_version, "v3");
        assert_eq!(manifest.contracts.len(), 3);
        assert!(manifest_hash_v3(&manifest).starts_with("sha256:"));
    }

    #[test]
    fn v3_canonical_form_orders_contracts_after_app() {
        let manifest = parse_manifest_v3(VALID_V3).expect("valid");
        let canonical = normalized_json_v3(&manifest);
        assert!(
            canonical.starts_with(r#"{"schema_version":"v3","backup":"#),
            "v3 canonical form must keep declaration order"
        );
        let app_pos = canonical.find(r#""app":"#).expect("app present");
        let contracts_pos = canonical
            .find(r#""contracts":"#)
            .expect("contracts present");
        let limits_pos = canonical.find(r#""limits":"#).expect("limits present");
        assert!(app_pos < contracts_pos && contracts_pos < limits_pos);
    }

    #[test]
    fn v3_rejects_contract_matrix() {
        // Unknown fields.
        let text = VALID_V3.replace(
            r#""run": {"owner": "recovery-drill"}"#,
            r#""run": {"owner": "recovery-drill"}, "scripts": ["echo hi"]"#,
        );
        assert_eq!(
            parse_manifest_v3(&text).expect_err("unknown field").code(),
            "manifest/schema"
        );
        // Blank names.
        let text = VALID_V3.replace(r#""name": "users-count""#, r#""name": "  ""#);
        assert_eq!(
            parse_manifest_v3(&text).expect_err("blank name").code(),
            "manifest/semantic/contract-name"
        );
        // Duplicate names.
        let text = VALID_V3.replace(r#""name": "health""#, r#""name": "users-count""#);
        assert_eq!(
            parse_manifest_v3(&text).expect_err("duplicate").code(),
            "manifest/semantic/contract-duplicate"
        );
        // Zero deadlines.
        let text = VALID_V3.replace(r#""timeout_ms": 5000"#, r#""timeout_ms": 0"#);
        assert_eq!(
            parse_manifest_v3(&text).expect_err("zero deadline").code(),
            "manifest/semantic/contract-deadline"
        );
        // Oversized deadlines.
        let text = VALID_V3.replace(r#""timeout_ms": 5000"#, r#""timeout_ms": 300001"#);
        assert_eq!(
            parse_manifest_v3(&text).expect_err("oversized").code(),
            "manifest/semantic/contract-deadline"
        );
        // Undeclared egress: HTTP without `egress_allow`.
        let text = VALID_V3.replace(r#", "egress_allow": ["api.example.com"]"#, "");
        assert_eq!(
            parse_manifest_v3(&text).expect_err("egress").code(),
            "manifest/semantic/contract-egress"
        );
        // Mutable refs: `latest` URL segment.
        let text = VALID_V3.replace(
            "https://api.example.com/healthz",
            "https://api.example.com/latest",
        );
        assert_eq!(
            parse_manifest_v3(&text).expect_err("mutable ref").code(),
            "manifest/semantic/contract-mutable-ref"
        );
        // Kind/spec mismatch: sql kind with an http-shaped spec.
        let text = VALID_V3.replace(
            r#"{"query": "SELECT count(*) FROM salvage_records"}"#,
            r#"{"url": "https://api.example.com/healthz"}"#,
        );
        assert_eq!(
            parse_manifest_v3(&text).expect_err("mismatch").code(),
            "manifest/semantic/contract-spec"
        );
    }

    #[test]
    fn v3_rejects_mutable_app_tag_like_v2() {
        let text = VALID_V3.replace(r#""tag": "v1.2.3""#, r#""tag": "latest""#);
        assert_eq!(
            parse_manifest_v3(&text).expect_err("latest tag").code(),
            "manifest/semantic/app-tag"
        );
    }

    #[test]
    fn any_manifest_dispatches_all_versions() {
        assert!(matches!(
            parse_any_manifest(VALID_V3).expect("v3"),
            AnyManifest::V3(_)
        ));
        let any = parse_any_manifest(VALID_V3).expect("v3");
        assert_eq!(any.schema_version(), "v3");
        assert_eq!(any.boot_seconds(), Some(120));
        assert!(any.manifest_hash_any().starts_with("sha256:"));
        assert_eq!(any.contracts().expect("contracts").len(), 3);
        assert!(parse_any_manifest(VALID).expect("v1").contracts().is_none());
        // v1/v2 entry points still reject v3 documents.
        assert_eq!(
            parse_manifest(VALID_V3).expect_err("v1 rejects v3").code(),
            "manifest/unsupported-version"
        );
        assert_eq!(
            parse_manifest_v2(VALID_V3)
                .expect_err("v2 rejects v3")
                .code(),
            "manifest/unsupported-version"
        );
    }
}
