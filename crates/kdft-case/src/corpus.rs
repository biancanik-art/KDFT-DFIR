//! Validation primitives for KDFT golden-corpus manifests.
//!
//! This first validation level checks the typed manifest contract and the
//! integrity of a local source file. It deliberately does not claim that any
//! parser expectation has been evaluated.

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenCorpusManifest {
    pub dataset_id: String,
    pub dataset_version: String,
    pub creation_script_version: String,
    pub purpose: String,
    #[serde(default)]
    pub scope: Vec<String>,
    pub source_image: CorpusSourceImage,
    pub environment: CorpusEnvironment,
    pub expected: CorpusExpectations,
    #[serde(default)]
    pub intentional_corruption: Vec<IntentionalCorruption>,
    pub limitations: Vec<String>,
    #[serde(default)]
    pub known_unsupported_results: Vec<KnownUnsupportedResult>,
    #[serde(default)]
    pub validation_commands: Vec<String>,
    pub sources: Vec<CorpusReference>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusSourceImage {
    pub format: CorpusImageFormat,
    pub path_or_external_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub segment_count: Option<u64>,
    pub sparse: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusImageFormat {
    Raw,
    Dd,
    E01,
    SegmentedE01,
    Vhd,
    Vhdx,
    Vdi,
    Vmdk,
    Aff4,
    Fixture,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusEnvironment {
    pub os: String,
    pub os_build: Option<String>,
    pub architecture: CorpusArchitecture,
    pub partition_table: CorpusPartitionTable,
    pub sector_size_bytes: u64,
    pub filesystems: Vec<CorpusFilesystem>,
    pub encryption: Option<CorpusEncryption>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusArchitecture {
    X86_64,
    Aarch64,
    Arm64,
    I386,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusPartitionTable {
    Mbr,
    Gpt,
    Hybrid,
    None,
    Corrupt,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusFilesystem {
    pub name: String,
    pub version: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusEncryption {
    #[serde(rename = "type")]
    pub encryption_type: CorpusEncryptionType,
    pub state: CorpusEncryptionState,
    pub method: Option<String>,
    pub credential_policy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusEncryptionType {
    None,
    Bitlocker,
    Filevault,
    Luks,
    Other,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusEncryptionState {
    Unencrypted,
    Locked,
    Unlockable,
    Unsupported,
    DetectOnly,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusExpectations {
    #[serde(default)]
    pub partitions: Vec<PartitionExpectation>,
    #[serde(default)]
    pub files: Vec<FileExpectation>,
    #[serde(default)]
    pub deleted_files: Vec<DeletedFileExpectation>,
    #[serde(default)]
    pub timestamps: Vec<TimestampExpectation>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactExpectation>,
    #[serde(default)]
    pub parser_outputs: Vec<ParserOutputExpectation>,
    #[serde(default)]
    pub raw_search_hits: Vec<RawSearchHitExpectation>,
    #[serde(default)]
    pub reports: Vec<ReportExpectation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionExpectation {
    pub index: u64,
    pub name: Option<String>,
    pub start_offset: u64,
    pub size_bytes: u64,
    pub filesystem: String,
    pub expected_region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileExpectation {
    pub path: String,
    pub sha256: String,
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub physical_offsets: Vec<u64>,
    #[serde(default)]
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedFileExpectation {
    pub path: String,
    pub sha256: String,
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub physical_offsets: Vec<u64>,
    #[serde(default)]
    pub attributes: Vec<String>,
    pub recovery: DeletedRecovery,
    pub layout: DeletedLayout,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletedRecovery {
    Complete,
    Partial,
    MetadataOnly,
    NotRecoverable,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletedLayout {
    Contiguous,
    Fragmented,
    PartiallyOverwritten,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampExpectation {
    pub path: String,
    pub field: TimestampField,
    pub value_utc: String,
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampField {
    Created,
    Modified,
    Accessed,
    MftModified,
    ArtifactTime,
    Other,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExpectation {
    pub artifact_kind: String,
    pub path: String,
    pub expected_count: u64,
    #[serde(default)]
    pub expected_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserOutputExpectation {
    pub parser: String,
    pub expected_entries: u64,
    pub expected_status: Option<String>,
    pub canonical_json_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSearchHitExpectation {
    pub query: String,
    pub offset: u64,
    pub length: u64,
    pub encoding: String,
    pub sector: Option<u64>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportExpectation {
    pub bookmark_folder: String,
    pub expected_item_count: u64,
    #[serde(default)]
    pub must_include: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalCorruption {
    pub description: String,
    pub offset: Option<u64>,
    pub expected_behavior: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownUnsupportedResult {
    pub capability: String,
    pub expected_message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusReference {
    pub name: String,
    pub url: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusSourceExpected {
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CorpusSourceObserved {
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusSourceStatus {
    NotChecked,
    Unavailable,
    Unsupported,
    Verified,
    Mismatch,
    Error,
}

impl CorpusSourceStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusValidationStatus {
    Passed,
    Incomplete,
    Mismatch,
    Invalid,
}

impl CorpusValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Incomplete => "incomplete",
            Self::Mismatch => "mismatch",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusValidationReport {
    pub manifest_path: String,
    pub dataset_id: Option<String>,
    pub dataset_version: Option<String>,
    pub structural_valid: bool,
    pub structural_errors: Vec<String>,
    pub validation_scope: String,
    pub source_status: CorpusSourceStatus,
    pub source_path: Option<String>,
    pub source_expected: CorpusSourceExpected,
    pub source_observed: CorpusSourceObserved,
    pub expectation_counts: BTreeMap<String, usize>,
    pub expectations_declared: usize,
    pub expectations_checked: usize,
    pub unsupported_expectation_classes: Vec<String>,
    pub passed: bool,
    pub status: CorpusValidationStatus,
    pub limitations: Vec<String>,
}

impl CorpusValidationReport {
    pub fn to_human_string(&self) -> String {
        let expected_size = display_option(self.source_expected.size_bytes.as_ref());
        let expected_sha = display_option(self.source_expected.sha256.as_ref());
        let observed_size = display_option(self.source_observed.size_bytes.as_ref());
        let observed_sha = display_option(self.source_observed.sha256.as_ref());
        let unsupported = if self.unsupported_expectation_classes.is_empty() {
            "none".to_string()
        } else {
            self.unsupported_expectation_classes.join(", ")
        };
        let limitations = if self.limitations.is_empty() {
            "none".to_string()
        } else {
            self.limitations.join(" | ")
        };
        format!(
            "Golden corpus validation\n\
             Manifest: {}\n\
             Dataset: {} version {}\n\
             Structural valid: {}\n\
             Scope: {}\n\
             Source status: {}\n\
             Source path: {}\n\
             Expected source: size={} sha256={}\n\
             Observed source: size={} sha256={}\n\
             Expectations: declared={} checked={}\n\
             Unsupported expectation classes: {}\n\
             Passed: {}\n\
             Status: {}\n\
             Limitations: {}",
            self.manifest_path,
            self.dataset_id.as_deref().unwrap_or("unknown"),
            self.dataset_version.as_deref().unwrap_or("unknown"),
            self.structural_valid,
            self.validation_scope,
            self.source_status.as_str(),
            self.source_path.as_deref().unwrap_or("not resolved"),
            expected_size,
            expected_sha,
            observed_size,
            observed_sha,
            self.expectations_declared,
            self.expectations_checked,
            unsupported,
            self.passed,
            self.status.as_str(),
            limitations
        )
    }
}

fn display_option<T: ToString>(value: Option<&T>) -> String {
    value
        .map(ToString::to_string)
        .unwrap_or_else(|| "not available".to_string())
}

/// Validate a golden-corpus manifest and, when it names a local source, stream
/// that source to verify its exact byte length and SHA-256 digest.
pub fn validate_corpus_manifest(manifest_path: &Path) -> CorpusValidationReport {
    let manifest_label = manifest_path.display().to_string();
    let mut report = empty_report(manifest_label);
    let contents = match std::fs::read_to_string(manifest_path) {
        Ok(contents) => contents,
        Err(error) => {
            report
                .structural_errors
                .push(format!("could not read manifest: {error}"));
            return report;
        }
    };

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) {
        report.dataset_id = value
            .get("dataset_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        report.dataset_version = value
            .get("dataset_version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if let Some(source) = value.get("source_image") {
            report.source_expected.size_bytes =
                source.get("size_bytes").and_then(serde_json::Value::as_u64);
            report.source_expected.sha256 = source
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
    }

    let manifest: GoldenCorpusManifest = match serde_json::from_str(&contents) {
        Ok(manifest) => manifest,
        Err(error) => {
            report.structural_errors.push(format!(
                "manifest does not satisfy the typed contract: {error}"
            ));
            return report;
        }
    };

    report.dataset_id = Some(manifest.dataset_id.clone());
    report.dataset_version = Some(manifest.dataset_version.clone());
    report.source_expected = CorpusSourceExpected {
        size_bytes: Some(manifest.source_image.size_bytes),
        sha256: Some(manifest.source_image.sha256.clone()),
    };
    report.limitations.extend(manifest.limitations.clone());

    validate_structure(&manifest, &mut report.structural_errors);
    if !report.structural_errors.is_empty() {
        return report;
    }
    report.structural_valid = true;

    report.expectation_counts = expectation_counts(&manifest);
    report.expectations_declared = report.expectation_counts.values().sum();
    report.unsupported_expectation_classes = report
        .expectation_counts
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(name, _)| name.clone())
        .collect();
    if report.expectations_declared > 0 {
        report.limitations.push(
            "Parser and report expectation evaluation is not implemented at this validation level."
                .to_string(),
        );
    }

    let source_id = &manifest.source_image.path_or_external_id;
    let source_path_candidate = PathBuf::from(source_id);
    if source_path_candidate.is_absolute() {
        report.source_status = CorpusSourceStatus::Error;
        report.source_path = Some(source_id.clone());
        report.status = CorpusValidationStatus::Invalid;
        report.limitations.push(
            "Local corpus source paths must be relative to the manifest directory.".to_string(),
        );
        return report;
    }
    if source_is_external_identifier(source_id) {
        report.source_status = CorpusSourceStatus::Unavailable;
        report.source_path = Some(source_id.clone());
        report.status = CorpusValidationStatus::Incomplete;
        report.limitations.push(
            "The manifest references an external or synthetic source; no local source bytes were checked."
                .to_string(),
        );
        return report;
    }

    if matches!(
        manifest.source_image.format,
        CorpusImageFormat::SegmentedE01
    ) || manifest.source_image.segment_count.unwrap_or(1) > 1
    {
        report.source_status = CorpusSourceStatus::Unsupported;
        report.source_path = Some(source_id.clone());
        report.status = CorpusValidationStatus::Incomplete;
        report.limitations.push(
            "Multi-segment source integrity verification is not implemented; no segment was treated as the complete source."
                .to_string(),
        );
        return report;
    }

    let source_path = match resolve_source_path(manifest_path, source_id) {
        Ok(path) => path,
        Err(error) => {
            report.source_status = CorpusSourceStatus::Error;
            report.status = CorpusValidationStatus::Invalid;
            report.limitations.push(error);
            return report;
        }
    };
    report.source_path = Some(source_path.display().to_string());
    let metadata = match std::fs::symlink_metadata(&source_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            report.source_status = if error.kind() == std::io::ErrorKind::NotFound {
                CorpusSourceStatus::Unavailable
            } else {
                CorpusSourceStatus::Error
            };
            report.status = CorpusValidationStatus::Incomplete;
            report
                .limitations
                .push(format!("Local source could not be inspected: {error}"));
            return report;
        }
    };
    if metadata.file_type().is_symlink() {
        report.source_status = CorpusSourceStatus::Error;
        report.status = CorpusValidationStatus::Invalid;
        report.limitations.push(
            "The local source is a symbolic link or reparse point and was not followed."
                .to_string(),
        );
        return report;
    }
    if !metadata.is_file() {
        report.source_status = CorpusSourceStatus::Error;
        report.status = CorpusValidationStatus::Incomplete;
        report
            .limitations
            .push("The resolved local source is not a regular file.".to_string());
        return report;
    }
    report.source_observed.size_bytes = Some(metadata.len());
    if metadata.len() != manifest.source_image.size_bytes {
        report.source_status = CorpusSourceStatus::Mismatch;
        report.status = CorpusValidationStatus::Mismatch;
        return report;
    }

    match stream_sha256(&source_path) {
        Ok(observed) => report.source_observed = observed,
        Err(error) => {
            report.source_status = CorpusSourceStatus::Error;
            report.status = CorpusValidationStatus::Incomplete;
            report
                .limitations
                .push(format!("Local source could not be hashed: {error}"));
            return report;
        }
    }

    let size_matches = report.source_observed.size_bytes == report.source_expected.size_bytes;
    let sha_matches = report
        .source_observed
        .sha256
        .as_deref()
        .zip(report.source_expected.sha256.as_deref())
        .map(|(observed, expected)| observed.eq_ignore_ascii_case(expected))
        .unwrap_or(false);
    if !size_matches || !sha_matches {
        report.source_status = CorpusSourceStatus::Mismatch;
        report.status = CorpusValidationStatus::Mismatch;
        return report;
    }

    report.source_status = CorpusSourceStatus::Verified;
    if report.expectations_declared == 0 {
        report.passed = true;
        report.status = CorpusValidationStatus::Passed;
    } else {
        report.status = CorpusValidationStatus::Incomplete;
    }
    report
}

fn empty_report(manifest_path: String) -> CorpusValidationReport {
    CorpusValidationReport {
        manifest_path,
        dataset_id: None,
        dataset_version: None,
        structural_valid: false,
        structural_errors: Vec::new(),
        validation_scope: "manifest_and_source_integrity_only".to_string(),
        source_status: CorpusSourceStatus::NotChecked,
        source_path: None,
        source_expected: CorpusSourceExpected {
            size_bytes: None,
            sha256: None,
        },
        source_observed: CorpusSourceObserved::default(),
        expectation_counts: BTreeMap::new(),
        expectations_declared: 0,
        expectations_checked: 0,
        unsupported_expectation_classes: Vec::new(),
        passed: false,
        status: CorpusValidationStatus::Invalid,
        limitations: vec![
            "This validation level checks only manifest structure and local source size/SHA-256; it does not evaluate expected forensic outcomes."
                .to_string(),
        ],
    }
}

fn validate_structure(manifest: &GoldenCorpusManifest, errors: &mut Vec<String>) {
    if !valid_dataset_id(&manifest.dataset_id) {
        errors
            .push("dataset_id must match kdft-<lowercase letters/digits/hyphens>-NNN".to_string());
    }
    if !valid_three_component_version(&manifest.dataset_version) {
        errors.push("dataset_version must contain exactly three numeric components".to_string());
    }
    require_nonempty(
        "creation_script_version",
        &manifest.creation_script_version,
        errors,
    );
    require_nonempty("purpose", &manifest.purpose, errors);
    require_unique("scope", &manifest.scope, errors);
    require_nonempty(
        "source_image.path_or_external_id",
        &manifest.source_image.path_or_external_id,
        errors,
    );
    validate_sha256("source_image.sha256", &manifest.source_image.sha256, errors);
    if matches!(manifest.source_image.segment_count, Some(0)) {
        errors.push("source_image.segment_count must be at least 1".to_string());
    }
    require_nonempty("environment.os", &manifest.environment.os, errors);
    if manifest.environment.sector_size_bytes == 0 {
        errors.push("environment.sector_size_bytes must be at least 1".to_string());
    }
    if manifest.environment.filesystems.is_empty() {
        errors.push("environment.filesystems must contain at least one item".to_string());
    }
    for (index, filesystem) in manifest.environment.filesystems.iter().enumerate() {
        require_nonempty(
            &format!("environment.filesystems[{index}].name"),
            &filesystem.name,
            errors,
        );
        require_unique(
            &format!("environment.filesystems[{index}].options"),
            &filesystem.options,
            errors,
        );
    }
    if manifest.sources.is_empty() {
        errors.push("sources must contain at least one item".to_string());
    }
    for (index, source) in manifest.sources.iter().enumerate() {
        require_nonempty(&format!("sources[{index}].name"), &source.name, errors);
        if !valid_uri(&source.url) {
            errors.push(format!("sources[{index}].url must be an absolute URI"));
        }
    }
    for (index, file) in manifest.expected.files.iter().enumerate() {
        validate_sha256(
            &format!("expected.files[{index}].sha256"),
            &file.sha256,
            errors,
        );
        require_unique(
            &format!("expected.files[{index}].attributes"),
            &file.attributes,
            errors,
        );
    }
    for (index, file) in manifest.expected.deleted_files.iter().enumerate() {
        validate_sha256(
            &format!("expected.deleted_files[{index}].sha256"),
            &file.sha256,
            errors,
        );
        require_unique(
            &format!("expected.deleted_files[{index}].attributes"),
            &file.attributes,
            errors,
        );
    }
    for (index, timestamp) in manifest.expected.timestamps.iter().enumerate() {
        if DateTime::parse_from_rfc3339(&timestamp.value_utc).is_err() {
            errors.push(format!(
                "expected.timestamps[{index}].value_utc must be an RFC 3339 date-time"
            ));
        }
    }
    for (index, artifact) in manifest.expected.artifacts.iter().enumerate() {
        for (field, value) in &artifact.expected_fields {
            if !(value.is_null() || value.is_boolean() || value.is_number() || value.is_string()) {
                errors.push(format!(
                    "expected.artifacts[{index}].expected_fields.{field} must be a scalar JSON value"
                ));
            }
        }
    }
    for (index, hit) in manifest.expected.raw_search_hits.iter().enumerate() {
        if hit.length == 0 {
            errors.push(format!(
                "expected.raw_search_hits[{index}].length must be at least 1"
            ));
        }
    }
}

fn expectation_counts(manifest: &GoldenCorpusManifest) -> BTreeMap<String, usize> {
    let expected = &manifest.expected;
    BTreeMap::from([
        ("artifacts".to_string(), expected.artifacts.len()),
        ("deleted_files".to_string(), expected.deleted_files.len()),
        ("files".to_string(), expected.files.len()),
        ("parser_outputs".to_string(), expected.parser_outputs.len()),
        ("partitions".to_string(), expected.partitions.len()),
        (
            "raw_search_hits".to_string(),
            expected.raw_search_hits.len(),
        ),
        ("reports".to_string(), expected.reports.len()),
        ("timestamps".to_string(), expected.timestamps.len()),
    ])
}

fn resolve_source_path(manifest_path: &Path, source: &str) -> Result<PathBuf, String> {
    let source_path = PathBuf::from(source);
    if source_path.is_absolute() {
        return Err(
            "Local corpus source paths must be relative to the manifest directory.".to_string(),
        );
    }
    if source_path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(
            "Local corpus source paths must not escape the manifest directory.".to_string(),
        );
    }
    Ok(manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(source_path))
}

fn stream_sha256(path: &Path) -> std::io::Result<CorpusSourceObserved> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size.saturating_add(read as u64);
    }
    Ok(CorpusSourceObserved {
        size_bytes: Some(size),
        sha256: Some(format!("{:x}", hasher.finalize())),
    })
}

fn valid_dataset_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("kdft-") else {
        return false;
    };
    let Some((name, sequence)) = rest.rsplit_once('-') else {
        return false;
    };
    !name.is_empty()
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && sequence.len() == 3
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_three_component_version(value: &str) -> bool {
    let mut parts = value.split('.');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
}

fn validate_sha256(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        errors.push(format!(
            "{field} must contain exactly 64 hexadecimal characters"
        ));
    }
}

fn require_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn require_unique(field: &str, values: &[String], errors: &mut Vec<String>) {
    let mut seen = HashSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        errors.push(format!("{field} must contain unique items"));
    }
}

fn valid_uri(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    !remainder.is_empty()
        && scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn source_is_external_identifier(value: &str) -> bool {
    value.contains("://") || value.starts_with("urn:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempCorpus {
        root: PathBuf,
    }

    impl TempCorpus {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should follow the Unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "kdft-corpus-validation-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).expect("temporary corpus directory should be created");
            Self { root }
        }

        fn write_manifest(&self, value: &serde_json::Value) -> PathBuf {
            let path = self.root.join("manifest.json");
            std::fs::write(
                &path,
                serde_json::to_vec_pretty(value).expect("manifest JSON should serialize"),
            )
            .expect("manifest should be written");
            path
        }
    }

    impl Drop for TempCorpus {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn valid_manifest(source: &str, size: u64, sha256: &str) -> serde_json::Value {
        json!({
            "dataset_id": "kdft-validator-001",
            "dataset_version": "1.0.0",
            "creation_script_version": "test",
            "purpose": "Validator unit test",
            "scope": ["source-integrity"],
            "source_image": {
                "format": "fixture",
                "path_or_external_id": source,
                "sha256": sha256,
                "size_bytes": size
            },
            "environment": {
                "os": "synthetic",
                "architecture": "unknown",
                "partition_table": "none",
                "sector_size_bytes": 512,
                "filesystems": [{ "name": "none", "options": ["fixture"] }]
            },
            "expected": {},
            "limitations": ["Unit-test fixture"],
            "sources": [{ "name": "Local test", "url": "urn:kdft:test" }]
        })
    }

    #[test]
    fn local_source_with_no_parser_expectations_passes_integrity_scope() {
        let temp = TempCorpus::new();
        let bytes = b"known corpus bytes";
        std::fs::write(temp.root.join("source.bin"), bytes).expect("source should be written");
        let sha = format!("{:x}", Sha256::digest(bytes));
        let manifest = temp.write_manifest(&valid_manifest("source.bin", bytes.len() as u64, &sha));

        let report = validate_corpus_manifest(&manifest);

        assert!(report.structural_valid);
        assert_eq!(report.source_status, CorpusSourceStatus::Verified);
        assert_eq!(report.expectations_declared, 0);
        assert_eq!(report.expectations_checked, 0);
        assert!(report.passed);
        assert_eq!(report.status, CorpusValidationStatus::Passed);
        assert_eq!(
            report.validation_scope,
            "manifest_and_source_integrity_only"
        );
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("does not evaluate expected forensic outcomes")));
    }

    #[test]
    fn source_digest_mismatch_does_not_pass() {
        let temp = TempCorpus::new();
        let bytes = b"known corpus bytes";
        std::fs::write(temp.root.join("source.bin"), bytes).expect("source should be written");
        let manifest = temp.write_manifest(&valid_manifest(
            "source.bin",
            bytes.len() as u64,
            &"0".repeat(64),
        ));

        let report = validate_corpus_manifest(&manifest);

        assert_eq!(report.source_status, CorpusSourceStatus::Mismatch);
        assert_eq!(report.status, CorpusValidationStatus::Mismatch);
        assert!(!report.passed);
    }

    #[test]
    fn unknown_field_and_invalid_dataset_id_are_rejected() {
        let temp = TempCorpus::new();
        let mut value = valid_manifest("source.bin", 0, &"0".repeat(64));
        value["dataset_id"] = json!("INVALID");
        value["source_image"]["unexpected"] = json!(true);
        let manifest = temp.write_manifest(&value);

        let report = validate_corpus_manifest(&manifest);

        assert!(!report.structural_valid);
        assert_eq!(report.status, CorpusValidationStatus::Invalid);
        assert!(!report.passed);
        assert!(report.structural_errors[0].contains("unknown field"));
    }

    #[test]
    fn invalid_dataset_id_is_rejected_by_manual_contract_validation() {
        let temp = TempCorpus::new();
        let mut value = valid_manifest("source.bin", 0, &"0".repeat(64));
        value["dataset_id"] = json!("INVALID");
        let manifest = temp.write_manifest(&value);

        let report = validate_corpus_manifest(&manifest);

        assert!(!report.structural_valid);
        assert_eq!(report.status, CorpusValidationStatus::Invalid);
        assert!(report
            .structural_errors
            .iter()
            .any(|error| error.contains("dataset_id")));
    }

    #[test]
    fn external_source_is_incomplete() {
        let temp = TempCorpus::new();
        let manifest = temp.write_manifest(&valid_manifest(
            "external://fixture.raw",
            10,
            &"0".repeat(64),
        ));

        let report = validate_corpus_manifest(&manifest);

        assert!(report.structural_valid);
        assert_eq!(report.source_status, CorpusSourceStatus::Unavailable);
        assert_eq!(report.status, CorpusValidationStatus::Incomplete);
        assert!(!report.passed);
    }

    #[test]
    fn declared_parser_expectation_is_unsupported_and_cannot_pass() {
        let temp = TempCorpus::new();
        let bytes = b"known corpus bytes";
        std::fs::write(temp.root.join("source.bin"), bytes).expect("source should be written");
        let sha = format!("{:x}", Sha256::digest(bytes));
        let mut value = valid_manifest("source.bin", bytes.len() as u64, &sha);
        value["expected"]["parser_outputs"] = json!([{
            "parser": "ntfs",
            "expected_entries": 1,
            "expected_status": "complete"
        }]);
        let manifest = temp.write_manifest(&value);

        let report = validate_corpus_manifest(&manifest);

        assert_eq!(report.source_status, CorpusSourceStatus::Verified);
        assert_eq!(report.expectations_declared, 1);
        assert_eq!(report.expectations_checked, 0);
        assert_eq!(report.unsupported_expectation_classes, ["parser_outputs"]);
        assert_eq!(report.status, CorpusValidationStatus::Incomplete);
        assert!(!report.passed);
    }

    #[test]
    fn corruption_metadata_does_not_become_a_parser_expectation() {
        let temp = TempCorpus::new();
        let bytes = b"known corpus bytes";
        std::fs::write(temp.root.join("source.bin"), bytes).expect("source should be written");
        let sha = format!("{:x}", Sha256::digest(bytes));
        let mut value = valid_manifest("source.bin", bytes.len() as u64, &sha);
        value["intentional_corruption"] = json!([{
            "description": "Damaged test record",
            "expected_behavior": "Parser emits a bounded diagnostic"
        }]);
        let manifest = temp.write_manifest(&value);

        let report = validate_corpus_manifest(&manifest);

        assert_eq!(report.expectations_declared, 0);
        assert!(report.unsupported_expectation_classes.is_empty());
        assert_eq!(report.status, CorpusValidationStatus::Passed);
        assert!(report.passed);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("does not evaluate expected forensic outcomes")));
    }

    #[test]
    fn size_mismatch_is_rejected_before_hashing() {
        let temp = TempCorpus::new();
        let bytes = b"known corpus bytes";
        std::fs::write(temp.root.join("source.bin"), bytes).expect("source should be written");
        let sha = format!("{:x}", Sha256::digest(bytes));
        let manifest =
            temp.write_manifest(&valid_manifest("source.bin", bytes.len() as u64 + 1, &sha));

        let report = validate_corpus_manifest(&manifest);

        assert_eq!(report.source_status, CorpusSourceStatus::Mismatch);
        assert_eq!(report.source_observed.size_bytes, Some(bytes.len() as u64));
        assert_eq!(report.source_observed.sha256, None);
        assert!(!report.passed);
    }

    #[test]
    fn segmented_source_is_incomplete_instead_of_false_verified() {
        let temp = TempCorpus::new();
        let bytes = b"first segment only";
        std::fs::write(temp.root.join("source.E01"), bytes).expect("source should be written");
        let sha = format!("{:x}", Sha256::digest(bytes));
        let mut value = valid_manifest("source.E01", bytes.len() as u64, &sha);
        value["source_image"]["format"] = json!("segmented_e01");
        value["source_image"]["segment_count"] = json!(2);
        let manifest = temp.write_manifest(&value);

        let report = validate_corpus_manifest(&manifest);

        assert_eq!(report.source_status, CorpusSourceStatus::Unsupported);
        assert_eq!(report.status, CorpusValidationStatus::Incomplete);
        assert_eq!(report.source_observed.sha256, None);
        assert!(!report.passed);
    }
}
