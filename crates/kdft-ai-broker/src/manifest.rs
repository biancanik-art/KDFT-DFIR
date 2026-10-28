use crate::{is_commit_hash, is_sha256, BrokerError, Result};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path};

pub const MANIFEST_SCHEMA_VERSION: &str = "1.0.0";
const MAX_MANIFEST_FILES: usize = 10_000;
const MAX_DECLARED_CONTEXT_TOKENS: u64 = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledModelManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub installed_at_utc: String,
    pub source: ModelSource,
    pub model: ModelDescription,
    pub files: Vec<ManifestFile>,
    pub license: LicenseReview,
    pub compatible_adapters: Vec<CompatibleAdapter>,
    pub verification: VerificationAttestation,
    pub network_state_after_install: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelSource {
    HuggingFaceSnapshot {
        repository_id: String,
        revision_commit: String,
        download_tool: String,
        download_tool_version: String,
    },
    LocalImport {
        imported_file_sha256: String,
        #[serde(default)]
        provenance_note: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelFormat {
    Gguf,
    OnnxGenai,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelDescription {
    pub model_id: String,
    pub display_name: String,
    pub format: ModelFormat,
    pub architecture: String,
    pub quantization: Option<String>,
    #[serde(default)]
    pub parameter_count: Option<u64>,
    pub declared_context_tokens: u64,
    #[serde(default)]
    pub chat_template_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManifestFileRole {
    ModelWeights,
    Tokenizer,
    Configuration,
    ChatTemplate,
    ModelCard,
    License,
    RuntimeAuxiliary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub relative_path: String,
    pub role: ManifestFileRole,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseReviewStatus {
    RecognizedLicenseAccepted,
    CustomLicenseExaminerAcknowledged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LicenseReview {
    pub declared_identifier: String,
    #[serde(default)]
    pub declared_name: Option<String>,
    #[serde(default)]
    pub declared_url: Option<String>,
    #[serde(default)]
    pub license_text_relative_path: Option<String>,
    pub license_text_sha256: String,
    pub review_status: LicenseReviewStatus,
    pub accepted_at_utc: String,
    #[serde(default)]
    pub accepted_by: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdapterId {
    LlamaCpp,
    OnnxRuntimeGenai,
    OllamaDeveloper,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibleAdapter {
    pub adapter_id: AdapterId,
    pub minimum_tested_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationAttestation {
    pub all_file_hashes_verified: bool,
    pub all_file_sizes_verified: bool,
    pub license_reviewed: bool,
    pub model_metadata_parsed: bool,
    pub verification_tool_version: String,
}

impl InstalledModelManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(BrokerError::InvalidManifest(format!(
                "unsupported schema version {:?}",
                self.schema_version
            )));
        }
        nonempty_bounded("manifest_id", &self.manifest_id, 256)?;
        validate_utc_timestamp("installed_at_utc", &self.installed_at_utc)?;
        self.source.validate()?;
        self.model.validate()?;
        if self.files.is_empty() || self.files.len() > MAX_MANIFEST_FILES {
            return Err(BrokerError::InvalidManifest(format!(
                "files must contain 1..={MAX_MANIFEST_FILES} entries"
            )));
        }

        let mut paths = BTreeSet::new();
        let mut has_weights = false;
        let mut matching_license_file = false;
        for file in &self.files {
            file.validate()?;
            if !paths.insert(file.relative_path.as_str()) {
                return Err(BrokerError::InvalidManifest(format!(
                    "duplicate file path {:?}",
                    file.relative_path
                )));
            }
            has_weights |= file.role == ManifestFileRole::ModelWeights;
            if file.role == ManifestFileRole::License
                && file
                    .sha256
                    .eq_ignore_ascii_case(&self.license.license_text_sha256)
            {
                matching_license_file = true;
            }
        }
        if !has_weights {
            return Err(BrokerError::InvalidManifest(
                "at least one model_weights file is required".to_string(),
            ));
        }

        self.license.validate()?;
        if !matching_license_file {
            return Err(BrokerError::InvalidManifest(
                "a declared license file with the accepted license-text SHA-256 is required"
                    .to_string(),
            ));
        }
        if let Some(path) = self.license.license_text_relative_path.as_deref() {
            let Some(file) = self.files.iter().find(|file| file.relative_path == path) else {
                return Err(BrokerError::InvalidManifest(
                    "license_text_relative_path is not present in files".to_string(),
                ));
            };
            if file.role != ManifestFileRole::License
                || !file
                    .sha256
                    .eq_ignore_ascii_case(&self.license.license_text_sha256)
            {
                return Err(BrokerError::InvalidManifest(
                    "license_text_relative_path does not identify the accepted license file"
                        .to_string(),
                ));
            }
        }

        if self.compatible_adapters.is_empty() || self.compatible_adapters.len() > 50 {
            return Err(BrokerError::InvalidManifest(
                "compatible_adapters must contain 1..=50 entries".to_string(),
            ));
        }
        let mut adapters = BTreeSet::new();
        for adapter in &self.compatible_adapters {
            if !adapters.insert(adapter.adapter_id) {
                return Err(BrokerError::InvalidManifest(
                    "compatible adapter ids must be unique".to_string(),
                ));
            }
            nonempty_bounded(
                "minimum_tested_version",
                &adapter.minimum_tested_version,
                256,
            )?;
            if !adapter_supports_format(adapter.adapter_id, self.model.format) {
                return Err(BrokerError::InvalidManifest(format!(
                    "adapter {:?} is incompatible with model format {:?}",
                    adapter.adapter_id, self.model.format
                )));
            }
        }

        if !self.verification.all_file_hashes_verified
            || !self.verification.all_file_sizes_verified
            || !self.verification.license_reviewed
            || !self.verification.model_metadata_parsed
        {
            return Err(BrokerError::InvalidManifest(
                "all verification attestations must be true".to_string(),
            ));
        }
        nonempty_bounded(
            "verification_tool_version",
            &self.verification.verification_tool_version,
            256,
        )?;
        if self.network_state_after_install != "local_offline" {
            return Err(BrokerError::InvalidManifest(
                "network_state_after_install must be local_offline".to_string(),
            ));
        }
        Ok(())
    }
}

impl ModelSource {
    fn validate(&self) -> Result<()> {
        match self {
            Self::HuggingFaceSnapshot {
                repository_id,
                revision_commit,
                download_tool,
                download_tool_version,
            } => {
                if repository_id.len() > 512
                    || repository_id.split('/').count() != 2
                    || repository_id
                        .bytes()
                        .any(|byte| !(byte.is_ascii_alphanumeric() || b"._-/".contains(&byte)))
                {
                    return Err(BrokerError::InvalidManifest(
                        "repository_id must be an owner/name identifier".to_string(),
                    ));
                }
                if !is_commit_hash(revision_commit) {
                    return Err(BrokerError::InvalidManifest(
                        "revision_commit must be a full immutable 40..=64 digit hex commit"
                            .to_string(),
                    ));
                }
                nonempty_bounded("download_tool", download_tool, 256)?;
                nonempty_bounded("download_tool_version", download_tool_version, 256)?;
            }
            Self::LocalImport {
                imported_file_sha256,
                provenance_note,
            } => {
                require_sha256("imported_file_sha256", imported_file_sha256)?;
                if provenance_note
                    .as_ref()
                    .is_some_and(|note| note.len() > 4_000)
                {
                    return Err(BrokerError::InvalidManifest(
                        "provenance_note exceeds 4000 bytes".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ModelDescription {
    fn validate(&self) -> Result<()> {
        nonempty_bounded("model_id", &self.model_id, 1_024)?;
        nonempty_bounded("display_name", &self.display_name, 1_024)?;
        nonempty_bounded("architecture", &self.architecture, 256)?;
        if self.declared_context_tokens == 0
            || self.declared_context_tokens > MAX_DECLARED_CONTEXT_TOKENS
        {
            return Err(BrokerError::InvalidManifest(format!(
                "declared_context_tokens must be 1..={MAX_DECLARED_CONTEXT_TOKENS}"
            )));
        }
        if self
            .quantization
            .as_ref()
            .is_some_and(|value| value.len() > 256)
        {
            return Err(BrokerError::InvalidManifest(
                "quantization exceeds 256 bytes".to_string(),
            ));
        }
        if self.parameter_count == Some(0) {
            return Err(BrokerError::InvalidManifest(
                "parameter_count must be positive when present".to_string(),
            ));
        }
        if let Some(hash) = self.chat_template_sha256.as_deref() {
            require_sha256("chat_template_sha256", hash)?;
        }
        Ok(())
    }
}

impl ManifestFile {
    fn validate(&self) -> Result<()> {
        validate_relative_path(&self.relative_path)?;
        if matches!(
            self.role,
            ManifestFileRole::ModelWeights | ManifestFileRole::License
        ) && self.size_bytes == 0
        {
            return Err(BrokerError::InvalidManifest(
                "model-weight and license files must not be empty".to_string(),
            ));
        }
        require_sha256("file sha256", &self.sha256)
    }
}

impl LicenseReview {
    fn validate(&self) -> Result<()> {
        nonempty_bounded("declared_identifier", &self.declared_identifier, 512)?;
        require_sha256("license_text_sha256", &self.license_text_sha256)?;
        validate_utc_timestamp("accepted_at_utc", &self.accepted_at_utc)?;
        if self
            .declared_name
            .as_ref()
            .is_some_and(|value| value.len() > 1_024)
            || self
                .declared_url
                .as_ref()
                .is_some_and(|value| value.len() > 4_096)
            || self
                .accepted_by
                .as_ref()
                .is_some_and(|value| value.len() > 512)
        {
            return Err(BrokerError::InvalidManifest(
                "license metadata exceeds its bounded field size".to_string(),
            ));
        }
        if let Some(path) = self.license_text_relative_path.as_deref() {
            validate_relative_path(path)?;
        }
        match self.review_status {
            LicenseReviewStatus::RecognizedLicenseAccepted
                if !is_recognized_license_identifier(&self.declared_identifier) =>
            {
                return Err(BrokerError::InvalidManifest(format!(
                    "license identifier {:?} is not in the recognized-license allow-list; record it as an examiner-acknowledged custom license instead",
                    self.declared_identifier
                )));
            }
            LicenseReviewStatus::CustomLicenseExaminerAcknowledged
                if self
                    .accepted_by
                    .as_deref()
                    .is_none_or(|examiner| examiner.trim().is_empty()) =>
            {
                return Err(BrokerError::InvalidManifest(
                    "a custom license requires a non-empty examiner acknowledgement".to_string(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn adapter_supports_format(adapter: AdapterId, format: ModelFormat) -> bool {
    matches!(
        (adapter, format),
        (AdapterId::LlamaCpp, ModelFormat::Gguf)
            | (AdapterId::OllamaDeveloper, ModelFormat::Gguf)
            | (AdapterId::OnnxRuntimeGenai, ModelFormat::OnnxGenai)
    )
}

fn is_recognized_license_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "MIT"
            | "Apache-2.0"
            | "BSD-2-Clause"
            | "BSD-3-Clause"
            | "ISC"
            | "MPL-2.0"
            | "GPL-2.0-only"
            | "GPL-2.0-or-later"
            | "GPL-3.0-only"
            | "GPL-3.0-or-later"
            | "LGPL-2.1-only"
            | "LGPL-2.1-or-later"
            | "LGPL-3.0-only"
            | "LGPL-3.0-or-later"
            | "AGPL-3.0-only"
            | "AGPL-3.0-or-later"
            | "CC-BY-4.0"
            | "CC-BY-SA-4.0"
            | "CC0-1.0"
            | "Unlicense"
    )
}

pub(crate) fn validate_relative_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4_096
        || value.contains('\\')
        || value.contains('\0')
        || Path::new(value).is_absolute()
        || Path::new(value).components().any(|component| {
            matches!(
                component,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::ParentDir
                    | Component::CurDir
            )
        })
    {
        return Err(BrokerError::InvalidManifest(format!(
            "manifest file path must be a normalized relative path: {value:?}"
        )));
    }
    Ok(())
}

fn require_sha256(field: &str, value: &str) -> Result<()> {
    if !is_sha256(value) {
        return Err(BrokerError::InvalidManifest(format!(
            "{field} must be exactly 64 hexadecimal digits"
        )));
    }
    Ok(())
}

fn validate_utc_timestamp(field: &str, value: &str) -> Result<()> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| {
        BrokerError::InvalidManifest(format!("{field} must be an RFC 3339 timestamp"))
    })?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(BrokerError::InvalidManifest(format!(
            "{field} must use a UTC offset"
        )));
    }
    Ok(())
}

fn nonempty_bounded(field: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(BrokerError::InvalidManifest(format!(
            "{field} must contain 1..={maximum} bytes"
        )));
    }
    Ok(())
}
