use crate::manifest::{AdapterId, InstalledModelManifest, ManifestFileRole, ModelSource};
use crate::{is_sha256, BrokerError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

pub const MAX_CONFIG_BYTES: u64 = 64 * 1_024;
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1_024 * 1_024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalModelVerificationConfig {
    pub manifest_path: PathBuf,
    pub expected_manifest_sha256: String,
    pub model_directory: PathBuf,
    pub runtime: RuntimeVerificationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVerificationConfig {
    pub executable_path: PathBuf,
    pub expected_sha256: String,
    pub adapter_id: AdapterId,
    pub declared_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFile {
    pub relative_path: String,
    pub role: ManifestFileRole,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedLocalModel {
    pub schema_version: String,
    pub offline_only: bool,
    pub network_access_performed: bool,
    pub runtime_started: bool,
    pub manifest_id: String,
    pub manifest_sha256: String,
    pub model_id: String,
    pub model_weight_sha256: Vec<String>,
    pub verified_files: Vec<VerifiedFile>,
    pub verified_bytes: u64,
    pub license_identifier: String,
    pub runtime_adapter: AdapterId,
    pub declared_runtime_version: String,
    pub runtime_executable_sha256: String,
    pub limitations: Vec<String>,
}

/// Load and verify an examiner-selected local configuration. Relative paths in
/// the configuration are resolved against the configuration file's directory.
/// No file is downloaded, executed, modified, or copied.
pub fn verify_config_file(config_path: impl AsRef<Path>) -> Result<PreparedLocalModel> {
    let config_path = config_path.as_ref();
    let bytes = read_bounded(config_path, MAX_CONFIG_BYTES, "reading local-AI config")?;
    let mut config: LocalModelVerificationConfig =
        serde_json::from_slice(&bytes).map_err(|source| BrokerError::Json {
            operation: "parsing local-AI config",
            source,
        })?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    config.manifest_path = resolve_from(base, &config.manifest_path);
    config.model_directory = resolve_from(base, &config.model_directory);
    config.runtime.executable_path = resolve_from(base, &config.runtime.executable_path);
    prepare_local_model(&config)
}

/// Verify a pinned manifest, every declared local model file, the accepted
/// license text, and the local runtime executable. This function has no network
/// client and never launches the runtime.
pub fn prepare_local_model(config: &LocalModelVerificationConfig) -> Result<PreparedLocalModel> {
    validate_config(config)?;
    let manifest_bytes = read_bounded(
        &config.manifest_path,
        MAX_MANIFEST_BYTES,
        "reading installed-model manifest",
    )?;
    let manifest_digest = sha256_bytes(&manifest_bytes);
    require_digest_match(
        "manifest",
        &config.expected_manifest_sha256,
        &manifest_digest,
    )?;
    let manifest: InstalledModelManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| BrokerError::Json {
            operation: "parsing installed-model manifest",
            source,
        })?;
    manifest.validate()?;

    if !manifest
        .compatible_adapters
        .iter()
        .any(|adapter| adapter.adapter_id == config.runtime.adapter_id)
    {
        return Err(BrokerError::Verification(format!(
            "manifest does not declare compatibility with {:?}",
            config.runtime.adapter_id
        )));
    }
    if config.runtime.adapter_id == AdapterId::OllamaDeveloper {
        return Err(BrokerError::InvalidConfig(
            "ollama_developer is not accepted by the offline production verifier".to_string(),
        ));
    }

    let model_root = canonical_regular_directory(&config.model_directory)?;
    let mut verified_files = Vec::with_capacity(manifest.files.len());
    let mut verified_bytes = 0_u64;
    let mut model_weight_sha256 = Vec::new();
    for declared in &manifest.files {
        let canonical = resolve_verified_model_file(&model_root, &declared.relative_path)?;
        let metadata = fs::metadata(&canonical).map_err(|source| BrokerError::Io {
            operation: "reading model-file metadata",
            source,
        })?;
        if !metadata.is_file() {
            return Err(BrokerError::Verification(format!(
                "declared model path is not a regular file: {:?}",
                declared.relative_path
            )));
        }
        if metadata.len() != declared.size_bytes {
            return Err(BrokerError::Verification(format!(
                "size mismatch for {:?}: manifest={}, actual={}",
                declared.relative_path,
                declared.size_bytes,
                metadata.len()
            )));
        }
        let actual_digest = sha256_file(&canonical)?;
        require_digest_match(&declared.relative_path, &declared.sha256, &actual_digest)?;
        verified_bytes = verified_bytes.checked_add(metadata.len()).ok_or_else(|| {
            BrokerError::Verification("verified byte count overflowed".to_string())
        })?;
        if declared.role == ManifestFileRole::ModelWeights {
            model_weight_sha256.push(actual_digest.clone());
        }
        verified_files.push(VerifiedFile {
            relative_path: declared.relative_path.clone(),
            role: declared.role,
            size_bytes: metadata.len(),
            sha256: actual_digest,
        });
    }

    if let ModelSource::LocalImport {
        imported_file_sha256,
        ..
    } = &manifest.source
    {
        if !model_weight_sha256
            .iter()
            .any(|hash| hash.eq_ignore_ascii_case(imported_file_sha256))
        {
            return Err(BrokerError::Verification(
                "local-import digest does not match any verified model_weights file".to_string(),
            ));
        }
    }

    let runtime_path = &config.runtime.executable_path;
    reject_symlink(runtime_path, "runtime executable")?;
    let runtime_metadata = fs::metadata(runtime_path).map_err(|source| BrokerError::Io {
        operation: "reading runtime-executable metadata",
        source,
    })?;
    if !runtime_metadata.is_file() {
        return Err(BrokerError::Verification(
            "runtime executable is not a regular file".to_string(),
        ));
    }
    verify_platform_executable(runtime_path, &runtime_metadata)?;
    let runtime_digest = sha256_file(runtime_path)?;
    require_digest_match(
        "runtime executable",
        &config.runtime.expected_sha256,
        &runtime_digest,
    )?;

    Ok(PreparedLocalModel {
        schema_version: "1.0.0".to_string(),
        offline_only: true,
        network_access_performed: false,
        runtime_started: false,
        manifest_id: manifest.manifest_id,
        manifest_sha256: manifest_digest,
        model_id: manifest.model.model_id,
        model_weight_sha256,
        verified_files,
        verified_bytes,
        license_identifier: manifest.license.declared_identifier,
        runtime_adapter: config.runtime.adapter_id,
        declared_runtime_version: config.runtime.declared_version.clone(),
        runtime_executable_sha256: runtime_digest,
        limitations: vec![
            "Files and declared metadata were verified, but the runtime was not launched or version-probed."
                .to_string(),
            "Architecture, quantization, chat template, and context metadata were not independently parsed from the model weights by this verifier."
                .to_string(),
            "The accepted license text was hash-verified, but legal compatibility with the examiner's intended use is not determined by this verifier."
                .to_string(),
            "Model quality, memory requirements, schema compliance, and forensic grounding are not established by file verification."
                .to_string(),
        ],
    })
}

fn validate_config(config: &LocalModelVerificationConfig) -> Result<()> {
    if !is_sha256(&config.expected_manifest_sha256) {
        return Err(BrokerError::InvalidConfig(
            "expected_manifest_sha256 must be exactly 64 hexadecimal digits".to_string(),
        ));
    }
    if !is_sha256(&config.runtime.expected_sha256) {
        return Err(BrokerError::InvalidConfig(
            "runtime expected_sha256 must be exactly 64 hexadecimal digits".to_string(),
        ));
    }
    if config.runtime.declared_version.is_empty() || config.runtime.declared_version.len() > 256 {
        return Err(BrokerError::InvalidConfig(
            "runtime declared_version must contain 1..=256 bytes".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn canonical_regular_directory(path: &Path) -> Result<PathBuf> {
    reject_symlink(path, "model directory")?;
    let metadata = fs::metadata(path).map_err(|source| BrokerError::Io {
        operation: "reading model-directory metadata",
        source,
    })?;
    if !metadata.is_dir() {
        return Err(BrokerError::Verification(
            "model_directory is not a directory".to_string(),
        ));
    }
    match path.canonicalize() {
        Ok(canonical) => {
            if !canonical.is_dir() {
                return Err(BrokerError::Verification(
                    "model_directory is not a directory".to_string(),
                ));
            }
            Ok(canonical)
        }
        Err(source) if cfg!(windows) && source.kind() == std::io::ErrorKind::PermissionDenied => {
            if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                let cwd = std::env::current_dir().map_err(|cwd_err| BrokerError::Io {
                    operation: "canonicalizing model directory",
                    source: cwd_err,
                })?;
                Ok(cwd.join(path))
            }
        }
        Err(source) => Err(BrokerError::Io {
            operation: "canonicalizing model directory",
            source,
        }),
    }
}

pub(crate) fn resolve_verified_model_file(
    model_root: &Path,
    relative_path: &str,
) -> Result<PathBuf> {
    crate::manifest::validate_relative_path(relative_path)?;
    let mut cursor = model_root.to_path_buf();
    for component in Path::new(relative_path).components() {
        let std::path::Component::Normal(segment) = component else {
            return Err(BrokerError::Verification(format!(
                "model file escapes the managed directory: {relative_path:?}"
            )));
        };
        cursor.push(segment);
        reject_symlink(&cursor, "model file")?;
    }
    match cursor.canonicalize() {
        Ok(canonical) => {
            if !canonical.starts_with(model_root) {
                return Err(BrokerError::Verification(format!(
                    "model file escapes the managed directory: {relative_path:?}"
                )));
            }
            Ok(canonical)
        }
        Err(source) if cfg!(windows) && source.kind() == std::io::ErrorKind::PermissionDenied => {
            if !cursor.starts_with(model_root) {
                return Err(BrokerError::Verification(format!(
                    "model file escapes the managed directory: {relative_path:?}"
                )));
            }
            Ok(cursor)
        }
        Err(source) => Err(BrokerError::Io {
            operation: "canonicalizing model file",
            source,
        }),
    }
}

pub(crate) fn reject_symlink(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BrokerError::Io {
        operation: "reading local-file metadata",
        source,
    })?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(BrokerError::Verification(format!(
            "{label} must not be a symbolic link"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn verify_platform_executable(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(BrokerError::Verification(format!(
            "runtime file is not executable: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_platform_executable(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, maximum: u64, operation: &'static str) -> Result<Vec<u8>> {
    reject_symlink(path, "configuration file")?;
    let metadata = fs::metadata(path).map_err(|source| BrokerError::Io { operation, source })?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(BrokerError::Verification(format!(
            "{} must be a regular file no larger than {} bytes",
            path.display(),
            maximum
        )));
    }
    fs::read(path).map_err(|source| BrokerError::Io { operation, source })
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|source| BrokerError::Io {
        operation: "opening local file for SHA-256 verification",
        source,
    })?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_BYTES, file);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(|source| BrokerError::Io {
            operation: "streaming local file for SHA-256 verification",
            source,
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn require_digest_match(label: &str, expected: &str, actual: &str) -> Result<()> {
    if !expected.eq_ignore_ascii_case(actual) {
        return Err(BrokerError::Verification(format!(
            "SHA-256 mismatch for {label}: expected {}, actual {}",
            expected.to_ascii_lowercase(),
            actual.to_ascii_lowercase()
        )));
    }
    Ok(())
}

pub(crate) fn resolve_from(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
pub(crate) fn digest_for_test(bytes: &[u8]) -> String {
    sha256_bytes(bytes)
}
