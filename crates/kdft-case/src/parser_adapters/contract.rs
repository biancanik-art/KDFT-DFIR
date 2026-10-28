use crate::semantic_artifacts::{
    ArtifactSourceCoordinate, NewSemanticArtifact, SourceCoordinateSystem,
};
use anyhow::{bail, Result};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

/// Immutable identity of the executable accepted by an examiner.
///
/// A source commit or marketing version is not an executable identity. The
/// SHA-256 here is always the hash of the exact local program file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

impl ExecutableIdentity {
    pub fn validate(&self) -> Result<()> {
        if !self.path.is_absolute() {
            bail!("locked executable path must be absolute");
        }
        if self.size_bytes == 0 {
            bail!("locked executable size must be greater than zero");
        }
        validate_sha256("locked executable SHA-256", &self.sha256)
    }
}

/// Examiner-accepted lock for one adapter/tool combination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolLock {
    pub adapter_id: String,
    pub parser_name: String,
    pub parser_version: String,
    pub source_repository: String,
    pub source_commit: String,
    pub executable: ExecutableIdentity,
    /// Logical companion name -> exact SHA-256. Maps, batch files, templates,
    /// and result-affecting DLLs belong here.
    #[serde(default)]
    pub companion_sha256: BTreeMap<String, String>,
    /// Exact command switches the adapter may emit. Values are separate argv
    /// elements and are never interpreted by a shell.
    #[serde(default)]
    pub allowed_switches: BTreeSet<String>,
    /// Network access is opt-in in the serialized schema, but KDFT evidence
    /// processing currently enforces the offline policy and rejects `true`.
    #[serde(default)]
    pub network_allowed: bool,
}

impl ToolLock {
    pub fn validate(&self) -> Result<()> {
        validate_stable_id("adapter id", &self.adapter_id)?;
        validate_nonempty("parser name", &self.parser_name)?;
        validate_nonempty("parser version", &self.parser_version)?;
        validate_nonempty("source repository", &self.source_repository)?;
        validate_nonempty("source commit", &self.source_commit)?;
        self.executable.validate()?;
        if self.network_allowed {
            bail!("external forensic parser locks must declare network_allowed=false");
        }
        for (name, sha256) in &self.companion_sha256 {
            validate_nonempty("companion logical name", name)?;
            validate_sha256(&format!("companion {name} SHA-256"), sha256)?;
        }
        for switch in &self.allowed_switches {
            validate_switch(switch)?;
        }
        Ok(())
    }

    /// Confirms the program observed at run time is the exact examiner-locked
    /// identity. The caller computes the hash and size; this function performs
    /// no I/O and cannot launch the program.
    pub fn verify_observed_executable(
        &self,
        observed_path: &Path,
        observed_sha256: &str,
        observed_size_bytes: u64,
    ) -> Result<()> {
        self.validate()?;
        if observed_path != self.executable.path {
            bail!("observed executable path does not match the accepted tool lock");
        }
        validate_sha256("observed executable SHA-256", observed_sha256)?;
        if !constant_time_ascii_eq(
            observed_sha256.as_bytes(),
            self.executable.sha256.as_bytes(),
        ) {
            bail!("observed executable SHA-256 does not match the accepted tool lock");
        }
        if observed_size_bytes != self.executable.size_bytes {
            bail!("observed executable size does not match the accepted tool lock");
        }
        Ok(())
    }

    pub fn validate_command(&self, command: &LockedCommand) -> Result<()> {
        self.validate()?;
        command.validate()?;
        if command.program != self.executable.path {
            bail!("command program does not match the accepted executable path");
        }
        for (index, argument) in command.argv.iter().enumerate() {
            if let Some(switch) = command_switch(argument) {
                if !self.allowed_switches.contains(switch) {
                    bail!("command argv[{index}] uses a switch not allowed by the tool lock");
                }
            }
        }
        Ok(())
    }
}

/// A program path plus discrete arguments. There is deliberately no shell
/// command string, shell executable, or arbitrary environment map in this
/// type. A runner must pass `program` and `argv` directly to the OS process API.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedCommand {
    pub program: PathBuf,
    #[serde(default)]
    pub argv: Vec<String>,
    pub working_directory: PathBuf,
}

impl Debug for LockedCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedCommand")
            .field("program", &self.program)
            .field("argv_count", &self.argv.len())
            .field("working_directory", &self.working_directory)
            .finish()
    }
}

impl LockedCommand {
    pub fn validate(&self) -> Result<()> {
        if !self.program.is_absolute() {
            bail!("command program path must be absolute");
        }
        if !self.working_directory.is_absolute() {
            bail!("command working directory must be absolute");
        }
        for (index, argument) in self.argv.iter().enumerate() {
            if argument.is_empty() {
                bail!("command argv[{index}] cannot be empty");
            }
            if argument.contains('\0') {
                bail!("command argv[{index}] contains a NUL character");
            }
            validate_secret_safe_text(argument, &format!("command.argv[{index}]"))?;
        }
        Ok(())
    }
}

/// JSON configuration that has passed KDFT's persistence safety checks.
///
/// The value is intentionally redacted from `Debug`. Construction and
/// deserialization both reject secret-bearing field names and high-confidence
/// secret value patterns, so this type can safely be embedded in a manifest.
#[derive(Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecretSafeConfiguration(JsonValue);

impl SecretSafeConfiguration {
    pub fn new(value: JsonValue) -> Result<Self> {
        if !value.is_object() {
            bail!("adapter configuration must be a JSON object");
        }
        validate_secret_safe_json(&value, "configuration")?;
        Ok(Self(value))
    }

    pub fn empty() -> Self {
        Self(JsonValue::Object(Default::default()))
    }

    pub fn as_json(&self) -> &JsonValue {
        &self.0
    }

    pub fn into_json(self) -> JsonValue {
        self.0
    }
}

impl Default for SecretSafeConfiguration {
    fn default() -> Self {
        Self::empty()
    }
}

impl Debug for SecretSafeConfiguration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSafeConfiguration")
            .field("validated", &true)
            .field(
                "top_level_fields",
                &self.0.as_object().map_or(0, serde_json::Map::len),
            )
            .finish()
    }
}

impl<'de> Deserialize<'de> for SecretSafeConfiguration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = JsonValue::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterDescriptor {
    pub adapter_id: String,
    pub adapter_schema_version: String,
    pub parser_name: String,
    pub importer_schema: String,
    #[serde(default)]
    pub supported_source_kinds: BTreeSet<String>,
    #[serde(default)]
    pub supported_artifact_kinds: BTreeSet<String>,
}

impl AdapterDescriptor {
    pub fn validate(&self) -> Result<()> {
        validate_stable_id("adapter id", &self.adapter_id)?;
        validate_nonempty("adapter schema version", &self.adapter_schema_version)?;
        validate_nonempty("parser name", &self.parser_name)?;
        validate_nonempty("importer schema", &self.importer_schema)?;
        if self.supported_source_kinds.is_empty() {
            bail!("adapter must declare at least one supported source kind");
        }
        if self.supported_artifact_kinds.is_empty() {
            bail!("adapter must declare at least one supported artifact kind");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSourceObject {
    pub evidence_id: i64,
    pub source_entry_id: Option<i64>,
    pub canonical_path: String,
    pub source_kind: String,
    pub size_bytes: u64,
    pub sha256: String,
}

impl AdapterSourceObject {
    pub fn validate(&self) -> Result<()> {
        if self.evidence_id <= 0 {
            bail!("adapter source evidence id must be positive");
        }
        if self.source_entry_id.is_some_and(|id| id <= 0) {
            bail!("adapter source entry id must be positive when present");
        }
        validate_nonempty("adapter source canonical path", &self.canonical_path)?;
        validate_stable_id("adapter source kind", &self.source_kind)?;
        validate_sha256("adapter source SHA-256", &self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub supported: bool,
    pub detected_source_kind: Option<String>,
    pub confidence_basis: String,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedInput {
    pub logical_name: String,
    pub staged_path: PathBuf,
    pub source_sha256: String,
    pub staged_sha256: String,
    pub size_bytes: u64,
}

impl StagedInput {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty("staged input logical name", &self.logical_name)?;
        if !self.staged_path.is_absolute() {
            bail!("staged input path must be absolute");
        }
        validate_sha256("staged input source SHA-256", &self.source_sha256)?;
        validate_sha256("staged input copy SHA-256", &self.staged_sha256)?;
        if !constant_time_ascii_eq(self.source_sha256.as_bytes(), self.staged_sha256.as_bytes()) {
            bail!("staged input hash does not match its source hash");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedInputs {
    pub private_directory: PathBuf,
    pub primary: StagedInput,
    #[serde(default)]
    pub companions: Vec<StagedInput>,
}

impl StagedInputs {
    pub fn validate(&self) -> Result<()> {
        if !self.private_directory.is_absolute() {
            bail!("private staging directory must be absolute");
        }
        self.primary.validate()?;
        for companion in &self.companions {
            companion.validate()?;
        }
        Ok(())
    }
}

/// The precise address space used by an upstream parser. These names are
/// intentionally more specific than a generic `offset` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedCoordinateSystem {
    EvidencePhysicalBytes,
    StandaloneMftSourceStream,
    NtfsVolumeLogicalBytes,
    DecryptedPartitionLogicalBytes,
    FilesystemFileBytes,
    RegistryHiveFileBytes,
    EvtxFileBytes,
    EvtxEventRecordIdentifier,
    LnkFileBytes,
    SqliteDatabaseBytes,
    SqliteRowIdentifier,
}

impl NamedCoordinateSystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvidencePhysicalBytes => "evidence_physical_bytes",
            Self::StandaloneMftSourceStream => "standalone_mft_source_stream",
            Self::NtfsVolumeLogicalBytes => "ntfs_volume_logical_bytes",
            Self::DecryptedPartitionLogicalBytes => "decrypted_partition_logical_bytes",
            Self::FilesystemFileBytes => "filesystem_file_bytes",
            Self::RegistryHiveFileBytes => "registry_hive_file_bytes",
            Self::EvtxFileBytes => "evtx_file_bytes",
            Self::EvtxEventRecordIdentifier => "evtx_event_record_identifier",
            Self::LnkFileBytes => "lnk_file_bytes",
            Self::SqliteDatabaseBytes => "sqlite_database_bytes",
            Self::SqliteRowIdentifier => "sqlite_row_identifier",
        }
    }

    const fn semantic_store_system(self) -> SourceCoordinateSystem {
        match self {
            Self::EvidencePhysicalBytes => SourceCoordinateSystem::PhysicalMediaBytes,
            Self::StandaloneMftSourceStream | Self::FilesystemFileBytes | Self::LnkFileBytes => {
                SourceCoordinateSystem::FilesystemFileBytes
            }
            Self::NtfsVolumeLogicalBytes => SourceCoordinateSystem::PartitionLogicalBytes,
            Self::DecryptedPartitionLogicalBytes => {
                SourceCoordinateSystem::DecryptedBitlockerVolumeLogicalBytes
            }
            Self::RegistryHiveFileBytes => SourceCoordinateSystem::RegistryHiveBytes,
            Self::EvtxFileBytes | Self::EvtxEventRecordIdentifier => {
                SourceCoordinateSystem::EvtxFileBytes
            }
            Self::SqliteDatabaseBytes => SourceCoordinateSystem::SqliteDatabaseBytes,
            Self::SqliteRowIdentifier => SourceCoordinateSystem::SqliteRow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinateQuality {
    Exact,
    Derived,
    IdentifierOnly,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterSourceCoordinate {
    pub role: String,
    pub source_entry_id: Option<i64>,
    pub source_path: Option<String>,
    pub source_sha256: Option<String>,
    pub coordinate_system: NamedCoordinateSystem,
    pub partition_index: Option<i64>,
    pub volume_index: Option<i64>,
    /// Context only. For a decrypted BitLocker coordinate, this encrypted
    /// partition start must never be added to the plaintext logical offset.
    pub partition_start_offset_bytes: Option<i64>,
    pub offset_bytes: Option<i64>,
    pub length_bytes: Option<i64>,
    pub record_identifier: Option<String>,
    pub extent_index: Option<u32>,
    pub derivation: String,
    pub quality: CoordinateQuality,
    pub verified: bool,
    pub unavailable_reason: Option<String>,
}

impl AdapterSourceCoordinate {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty("coordinate role", &self.role)?;
        validate_nonempty("coordinate derivation", &self.derivation)?;
        if self.source_entry_id.is_some_and(|id| id <= 0) {
            bail!("coordinate source entry id must be positive when present");
        }
        for (label, value) in [
            ("partition index", self.partition_index),
            ("volume index", self.volume_index),
            ("partition start", self.partition_start_offset_bytes),
            ("offset", self.offset_bytes),
            ("length", self.length_bytes),
        ] {
            if value.is_some_and(|value| value < 0) {
                bail!("coordinate {label} cannot be negative");
            }
        }
        if self.offset_bytes.is_some() != self.length_bytes.is_some() {
            bail!("coordinate byte offset and length must be supplied together");
        }
        if let Some(sha256) = &self.source_sha256 {
            validate_sha256("coordinate source SHA-256", sha256)?;
        }
        match self.quality {
            CoordinateQuality::Exact | CoordinateQuality::Derived => {
                if self.offset_bytes.is_none() && self.record_identifier.is_none() {
                    bail!("exact or derived coordinate requires bytes or a record identifier");
                }
                if self.unavailable_reason.is_some() {
                    bail!("available coordinate cannot include an unavailable reason");
                }
            }
            CoordinateQuality::IdentifierOnly => {
                if self.record_identifier.as_deref().is_none_or(str::is_empty) {
                    bail!("identifier-only coordinate requires a record identifier");
                }
                if self.offset_bytes.is_some() {
                    bail!("identifier-only coordinate cannot claim a byte offset");
                }
            }
            CoordinateQuality::Unavailable => {
                if self.unavailable_reason.as_deref().is_none_or(str::is_empty) {
                    bail!("unavailable coordinate requires an unavailable reason");
                }
                if self.offset_bytes.is_some() || self.record_identifier.is_some() || self.verified
                {
                    bail!(
                        "unavailable coordinate cannot claim bytes, an identifier, or verification"
                    );
                }
            }
        }
        if self.coordinate_system == NamedCoordinateSystem::EvtxEventRecordIdentifier
            && (self.quality != CoordinateQuality::IdentifierOnly || self.offset_bytes.is_some())
        {
            bail!("EVTX event record IDs are identifiers, not byte offsets");
        }
        Ok(())
    }

    /// Converts an adapter coordinate into the normalized semantic store while
    /// retaining the adapter's more specific coordinate name and quality in
    /// provenance JSON.
    pub fn to_semantic_coordinate(&self) -> Result<ArtifactSourceCoordinate> {
        self.validate()?;
        Ok(ArtifactSourceCoordinate {
            role: self.role.clone(),
            source_entry_id: self.source_entry_id,
            coordinate_system: self.coordinate_system.semantic_store_system(),
            source_path: self.source_path.clone(),
            partition_index: self.partition_index,
            volume_index: self.volume_index,
            partition_start_offset_bytes: self.partition_start_offset_bytes,
            offset_bytes: self.offset_bytes,
            length_bytes: self.length_bytes,
            record_identifier: self.record_identifier.clone(),
            source_sha256: self.source_sha256.clone(),
            provenance_json: json!({
                "adapter_coordinate_system": self.coordinate_system.as_str(),
                "coordinate_quality": self.quality,
                "derivation": self.derivation,
                "extent_index": self.extent_index,
                "verified": self.verified,
                "unavailable_reason": self.unavailable_reason,
            }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportSummary {
    pub emitted_rows: u64,
    pub imported_rows: u64,
    pub rejected_rows: u64,
    pub duplicate_rows: u64,
    pub linked_rows: u64,
}

impl ImportSummary {
    pub fn validate(&self) -> Result<()> {
        let accounted = self
            .imported_rows
            .saturating_add(self.rejected_rows)
            .saturating_add(self.duplicate_rows);
        if accounted > self.emitted_rows {
            bail!("imported + rejected + duplicate rows exceed emitted rows");
        }
        if self.linked_rows > self.imported_rows {
            bail!("linked rows cannot exceed imported rows");
        }
        Ok(())
    }
}

/// Store-facing sink used by streaming tool-specific importers.
pub trait SemanticArtifactSink {
    fn emit(&mut self, artifact: NewSemanticArtifact) -> Result<()>;
}

/// Tool-specific adapter behavior. The trait separates detection, staging,
/// argv construction, and streaming import from the future common runner.
pub trait ParserAdapter: Send + Sync {
    fn descriptor(&self) -> &AdapterDescriptor;
    fn detect(&self, source: &AdapterSourceObject) -> Result<Detection>;
    fn stage(&self, source: &AdapterSourceObject, private_directory: &Path)
        -> Result<StagedInputs>;
    fn command(
        &self,
        lock: &ToolLock,
        staged: &StagedInputs,
        output_directory: &Path,
        configuration: &SecretSafeConfiguration,
    ) -> Result<LockedCommand>;
    fn import(
        &self,
        manifest: &super::ParserRunManifest,
        sink: &mut dyn SemanticArtifactSink,
    ) -> Result<ImportSummary>;
}

pub(crate) fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("{label} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

pub(crate) fn validate_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} cannot be empty");
    }
    Ok(())
}

pub(crate) fn validate_secret_safe_text(value: &str, path: &str) -> Result<()> {
    let trimmed = value.trim();
    let lowered = trimmed.to_ascii_lowercase();
    if looks_like_bitlocker_recovery_key(trimmed)
        || lowered.starts_with("bearer ")
        || lowered.contains("-----begin private key-----")
        || lowered.contains("-----begin rsa private key-----")
        || lowered.contains("-----begin openssh private key-----")
    {
        bail!("{path} contains prohibited secret material");
    }
    Ok(())
}

fn validate_secret_safe_json(value: &JsonValue, path: &str) -> Result<()> {
    match value {
        JsonValue::Object(fields) => {
            for (key, child) in fields {
                if sensitive_field_name(key) {
                    bail!("{path}.{key} is a prohibited sensitive configuration field");
                }
                validate_secret_safe_json(child, &format!("{path}.{key}"))?;
            }
        }
        JsonValue::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_secret_safe_json(child, &format!("{path}[{index}]"))?;
            }
        }
        JsonValue::String(value) => validate_secret_safe_text(value, path)?,
        _ => {}
    }
    Ok(())
}

fn validate_stable_id(label: &str, value: &str) -> Result<()> {
    validate_nonempty(label, value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
    }) {
        bail!("{label} must contain only lowercase ASCII letters, digits, '.', '-', or '_'");
    }
    Ok(())
}

fn validate_switch(value: &str) -> Result<()> {
    if value.len() < 2
        || !value.starts_with('-')
        || value.contains('=')
        || value.chars().any(char::is_whitespace)
    {
        bail!("allowed command switches must be discrete argv switches without values");
    }
    validate_secret_safe_text(value, "allowed switch")
}

fn command_switch(argument: &str) -> Option<&str> {
    if argument.len() < 2 || !argument.starts_with('-') {
        return None;
    }
    Some(
        argument
            .split_once('=')
            .map_or(argument, |(switch, _)| switch),
    )
}

fn sensitive_field_name(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "authorization"
            | "credential"
            | "credentials"
            | "secret"
            | "secretvalue"
            | "clientsecret"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "sessiontoken"
            | "apikey"
            | "privatekey"
            | "recoverykey"
            | "recoverypassword"
            | "bitlockerkey"
            | "bitlockerrecoverykey"
    ) || normalized.ends_with("password")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("clientsecret")
        || normalized.ends_with("privatekey")
}

fn looks_like_bitlocker_recovery_key(value: &str) -> bool {
    let groups = value.split('-').collect::<Vec<_>>();
    groups.len() == 8
        && groups
            .iter()
            .all(|group| group.len() == 6 && group.bytes().all(|byte| byte.is_ascii_digit()))
}

fn constant_time_ascii_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture_path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join("kdft-parser-adapter-contract-tests")
            .join(name)
    }

    fn lock() -> ToolLock {
        ToolLock {
            adapter_id: "mftecmd-json-v1".to_string(),
            parser_name: "MFTECmd".to_string(),
            parser_version: "2026.5.0".to_string(),
            source_repository: "https://github.com/EricZimmerman/MFTECmd".to_string(),
            source_commit: "6aadd87ae0526efca95dd5a59e62e186806cd4c8".to_string(),
            executable: ExecutableIdentity {
                path: fixture_path("MFTECmd.exe"),
                sha256: SHA_A.to_string(),
                size_bytes: 42,
            },
            companion_sha256: BTreeMap::new(),
            allowed_switches: ["-f", "--json", "--jsonf"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            network_allowed: false,
        }
    }

    #[test]
    fn network_policy_defaults_to_false() {
        let mut value = serde_json::to_value(lock()).unwrap();
        value.as_object_mut().unwrap().remove("network_allowed");
        let decoded: ToolLock = serde_json::from_value(value).unwrap();
        assert!(!decoded.network_allowed);
        decoded.validate().unwrap();
    }

    #[test]
    fn locked_command_uses_discrete_argv_and_rejects_unknown_switches() {
        let lock = lock();
        let mut command = LockedCommand {
            program: lock.executable.path.clone(),
            argv: vec![
                "-f".to_string(),
                fixture_path("staged-$MFT").to_string_lossy().into_owned(),
                "--json".to_string(),
                fixture_path("output & literal")
                    .to_string_lossy()
                    .into_owned(),
            ],
            working_directory: fixture_path("run"),
        };
        lock.validate_command(&command).unwrap();
        command.argv.push("--sync".to_string());
        assert!(lock.validate_command(&command).is_err());
    }

    #[test]
    fn observed_executable_must_match_the_locked_hash_and_size() {
        let lock = lock();
        lock.verify_observed_executable(&lock.executable.path, SHA_A, 42)
            .unwrap();
        assert!(lock
            .verify_observed_executable(
                &lock.executable.path,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                42,
            )
            .is_err());
    }

    #[test]
    fn secret_safe_configuration_rejects_secret_fields_and_values_without_echoing_them() {
        let error = SecretSafeConfiguration::new(json!({
            "nested": {"password": "do-not-echo"}
        }))
        .unwrap_err()
        .to_string();
        assert!(!error.contains("do-not-echo"));

        let sensitive = "111111-222222-333333-444444-555555-666666-777777-888888";
        let error = SecretSafeConfiguration::new(json!({"note": sensitive}))
            .unwrap_err()
            .to_string();
        assert!(!error.contains(sensitive));
    }

    #[test]
    fn decrypted_coordinate_keeps_plaintext_and_physical_spaces_separate() {
        let coordinate = AdapterSourceCoordinate {
            role: "primary".to_string(),
            source_entry_id: Some(7),
            source_path: Some("/Windows/System32/config/SYSTEM".to_string()),
            source_sha256: Some(SHA_A.to_string()),
            coordinate_system: NamedCoordinateSystem::DecryptedPartitionLogicalBytes,
            partition_index: Some(3),
            volume_index: Some(2),
            partition_start_offset_bytes: Some(1_048_576),
            offset_bytes: Some(4096),
            length_bytes: Some(512),
            record_identifier: Some("mft:42-3".to_string()),
            extent_index: Some(0),
            derivation: "BitLocker plaintext reader".to_string(),
            quality: CoordinateQuality::Exact,
            verified: true,
            unavailable_reason: None,
        };
        let stored = coordinate.to_semantic_coordinate().unwrap();
        assert_eq!(
            stored.coordinate_system,
            SourceCoordinateSystem::DecryptedBitlockerVolumeLogicalBytes
        );
        assert_eq!(stored.offset_bytes, Some(4096));
        assert_eq!(stored.partition_start_offset_bytes, Some(1_048_576));
        assert_eq!(
            stored.provenance_json["adapter_coordinate_system"],
            "decrypted_partition_logical_bytes"
        );
    }

    #[test]
    fn evtx_record_id_cannot_be_claimed_as_a_byte_offset() {
        let coordinate = AdapterSourceCoordinate {
            role: "primary".to_string(),
            source_entry_id: Some(8),
            source_path: Some("Security.evtx".to_string()),
            source_sha256: Some(SHA_A.to_string()),
            coordinate_system: NamedCoordinateSystem::EvtxEventRecordIdentifier,
            partition_index: None,
            volume_index: None,
            partition_start_offset_bytes: None,
            offset_bytes: Some(4624),
            length_bytes: Some(1),
            record_identifier: Some("4624".to_string()),
            extent_index: None,
            derivation: "EvtxECmd EventRecordId".to_string(),
            quality: CoordinateQuality::IdentifierOnly,
            verified: true,
            unavailable_reason: None,
        };
        assert!(coordinate.validate().is_err());
    }

    #[test]
    fn locked_command_debug_does_not_disclose_arguments() {
        let command = LockedCommand {
            program: PathBuf::from("C:\\Tools\\tool.exe"),
            argv: vec!["confidential-value".to_string()],
            working_directory: PathBuf::from("C:\\run"),
        };
        assert!(!format!("{command:?}").contains("confidential-value"));
    }
}
