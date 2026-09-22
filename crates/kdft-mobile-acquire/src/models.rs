use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Quick,
    Logical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub platform: Platform,
    pub identifier: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub build: Option<String>,
    pub serial_number: Option<String>,
    pub pairing_or_adb_authorized: Option<bool>,
    pub ce_unlocked_since_boot: Option<bool>,
    pub root_or_jailbreak_detected: Option<bool>,
    pub bootloader_locked: Option<bool>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionSummary {
    pub tool: String,
    pub version: String,
    pub case_id: String,
    pub evidence_id: String,
    pub examiner: String,
    pub platform: Platform,
    pub profile: Profile,
    pub device_identifier: String,
    pub started_utc: String,
    pub ended_utc: String,
    pub status: String,
    pub output_directory: String,
    pub files_hashed: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ActionRecord<'a> {
    pub timestamp_utc: String,
    pub action: &'a str,
    pub command: Option<String>,
    pub status: &'a str,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorRecord<'a> {
    pub timestamp_utc: String,
    pub stage: &'a str,
    pub error: String,
}
