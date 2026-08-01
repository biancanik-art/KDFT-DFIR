#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Read, Seek, SeekFrom};

use bitlocker::{BdeError, BitLockerVolume, DecryptedVolume, FveMetadata, VolumeHeader};
use zeroize::Zeroizing;

pub const BITLOCKER_SECTOR_SIZE: u64 = 512;

const SIG_FVE: &[u8; 8] = b"-FVE-FS-";
const SIG_TO_GO: &[u8; 8] = b"MSWIN4.1";

const PROTECTOR_CLEAR_KEY: u16 = 0x0000;
const PROTECTOR_TPM: u16 = 0x0100;
const PROTECTOR_STARTUP_KEY: u16 = 0x0200;
const PROTECTOR_TPM_AND_PIN: u16 = 0x0500;
const PROTECTOR_RECOVERY_PASSWORD: u16 = 0x0800;
const PROTECTOR_PASSWORD: u16 = 0x2000;

pub type Result<T> = std::result::Result<T, BitLockerDecryptError>;

#[derive(Debug, thiserror::Error)]
pub enum BitLockerDecryptError {
    #[error("i/o error reading BitLocker volume: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Bde(#[from] BdeError),
    #[error("invalid BitLocker recovery key: {0}")]
    InvalidRecoveryKey(RecoveryKeyFormatError),
    #[error("invalid BitLocker metadata geometry: {0}")]
    InvalidMetadataGeometry(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryKeyFormatError {
    #[error("recovery key must be exactly 8 groups")]
    WrongGroupCount,
    #[error("each recovery key group must be 6 decimal digits")]
    BadGroupDigits,
    #[error("recovery key group failed the divisible-by-11 checksum")]
    BadChecksum,
    #[error("recovery key group is out of range")]
    GroupOutOfRange,
}

pub enum BitLockerCredential {
    Password(Zeroizing<String>),
    RecoveryKey(Zeroizing<String>),
}

impl BitLockerCredential {
    pub fn password(password: impl Into<String>) -> Self {
        Self::Password(Zeroizing::new(password.into()))
    }

    pub fn recovery_key(recovery_key: impl Into<String>) -> Result<Self> {
        // Wrap before validation so malformed credentials are zeroized too.
        let recovery_key = Zeroizing::new(recovery_key.into());
        validate_recovery_key_format(&recovery_key)
            .map_err(BitLockerDecryptError::InvalidRecoveryKey)?;
        Ok(Self::RecoveryKey(recovery_key))
    }
}

impl fmt::Debug for BitLockerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.write_str("BitLockerCredential::Password(<redacted>)"),
            Self::RecoveryKey(_) => f.write_str("BitLockerCredential::RecoveryKey(<redacted>)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitLockerInspection {
    pub variant: BitLockerVariant,
    pub metadata_state: BitLockerMetadataState,
    pub encryption_method: Option<BitLockerEncryptionMethod>,
    pub metadata_offsets: [u64; 3],
    pub metadata_size: Option<u32>,
    pub encrypted_volume_size: Option<u64>,
    pub volume_header_offset: Option<u64>,
    pub volume_header_size: Option<u64>,
    pub protectors: Vec<BitLockerKeyProtector>,
    pub unlock_state: BitLockerUnlockState,
}

impl BitLockerInspection {
    pub fn can_unlock_with_recovery_key(&self) -> bool {
        self.protectors
            .iter()
            .any(|protector| protector.kind == BitLockerProtectorKind::RecoveryPassword)
    }

    pub fn can_unlock_with_password(&self) -> bool {
        self.protectors
            .iter()
            .any(|protector| protector.kind == BitLockerProtectorKind::Password)
    }

    pub fn is_tpm_only(&self) -> bool {
        !self.can_unlock_with_recovery_key()
            && !self.can_unlock_with_password()
            && !self.protectors.is_empty()
            && self
                .protectors
                .iter()
                .all(|protector| protector.kind.is_tpm_backed())
    }

    pub fn status_message(&self) -> &'static str {
        match self.unlock_state {
            BitLockerUnlockState::CredentialRequired => {
                "BitLocker volume detected; recovery key or password is required to decrypt"
            }
            BitLockerUnlockState::CannotDecryptWithoutRecoveryKeyOrPassword => {
                "BitLocker volume detected; cannot decrypt without recovery key/password"
            }
            BitLockerUnlockState::MetadataUnavailable => {
                "BitLocker header detected but FVE metadata could not be parsed"
            }
            BitLockerUnlockState::UnsupportedProtector => {
                "BitLocker volume detected; no recovery-key/password protector is available"
            }
            BitLockerUnlockState::UnsupportedEncryptionMethod => {
                "BitLocker volume detected; its encryption method is not supported"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitLockerVariant {
    WindowsVista,
    Windows7OrLater,
    BitLockerToGo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitLockerMetadataState {
    Parsed,
    HeaderOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitLockerEncryptionMethod {
    pub raw: u16,
    pub description: &'static str,
    pub decrypt_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitLockerKeyProtector {
    pub raw: u16,
    pub kind: BitLockerProtectorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitLockerProtectorKind {
    ClearKey,
    Tpm,
    StartupKey,
    TpmAndPin,
    RecoveryPassword,
    Password,
    Unknown,
}

impl BitLockerProtectorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClearKey => "clear key",
            Self::Tpm => "TPM",
            Self::StartupKey => "startup key",
            Self::TpmAndPin => "TPM and PIN",
            Self::RecoveryPassword => "recovery password",
            Self::Password => "password",
            Self::Unknown => "unknown",
        }
    }

    fn is_tpm_backed(self) -> bool {
        matches!(self, Self::Tpm | Self::TpmAndPin)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitLockerUnlockState {
    CredentialRequired,
    CannotDecryptWithoutRecoveryKeyOrPassword,
    MetadataUnavailable,
    UnsupportedProtector,
    UnsupportedEncryptionMethod,
}

pub fn validate_recovery_key_format(
    recovery_key: &str,
) -> std::result::Result<(), RecoveryKeyFormatError> {
    let mut group_count = 0usize;
    for (index, group) in recovery_key.split('-').enumerate() {
        if index >= 8 {
            return Err(RecoveryKeyFormatError::WrongGroupCount);
        }
        if group.len() != 6 || !group.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RecoveryKeyFormatError::BadGroupDigits);
        }
        let value: u32 = group
            .parse()
            .map_err(|_| RecoveryKeyFormatError::BadGroupDigits)?;
        if !value.is_multiple_of(11) {
            return Err(RecoveryKeyFormatError::BadChecksum);
        }
        if value / 11 > u32::from(u16::MAX) {
            return Err(RecoveryKeyFormatError::GroupOutOfRange);
        }
        group_count = index + 1;
    }
    if group_count != 8 {
        return Err(RecoveryKeyFormatError::WrongGroupCount);
    }
    Ok(())
}

pub fn bitlocker_sector_start(byte_offset: u64) -> u64 {
    byte_offset - (byte_offset % BITLOCKER_SECTOR_SIZE)
}

pub fn bitlocker_xts_tweak_value(byte_offset: u64) -> u128 {
    u128::from(byte_offset / BITLOCKER_SECTOR_SIZE)
}

pub fn inspect_reader<R: Read + Seek>(reader: &mut R) -> Result<Option<BitLockerInspection>> {
    let mut sector = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    let bytes_read = read_available(reader, &mut sector)?;
    if bytes_read < 11 {
        return Ok(None);
    }

    let fixed_signature = sector.get(3..11) == Some(SIG_FVE.as_slice());
    let to_go_signature = sector.get(3..11) == Some(SIG_TO_GO.as_slice());
    let header = match VolumeHeader::parse(&sector) {
        Ok(header) => header,
        Err(BdeError::NotBitLocker { .. }) => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    reader.seek(SeekFrom::Start(0))?;
    let metadata = match BitLockerVolume::read_metadata(reader) {
        Ok(metadata) => Some(metadata),
        Err(BdeError::NoValidMetadata { .. }) if fixed_signature => None,
        Err(BdeError::NoValidMetadata { .. }) if to_go_signature => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let inspection = BitLockerInspection::from_header_and_metadata(&header, metadata);
    let total_size = reader.seek(SeekFrom::End(0))?;
    validate_inspection_geometry(&inspection, total_size)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(Some(inspection))
}

pub fn unlock_reader<R: Read + Seek>(
    mut reader: R,
    credential: BitLockerCredential,
) -> Result<DecryptedVolume<R>> {
    let inspection = inspect_reader(&mut reader)?.ok_or_else(|| {
        BitLockerDecryptError::InvalidMetadataGeometry(
            "reader does not contain a supported BitLocker volume".to_string(),
        )
    })?;
    if inspection.metadata_state != BitLockerMetadataState::Parsed {
        return Err(BitLockerDecryptError::InvalidMetadataGeometry(
            "no valid FVE metadata copy is available".to_string(),
        ));
    }
    match credential {
        BitLockerCredential::Password(password) => Ok(BitLockerVolume::unlock_with_password(
            reader,
            password.as_str(),
        )?),
        BitLockerCredential::RecoveryKey(recovery_key) => Ok(
            BitLockerVolume::unlock_with_recovery_password(reader, recovery_key.as_str())?,
        ),
    }
}

impl BitLockerInspection {
    fn from_header_and_metadata(
        header: &VolumeHeader,
        metadata: Option<FveMetadata>,
    ) -> BitLockerInspection {
        let variant = match header.variant {
            bitlocker::BdeVariant::WindowsVista => BitLockerVariant::WindowsVista,
            bitlocker::BdeVariant::Windows7OrLater => BitLockerVariant::Windows7OrLater,
            bitlocker::BdeVariant::BitLockerToGo => BitLockerVariant::BitLockerToGo,
        };
        let Some(metadata) = metadata else {
            return BitLockerInspection {
                variant,
                metadata_state: BitLockerMetadataState::HeaderOnly,
                encryption_method: None,
                metadata_offsets: header.fve_metadata_offsets,
                metadata_size: None,
                encrypted_volume_size: None,
                volume_header_offset: None,
                volume_header_size: None,
                protectors: Vec::new(),
                unlock_state: BitLockerUnlockState::MetadataUnavailable,
            };
        };

        let protectors = metadata
            .protector_types()
            .into_iter()
            .map(|raw| BitLockerKeyProtector {
                raw,
                kind: protector_kind(raw),
            })
            .collect::<Vec<_>>();
        let has_recovery_or_password = protectors.iter().any(|protector| {
            matches!(
                protector.kind,
                BitLockerProtectorKind::RecoveryPassword | BitLockerProtectorKind::Password
            )
        });
        let tpm_only = !has_recovery_or_password
            && !protectors.is_empty()
            && protectors
                .iter()
                .all(|protector| protector.kind.is_tpm_backed());
        let method = encryption_method(metadata.encryption_method);
        let unlock_state = if !method.decrypt_supported {
            BitLockerUnlockState::UnsupportedEncryptionMethod
        } else if has_recovery_or_password {
            BitLockerUnlockState::CredentialRequired
        } else if tpm_only {
            BitLockerUnlockState::CannotDecryptWithoutRecoveryKeyOrPassword
        } else {
            BitLockerUnlockState::UnsupportedProtector
        };

        BitLockerInspection {
            variant,
            metadata_state: BitLockerMetadataState::Parsed,
            encryption_method: Some(method),
            metadata_offsets: metadata.metadata_offsets,
            metadata_size: Some(metadata.metadata_size),
            encrypted_volume_size: Some(metadata.encrypted_volume_size),
            volume_header_offset: Some(metadata.volume_header_offset),
            volume_header_size: Some(metadata.volume_header_size),
            protectors,
            unlock_state,
        }
    }
}

fn protector_kind(raw: u16) -> BitLockerProtectorKind {
    match raw {
        PROTECTOR_CLEAR_KEY => BitLockerProtectorKind::ClearKey,
        PROTECTOR_TPM => BitLockerProtectorKind::Tpm,
        PROTECTOR_STARTUP_KEY => BitLockerProtectorKind::StartupKey,
        PROTECTOR_TPM_AND_PIN => BitLockerProtectorKind::TpmAndPin,
        PROTECTOR_RECOVERY_PASSWORD => BitLockerProtectorKind::RecoveryPassword,
        PROTECTOR_PASSWORD => BitLockerProtectorKind::Password,
        _ => BitLockerProtectorKind::Unknown,
    }
}

fn encryption_method(raw: u16) -> BitLockerEncryptionMethod {
    let (description, decrypt_supported) = match raw {
        0x0000 => ("not encrypted", false),
        0x8000 => ("AES-128-CBC + Elephant diffuser", true),
        0x8001 => ("AES-256-CBC + Elephant diffuser", false),
        0x8002 => ("AES-128-CBC", true),
        0x8003 => ("AES-256-CBC", true),
        0x8004 => ("XTS-AES-128", true),
        0x8005 => ("XTS-AES-256", true),
        _ => ("unknown BitLocker encryption method", false),
    };
    BitLockerEncryptionMethod {
        raw,
        description,
        decrypt_supported,
    }
}

fn validate_inspection_geometry(inspection: &BitLockerInspection, total_size: u64) -> Result<()> {
    if inspection.metadata_state != BitLockerMetadataState::Parsed {
        return Ok(());
    }
    let metadata_size = u64::from(inspection.metadata_size.ok_or_else(|| {
        BitLockerDecryptError::InvalidMetadataGeometry(
            "parsed metadata has no declared size".to_string(),
        )
    })?);
    if !(48..=65_536).contains(&metadata_size) {
        return Err(BitLockerDecryptError::InvalidMetadataGeometry(format!(
            "metadata size {metadata_size} is outside 48..=65536 bytes"
        )));
    }
    for offset in inspection
        .metadata_offsets
        .iter()
        .copied()
        .filter(|offset| *offset != 0)
    {
        validate_range("metadata", offset, metadata_size, total_size, false)?;
    }
    if let Some(encrypted_size) = inspection.encrypted_volume_size {
        if encrypted_size != 0 && encrypted_size > total_size {
            return Err(BitLockerDecryptError::InvalidMetadataGeometry(format!(
                "encrypted byte count {encrypted_size} exceeds volume size {total_size}"
            )));
        }
    }
    let header_offset = inspection.volume_header_offset.unwrap_or(0);
    let header_size = inspection.volume_header_size.unwrap_or(0);
    if header_size != 0 {
        validate_range(
            "relocated volume header",
            header_offset,
            header_size,
            total_size,
            true,
        )?;
    }
    Ok(())
}

fn validate_range(
    label: &str,
    offset: u64,
    size: u64,
    total_size: u64,
    require_aligned_size: bool,
) -> Result<()> {
    if !offset.is_multiple_of(BITLOCKER_SECTOR_SIZE)
        || (require_aligned_size && !size.is_multiple_of(BITLOCKER_SECTOR_SIZE))
    {
        return Err(BitLockerDecryptError::InvalidMetadataGeometry(format!(
            "{label} range {offset}+{size} is not 512-byte aligned"
        )));
    }
    let end = offset.checked_add(size).ok_or_else(|| {
        BitLockerDecryptError::InvalidMetadataGeometry(format!("{label} range overflows"))
    })?;
    if end > total_size {
        return Err(BitLockerDecryptError::InvalidMetadataGeometry(format!(
            "{label} range {offset}..{end} exceeds volume size {total_size}"
        )));
    }
    Ok(())
}

fn read_available<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const META_BLOCK_OFFSET: u64 = 0x1000;

    fn synthetic_recovery_key(words: [u16; 8]) -> String {
        words
            .iter()
            .map(|word| format!("{:06}", u32::from(*word) * 11))
            .collect::<Vec<_>>()
            .join("-")
    }

    fn entry(entry_type: u16, value_type: u16, data: &[u8]) -> Vec<u8> {
        let size = (8 + data.len()) as u16;
        let mut out = Vec::with_capacity(usize::from(size));
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&entry_type.to_le_bytes());
        out.extend_from_slice(&value_type.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn metadata_image(method: u16, protectors: &[u16]) -> Vec<u8> {
        let mut entries = Vec::new();
        for protector in protectors {
            let mut data = vec![0u8; 28];
            data[26..28].copy_from_slice(&protector.to_le_bytes());
            entries.extend_from_slice(&entry(0x0002, 0x0008, &data));
        }
        let metadata_size = 48 + entries.len();
        let mut image = vec![0u8; 0x2000];
        image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[3..11].copy_from_slice(SIG_FVE);
        image[11..13].copy_from_slice(&512u16.to_le_bytes());
        image[176..184].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());

        let mb = META_BLOCK_OFFSET as usize;
        image[mb..mb + 8].copy_from_slice(SIG_FVE);
        image[mb + 32..mb + 40].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());
        image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
        image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&method.to_le_bytes());
        image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);
        image
    }

    #[test]
    fn recovery_key_format_accepts_generated_valid_key() {
        let key = synthetic_recovery_key([0, 1, 2, 3, 4, 5, 1024, u16::MAX]);
        validate_recovery_key_format(&key).unwrap();
        assert!(matches!(
            BitLockerCredential::recovery_key(key).unwrap(),
            BitLockerCredential::RecoveryKey(_)
        ));
    }

    #[test]
    fn recovery_key_format_rejects_malformed_values() {
        assert_eq!(
            validate_recovery_key_format("not-a-recovery-key").unwrap_err(),
            RecoveryKeyFormatError::BadGroupDigits
        );
        assert_eq!(
            validate_recovery_key_format("000000").unwrap_err(),
            RecoveryKeyFormatError::WrongGroupCount
        );
        let bad_checksum = synthetic_recovery_key([0, 1, 2, 3, 4, 5, 6, 7]).replacen('0', "1", 1);
        assert_eq!(
            validate_recovery_key_format(&bad_checksum).unwrap_err(),
            RecoveryKeyFormatError::BadChecksum
        );
        let out_of_range = [
            "720896", "000000", "000000", "000000", "000000", "000000", "000000", "000000",
        ]
        .join("-");
        assert_eq!(
            validate_recovery_key_format(&out_of_range).unwrap_err(),
            RecoveryKeyFormatError::GroupOutOfRange
        );
    }

    #[test]
    fn metadata_parsing_reports_recovery_password_and_password_protectors() {
        let image = metadata_image(0x8004, &[PROTECTOR_RECOVERY_PASSWORD, PROTECTOR_PASSWORD]);
        let mut reader = Cursor::new(image);
        let info = inspect_reader(&mut reader).unwrap().unwrap();
        assert_eq!(info.variant, BitLockerVariant::Windows7OrLater);
        assert_eq!(info.metadata_state, BitLockerMetadataState::Parsed);
        assert_eq!(
            info.encryption_method,
            Some(BitLockerEncryptionMethod {
                raw: 0x8004,
                description: "XTS-AES-128",
                decrypt_supported: true,
            })
        );
        assert!(info.can_unlock_with_recovery_key());
        assert!(info.can_unlock_with_password());
        assert_eq!(info.unlock_state, BitLockerUnlockState::CredentialRequired);
        assert_eq!(
            info.protectors
                .iter()
                .map(|protector| protector.kind)
                .collect::<Vec<_>>(),
            vec![
                BitLockerProtectorKind::RecoveryPassword,
                BitLockerProtectorKind::Password
            ]
        );
    }

    #[test]
    fn encryption_method_reports_only_wrapped_crate_decryptable_methods_as_supported() {
        assert!(encryption_method(0x8000).decrypt_supported);
        assert!(encryption_method(0x8002).decrypt_supported);
        assert!(!encryption_method(0x8001).decrypt_supported);
        assert!(encryption_method(0x8003).decrypt_supported);
        assert!(encryption_method(0x8004).decrypt_supported);
        assert!(encryption_method(0x8005).decrypt_supported);
        assert!(!encryption_method(0x0000).decrypt_supported);
    }

    #[test]
    fn metadata_parsing_reports_tpm_only_as_not_decryptable() {
        let image = metadata_image(0x8002, &[PROTECTOR_TPM, PROTECTOR_TPM_AND_PIN]);
        let mut reader = Cursor::new(image);
        let info = inspect_reader(&mut reader).unwrap().unwrap();
        assert!(info.is_tpm_only());
        assert_eq!(
            info.unlock_state,
            BitLockerUnlockState::CannotDecryptWithoutRecoveryKeyOrPassword
        );
        assert_eq!(
            info.status_message(),
            "BitLocker volume detected; cannot decrypt without recovery key/password"
        );
    }

    #[test]
    fn bitlocker_to_go_signature_without_metadata_is_not_enough() {
        let mut image = vec![0u8; 512];
        image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[3..11].copy_from_slice(SIG_TO_GO);
        image[11..13].copy_from_slice(&512u16.to_le_bytes());
        let mut reader = Cursor::new(image);
        assert!(inspect_reader(&mut reader).unwrap().is_none());
    }

    #[test]
    fn fixed_fve_header_without_metadata_still_reports_header_only() {
        let mut image = vec![0u8; 512];
        image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[3..11].copy_from_slice(SIG_FVE);
        image[11..13].copy_from_slice(&512u16.to_le_bytes());
        let mut reader = Cursor::new(image);
        let info = inspect_reader(&mut reader).unwrap().unwrap();
        assert_eq!(info.metadata_state, BitLockerMetadataState::HeaderOnly);
        assert_eq!(info.unlock_state, BitLockerUnlockState::MetadataUnavailable);
    }

    #[test]
    fn metadata_range_outside_volume_is_rejected() {
        let mut image = metadata_image(0x8004, &[PROTECTOR_PASSWORD]);
        let mb = META_BLOCK_OFFSET as usize;
        image[mb + 32..mb + 40].copy_from_slice(&(u64::MAX - 511).to_le_bytes());
        let mut reader = Cursor::new(image);
        assert!(matches!(
            inspect_reader(&mut reader),
            Err(BitLockerDecryptError::InvalidMetadataGeometry(_))
        ));
    }

    #[test]
    fn sector_tweak_logic_uses_bitlocker_512_byte_sector_number() {
        assert_eq!(bitlocker_sector_start(0), 0);
        assert_eq!(bitlocker_sector_start(511), 0);
        assert_eq!(bitlocker_sector_start(512), 512);
        assert_eq!(bitlocker_sector_start(1025), 1024);

        assert_eq!(bitlocker_xts_tweak_value(0), 0);
        assert_eq!(bitlocker_xts_tweak_value(511), 0);
        assert_eq!(bitlocker_xts_tweak_value(512), 1);
        assert_eq!(bitlocker_xts_tweak_value(4096), 8);
        assert_eq!(
            bitlocker_xts_tweak_value(u64::MAX),
            u128::from(u64::MAX / BITLOCKER_SECTOR_SIZE)
        );
    }
}
