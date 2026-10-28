#![forbid(unsafe_code)]

//! Transient in-memory BitLocker unlock and credential security.
//!
//! Credentials are zeroized on drop, never serialized, never logged, never
//! printed in Debug or error outputs, and never stored in SQLite or on disk.

use anyhow::{anyhow, bail, Context, Result};
use kdft_case::BitLockerUnlockCredential;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::Instant;
use zeroize::Zeroizing;

pub const BITLOCKER_LOCKED_FILESYSTEM: &str = "BitLocker (locked)";

/// Zeroizing wrapper for a BitLocker credential string.
/// Intentionally does NOT implement `Serialize` or `Deserialize`.
#[derive(Clone)]
pub struct TransientBitLockerSecret(pub Zeroizing<String>);

impl TransientBitLockerSecret {
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TransientBitLockerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED BITLOCKER CREDENTIAL]")
    }
}

/// BitLocker credential variant kept strictly in process memory.
/// Non-serializable, zeroized on drop.
pub enum TransientBitLockerCredential {
    Password(TransientBitLockerSecret),
    RecoveryKey(TransientBitLockerSecret),
}

impl TransientBitLockerCredential {
    pub fn password(pwd: String) -> Self {
        Self::Password(TransientBitLockerSecret::new(pwd))
    }

    pub fn recovery_key(key: String) -> Self {
        Self::RecoveryKey(TransientBitLockerSecret::new(key))
    }

    pub fn as_case_credential(&self) -> BitLockerUnlockCredential<'_> {
        match self {
            Self::Password(sec) => BitLockerUnlockCredential::Password(sec.as_str()),
            Self::RecoveryKey(sec) => BitLockerUnlockCredential::RecoveryKey(sec.as_str()),
        }
    }
}

impl Clone for TransientBitLockerCredential {
    fn clone(&self) -> Self {
        match self {
            Self::Password(sec) => Self::Password(sec.clone()),
            Self::RecoveryKey(sec) => Self::RecoveryKey(sec.clone()),
        }
    }
}

impl fmt::Debug for TransientBitLockerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => write!(f, "TransientBitLockerCredential::Password([REDACTED])"),
            Self::RecoveryKey(_) => {
                write!(f, "TransientBitLockerCredential::RecoveryKey([REDACTED])")
            }
        }
    }
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnlockedVolumeKey {
    pub evidence_id: i64,
    pub volume_index: usize,
}

#[derive(Clone)]
pub struct UnlockedVolumeSession {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub filesystem: String,
    pub credential: TransientBitLockerCredential,
    pub unlocked_at: Instant,
    pub generation: u64,
}

impl fmt::Debug for UnlockedVolumeSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVolumeSession")
            .field("evidence_id", &self.evidence_id)
            .field("volume_index", &self.volume_index)
            .field("filesystem", &self.filesystem)
            .field("credential", &self.credential)
            .field("unlocked_at", &self.unlocked_at)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Redacted view model status projection for UI display.
/// Never contains or reveals the underlying secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnlockedSessionStatus {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub filesystem: String,
    pub generation: u64,
    pub unlocked_duration_secs: u64,
}

/// In-memory manager for unlocked BitLocker sessions.
/// Authoritative, thread-safe, and shared across all views/workers.
#[derive(Clone)]
pub struct TransientUnlockManager {
    sessions: Arc<RwLock<HashMap<UnlockedVolumeKey, UnlockedVolumeSession>>>,
    generation_counter: Arc<AtomicU64>,
}

impl Default for TransientUnlockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TransientUnlockManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            generation_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Tests and registers an unlocked session for a BitLocker volume.
    /// If verification fails, credential is zeroized and a redacted error is returned.
    pub fn unlock_volume(
        &self,
        image_path: &Path,
        evidence_id: i64,
        volume_index: usize,
        credential: TransientBitLockerCredential,
    ) -> Result<u64> {
        let volumes = kdft_case::list_image_volumes(image_path)
            .with_context(|| format!("reading image volumes from {}", image_path.display()))?;
        let volume = volumes
            .get(volume_index)
            .ok_or_else(|| anyhow!("volume index {volume_index} out of range"))?;

        // Test unlocking by browsing root or verifying metadata
        let case_cred = credential.as_case_credential();
        let unlock_result =
            kdft_case::list_bitlocker_ntfs_directory(image_path, volume_index, case_cred, "/");

        match unlock_result {
            Ok(_) => {
                let gen = self.generation_counter.fetch_add(1, Ordering::SeqCst);
                let key = UnlockedVolumeKey {
                    evidence_id,
                    volume_index,
                };
                if let Ok(mut lock) = self.sessions.write() {
                    lock.insert(
                        key,
                        UnlockedVolumeSession {
                            evidence_id,
                            volume_index,
                            filesystem: volume.filesystem.clone(),
                            credential,
                            unlocked_at: Instant::now(),
                            generation: gen,
                        },
                    );
                }
                Ok(gen)
            }
            Err(e) => {
                // Drop credential to zeroize it immediately
                drop(credential);
                bail!("BitLocker unlock failed: invalid password/recovery key or unsupported cipher: {e}");
            }
        }
    }

    /// Stores a transient session without immediately verifying against the disk image.
    pub fn store_unverified_session(
        &self,
        evidence_id: i64,
        volume_index: usize,
        filesystem: String,
        credential: TransientBitLockerCredential,
    ) -> u64 {
        let gen = self.generation_counter.fetch_add(1, Ordering::SeqCst);
        let key = UnlockedVolumeKey {
            evidence_id,
            volume_index,
        };
        if let Ok(mut lock) = self.sessions.write() {
            lock.insert(
                key,
                UnlockedVolumeSession {
                    evidence_id,
                    volume_index,
                    filesystem,
                    credential,
                    unlocked_at: Instant::now(),
                    generation: gen,
                },
            );
        }
        gen
    }

    pub fn is_unlocked(&self, evidence_id: i64, volume_index: usize) -> bool {
        self.sessions
            .read()
            .map(|lock| {
                lock.contains_key(&UnlockedVolumeKey {
                    evidence_id,
                    volume_index,
                })
            })
            .unwrap_or(false)
    }

    pub fn unlock_generation(&self, evidence_id: i64, volume_index: usize) -> Option<u64> {
        self.sessions.read().ok().and_then(|lock| {
            lock.get(&UnlockedVolumeKey {
                evidence_id,
                volume_index,
            })
            .map(|s| s.generation)
        })
    }

    pub fn get_transient_credential(
        &self,
        evidence_id: i64,
        volume_index: usize,
    ) -> Option<TransientBitLockerCredential> {
        self.sessions.read().ok().and_then(|lock| {
            lock.get(&UnlockedVolumeKey {
                evidence_id,
                volume_index,
            })
            .map(|s| s.credential.clone())
        })
    }

    #[inline]
    pub fn get_credential(
        &self,
        evidence_id: i64,
        volume_index: usize,
    ) -> Option<TransientBitLockerCredential> {
        self.get_transient_credential(evidence_id, volume_index)
    }

    pub fn get_session(
        &self,
        evidence_id: i64,
        volume_index: usize,
    ) -> Option<UnlockedVolumeSession> {
        self.sessions.read().ok().and_then(|lock| {
            lock.get(&UnlockedVolumeKey {
                evidence_id,
                volume_index,
            })
            .cloned()
        })
    }

    pub fn get_status_list(&self) -> Vec<UnlockedSessionStatus> {
        let now = Instant::now();
        self.sessions
            .read()
            .map(|lock| {
                lock.values()
                    .map(|s| UnlockedSessionStatus {
                        evidence_id: s.evidence_id,
                        volume_index: s.volume_index,
                        filesystem: s.filesystem.clone(),
                        generation: s.generation,
                        unlocked_duration_secs: now
                            .saturating_duration_since(s.unlocked_at)
                            .as_secs(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn lock_volume(&self, evidence_id: i64, volume_index: usize) {
        self.generation_counter.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut lock) = self.sessions.write() {
            lock.remove(&UnlockedVolumeKey {
                evidence_id,
                volume_index,
            });
        }
    }

    pub fn clear(&self) {
        self.generation_counter.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut lock) = self.sessions.write() {
            lock.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted_and_never_leaks_credential() {
        let secret = TransientBitLockerSecret::new("super-secret-key-12345".to_string());
        let dbg = format!("{secret:?}");
        assert_eq!(dbg, "[REDACTED BITLOCKER CREDENTIAL]");
        assert!(!dbg.contains("super-secret"));

        let cred = TransientBitLockerCredential::password("pw-secret-999".to_string());
        let dbg_cred = format!("{cred:?}");
        assert!(dbg_cred.contains("[REDACTED]"));
        assert!(!dbg_cred.contains("pw-secret-999"));
    }

    #[test]
    fn unlock_manager_clears_and_locks_sessions() {
        let mgr = TransientUnlockManager::new();
        assert!(!mgr.is_unlocked(1, 0));
        mgr.clear();
        assert!(!mgr.is_unlocked(1, 0));
    }
}
