//! Atomic output file publication for forensic evidence and case artifacts.
//!
//! Output is written to a private temporary file beside the destination and only
//! published via hard link upon commit, guaranteeing that partial or failed writes
//! never corrupt or overwrite existing evidence files.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A same-directory temporary output that becomes visible at `destination`
/// only after every byte has been flushed and synced. Publication uses a hard
/// link, which is atomic and refuses to replace an existing destination.
pub struct AtomicOutput {
    file: fs::File,
    temporary_path: PathBuf,
    destination: PathBuf,
    committed: bool,
}

impl AtomicOutput {
    pub fn create(destination: &Path) -> Result<Self> {
        if destination.as_os_str().is_empty() {
            bail!("output path cannot be empty");
        }
        if destination.exists() {
            bail!(
                "output already exists; choose a new filename: {}",
                destination.display()
            );
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        static NEXT_ATOMIC_OUTPUT: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        for _ in 0..128 {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            let nonce = NEXT_ATOMIC_OUTPUT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let temporary_path = parent.join(format!(
                ".kdft-output-{}-{stamp}-{nonce}.tmp",
                std::process::id()
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
            {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        temporary_path,
                        destination: destination.to_path_buf(),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("creating temporary output in {}", parent.display())
                    });
                }
            }
        }
        bail!("could not reserve a unique temporary output after 128 attempts")
    }

    pub fn commit(mut self) -> Result<()> {
        self.file.flush().with_context(|| {
            format!(
                "flushing temporary output for {}",
                self.destination.display()
            )
        })?;
        self.file.sync_all().with_context(|| {
            format!(
                "syncing temporary output for {}",
                self.destination.display()
            )
        })?;
        fs::hard_link(&self.temporary_path, &self.destination).with_context(|| {
            format!(
                "publishing output without replacing an existing file {} (the destination filesystem must support hard links)",
                self.destination.display()
            )
        })?;
        self.committed = true;
        let _ = fs::remove_file(&self.temporary_path);
        Ok(())
    }
}

impl Write for AtomicOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.temporary_path);
        }
    }
}

pub fn write_new_file_atomically(destination: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = AtomicOutput::create(destination)?;
    output
        .write_all(bytes)
        .with_context(|| format!("writing output {}", destination.display()))?;
    output.commit()
}

#[cfg(test)]
mod atomic_output_tests {
    use super::{write_new_file_atomically, AtomicOutput};
    use std::fs;
    use std::io::Write;

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kdft-atomic-output-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn output_is_hidden_until_commit_and_existing_file_is_preserved() {
        let directory = temporary_directory("publish");
        let destination = directory.join("evidence.bin");
        let mut output = AtomicOutput::create(&destination).unwrap();
        output.write_all(b"complete evidence").unwrap();
        assert!(!destination.exists());
        output.commit().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"complete evidence");

        let error = write_new_file_atomically(&destination, b"replacement").unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(&destination).unwrap(), b"complete evidence");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dropped_output_never_creates_the_destination() {
        let directory = temporary_directory("drop");
        let destination = directory.join("partial.bin");
        {
            let mut output = AtomicOutput::create(&destination).unwrap();
            output.write_all(b"partial").unwrap();
        }
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir_all(directory).unwrap();
    }
}
