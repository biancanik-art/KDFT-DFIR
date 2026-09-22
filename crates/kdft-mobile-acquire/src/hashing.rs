use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open for hashing: {}", path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 1024 * 1024];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn hash_tree(root: &Path, manifest_path: &Path) -> Result<usize> {
    let mut files: Vec<PathBuf> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| p != manifest_path)
        .collect();

    files.sort();

    let mut manifest = File::create(manifest_path)?;
    let mut count = 0usize;

    for path in files {
        let digest = sha256_file(&path)?;
        let rel = path.strip_prefix(root).unwrap_or(&path);
        writeln!(
            manifest,
            "{}  {}",
            digest,
            rel.to_string_lossy().replace('\\', "/")
        )?;
        count += 1;
    }

    manifest.flush()?;
    Ok(count)
}
