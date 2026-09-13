#![forbid(unsafe_code)]

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
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
        let root =
            std::env::temp_dir().join(format!("kdft-corpus-cli-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&root).expect("temporary corpus directory should be created");
        Self { root }
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    fn write_manifest(&self, source: &str) {
        let value = json!({
            "dataset_id": "kdft-cli-test-001",
            "dataset_version": "1.0.0",
            "creation_script_version": "test",
            "purpose": "CLI integration test",
            "source_image": {
                "format": "fixture",
                "path_or_external_id": source,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size_bytes": 0
            },
            "environment": {
                "os": "synthetic",
                "architecture": "unknown",
                "partition_table": "none",
                "sector_size_bytes": 512,
                "filesystems": [{"name": "none"}]
            },
            "expected": {},
            "limitations": ["CLI integration fixture"],
            "sources": [{"name": "Local test", "url": "urn:kdft:cli-test"}]
        });
        std::fs::write(
            self.manifest_path(),
            serde_json::to_vec_pretty(&value).expect("manifest should serialize"),
        )
        .expect("manifest should be written");
    }
}

impl Drop for TempCorpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run_validator(manifest: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kdft"))
        .args(["corpus", "validate", "--manifest"])
        .arg(manifest)
        .arg("--json")
        .output()
        .expect("kdft corpus validator should run")
}

#[test]
fn corpus_cli_exit_and_json_match_validation_status() {
    let temp = TempCorpus::new();
    std::fs::write(temp.root.join("source.bin"), []).expect("source should be written");
    temp.write_manifest("source.bin");

    let passed = run_validator(&temp.manifest_path());
    assert!(passed.status.success());
    let passed_json: serde_json::Value =
        serde_json::from_slice(&passed.stdout).expect("stdout should contain only JSON");
    assert_eq!(passed_json["passed"], true);
    assert_eq!(passed_json["status"], "passed");
    assert_eq!(passed_json["source_status"], "verified");
    assert!(passed.stderr.is_empty());

    temp.write_manifest("external://missing-source.bin");
    let incomplete = run_validator(&temp.manifest_path());
    assert!(!incomplete.status.success());
    let incomplete_json: serde_json::Value =
        serde_json::from_slice(&incomplete.stdout).expect("stdout should contain only JSON");
    assert_eq!(incomplete_json["passed"], false);
    assert_eq!(incomplete_json["status"], "incomplete");
    assert_eq!(incomplete_json["source_status"], "unavailable");
    let stderr = String::from_utf8(incomplete.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("did not pass (incomplete)"));
}
