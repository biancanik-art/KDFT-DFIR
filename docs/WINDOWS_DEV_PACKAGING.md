# KDFT Windows Developer Packaging & Smoke Workflow

This document specifies the safe developer-package build, smoke test, and distribution workflow for the KDFT workspace on Windows. The workflow is automated by [scripts/package-windows-dev.ps1](file:///C:/Users/xt/Documents/Codex/KDFT-agy-worktrees/urgent-registry-mft/scripts/package-windows-dev.ps1).

---

## 1. Architectural Roles: Workbench vs. Desktop

KDFT provides two front-end executables. It is essential that examiners and developers understand their distinct roles and operational boundaries:

| Attribute | Desktop (`kdft-desktop.exe`) | Workbench (`kdft-ui.exe`) |
| :--- | :--- | :--- |
| **Primary Role** | **Primary native case/evidence workflow** | Optional browser-assisted workbench |
| **UI Model** | Native GUI window (`eframe`/`egui`) | Browser-assisted local web interface |
| **Network Surface** | **Zero network listeners** (no sockets opened) | Loopback HTTP only (`127.0.0.1:[port]`) |
| **Case Operations** | Create/open cases, attach evidence, start/cancel processing, review bounded results | Full read/write workbench operations |
| **Processing Pipeline** | Base filesystem inventory/content capture with optional email and browser parsing | Broader legacy workbench processors and inspection surfaces |
| **Memory Management** | Strict bounded keyset paging (200 rows/page, max 1,000) | Full multi-threaded processing pipeline |
| **Recommended Use** | Native-first examiner workflow and bounded-memory case review | Optional access to workbench-only capabilities during migration |

---

## 2. Safety and Integrity Guarantees

The developer packaging workflow adheres strictly to the following safety principles:

1. **No Recursive Deletion & No Overwriting**:
   - Output packages are written to a **NEW**, uniquely timestamped directory:
     `dist/kdft-windows-dev-yyyyMMdd-HHmmss/`
   - Existing distributions under `dist/` are never deleted, overwritten, or modified.
2. **Strict File Exclusion (Blacklist Audit)**:
   - Packaging uses an explicit whitelist to copy only target release executables, legal notices, and documentation.
   - A secondary post-staging audit verifies that the package contains **NO**:
     - Case databases (`*.sqlite`, `*.db`, `*.kdft.sqlite`, `*.sqlite-wal`, `*.sqlite-shm`)
     - Evidence disk images (`*.vhd`, `*.vhdx`, `*.e01`, `*.raw`, `*.img`, `*.dd`, `*.iso`)
     - Log files (`*.log`, `*.trace`)
     - Credentials or secrets (`*.key`, `*.pem`, `*.env`, tokens)
     - Staging or import folders (`ui-output/`, `testdata/`, `staging/`, `import/`)
     - Target debug artifacts (`*.pdb`, `*.d`, `*.rlib`, `*.rmeta`)
     - Pre-existing release binaries (e.g. `kdft-v1.0.1-windows-x64.*`, `kdft.exe`)
3. **Fail-Closed Design**:
   - Any failure in format checking, test execution, compilation, file copying, or hash calculation immediately aborts execution with a non-zero exit code.
4. **Git Provenance & Dirty-State Disclosure**:
   - Current commit SHA, active branch, and working-tree clean/dirty status (with a list of modified/untracked files) are captured and recorded in the machine-readable manifest and package documentation.
   - All uncommitted changes in the developer's workspace are strictly preserved.
5. **Isolated & Offline**:
   - Native PowerShell only; literal filesystem paths (`-LiteralPath`); no network access, code signing, or external publishing.

---

## 3. Workflow Steps

When executed, [scripts/package-windows-dev.ps1](file:///C:/Users/xt/Documents/Codex/KDFT-agy-worktrees/urgent-registry-mft/scripts/package-windows-dev.ps1) executes the following sequence:

1. **Validation & Toolchain Check**: Verifies repository root, `Cargo.toml`, legal notices (`LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES`), and reports versions of `rustc`, `cargo`, and `git`.
2. **Format Check**: Executes `cargo fmt --check` to ensure code conforms to repository style.
3. **Smoke Tests**: Executes target smoke tests for `kdft-desktop-core`, `kdft-desktop`, and `kdft-ui`.
4. **Release Compilation**: Compiles optimized binaries: `cargo build --release -p kdft-ui -p kdft-desktop`.
5. **Package Directory Creation**: Allocates a new `dist/kdft-windows-dev-<timestamp>/` directory.
6. **Staging & Blacklist Audit**: Copies `kdft-ui.exe`, `kdft-desktop.exe`, legal notices, and a generated `README.txt`, then runs the automated blacklist audit.
7. **Manifest & SHA-256 Hashes**:
   - Generates `manifest.json` containing component metadata, toolchain info, git provenance, and payload file hashes.
   - Generates `SHA256SUMS.txt` listing SHA-256 hashes of all staged files (including `manifest.json`).
8. **Optional Zip Compression**: If `-Zip` is requested, creates a timestamped `.zip` archive alongside the directory.

---

## 4. Usage Guide

All commands run under PowerShell (`pwsh` or Windows PowerShell 5.1).

### Non-Destructive Validation (Dry-Run)
To syntax-check the script and validate prerequisites, git disclosure, manifest schema, and file exclusion rules without running compilation or creating output files:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package-windows-dev.ps1 -DryRun
```

To test zip creation planning in dry-run mode:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package-windows-dev.ps1 -DryRun -Zip
```

### Full Production Build and Package
To run format checks, smoke tests, compile release binaries, stage files, compute checksums, and create a zip archive:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package-windows-dev.ps1 -Zip
```

### Fast Re-Packaging (Using Pre-Compiled Binaries)
If `target/release/kdft-ui.exe` and `target/release/kdft-desktop.exe` have already been compiled:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package-windows-dev.ps1 -SkipBuild -SkipTests -Zip
```

### Custom Distribution Directory
To place the new package into a custom destination folder:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\package-windows-dev.ps1 -DistRoot "D:\ForensicReleases" -Zip
```

---

## 5. Package Structure

A generated package contains:

```text
dist/kdft-windows-dev-20261016-143000/
├── kdft-ui.exe             # Full browser-based Workbench UI
├── kdft-desktop.exe        # Primary native case/evidence workflow
├── LICENSE                 # Apache-2.0 license
├── NOTICE                  # KDFT copyright notice
├── THIRD_PARTY_NOTICES     # Dependency licenses
├── README.txt              # Component roles, execution guide & safety boundaries
├── manifest.json           # Machine-readable provenance and file manifest
└── SHA256SUMS.txt          # Cryptographic checksums of all package contents
```

If `-Zip` was specified:
```text
dist/kdft-windows-dev-20261016-143000.zip
```

---

## 6. Verification and Checksums

Examiners can verify the package contents on any Windows workstation:

```powershell
# Verify all files match SHA256SUMS.txt
cd dist\kdft-windows-dev-<timestamp>
Get-FileHash -Algorithm SHA256 (Get-ChildItem -File)
```

Or inspect the machine-readable manifest:

```powershell
Get-Content manifest.json | ConvertFrom-Json | Select-Object -ExpandProperty components | Format-List
```
