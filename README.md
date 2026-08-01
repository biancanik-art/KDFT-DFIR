# KDFT-DFIR

KDFT-DFIR is a cross-platform digital-forensics workbench written in Rust. It provides a
local browser interface and a command-line interface for attaching evidence, examining disk
images, indexing file systems, searching content, reviewing parsed artifacts, bookmarking
findings, and producing reports.

KDFT binds its workbench to `127.0.0.1` by default. Evidence sources are opened read-only;
case databases, recovered files, exports, and reports are written only to examiner-selected
output locations.

> KDFT-DFIR is an examination aid. Validate important findings with independent tools and
> preserve the original evidence and acquisition hashes.

## Highlights

- Local-only browser workbench and scriptable CLI
- E01/EWF, raw and split-raw, VHD/VHDX, VMDK, and VDI image readers
- NTFS, FAT12/16/32, and ext2/3/4 browsing and indexing
- NTFS active files, alternate data streams, deleted MFT records, and unallocated space
- File hashing, signature verification, signature carving, and deep text/hex search
- Browser, email, archive, OOXML, identity/network, and Windows artifact processors
- Bookmarks, examiner notes, audit history, and integrity-stamped HTML reports
- Bounded parsing and explicit partial/truncated/error status for damaged evidence

## Download

Release packages are published at
[GitHub Releases](https://github.com/biancanik-art/KDFT-DFIR/releases):

- Windows x64: `kdft-vX.Y.Z-windows-x64.zip`
- Linux x64: `kdft-vX.Y.Z-linux-x64.tar.gz`
- macOS Apple Silicon: `kdft-vX.Y.Z-macos-arm64.tar.gz`
- macOS Intel: `kdft-vX.Y.Z-macos-x64.tar.gz`

Verify downloaded files against `SHA256SUMS.txt` from the same release.

## Run the workbench

Windows:

~~~powershell
.\kdft-ui.exe --port 8780 --open
~~~

Linux or macOS:

~~~bash
chmod +x kdft-ui kdft
./kdft-ui --port 8780 --open
~~~

The macOS release binaries are ad-hoc signed but not notarized. If Gatekeeper preserves the
download quarantine, remove it before first launch:

~~~bash
xattr -d com.apple.quarantine kdft-ui kdft
~~~

## Examiner workflow

1. Create or open a `.kdft.sqlite` case database.
2. Attach a disk image, directory, individual file, or browser-history source.
3. Use **Live browse** for immediate read-only file-system navigation, or select processors
   and run analysis to populate the searchable case index.
4. Review entries and artifact categories, search, and bookmark relevant material.
5. Export selected files or create an HTML report in a new output location.

Reprocessing is transactional: previously committed results are preserved if a later run is
cancelled or fails. Diagnostic messages are written to the case log directory for review.

## Build from source

Install the current stable Rust toolchain from [rustup.rs](https://rustup.rs/), then:

~~~bash
git clone https://github.com/biancanik-art/KDFT-DFIR.git
cd KDFT-DFIR
cargo build --release --locked -p kdft-ui -p kdft-cli
~~~

The resulting programs are:

- `target/release/kdft-ui` — local browser workbench
- `target/release/kdft` — command-line interface

Use `kdft-ui --help` or `kdft --help` for the current options and commands.

## Development checks

~~~bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo doc --workspace --no-deps
~~~

Production crates forbid unsafe Rust. The release workflow repeats formatting, linting,
tests, and dependency auditing before it builds platform packages and publishes checksums.

## Repository layout

- `crates/kdft-case` — case database, evidence readers, indexing, processors, and reports
- `crates/kdft-ui` — local HTTP workbench
- `crates/kdft-cli` — command-line interface
- `crates/*-vendored` — bounded, documented patches to upstream parsers
- `schemas` — case-database schema
- `scripts` — non-destructive demonstration utilities
- `testdata` — small synthetic fixtures used by automated tests

## Security and privacy

KDFT is designed for trusted, offline examination workstations. Keep the workbench bound to
localhost, do not expose its port to another network, and treat all evidence content as
untrusted input. The repository intentionally excludes forensic images, cases, reports, logs,
recovered files, local notes, and build output.

## License

KDFT-DFIR is licensed under the [Apache License 2.0](LICENSE). Vendored components retain
their original licenses and notices; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
