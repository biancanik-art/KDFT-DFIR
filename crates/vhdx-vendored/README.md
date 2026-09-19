# vhdx-core

[![Crates.io: vhdx-core](https://img.shields.io/crates/v/vhdx-core.svg?label=vhdx-core)](https://crates.io/crates/vhdx-core)
[![Crates.io: vhdx-forensic](https://img.shields.io/crates/v/vhdx-forensic.svg?label=vhdx-forensic)](https://crates.io/crates/vhdx-forensic)
[![Docs.rs](https://img.shields.io/docsrs/vhdx-core)](https://docs.rs/vhdx-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vhdx-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust VHDX (Hyper-V) virtual-disk container library — dynamic, fixed, differencing, and automatic dirty-log recovery.** Decodes the Microsoft VHDX format (Hyper-V, Windows 8+, WSL2, Azure) and hands you a `Read + Seek` view of the virtual sector stream. Zero `unsafe`, no C bindings, no external tools.

> The crate is published as **`vhdx-core`** (the bare `vhdx` name is taken on crates.io) but is **imported as `vhdx`** — your code reads `use vhdx::…`.

```toml
[dependencies]
vhdx-core = "0.2"   # imported as `vhdx`
```

```rust
use vhdx::VhdxReader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = VhdxReader::open("disk.vhdx")?;
println!("{} bytes, {}-byte sectors",
    reader.virtual_disk_size(), reader.logical_sector_size());

// VhdxReader is Read + Seek — drop it into any filesystem/partition crate.
let mut first = vec![0u8; reader.logical_sector_size() as usize];
reader.seek(SeekFrom::Start(0))?;
reader.read_exact(&mut first)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Differencing (child) disks are served from their parent via
`VhdxReader::from_bytes_with_parent`; dirty logs are replayed automatically on
open when the active header carries a non-zero `LogGuid`. An in-memory
constructor (`from_bytes`) is provided for evidence held in RAM.

## Supported formats

| Format | Supported |
|--------|:---------:|
| VHDX Version 1 (Windows 8 / Server 2012+) | ✓ |
| Dynamic disks (sparse, BAT-addressed) | ✓ |
| Fixed disks (pre-allocated) | ✓ |
| Differencing disks (single-level parent chain) | ✓ |
| Log replay (dirty-log recovery) | ✓ |

Currently read-only (a writer is planned). Differencing disks require the parent
image supplied explicitly.

## Separation of duty

`vhdx-core` is the **container reader** — raw decoding only. Forensic
*analysis* (integrity audit, tamper/anomaly findings, in-memory repair) lives in
its sibling **[`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic)**,
exactly as [`vmdk`](https://crates.io/crates/vmdk) pairs with
[`vmdk-forensic`](https://crates.io/crates/vmdk-forensic). Reach for `vhdx-core`
when you need bytes; `vhdx-forensic` when you need findings.

---

[Privacy Policy](https://securityronin.github.io/vhdx-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vhdx-forensic/terms/) · © 2026 Security Ronin Ltd
