//! Pure-Rust read-only VHDX container reader.
//!
//! Decodes the MS-VHDX outer container format and exposes a `Read + Seek`
//! interface over the virtual sector stream.
//!
//! # Supported formats
//! - VHDX Version 1 (Windows 8+ / Server 2012+)
//! - Dynamic disks
//! - Fixed disks
//!
//! # Layer
//! CONTAINER — equivalent role to `ewf` for E01 images.

// KDFT vendors the bounded-reader implementation from upstream vhdx-core
// 0.3.0 under the 0.2.1 package version required by disk-forensic 0.8.6.
// Upstream 0.2.1 used std::fs::read(path), retaining the complete VHDX in one
// Vec. This backport preserves the public API while using positioned reads for
// headers, metadata, BAT, dirty-log overlay, and on-demand payload blocks.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod backing;
mod bat;
mod bytes;
mod error;
pub mod header;
mod log;
pub mod metadata;
mod reader;
pub mod region;

pub use backing::Backing;
pub use error::{Result, VhdxError};
pub use reader::VhdxReader;

/// Well-known VHDX file magic (first 8 bytes of every VHDX file).
pub const FILE_MAGIC: &[u8; 8] = b"vhdxfile";
