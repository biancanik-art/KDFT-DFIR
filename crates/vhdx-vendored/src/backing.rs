//! Pluggable, positioned backing store for one VHDX container.
//!
//! The reader historically held the **entire image** in a `Vec<u8>` — a 2 TB
//! VHDX meant a 2 TB heap. [`Backing`] generalises that to three positioned-read
//! backings WITHOUT a boxed trait, so the hot read path stays vtable-free (a
//! `match` the compiler can inline, not a dynamic dispatch):
//!
//! - [`Backing::File`] — a loose container file (the bounded path), read with
//!   the OS positioned-read primitive: only the BAT-selected blocks ever touch
//!   RAM, so peak memory no longer scales with image size.
//! - [`Backing::Sub`] — a contiguous sub-range of a larger file (a STORED, i.e.
//!   uncompressed, zip entry sits at a fixed offset inside the archive):
//!   `read_at(buf, off)` preads at `base + off`, clamped to `len`.
//! - [`Backing::Mem`] — an in-RAM buffer (the legacy `from_bytes` path, or a
//!   DEFLATED zip entry inflated to memory once): `read_at` copies from the
//!   slice.
//!
//! All three expose the same cursor-free, thread-safe positioned-read API
//! (`read_at` + `len`), so the open/parse pass reads small structures from their
//! known offsets and the data path reads just the resolved block — never the
//! whole file.

use std::fs::File;
use std::io;
use std::sync::Arc;

/// Fill `buf` from `file` starting at `offset`, returning the bytes read (short
/// only at end of file).
///
/// Uses the OS positioned-read primitive — `pread(2)` on Unix, `seek_read`
/// (a `ReadFile` carrying its own `OVERLAPPED` offset) on Windows — so it takes
/// `&File` and never touches a shared cursor. That makes it safe to call
/// concurrently from many threads on one handle: each call carries its own
/// offset, so there is no read/seek race. Keeps `forbid(unsafe)` (no mmap).
fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;

    let mut total = 0usize;
    while total < buf.len() {
        #[cfg(unix)]
        let res = file.read_at(&mut buf[total..], offset + total as u64);
        #[cfg(windows)]
        let res = file.seek_read(&mut buf[total..], offset + total as u64);
        #[cfg(not(any(unix, windows)))]
        let res: io::Result<usize> = Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "positioned reads unsupported on this platform",
        ));
        match res {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// A positioned, cursor-free reader over one VHDX container's bytes.
///
/// `read_at(buf, offset)` fills `buf` from logical `offset` within the container
/// and returns the byte count (short only at end of container) — never touching
/// a shared cursor, so it is safe to call concurrently through `&self`.
pub enum Backing {
    /// A loose container file: positioned reads go straight to the OS handle.
    File(File),
    /// A contiguous sub-range `[base, base+len)` of a larger shared file.
    Sub {
        /// The backing file (shared; positioned reads carry their own offset).
        file: Arc<File>,
        /// Absolute file offset where this container's bytes begin.
        base: u64,
        /// Length of this container in bytes.
        len: u64,
    },
    /// An in-RAM container (e.g. the legacy `from_bytes` path or an inflated
    /// zip entry).
    Mem(Arc<[u8]>),
}

impl Backing {
    /// Construct a [`Backing::Sub`] over `[base, base+len)` of `file`.
    #[must_use]
    pub fn sub(file: Arc<File>, base: u64, len: u64) -> Self {
        Backing::Sub { file, base, len }
    }

    /// Construct an in-RAM [`Backing::Mem`] from owned bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Self {
        Backing::Mem(bytes.into())
    }

    /// Total length of this container in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Backing::File(f) => f.metadata().map_or(0, |m| m.len()),
            Backing::Sub { len, .. } => *len,
            Backing::Mem(b) => b.len() as u64,
        }
    }

    /// Whether the container is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` from logical `offset` within this container, returning the
    /// bytes read (short only at the container's end). Cursor-free and
    /// thread-safe.
    ///
    /// # Errors
    /// Propagates the underlying I/O error for [`Backing::File`] /
    /// [`Backing::Sub`]; [`Backing::Mem`] never fails.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            Backing::File(f) => pread(f, buf, offset),
            Backing::Sub { file, base, len } => {
                // Clamp the request to this container's window so a Sub never
                // reads past its end into a neighbouring entry. A read starting
                // beyond the window yields 0 (clean EOF), mirroring File/Mem.
                let avail = len.saturating_sub(offset);
                if avail == 0 {
                    return Ok(0);
                }
                let want = (buf.len() as u64).min(avail) as usize;
                pread(file, &mut buf[..want], base + offset)
            }
            Backing::Mem(bytes) => {
                let off = offset.min(bytes.len() as u64) as usize;
                let src = &bytes[off..];
                let n = src.len().min(buf.len());
                buf[..n].copy_from_slice(&src[..n]);
                Ok(n)
            }
        }
    }

    /// Read exactly `len` bytes starting at `offset` into a fresh `Vec`.
    ///
    /// Used by the open/parse pass to pull a small, known-size structure
    /// (a header slot, the region table, the metadata region, the BAT) into a
    /// bounded buffer. The returned `Vec` is short only when the container ends
    /// before `offset + len` (so the caller still range-checks the parse).
    ///
    /// # Errors
    /// Propagates the underlying positioned-read error.
    pub fn read_exact_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_at(&mut buf, offset)?;
        buf.truncate(n);
        Ok(buf)
    }
}

impl std::fmt::Debug for Backing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backing::File(_) => f.debug_struct("File").field("len", &self.len()).finish(),
            Backing::Sub { base, len, .. } => f
                .debug_struct("Sub")
                .field("base", base)
                .field("len", len)
                .finish(),
            Backing::Mem(b) => f.debug_struct("Mem").field("len", &b.len()).finish(),
        }
    }
}
