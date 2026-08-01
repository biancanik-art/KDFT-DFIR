use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use flate2::read::ZlibDecoder;
use lru::LruCache;

use crate::error::{EwfError, Result};
use crate::ewf2;
use crate::parse::{parse_error2_data, parse_header_text};
use crate::sections::{
    Chunk, ChunkEncoding, EwfFileHeader, EwfVolume, SectionDescriptor, TableEntry,
    DEFAULT_LRU_SIZE, FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE,
};
#[cfg(feature = "verify")]
use crate::types::VerifyResult;
use crate::types::{AcquisitionError, EwfMetadata, StoredHashes};

// ---------------------------------------------------------------------------
// Positioned read (thread-safe, cursor-free)
// ---------------------------------------------------------------------------

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
        let read_offset = offset
            .checked_add(total as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read offset overflow"))?;
        #[cfg(unix)]
        let res = file.read_at(&mut buf[total..], read_offset);
        #[cfg(windows)]
        let res = file.seek_read(&mut buf[total..], read_offset);
        match res {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Segment file discovery
// ---------------------------------------------------------------------------

/// Discover all segment files for an EWF image (E01, L01, Ex01, or Lx01).
///
/// Detects the extension prefix from the input path:
/// - 3-char (v1): `.E01`..`.EZZ`, `.L01`..`.LZZ`
/// - 4-char (v2): `.Ex01`..`.EzZZ`, `.Lx01`..`.LzZZ`
///
/// The directory to glob for sibling segment files of `first`.
///
/// `Path::parent()` returns `Some("")` — not `None` — for a bare filename, so a
/// naive `unwrap_or_else(|| ".")` leaves an empty directory and roots the glob at
/// the filesystem root. Map both the empty and missing cases to the current
/// directory so `ingest <bare.E01>` works from the evidence directory.
fn segment_dir(first: &Path) -> &Path {
    match first.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Returns paths sorted by expected segment order.
fn discover_segments(first: &Path) -> Result<Vec<PathBuf>> {
    let stem = first
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| EwfError::NoSegments(first.display().to_string()))?;
    let parent = segment_dir(first);

    let ext = first.extension().and_then(|e| e.to_str()).unwrap_or("E01");

    let escaped_stem = glob::Pattern::escape(stem);
    let parent_str = parent.display();
    let mut paths: Vec<PathBuf> = Vec::new();

    if ext.len() == 4 {
        // EWF2: 4-char extensions like Ex01, Lx01
        let prefix = ext
            .chars()
            .next()
            .ok_or_else(|| EwfError::NoSegments(first.display().to_string()))?
            .to_ascii_uppercase();
        let lc = prefix.to_ascii_lowercase();
        for pattern in &[
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][x-z][0-9][0-9]"),
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][x-z][A-Za-z][A-Za-z]"),
        ] {
            if let Ok(entries) = glob::glob(pattern) {
                paths.extend(entries.filter_map(std::result::Result::ok));
            }
        }
    } else {
        // EWF v1: 3-char extensions like E01, L01
        let prefix = ext
            .chars()
            .next()
            .ok_or_else(|| EwfError::NoSegments(first.display().to_string()))?
            .to_ascii_uppercase();
        let lc = prefix.to_ascii_lowercase();
        for pattern in &[
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][0-9][0-9]"),
            format!("{parent_str}/{escaped_stem}.[{prefix}{lc}][A-Za-z][A-Za-z]"),
        ] {
            if let Ok(entries) = glob::glob(pattern) {
                paths.extend(entries.filter_map(std::result::Result::ok));
            }
        }
    }

    if paths.is_empty() {
        return Err(EwfError::NoSegments(first.display().to_string()));
    }

    // Sort by extension for natural segment order
    paths.sort_by(|a, b| {
        let ext_a = a.extension().and_then(|e| e.to_str()).unwrap_or("");
        let ext_b = b.extension().and_then(|e| e.to_str()).unwrap_or("");
        ext_a.to_ascii_uppercase().cmp(&ext_b.to_ascii_uppercase())
    });

    Ok(paths)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Maximum section data size we'll read into memory (`DoS` guard).
const MAX_SECTION_DATA_SIZE: u64 = 1_000_000;

/// Maximum bytes accepted from a zlib-decompressed stream (deflate-bomb guard).
/// EWF header metadata is plain text; 10 MB is already extremely generous.
const MAX_DECOMPRESSED_SIZE: u64 = 10 * MAX_SECTION_DATA_SIZE;

/// Maximum table entries we'll allocate for (`DoS` guard).
/// 4M entries × 32 KB chunks = 128 TB image — far beyond any real forensic image.
const MAX_TABLE_ENTRIES: usize = 4_000_000;

/// Maximum chunk size in bytes. EWF typically uses 32 KB; 128 MB is a generous cap.
const MAX_CHUNK_SIZE: u64 = 128 * 1024 * 1024;

/// Maximum cumulative chunk count for an acquisition. 64M 32-KiB chunks
/// covers decoded media up to 2 TiB while retaining a finite allocation cap.
/// Bound descriptor storage while allowing chunk counts required by large
/// acquisition images.
const MAX_CHUNK_COUNT: usize = 64_000_000;

/// Bound caller-selected cache capacity before `LruCache` reserves storage.
const MAX_CACHE_CHUNKS: usize = 4_096;

/// Maximum number of section descriptors in one segment. Normal EWF segments
/// contain only a handful; this keeps a malicious backward/forward chain from
/// consuming unbounded memory even when every descriptor is otherwise valid.
const MAX_SECTION_DESCRIPTORS: usize = 65_536;

fn v1_section_data_range(desc: &SectionDescriptor, file_len: u64) -> Result<(u64, u64)> {
    let descriptor_size = SECTION_DESCRIPTOR_SIZE as u64;
    // Some producers encode terminal markers with a zero section size even
    // though the descriptor itself is present. Treat only those data-less
    // markers as descriptor-sized; every data-bearing section must declare its
    // complete range.
    let section_size =
        if desc.section_size == 0 && matches!(desc.section_type.as_str(), "done" | "next") {
            descriptor_size
        } else {
            desc.section_size
        };
    if section_size < descriptor_size {
        return Err(EwfError::Parse(format!(
            "EWF section '{}' at {:#x} is shorter than its descriptor: {} bytes",
            desc.section_type, desc.offset, desc.section_size
        )));
    }
    let data_start = desc
        .offset
        .checked_add(descriptor_size)
        .ok_or_else(|| EwfError::Parse("EWF section data offset overflow".to_string()))?;
    let section_end = desc.offset.checked_add(section_size).ok_or_else(|| {
        EwfError::Parse(format!(
            "EWF section '{}' at {:#x} range overflows",
            desc.section_type, desc.offset
        ))
    })?;
    if section_end > file_len {
        return Err(EwfError::Parse(format!(
            "EWF section '{}' range {:#x}..{section_end:#x} exceeds segment length {file_len:#x}",
            desc.section_type, desc.offset
        )));
    }
    Ok((data_start, section_end))
}

#[cfg(test)]
mod kdft_large_acquisition_tests {
    use super::MAX_CHUNK_COUNT;

    #[test]
    fn accepts_chunk_count_for_500gb_ftk_acquisition() {
        // 1,000,215,216 sectors / 64 sectors per 32-KiB chunk, rounded up.
        let chunks = 1_000_215_216_usize.div_ceil(64);
        assert_eq!(chunks, 15_628_363);
        assert!(chunks <= MAX_CHUNK_COUNT);
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn rejects_device_geometry_multiplication_overflow() {
        let text = format!("2\nmain\nb\tsc\tts\n{}\t2\t2\n", u64::MAX);
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut chunk_size = 0;
        let mut total_size = 0;
        let error = parse_ewf2_device_info(&bytes, &mut chunk_size, &mut total_size).unwrap_err();
        assert!(error.to_string().contains("chunk size overflow"));
    }

    #[test]
    fn rejects_logical_size_without_chunk_table_coverage() {
        let error = validate_chunk_layout(&[], &[], 32_768, 1).unwrap_err();
        assert!(error.to_string().contains("chunk tables cover only 0"));
    }

    #[test]
    fn rejects_unbounded_cache_capacity_before_opening_files() {
        let paths = [PathBuf::from("not-opened.E01")];
        let error =
            EwfReader::open_segments_with_cache_size(&paths, MAX_CACHE_CHUNKS + 1).unwrap_err();
        assert!(error.to_string().contains("cache size"));
    }

    #[test]
    fn rejects_v1_section_range_past_segment_end() {
        let descriptor = SectionDescriptor {
            section_type: "table".to_string(),
            next: 0,
            section_size: 100,
            offset: 950,
        };
        let error = v1_section_data_range(&descriptor, 1_000).unwrap_err();
        assert!(error.to_string().contains("exceeds segment length"));
    }

    #[test]
    fn accepts_zero_sized_terminal_v1_marker_only() {
        let done = SectionDescriptor {
            section_type: "done".to_string(),
            next: 0,
            section_size: 0,
            offset: 100,
        };
        assert_eq!(v1_section_data_range(&done, 176).unwrap(), (176, 176));

        let table = SectionDescriptor {
            section_type: "table".to_string(),
            ..done
        };
        assert!(v1_section_data_range(&table, 176).is_err());
    }
}

/// Default EWF2 chunk size when `device_info` is absent or unparseable.
const DEFAULT_V2_CHUNK_SIZE: u64 = 32768;

/// Validate that segment numbers are sequential (1, 2, 3, ...) and reorder
/// file handles to match. Shared by both v1 and v2 reader paths.
pub(crate) fn validate_and_reorder_segments(
    segments: Vec<File>,
    segment_numbers: Vec<u32>,
) -> Result<Vec<File>> {
    if segments.len() != segment_numbers.len() {
        return Err(EwfError::Parse(format!(
            "opened {} segment file(s), but parsed {} segment number(s)",
            segments.len(),
            segment_numbers.len()
        )));
    }
    let mut indexed: Vec<(usize, u32)> = segment_numbers.into_iter().enumerate().collect();
    indexed.sort_by_key(|&(_, seg)| seg);

    // Validate sequential segment numbers (1, 2, 3, ...)
    for (expected_pos, &(_, seg_num)) in indexed.iter().enumerate() {
        let expected = u32::try_from(expected_pos + 1)
            .map_err(|_| EwfError::Parse("segment count exceeds u32".to_string()))?;
        if seg_num != expected {
            return Err(EwfError::SegmentGap {
                expected,
                got: seg_num,
            });
        }
    }

    // Reorder file handles to match segment order
    let mut slots: Vec<Option<File>> = segments.into_iter().map(Some).collect();
    let mut ordered = Vec::with_capacity(slots.len());
    for &(idx, _) in &indexed {
        let file = slots
            .get_mut(idx)
            .and_then(Option::take)
            .ok_or_else(|| EwfError::Parse("invalid or duplicate segment index".to_string()))?;
        ordered.push(file);
    }
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// EWF2 helpers
// ---------------------------------------------------------------------------

/// Walk the EWF2 backward-linked section list and return descriptors in
/// forward (file) order.
///
/// EWF2 layout per section: `[data bytes][descriptor 64 B]`.  The terminal
/// section (Done/Next) sits at the very end of the file with `data_size = 0`.
/// Each descriptor's `previous_offset` is the absolute file offset of the
/// preceding descriptor; the first section has `previous_offset = 0`.
fn collect_ewf2_descriptors(
    file: &mut File,
    file_len: u64,
) -> Result<Vec<ewf2::Ewf2SectionDescriptor>> {
    const DS: u64 = ewf2::SECTION_DESCRIPTOR_SIZE as u64;
    if file_len < DS {
        return Ok(Vec::new());
    }
    let mut descriptors = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut desc_offset = file_len - DS;

    loop {
        if descriptors.len() >= MAX_SECTION_DESCRIPTORS {
            return Err(EwfError::Parse(format!(
                "EWF2 section descriptor count exceeds {MAX_SECTION_DESCRIPTORS}"
            )));
        }
        if !visited.insert(desc_offset) {
            return Err(EwfError::Parse(
                "EWF2 section descriptor list contains a cycle".to_string(),
            ));
        }
        file.seek(SeekFrom::Start(desc_offset))?;
        let mut buf = [0u8; ewf2::SECTION_DESCRIPTOR_SIZE];
        file.read_exact(&mut buf)?;
        let desc = ewf2::Ewf2SectionDescriptor::parse(&buf, desc_offset)?;
        if desc.descriptor_size != ewf2::SECTION_DESCRIPTOR_SIZE as u32 {
            return Err(EwfError::Parse(format!(
                "EWF2 descriptor at {desc_offset:#x} declares unsupported size {}",
                desc.descriptor_size
            )));
        }
        if desc.data_size > desc_offset {
            return Err(EwfError::Parse(format!(
                "EWF2 section data underflows its descriptor: offset {desc_offset:#x}, size {:#x}",
                desc.data_size
            )));
        }
        let data_offset = desc_offset - desc.data_size;
        if data_offset < ewf2::FILE_HEADER_SIZE as u64 {
            return Err(EwfError::Parse(format!(
                "EWF2 section data at {data_offset:#x} overlaps the file header"
            )));
        }
        let prev = desc.previous_offset;
        descriptors.push(desc);
        if prev == 0 {
            break;
        }
        if prev >= file_len {
            return Err(EwfError::Parse(format!(
                "EWF2 previous_offset {prev:#x} exceeds file length {file_len:#x}"
            )));
        }
        if prev >= desc_offset {
            return Err(EwfError::Parse(format!(
                "EWF2 previous_offset {prev:#x} does not point backward from {desc_offset:#x}"
            )));
        }
        let prev_end = prev.checked_add(DS).ok_or_else(|| {
            EwfError::Parse("EWF2 previous descriptor range overflows".to_string())
        })?;
        if prev_end > data_offset {
            return Err(EwfError::Parse(format!(
                "EWF2 previous descriptor {prev:#x} overlaps section data beginning at {data_offset:#x}"
            )));
        }
        desc_offset = prev;
    }

    descriptors.reverse();
    Ok(descriptors)
}

/// Decompress EWF2 metadata according to the segment header. Some producers
/// leave metadata sections uncompressed, so a method-specific stream signature
/// is required before decoding.
fn maybe_decompress_ewf2_metadata(raw: &[u8], method: ewf2::CompressionMethod) -> Result<Vec<u8>> {
    let decoder: Option<Box<dyn Read + '_>> = match method {
        ewf2::CompressionMethod::Zlib if raw.starts_with(&[0x78]) => {
            Some(Box::new(ZlibDecoder::new(raw)))
        }
        ewf2::CompressionMethod::Bzip2 if raw.starts_with(b"BZh") => {
            Some(Box::new(bzip2_rs::DecoderReader::new(raw)))
        }
        ewf2::CompressionMethod::None
        | ewf2::CompressionMethod::Zlib
        | ewf2::CompressionMethod::Bzip2 => None,
    };

    let Some(mut decoder) = decoder else {
        return Ok(raw.to_vec());
    };
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_SIZE + 1)
        .read_to_end(&mut out)
        .map_err(|e| EwfError::Parse(format!("EWF2 metadata decompression failed: {e}")))?;
    if out.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(EwfError::Parse(format!(
            "EWF2 metadata expands beyond {MAX_DECOMPRESSED_SIZE} bytes"
        )));
    }
    Ok(out)
}

fn append_ewf2_chunks(
    chunks: &mut Vec<Chunk>,
    first_chunk: u64,
    entries: &[ewf2::Ewf2TableEntry],
    segment_idx: usize,
    method: ewf2::CompressionMethod,
) -> Result<()> {
    let expected_first = chunks.len() as u64;
    if first_chunk != expected_first {
        return Err(EwfError::Parse(format!(
            "EWF2 sector table starts at chunk {first_chunk}, expected {expected_first}"
        )));
    }
    if chunks
        .len()
        .checked_add(entries.len())
        .is_none_or(|count| count > MAX_CHUNK_COUNT)
    {
        return Err(EwfError::Parse(format!(
            "cumulative EWF2 chunk count exceeds maximum {MAX_CHUNK_COUNT}"
        )));
    }

    for entry in entries {
        let (encoding, checksummed) = if entry.is_pattern_fill() {
            if entry.chunk_data_size != 0 {
                return Err(EwfError::Parse(
                    "EWF2 pattern-fill chunk has non-zero data size".to_string(),
                ));
            }
            (
                ChunkEncoding::Pattern(entry.chunk_data_offset.to_le_bytes()),
                false,
            )
        } else if entry.is_compressed() {
            if entry.is_checksumed() {
                return Err(EwfError::Parse(
                    "EWF2 compressed chunk unexpectedly has CHECKSUMED flag".to_string(),
                ));
            }
            if entry.chunk_data_size == 0 {
                return Err(EwfError::Parse(
                    "EWF2 compressed chunk has zero data size".to_string(),
                ));
            }
            let encoding = match method {
                ewf2::CompressionMethod::Zlib => ChunkEncoding::Zlib,
                ewf2::CompressionMethod::Bzip2 => ChunkEncoding::Bzip2,
                ewf2::CompressionMethod::None => {
                    return Err(EwfError::Parse(
                        "EWF2 chunk is marked compressed but header method is none".to_string(),
                    ));
                }
            };
            (encoding, false)
        } else {
            (ChunkEncoding::Raw, entry.is_checksumed())
        };

        chunks.push(Chunk {
            segment_idx,
            compressed: !matches!(encoding, ChunkEncoding::Raw),
            encoding,
            checksummed,
            offset: entry.chunk_data_offset,
            size: u64::from(entry.chunk_data_size),
        });
    }
    Ok(())
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for chunk in data.chunks(5_552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

fn decode_compressed_chunk(
    mut decoder: impl Read,
    page: &mut [u8],
    required: usize,
    chunk_id: usize,
) -> Result<()> {
    let mut total = 0usize;
    while total < page.len() {
        match decoder.read(&mut page[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Err(EwfError::Decompression(e.to_string())),
        }
    }
    if total < required {
        return Err(EwfError::Decompression(format!(
            "chunk {chunk_id} decoded to {total} bytes, expected at least {required}"
        )));
    }
    if total == page.len() {
        let mut extra = [0u8; 1];
        match decoder.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => {
                return Err(EwfError::Decompression(format!(
                    "chunk {chunk_id} expands beyond the configured chunk size"
                )));
            }
            Err(e) => return Err(EwfError::Decompression(e.to_string())),
        }
    }
    Ok(())
}

fn validate_chunk_layout(
    segments: &[File],
    chunks: &[Chunk],
    chunk_size: u64,
    total_size: u64,
) -> Result<()> {
    if chunk_size == 0 {
        return Err(EwfError::InvalidChunkSize(0));
    }
    let capacity = u64::try_from(chunks.len())
        .ok()
        .and_then(|count| count.checked_mul(chunk_size))
        .ok_or_else(|| EwfError::Parse("logical chunk capacity overflow".to_string()))?;
    if total_size > capacity {
        return Err(EwfError::Parse(format!(
            "image declares {total_size} logical bytes but its chunk tables cover only {capacity}"
        )));
    }
    let expected_chunks_u64 = total_size.div_ceil(chunk_size);
    let expected_chunks = usize::try_from(expected_chunks_u64)
        .map_err(|_| EwfError::Parse("logical chunk count exceeds usize".to_string()))?;
    if chunks.len() != expected_chunks {
        return Err(EwfError::Parse(format!(
            "chunk tables contain {} entries but logical media requires {expected_chunks}",
            chunks.len()
        )));
    }

    let compressed_overhead = (chunk_size / 8).max(1024 * 1024);
    let max_stored_size = chunk_size
        .checked_add(compressed_overhead)
        .ok_or_else(|| EwfError::Parse("stored chunk size limit overflow".to_string()))?;

    for (chunk_id, chunk) in chunks.iter().enumerate() {
        if matches!(chunk.encoding, ChunkEncoding::Pattern(_)) {
            continue;
        }
        let file = segments.get(chunk.segment_idx).ok_or_else(|| {
            EwfError::Parse(format!(
                "chunk {chunk_id} references missing segment {}",
                chunk.segment_idx
            ))
        })?;
        if chunk.size == 0 {
            return Err(EwfError::Parse(format!(
                "chunk {chunk_id} has zero stored size"
            )));
        }
        if chunk.size > max_stored_size {
            return Err(EwfError::Parse(format!(
                "chunk {chunk_id} stored size {} exceeds safe limit {max_stored_size}",
                chunk.size
            )));
        }
        if matches!(chunk.encoding, ChunkEncoding::Raw) {
            let checksum_bytes = if chunk.checksummed { 4 } else { 0 };
            let data_size = chunk.size.checked_sub(checksum_bytes).ok_or_else(|| {
                EwfError::Parse(format!("chunk {chunk_id} is shorter than its checksum"))
            })?;
            if data_size > chunk_size {
                return Err(EwfError::Parse(format!(
                    "raw chunk {chunk_id} stores {data_size} data bytes for a {chunk_size}-byte chunk"
                )));
            }
        }
        let end = chunk
            .offset
            .checked_add(chunk.size)
            .ok_or_else(|| EwfError::Parse(format!("chunk {chunk_id} file range overflows")))?;
        let file_len = file.metadata()?.len();
        if end > file_len {
            return Err(EwfError::Parse(format!(
                "chunk {chunk_id} range {}..{end} exceeds segment length {file_len}",
                chunk.offset
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EwfReader - main public API
// ---------------------------------------------------------------------------

/// A reader for Expert Witness Format (E01/EWF) forensic disk images.
///
/// Implements `Read` and `Seek` over the logical disk image stored across
/// one or more `.E01`/`.E02`/... segment files.
///
/// # Example
/// ```no_run
/// use std::io::Read;
/// let mut reader = ewf::EwfReader::open("disk.E01").unwrap();
/// let mut buf = [0u8; 512];
/// reader.read_exact(&mut buf).unwrap(); // read first sector
/// ```
pub struct EwfReader {
    // Note: LruCache does not implement Debug, so we cannot derive Debug.
    // We provide a manual impl below.
    /// Opened segment file handles.
    segments: Vec<File>,
    /// Flat chunk table: chunk[i] covers logical bytes [i*`chunk_size`, (i+1)*`chunk_size`).
    chunks: Vec<Chunk>,
    /// Chunk size in bytes (typically 32 KB).
    chunk_size: u64,
    /// Total logical image size in bytes.
    total_size: u64,
    /// Current read position (for Read + Seek).
    position: u64,
    /// LRU cache: `chunk_id` -> decompressed chunk data. `Mutex`-guarded so the
    /// reader can serve positioned reads through a shared `&self` from many
    /// threads — the cache is the only interior mutation on the read path.
    cache: Mutex<LruCache<usize, Vec<u8>>>,
    /// MD5 from hash/digest section (16 bytes), if present.
    stored_md5: Option<[u8; 16]>,
    /// SHA-1 from digest section (20 bytes), if present.
    stored_sha1: Option<[u8; 20]>,
    /// Case and acquisition metadata from header sections.
    metadata: EwfMetadata,
    /// Sectors with read errors during acquisition (from error2 section).
    acquisition_errors: Vec<AcquisitionError>,
}

impl EwfReader {
    /// Open an EWF image from a path to the first segment file (e.g. `image.E01`).
    ///
    /// Automatically discovers and opens all additional segment files.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let paths = discover_segments(path.as_ref())?;
        Self::open_segments(&paths)
    }

    /// Open an EWF image with a custom LRU cache size.
    ///
    /// `cache_size` is the number of decompressed chunks to keep in memory.
    /// Each chunk is typically 32 KB, so 100 chunks ≈ 3.2 MB, 1000 ≈ 32 MB.
    pub fn open_with_cache_size<P: AsRef<Path>>(path: P, cache_size: usize) -> Result<Self> {
        let paths = discover_segments(path.as_ref())?;
        Self::open_segments_with_cache_size(&paths, cache_size)
    }

    /// Open an EWF image from explicit segment file paths (must be in order).
    pub fn open_segments(paths: &[PathBuf]) -> Result<Self> {
        Self::open_segments_with_cache_size(paths, DEFAULT_LRU_SIZE)
    }

    /// Open from explicit segment paths with a custom LRU cache size.
    pub fn open_segments_with_cache_size(paths: &[PathBuf], cache_size: usize) -> Result<Self> {
        if paths.is_empty() {
            return Err(EwfError::NoSegments("empty path list".into()));
        }
        if cache_size > MAX_CACHE_CHUNKS {
            return Err(EwfError::Parse(format!(
                "cache size {cache_size} exceeds maximum {MAX_CACHE_CHUNKS} chunks"
            )));
        }

        // Peek at the first 8 bytes to determine format version
        {
            let mut probe = File::open(&paths[0])?;
            let mut sig = [0u8; 8];
            probe.read_exact(&mut sig)?;
            if sig == ewf2::EVF2_SIGNATURE || sig == ewf2::LEF2_SIGNATURE {
                return Self::open_segments_v2(paths, cache_size);
            }
        }

        // EWF v1 path
        // Open all segment files and parse file headers
        let mut segments = Vec::with_capacity(paths.len());
        let mut headers = Vec::with_capacity(paths.len());
        for path in paths {
            let mut f = File::open(path)?;
            let mut hdr_buf = [0u8; FILE_HEADER_SIZE];
            f.read_exact(&mut hdr_buf)?;
            headers.push(EwfFileHeader::parse(&hdr_buf)?);
            segments.push(f);
        }

        let segment_numbers: Vec<u32> = headers
            .iter()
            .map(|h| u32::from(h.segment_number))
            .collect();
        let mut ordered_segments = validate_and_reorder_segments(segments, segment_numbers)?;

        // Walk section descriptors in each segment
        let mut chunk_size: u64 = 0;
        let mut total_size: u64 = 0;
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut stored_md5: Option<[u8; 16]> = None;
        let mut stored_sha1: Option<[u8; 20]> = None;
        let mut metadata = EwfMetadata::default();
        let mut acquisition_errors: Vec<AcquisitionError> = Vec::new();

        for (seg_idx, file) in ordered_segments.iter_mut().enumerate() {
            let mut desc_offset: u64 = FILE_HEADER_SIZE as u64;
            let mut descriptors = Vec::new();
            let mut visited = std::collections::HashSet::new();

            let file_len = file.seek(SeekFrom::End(0))?;
            loop {
                if descriptors.len() >= MAX_SECTION_DESCRIPTORS {
                    return Err(EwfError::Parse(format!(
                        "EWF section descriptor count exceeds {MAX_SECTION_DESCRIPTORS}"
                    )));
                }
                if !visited.insert(desc_offset) {
                    return Err(EwfError::Parse(
                        "EWF section descriptor list contains a cycle".to_string(),
                    ));
                }
                let chain_end = desc_offset
                    .checked_add(SECTION_DESCRIPTOR_SIZE as u64)
                    .ok_or_else(|| EwfError::Parse("EWF descriptor offset overflow".to_string()))?;
                if chain_end > file_len {
                    log::debug!("truncated chain at {desc_offset}, EOF {file_len}");
                    break;
                }

                file.seek(SeekFrom::Start(desc_offset))?;
                let mut desc_buf = [0u8; SECTION_DESCRIPTOR_SIZE];
                file.read_exact(&mut desc_buf)?;
                let desc = SectionDescriptor::parse(&desc_buf, desc_offset)?;
                v1_section_data_range(&desc, file_len)?;
                let next = desc.next;
                descriptors.push(desc);

                if next == 0 {
                    break;
                }
                if next <= desc_offset {
                    return Err(EwfError::Parse(format!(
                        "EWF next section offset {next:#x} does not advance from {desc_offset:#x}"
                    )));
                }
                desc_offset = next;
            }

            // Prefer "table" over "table2"
            let has_table = descriptors.iter().any(|d| d.section_type == "table");
            let table_type = if has_table { "table" } else { "table2" };

            // Find the sectors data range for table-offset validation and final
            // compressed-chunk size recovery.
            let sectors_data_range = descriptors
                .iter()
                .find(|d| d.section_type == "sectors")
                .map(|d| v1_section_data_range(d, file_len))
                .transpose()?;

            for desc in &descriptors {
                match desc.section_type.as_str() {
                    "volume" | "disk" => {
                        let (data_offset, section_end) = v1_section_data_range(desc, file_len)?;
                        if section_end - data_offset < 94 {
                            return Err(EwfError::Parse(format!(
                                "EWF {} section is too short for volume metadata",
                                desc.section_type
                            )));
                        }
                        let mut vol_buf = [0u8; 94];
                        file.seek(SeekFrom::Start(data_offset))?;
                        file.read_exact(&mut vol_buf)?;
                        let vol = EwfVolume::parse(&vol_buf)?;
                        let cs = vol.chunk_size()?;
                        if cs > MAX_CHUNK_SIZE {
                            return Err(EwfError::InvalidChunkSize(
                                cs.min(u64::from(u32::MAX)) as u32
                            ));
                        }
                        if vol.chunk_count as usize > MAX_CHUNK_COUNT {
                            return Err(EwfError::Parse(format!(
                                "volume chunk_count {} exceeds maximum {MAX_CHUNK_COUNT}",
                                vol.chunk_count
                            )));
                        }
                        chunk_size = cs;
                        total_size = vol.total_size()?;
                        if total_size == 0 {
                            total_size = chunk_size
                                .checked_mul(u64::from(vol.chunk_count))
                                .ok_or_else(|| {
                                    EwfError::Parse("EWF logical size overflow".to_string())
                                })?;
                        }
                        // Do not reserve the header-declared count eagerly. Real 500-GB
                        // acquisitions commonly declare ~15.6M chunks, and the table
                        // sections below are the authoritative data that grow this vector.
                    }
                    t if t == table_type => {
                        let (data_offset, section_end) = v1_section_data_range(desc, file_len)?;
                        let section_data_size = section_end - data_offset;
                        if section_data_size < 24 {
                            return Err(EwfError::Parse(
                                "EWF table section is shorter than its header".to_string(),
                            ));
                        }
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut tbl_hdr = [0u8; 24];
                        file.read_exact(&mut tbl_hdr)?;

                        let entry_count =
                            u32::from_le_bytes([tbl_hdr[0], tbl_hdr[1], tbl_hdr[2], tbl_hdr[3]])
                                as usize;
                        if entry_count > MAX_TABLE_ENTRIES {
                            return Err(EwfError::Parse(format!(
                                "table entry count {entry_count} exceeds maximum {MAX_TABLE_ENTRIES}"
                            )));
                        }
                        if chunks
                            .len()
                            .checked_add(entry_count)
                            .is_none_or(|count| count > MAX_CHUNK_COUNT)
                        {
                            return Err(EwfError::Parse(format!(
                                "cumulative table chunk count exceeds maximum {MAX_CHUNK_COUNT}"
                            )));
                        }
                        let base_offset = u64::from_le_bytes([
                            tbl_hdr[8],
                            tbl_hdr[9],
                            tbl_hdr[10],
                            tbl_hdr[11],
                            tbl_hdr[12],
                            tbl_hdr[13],
                            tbl_hdr[14],
                            tbl_hdr[15],
                        ]);

                        let entries_bytes = entry_count.checked_mul(4).ok_or_else(|| {
                            EwfError::Parse("EWF table entry byte length overflow".to_string())
                        })?;
                        let required_table_size =
                            24usize.checked_add(entries_bytes).ok_or_else(|| {
                                EwfError::Parse("EWF table size overflow".to_string())
                            })?;
                        let required_table_size_u64 =
                            u64::try_from(required_table_size).map_err(|_| {
                                EwfError::Parse("EWF table size exceeds u64".to_string())
                            })?;
                        if required_table_size_u64 > section_data_size {
                            return Err(EwfError::Parse(format!(
                                "EWF table needs {required_table_size} bytes but section has {section_data_size}"
                            )));
                        }
                        let entries_offset = data_offset.checked_add(24).ok_or_else(|| {
                            EwfError::Parse("EWF table entry offset overflow".to_string())
                        })?;
                        file.seek(SeekFrom::Start(entries_offset))?;
                        let mut entries_buf = vec![0u8; entries_bytes];
                        file.read_exact(&mut entries_buf)?;

                        let table_first_chunk = chunks.len();
                        let mut prev_offset: Option<u64> = None;
                        for i in 0..entry_count {
                            let entry = TableEntry::parse(&entries_buf[i * 4..(i + 1) * 4])?;
                            let abs_offset = u64::from(entry.chunk_offset)
                                .checked_add(base_offset)
                                .ok_or_else(|| {
                                    EwfError::Parse("EWF table chunk offset overflow".to_string())
                                })?;
                            if let Some((sectors_start, sectors_end)) = sectors_data_range {
                                if abs_offset < sectors_start || abs_offset >= sectors_end {
                                    return Err(EwfError::Parse(format!(
                                        "EWF table chunk offset {abs_offset:#x} is outside sectors data range {sectors_start:#x}..{sectors_end:#x}"
                                    )));
                                }
                            }

                            if let Some(po) = prev_offset {
                                if abs_offset <= po {
                                    return Err(EwfError::Parse(format!(
                                        "EWF table chunk offsets are not strictly increasing: {po} then {abs_offset}"
                                    )));
                                }
                                if let Some(prev_chunk) = chunks.last_mut() {
                                    if prev_chunk.compressed {
                                        prev_chunk.size = abs_offset - po;
                                    }
                                }
                            }

                            chunks.push(Chunk {
                                segment_idx: seg_idx,
                                compressed: entry.compressed,
                                encoding: if entry.compressed {
                                    ChunkEncoding::Zlib
                                } else {
                                    ChunkEncoding::Raw
                                },
                                checksummed: false,
                                offset: abs_offset,
                                size: chunk_size,
                            });

                            prev_offset = Some(abs_offset);
                        }

                        // Back-fill last compressed chunk from sectors boundary
                        if let Some((_, end)) = sectors_data_range {
                            if chunks.len() > table_first_chunk {
                                if let Some(last) = chunks.last_mut() {
                                    if last.compressed {
                                        let actual =
                                            end.checked_sub(last.offset).ok_or_else(|| {
                                                EwfError::Parse(
                                                    "EWF final chunk begins beyond sectors data"
                                                        .to_string(),
                                                )
                                            })?;
                                        if actual == 0 {
                                            return Err(EwfError::Parse(
                                                "EWF final compressed chunk has zero stored size"
                                                    .to_string(),
                                            ));
                                        }
                                        last.size = actual;
                                    }
                                }
                            }
                        }
                    }
                    "hash" => {
                        let (data_offset, section_end) = v1_section_data_range(desc, file_len)?;
                        if section_end - data_offset < 16 {
                            return Err(EwfError::Parse(
                                "EWF hash section is shorter than its MD5 value".to_string(),
                            ));
                        }
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut hash_buf = [0u8; 16];
                        file.read_exact(&mut hash_buf)?;
                        if stored_md5.is_none() {
                            stored_md5 = Some(hash_buf);
                        }
                        log::debug!("parsed hash section: MD5 = {hash_buf:02x?}");
                    }
                    "digest" => {
                        let (data_offset, section_end) = v1_section_data_range(desc, file_len)?;
                        if section_end - data_offset < 36 {
                            return Err(EwfError::Parse(
                                "EWF digest section is shorter than its hash values".to_string(),
                            ));
                        }
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut digest_buf = [0u8; 36];
                        file.read_exact(&mut digest_buf)?;
                        let mut md5 = [0u8; 16];
                        let mut sha1 = [0u8; 20];
                        md5.copy_from_slice(&digest_buf[0..16]);
                        sha1.copy_from_slice(&digest_buf[16..36]);
                        stored_md5 = Some(md5);
                        stored_sha1 = Some(sha1);
                        log::debug!("parsed digest section: MD5 = {md5:02x?}, SHA-1 = {sha1:02x?}");
                    }
                    "header" if metadata.case_number.is_none() && metadata.os_version.is_none() => {
                        let (data_offset, section_end) = v1_section_data_range(desc, file_len)?;
                        let data_size = section_end - data_offset;
                        if data_size > 0 && data_size < MAX_SECTION_DATA_SIZE {
                            file.seek(SeekFrom::Start(data_offset))?;
                            let data_size = usize::try_from(data_size).map_err(|_| {
                                EwfError::Parse("EWF header size exceeds usize".to_string())
                            })?;
                            let mut compressed = vec![0u8; data_size];
                            file.read_exact(&mut compressed)?;
                            // Limit decompressed output — a crafted stream could expand 1 MB
                            // compressed input into gigabytes (deflate bomb).
                            let mut decompressed = Vec::new();
                            let mut limited = std::io::Read::take(
                                flate2::read::ZlibDecoder::new(&compressed[..]),
                                MAX_DECOMPRESSED_SIZE + 1,
                            );
                            std::io::Read::read_to_end(&mut limited, &mut decompressed).map_err(
                                |error| {
                                    EwfError::Parse(format!(
                                        "EWF header metadata decompression failed: {error}"
                                    ))
                                },
                            )?;
                            if decompressed.len() as u64 > MAX_DECOMPRESSED_SIZE {
                                return Err(EwfError::Parse(format!(
                                    "EWF header metadata expands beyond {MAX_DECOMPRESSED_SIZE} bytes"
                                )));
                            }
                            let text = String::from_utf8_lossy(&decompressed);
                            parse_header_text(&text, &mut metadata);
                        }
                    }
                    "error2" => {
                        let (data_offset, section_end) = v1_section_data_range(desc, file_len)?;
                        let data_size = section_end - data_offset;
                        if data_size > 0 && data_size < MAX_SECTION_DATA_SIZE {
                            file.seek(SeekFrom::Start(data_offset))?;
                            let data_size = usize::try_from(data_size).map_err(|_| {
                                EwfError::Parse("EWF error table size exceeds usize".to_string())
                            })?;
                            let mut buf = vec![0u8; data_size];
                            file.read_exact(&mut buf)?;
                            acquisition_errors = parse_error2_data(&buf);
                            log::debug!(
                                "parsed error2 section: {} entries",
                                acquisition_errors.len()
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        if chunk_size == 0 {
            return Err(EwfError::MissingVolume);
        }

        validate_chunk_layout(&ordered_segments, &chunks, chunk_size, total_size)?;

        let cache = Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
        ));

        Ok(Self {
            segments: ordered_segments,
            chunks,
            chunk_size,
            total_size,
            position: 0,
            cache,
            stored_md5,
            stored_sha1,
            metadata,
            acquisition_errors,
        })
    }

    /// Open EWF2 (Ex01/Lx01) segments.
    fn open_segments_v2(paths: &[PathBuf], cache_size: usize) -> Result<Self> {
        // Open all segment files and parse v2 headers
        let mut segments = Vec::with_capacity(paths.len());
        let mut v2_headers = Vec::with_capacity(paths.len());
        for path in paths {
            let mut f = File::open(path)?;
            let mut hdr_buf = [0u8; ewf2::FILE_HEADER_SIZE];
            f.read_exact(&mut hdr_buf)?;
            v2_headers.push(ewf2::Ewf2FileHeader::parse(&hdr_buf)?);
            segments.push(f);
        }

        let mut ordered_segments = validate_and_reorder_segments(
            segments,
            v2_headers.iter().map(|h| h.segment_number).collect(),
        )?;

        let first_header = v2_headers
            .first()
            .ok_or_else(|| EwfError::NoSegments("empty EWF2 header list".to_string()))?;
        if first_header.major_version != 2 {
            return Err(EwfError::Parse(format!(
                "unsupported EWF2 major version {}.{}",
                first_header.major_version, first_header.minor_version
            )));
        }
        for header in &v2_headers[1..] {
            if header.major_version != first_header.major_version
                || header.minor_version != first_header.minor_version
                || header.compression_method != first_header.compression_method
                || header.set_identifier != first_header.set_identifier
                || header.is_physical != first_header.is_physical
            {
                return Err(EwfError::Parse(
                    "EWF2 segment headers do not describe the same acquisition".to_string(),
                ));
            }
        }
        let compression_method = first_header.compression_method;

        let mut chunk_size: u64 = 0;
        let mut total_size: u64 = 0;
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut stored_md5: Option<[u8; 16]> = None;
        let mut stored_sha1: Option<[u8; 20]> = None;
        let mut metadata = EwfMetadata::default();
        let acquisition_errors: Vec<AcquisitionError> = Vec::new();

        for (seg_idx, file) in ordered_segments.iter_mut().enumerate() {
            let file_len = file.seek(SeekFrom::End(0))?;

            // EWF2 uses a backward-linked list: each section is [data][descriptor].
            // Traverse from the terminal Done/Next descriptor at the end of the file
            // backward via `previous_offset`, then process descriptors forward.
            let descriptors = collect_ewf2_descriptors(file, file_len)?;

            for desc in &descriptors {
                if desc.is_encrypted() {
                    return Err(EwfError::EncryptedNotSupported);
                }

                // Section data immediately precedes the descriptor:
                //   data_offset = desc.offset - desc.data_size
                match desc.section_type {
                    ewf2::Ewf2SectionType::CaseData
                        if desc.data_size > 0
                            && desc.data_size < MAX_SECTION_DATA_SIZE
                            && metadata.case_number.is_none() =>
                    {
                        let data_offset =
                            desc.offset.checked_sub(desc.data_size).ok_or_else(|| {
                                EwfError::Parse(format!(
                                    "EWF2 case_data offset underflow: desc={:#x} size={:#x}",
                                    desc.offset, desc.data_size
                                ))
                            })?;
                        file.seek(SeekFrom::Start(data_offset))?;
                        let data_size = usize::try_from(desc.data_size).map_err(|_| {
                            EwfError::Parse("EWF2 case_data size exceeds usize".to_string())
                        })?;
                        let mut buf = vec![0u8; data_size];
                        file.read_exact(&mut buf)?;
                        let raw = maybe_decompress_ewf2_metadata(&buf, compression_method)?;
                        parse_ewf2_case_data(&raw, &mut metadata);
                        log::debug!("parsed v2 case_data: case={:?}", metadata.case_number);
                    }
                    ewf2::Ewf2SectionType::DeviceInfo
                        if desc.data_size > 0
                            && desc.data_size < MAX_SECTION_DATA_SIZE
                            && chunk_size == 0 =>
                    {
                        let data_offset =
                            desc.offset.checked_sub(desc.data_size).ok_or_else(|| {
                                EwfError::Parse(format!(
                                    "EWF2 device_info offset underflow: desc={:#x} size={:#x}",
                                    desc.offset, desc.data_size
                                ))
                            })?;
                        file.seek(SeekFrom::Start(data_offset))?;
                        let data_size = usize::try_from(desc.data_size).map_err(|_| {
                            EwfError::Parse("EWF2 device_info size exceeds usize".to_string())
                        })?;
                        let mut buf = vec![0u8; data_size];
                        file.read_exact(&mut buf)?;
                        let raw = maybe_decompress_ewf2_metadata(&buf, compression_method)?;
                        parse_ewf2_device_info(&raw, &mut chunk_size, &mut total_size)?;
                        log::debug!(
                            "parsed v2 device_info: chunk_size={chunk_size}, total_size={total_size}"
                        );
                    }
                    ewf2::Ewf2SectionType::SectorTable => {
                        if desc.data_size < 32 {
                            return Err(EwfError::Parse(
                                "EWF2 sector table is shorter than its header".to_string(),
                            ));
                        }
                        let data_offset =
                            desc.offset.checked_sub(desc.data_size).ok_or_else(|| {
                                EwfError::Parse(format!(
                                    "EWF2 sector_table offset underflow: desc={:#x} size={:#x}",
                                    desc.offset, desc.data_size
                                ))
                            })?;
                        file.seek(SeekFrom::Start(data_offset))?;
                        // EWF2 table header is 32 bytes: first_chunk(8) + entry_count(4)
                        // + 20 bytes of reserved/checksum fields. Entries follow the header.
                        let mut tbl_hdr_buf = [0u8; 32];
                        file.read_exact(&mut tbl_hdr_buf)?;
                        let tbl_hdr = ewf2::Ewf2TableHeader::parse(&tbl_hdr_buf)?;

                        let entry_count = tbl_hdr.entry_count as usize;
                        if entry_count > MAX_TABLE_ENTRIES {
                            return Err(EwfError::Parse(format!(
                                "table entry count {entry_count} exceeds maximum {MAX_TABLE_ENTRIES}"
                            )));
                        }
                        let entries_size = entry_count
                            .checked_mul(ewf2::TABLE_ENTRY_SIZE)
                            .and_then(|size| size.checked_add(32))
                            .ok_or_else(|| {
                                EwfError::Parse("EWF2 table size overflow".to_string())
                            })?;
                        let entries_size_u64 = u64::try_from(entries_size).map_err(|_| {
                            EwfError::Parse("EWF2 table size exceeds u64".to_string())
                        })?;
                        if entries_size_u64 > desc.data_size {
                            return Err(EwfError::Parse(format!(
                                "EWF2 sector table needs {entries_size} bytes but section has {}",
                                desc.data_size
                            )));
                        }
                        let entries_offset = data_offset.checked_add(32).ok_or_else(|| {
                            EwfError::Parse("EWF2 table entry offset overflow".to_string())
                        })?;
                        file.seek(SeekFrom::Start(entries_offset))?;
                        let entries_byte_len = entry_count
                            .checked_mul(ewf2::TABLE_ENTRY_SIZE)
                            .ok_or_else(|| {
                                EwfError::Parse("EWF2 table entry byte length overflow".to_string())
                            })?;
                        let mut entries_buf = vec![0u8; entries_byte_len];
                        file.read_exact(&mut entries_buf)?;

                        log::debug!(
                            "parsed v2 sector_table: first_chunk={}, entries={entry_count}",
                            tbl_hdr.first_chunk
                        );

                        let mut entries = Vec::with_capacity(entry_count);
                        for i in 0..entry_count {
                            let start = i * ewf2::TABLE_ENTRY_SIZE;
                            let end = start + ewf2::TABLE_ENTRY_SIZE;
                            let entry = ewf2::Ewf2TableEntry::parse(&entries_buf[start..end])?;
                            entries.push(entry);
                        }
                        append_ewf2_chunks(
                            &mut chunks,
                            tbl_hdr.first_chunk,
                            &entries,
                            seg_idx,
                            compression_method,
                        )?;
                    }
                    ewf2::Ewf2SectionType::Md5Hash if desc.data_size >= 16 => {
                        let data_offset =
                            desc.offset.checked_sub(desc.data_size).ok_or_else(|| {
                                EwfError::Parse(format!(
                                    "EWF2 md5_hash offset underflow: desc={:#x} size={:#x}",
                                    desc.offset, desc.data_size
                                ))
                            })?;
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut hash = [0u8; 16];
                        file.read_exact(&mut hash)?;
                        stored_md5 = Some(hash);
                        log::debug!("parsed v2 md5_hash section: {hash:02x?}");
                    }
                    ewf2::Ewf2SectionType::Sha1Hash if desc.data_size >= 20 => {
                        let data_offset =
                            desc.offset.checked_sub(desc.data_size).ok_or_else(|| {
                                EwfError::Parse(format!(
                                    "EWF2 sha1_hash offset underflow: desc={:#x} size={:#x}",
                                    desc.offset, desc.data_size
                                ))
                            })?;
                        file.seek(SeekFrom::Start(data_offset))?;
                        let mut hash = [0u8; 20];
                        file.read_exact(&mut hash)?;
                        stored_sha1 = Some(hash);
                        log::debug!("parsed v2 sha1_hash section: {hash:02x?}");
                    }
                    _ => {}
                }
            }
        }

        // Default chunk_size if device_info didn't provide it
        if chunk_size == 0 {
            chunk_size = DEFAULT_V2_CHUNK_SIZE;
        }
        if chunk_size > MAX_CHUNK_SIZE {
            return Err(EwfError::InvalidChunkSize(
                chunk_size.min(u64::from(u32::MAX)) as u32,
            ));
        }
        if total_size == 0 {
            total_size = u64::try_from(chunks.len())
                .map_err(|_| EwfError::Parse("EWF2 chunk count exceeds u64".to_string()))?
                .checked_mul(chunk_size)
                .ok_or_else(|| EwfError::Parse("EWF2 logical size overflow".to_string()))?;
        } else {
            let capacity = u64::try_from(chunks.len())
                .map_err(|_| EwfError::Parse("EWF2 chunk count exceeds u64".to_string()))?
                .checked_mul(chunk_size)
                .ok_or_else(|| EwfError::Parse("EWF2 logical size overflow".to_string()))?;
            if total_size > capacity {
                return Err(EwfError::Parse(format!(
                    "EWF2 declares {total_size} logical bytes but chunk table covers {capacity}"
                )));
            }
        }

        validate_chunk_layout(&ordered_segments, &chunks, chunk_size, total_size)?;

        let cache = Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
        ));

        Ok(Self {
            segments: ordered_segments,
            chunks,
            chunk_size,
            total_size,
            position: 0,
            cache,
            stored_md5,
            stored_sha1,
            metadata,
            acquisition_errors,
        })
    }

    /// Total logical size of the disk image in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Chunk size in bytes (typically 32768).
    #[must_use]
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Number of chunks in the image.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Access raw chunk metadata (for testing/diagnostics).
    #[cfg(test)]
    pub(crate) fn chunk_meta(&self, idx: usize) -> &Chunk {
        &self.chunks[idx]
    }

    /// Returns the integrity hashes stored within the EWF image by the acquisition tool.
    ///
    /// The `hash` section (`EnCase` 1+) stores an MD5 of the acquired media.
    /// The `digest` section (`EnCase` 6.12+) stores both MD5 and SHA-1.
    /// If neither section is present (e.g. some FTK Imager images), both fields will be `None`.
    #[must_use]
    pub fn stored_hashes(&self) -> StoredHashes {
        StoredHashes {
            md5: self.stored_md5,
            sha1: self.stored_sha1,
        }
    }

    /// Returns case and acquisition metadata from the EWF header sections.
    #[must_use]
    pub fn metadata(&self) -> &EwfMetadata {
        &self.metadata
    }

    /// Returns sectors that had read errors during acquisition.
    ///
    /// Empty for clean acquisitions. Populated from the `error2` section when present.
    #[must_use]
    pub fn acquisition_errors(&self) -> &[AcquisitionError] {
        &self.acquisition_errors
    }

    /// Verify image integrity by streaming all media data through MD5 (and SHA-1 if
    /// a stored SHA-1 exists) and comparing against the hashes stored in the image.
    ///
    /// Returns a [`VerifyResult`] with the computed hashes and match status.
    /// If the image has no stored hashes, the computed hashes are still returned
    /// but the match fields will be `None`.
    ///
    /// Requires the `verify` feature (enabled by default).
    ///
    /// # Example
    ///
    /// ```no_run
    /// let mut reader = ewf::EwfReader::open("image.E01").unwrap();
    /// let result = reader.verify().unwrap();
    /// if let Some(true) = result.md5_match {
    ///     println!("Image integrity verified (MD5 match)");
    /// }
    /// ```
    #[cfg(feature = "verify")]
    pub fn verify(&self) -> Result<VerifyResult> {
        use md5::Digest;
        use rayon::prelude::*;

        let mut md5_hasher = md5::Md5::new();
        let mut sha1_hasher = if self.stored_sha1.is_some() {
            Some(sha1::Sha1::new())
        } else {
            None
        };

        // Hashing is serial (MD5/SHA1 chain their state), but zlib decompression
        // — the CPU cost of a full-image hash — is not. Decompress chunks in
        // parallel BATCHES, then feed them to the hashers IN ORDER. A batch of
        // `threads * 4` chunks keeps every core busy while bounding peak memory
        // to one batch of decompressed chunks. `decompress_chunk` is cacheless,
        // so streaming the whole image neither pollutes nor contends the LRU.
        let chunk_count = self.chunks.len();
        let batch = rayon::current_num_threads().saturating_mul(4).max(1);
        let mut hashed: u64 = 0;

        for start in (0..chunk_count).step_by(batch) {
            let end = (start + batch).min(chunk_count);
            let pages: Vec<Vec<u8>> = (start..end)
                .into_par_iter()
                .map(|ci| self.decompress_chunk(ci))
                .collect::<Result<Vec<_>>>()?;
            for page in pages {
                // Trim the final chunk to the image's true length: a chunk
                // decompresses into a full chunk_size buffer, but the last one
                // may back fewer logical bytes.
                let remaining = self.total_size.saturating_sub(hashed);
                let take = (page.len() as u64).min(remaining) as usize;
                md5_hasher.update(&page[..take]);
                if let Some(ref mut h) = sha1_hasher {
                    h.update(&page[..take]);
                }
                hashed += take as u64;
            }
        }

        let computed_md5: [u8; 16] = md5_hasher.finalize().into();
        let computed_sha1: Option<[u8; 20]> = sha1_hasher.map(|h| h.finalize().into());

        let md5_match = self.stored_md5.map(|stored| stored == computed_md5);
        let sha1_match = match (self.stored_sha1, computed_sha1) {
            (Some(stored), Some(computed)) => Some(stored == computed),
            _ => None,
        };

        Ok(VerifyResult {
            computed_md5,
            computed_sha1,
            md5_match,
            sha1_match,
        })
    }

    /// Read and decompress a single chunk by its index.
    ///
    /// Takes `&self`: the compressed bytes are fetched with a positioned read
    /// (no shared cursor) and decompressed WITHOUT holding the cache lock, so
    /// distinct chunks decompress in parallel across threads. The lock is held
    /// only for the brief cache probe and insert.
    fn read_chunk(&self, chunk_id: usize) -> Result<Vec<u8>> {
        // Fast path: serve from cache. Recover a poisoned lock rather than
        // panic — a poisoned cache is still readable and a panic here would
        // take down every concurrent reader.
        {
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = cache.get(&chunk_id) {
                return Ok(cached.clone());
            }
        }

        let page = self.decompress_chunk(chunk_id)?;

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.put(chunk_id, page.clone());
        Ok(page)
    }

    /// Decompress a chunk by index WITHOUT touching the cache.
    ///
    /// The cacheless counterpart to [`read_chunk`]: used by the parallel
    /// [`verify`](Self::verify), which streams every chunk exactly once and so
    /// must neither pollute the LRU nor serialize on its lock. Positioned read
    /// + decompress, all through `&self`.
    fn decompress_chunk(&self, chunk_id: usize) -> Result<Vec<u8>> {
        let page_size = usize::try_from(self.chunk_size)
            .map_err(|_| EwfError::Parse("chunk size exceeds usize".to_string()))?;
        let mut page = vec![0u8; page_size];
        let chunk = self.chunks.get(chunk_id).cloned().ok_or_else(|| {
            EwfError::Parse(format!("chunk index {chunk_id} is outside the chunk table"))
        })?;
        let file = self.segments.get(chunk.segment_idx).ok_or_else(|| {
            EwfError::Parse(format!(
                "chunk {chunk_id} references missing segment {}",
                chunk.segment_idx
            ))
        })?;

        let chunk_start = (chunk_id as u64)
            .checked_mul(self.chunk_size)
            .ok_or_else(|| EwfError::Parse("chunk logical offset overflow".to_string()))?;
        let required = self
            .total_size
            .saturating_sub(chunk_start)
            .min(self.chunk_size) as usize;

        if let ChunkEncoding::Pattern(pattern) = chunk.encoding {
            for (index, byte) in page.iter_mut().enumerate() {
                *byte = pattern[index % pattern.len()];
            }
            return Ok(page);
        }

        if chunk.compressed {
            let stored_size = usize::try_from(chunk.size)
                .map_err(|_| EwfError::Parse("chunk size does not fit memory".to_string()))?;
            let mut compressed = vec![0u8; stored_size];
            let total_read = pread(file, &mut compressed, chunk.offset)?;
            if total_read != compressed.len() {
                return Err(EwfError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "short read for compressed chunk {chunk_id}: got {total_read} of {} bytes",
                        compressed.len()
                    ),
                )));
            }
            match chunk.encoding {
                ChunkEncoding::Zlib => decode_compressed_chunk(
                    ZlibDecoder::new(compressed.as_slice()),
                    &mut page,
                    required,
                    chunk_id,
                )?,
                ChunkEncoding::Bzip2 => decode_compressed_chunk(
                    bzip2_rs::DecoderReader::new(compressed.as_slice()),
                    &mut page,
                    required,
                    chunk_id,
                )?,
                ChunkEncoding::Raw | ChunkEncoding::Pattern(_) => {
                    return Err(EwfError::Parse(format!(
                        "chunk {chunk_id} entered the compressed decoder with a non-compressed encoding"
                    )));
                }
            }
        } else {
            let stored_size = usize::try_from(chunk.size)
                .map_err(|_| EwfError::Parse("chunk size does not fit memory".to_string()))?;
            let mut raw = vec![0u8; stored_size];
            let n = pread(file, &mut raw, chunk.offset)?;
            if n < stored_size {
                // An uncompressed chunk truncated on disk — fail loud rather
                // than silently serve zero-padded bytes.
                return Err(EwfError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("short read for chunk {chunk_id}: got {n} of {stored_size} bytes"),
                )));
            }
            let data = if chunk.checksummed {
                if raw.len() < 4 {
                    return Err(EwfError::Parse(format!(
                        "checksummed chunk {chunk_id} is shorter than its checksum"
                    )));
                }
                let split = raw.len() - 4;
                let stored = u32::from_le_bytes([
                    raw[split],
                    raw[split + 1],
                    raw[split + 2],
                    raw[split + 3],
                ]);
                let computed = adler32(&raw[..split]);
                if stored != computed {
                    return Err(EwfError::Parse(format!(
                        "Adler-32 mismatch for chunk {chunk_id}: stored {stored:08x}, computed {computed:08x}"
                    )));
                }
                &raw[..split]
            } else {
                raw.as_slice()
            };
            if data.len() < required || data.len() > page.len() {
                return Err(EwfError::Parse(format!(
                    "raw chunk {chunk_id} contains {} data bytes, expected {required}..={} bytes",
                    data.len(),
                    page.len()
                )));
            }
            page[..data.len()].copy_from_slice(data);
        }

        Ok(page)
    }

    /// Read bytes at an arbitrary logical offset through a shared `&self`.
    ///
    /// Positioned + thread-safe: many threads may call this concurrently on one
    /// `EwfReader` (e.g. parallel full-image hashing), each decompressing its
    /// own chunks. Returns the number of bytes read (short only at end of
    /// image). This is the concurrency-safe counterpart to the cursor-based
    /// [`Read`] impl, which layers position tracking on top.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let requested = u64::try_from(buf.len())
            .map_err(|_| EwfError::Parse("read length exceeds u64".to_string()))?;
        let readable_u64 = self.total_size.saturating_sub(offset).min(requested);
        let readable = usize::try_from(readable_u64)
            .map_err(|_| EwfError::Parse("read length exceeds usize".to_string()))?;
        if readable == 0 {
            return Ok(0);
        }

        let first_chunk = usize::try_from(offset / self.chunk_size)
            .map_err(|_| EwfError::Parse("first chunk index exceeds usize".to_string()))?;
        let last_offset = offset
            .checked_add(readable_u64)
            .and_then(|end| end.checked_sub(1))
            .ok_or_else(|| EwfError::Parse("read range overflow".to_string()))?;
        let last_chunk = usize::try_from(last_offset / self.chunk_size)
            .map_err(|_| EwfError::Parse("last chunk index exceeds usize".to_string()))?;
        let chunk_count = last_chunk
            .checked_sub(first_chunk)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| EwfError::Parse("read chunk count overflow".to_string()))?;

        // Large logical reads are the recovery/hash hot path. EWF chunks are
        // independently checksummed and compressed, so decode them on Rayon
        // workers, then copy the verified pages into the caller buffer in
        // logical order. Small/random filesystem reads stay serial to avoid
        // scheduler overhead and cache contention.
        if chunk_count > 1 && readable >= 64 * 1024 {
            use rayon::prelude::*;

            let pages = (first_chunk..=last_chunk)
                .into_par_iter()
                .map(|chunk_id| self.read_chunk(chunk_id).map(|page| (chunk_id, page)))
                .collect::<Result<Vec<_>>>()?;
            for (chunk_id, page) in pages {
                let chunk_logical_start = (chunk_id as u64)
                    .checked_mul(self.chunk_size)
                    .ok_or_else(|| EwfError::Parse("chunk logical offset overflow".to_string()))?;
                let copy_start = offset.max(chunk_logical_start);
                let read_end = offset
                    .checked_add(readable_u64)
                    .ok_or_else(|| EwfError::Parse("read end overflow".to_string()))?;
                let chunk_logical_end = chunk_logical_start
                    .checked_add(self.chunk_size)
                    .ok_or_else(|| EwfError::Parse("chunk logical end overflow".to_string()))?;
                let copy_end = read_end.min(chunk_logical_end);
                if copy_end <= copy_start {
                    continue;
                }
                let page_start = usize::try_from(copy_start - chunk_logical_start)
                    .map_err(|_| EwfError::Parse("chunk page offset exceeds usize".to_string()))?;
                let output_start = usize::try_from(copy_start - offset)
                    .map_err(|_| EwfError::Parse("output offset exceeds usize".to_string()))?;
                let count = usize::try_from(copy_end - copy_start)
                    .map_err(|_| EwfError::Parse("copy length exceeds usize".to_string()))?;
                buf[output_start..output_start + count]
                    .copy_from_slice(&page[page_start..page_start + count]);
            }
            return Ok(readable);
        }

        let mut buf_idx = 0usize;
        let mut off = offset;

        loop {
            let remaining_image = self.total_size.saturating_sub(off);
            let remaining_buf = buf.len() - buf_idx;
            let in_chunk = self.chunk_size - (off % self.chunk_size);

            let to_read = in_chunk.min(remaining_image).min(remaining_buf as u64) as usize;

            if to_read == 0 {
                break;
            }

            let chunk_id = usize::try_from(off / self.chunk_size)
                .map_err(|_| EwfError::Parse("chunk index exceeds usize".to_string()))?;
            let page = self.read_chunk(chunk_id)?;

            let page_offset = (off % self.chunk_size) as usize;
            buf[buf_idx..buf_idx + to_read]
                .copy_from_slice(&page[page_offset..page_offset + to_read]);

            off = off
                .checked_add(
                    u64::try_from(to_read)
                        .map_err(|_| EwfError::Parse("read increment exceeds u64".to_string()))?,
                )
                .ok_or_else(|| EwfError::Parse("read offset overflow".to_string()))?;
            buf_idx += to_read;
        }

        Ok(buf_idx)
    }
}

impl Read for EwfReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(buf, self.position).map_err(io::Error::other)?;
        self.position = self
            .position
            .checked_add(u64::try_from(n).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "read position overflow"))?;
        Ok(n)
    }
}

impl Seek for EwfReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::End(p) => i128::from(self.total_size) + i128::from(p),
            SeekFrom::Current(p) => i128::from(self.position) + i128::from(p),
        };
        if !(0..=i128::from(u64::MAX)).contains(&new_pos) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek position is outside the u64 range",
            ));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

/// Parse EWF2 `device_info` section data (UTF-16LE tab-separated text) to extract
/// `bytes_per_sector`, `sectors_per_chunk`, and `total_sectors` for media geometry.
///
/// Format:
///   Line 1: version ("2")
///   Line 2: section name ("main")
///   Line 3: field names (tab-separated, e.g. "b\tsc\tts")
///   Line 4: field values (tab-separated)
pub(crate) fn parse_ewf2_device_info(
    raw: &[u8],
    chunk_size: &mut u64,
    total_size: &mut u64,
) -> Result<()> {
    // Decode UTF-16LE to String
    if raw.len() < 2 {
        return Ok(());
    }
    let u16_iter = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let text: String = char::decode_utf16(u16_iter)
        .filter_map(std::result::Result::ok)
        .collect();

    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 {
        return Ok(());
    }

    let names: Vec<&str> = lines[2].split('\t').collect();
    let values: Vec<&str> = lines[3].split('\t').collect();

    let mut bytes_per_sector: u64 = 512;
    let mut sectors_per_chunk: u64 = 64;
    let mut total_sectors: u64 = 0;

    for (i, &name) in names.iter().enumerate() {
        if let Some(&val_str) = values.get(i) {
            match name {
                "b" => {
                    if let Ok(v) = val_str.parse::<u64>() {
                        bytes_per_sector = v;
                    }
                }
                "sc" => {
                    if let Ok(v) = val_str.parse::<u64>() {
                        sectors_per_chunk = v;
                    }
                }
                "ts" => {
                    if let Ok(v) = val_str.parse::<u64>() {
                        total_sectors = v;
                    }
                }
                _ => {}
            }
        }
    }

    let computed_chunk_size = bytes_per_sector
        .checked_mul(sectors_per_chunk)
        .ok_or_else(|| EwfError::Parse("EWF2 device_info chunk size overflow".to_string()))?;
    if computed_chunk_size > 0 {
        *chunk_size = computed_chunk_size;
    }
    if total_sectors > 0 && bytes_per_sector > 0 {
        *total_size = bytes_per_sector
            .checked_mul(total_sectors)
            .ok_or_else(|| EwfError::Parse("EWF2 device_info byte length overflow".to_string()))?;
    }
    Ok(())
}

/// Parse EWF2 `case_data` section (UTF-16LE tab-separated) to extract case metadata.
///
/// Field codes: `cn`=`case_number`, `en`=`evidence_number`, `ex`=examiner,
/// `de`=description, `nt`=notes, `av`=`acquiry_software`, `ov`=`os_version`,
/// `ad`=`acquiry_date`, `sd`=`system_date`.
pub(crate) fn parse_ewf2_case_data(raw: &[u8], metadata: &mut EwfMetadata) {
    if raw.len() < 2 {
        return;
    }
    let u16_iter = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let text: String = char::decode_utf16(u16_iter)
        .filter_map(std::result::Result::ok)
        .collect();

    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 {
        return;
    }

    let names: Vec<&str> = lines[2].split('\t').collect();
    let values: Vec<&str> = lines[3].split('\t').collect();

    for (i, &name) in names.iter().enumerate() {
        if let Some(&val) = values.get(i) {
            if val.is_empty() {
                continue;
            }
            match name {
                "cn" => metadata.case_number = Some(val.to_string()),
                "en" => metadata.evidence_number = Some(val.to_string()),
                "ex" => metadata.examiner = Some(val.to_string()),
                "de" => metadata.description = Some(val.to_string()),
                "nt" => metadata.notes = Some(val.to_string()),
                "av" => metadata.acquiry_software = Some(val.to_string()),
                "ov" => metadata.os_version = Some(val.to_string()),
                "ad" => metadata.acquiry_date = Some(val.to_string()),
                "sd" => metadata.system_date = Some(val.to_string()),
                _ => {}
            }
        }
    }
}

impl std::fmt::Debug for EwfReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EwfReader")
            .field("chunk_size", &self.chunk_size)
            .field("total_size", &self.total_size)
            .field("position", &self.position)
            .field("chunk_count", &self.chunks.len())
            .field("segment_count", &self.segments.len())
            .field(
                "cached_chunks",
                &self
                    .cache
                    .try_lock()
                    .map_or_else(|_| "<locked>".to_string(), |c| c.len().to_string()),
            )
            .field("stored_md5", &self.stored_md5)
            .field("stored_sha1", &self.stored_sha1)
            .field("metadata", &self.metadata)
            .field("acquisition_errors", &self.acquisition_errors)
            .finish()
    }
}

#[cfg(test)]
mod segment_dir_tests {
    use super::segment_dir;
    use std::path::Path;

    #[test]
    fn bare_filename_globs_current_dir_not_root() {
        // `Path::parent()` returns Some("") — not None — for a bare filename, so
        // the segment glob must fall back to the current directory, not "/".
        // Reproduces finding F1: `ingest <bare.E01>` from the evidence dir.
        assert_eq!(segment_dir(Path::new("bare.E01")), Path::new("."));
    }

    #[test]
    fn directory_qualified_filename_keeps_its_parent() {
        assert_eq!(
            segment_dir(Path::new("/evidence/case/bare.E01")),
            Path::new("/evidence/case")
        );
        assert_eq!(segment_dir(Path::new("sub/bare.E01")), Path::new("sub"));
    }
}

#[cfg(test)]
mod forensic_correctness_tests {
    use super::*;
    use std::io::Write;

    fn reader_for_chunk(
        bytes: &[u8],
        encoding: ChunkEncoding,
        checksummed: bool,
        chunk_size: u64,
        total_size: u64,
    ) -> (tempfile::NamedTempFile, EwfReader) {
        let mut temporary = tempfile::NamedTempFile::new().unwrap();
        temporary.write_all(bytes).unwrap();
        temporary.flush().unwrap();
        let file = File::open(temporary.path()).unwrap();
        let reader = EwfReader {
            segments: vec![file],
            chunks: vec![Chunk {
                segment_idx: 0,
                compressed: !matches!(encoding, ChunkEncoding::Raw),
                encoding,
                checksummed,
                offset: 0,
                size: bytes.len() as u64,
            }],
            chunk_size,
            total_size,
            position: 0,
            cache: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(1).unwrap())),
            stored_md5: None,
            stored_sha1: None,
            metadata: EwfMetadata::default(),
            acquisition_errors: Vec::new(),
        };
        (temporary, reader)
    }

    #[test]
    fn clean_early_end_in_compressed_chunk_is_an_error() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"too short").unwrap();
        let compressed = encoder.finish().unwrap();
        let (_temporary, reader) =
            reader_for_chunk(&compressed, ChunkEncoding::Zlib, false, 16, 16);

        let error = reader.decompress_chunk(0).unwrap_err().to_string();
        assert!(error.contains("decoded to 9 bytes"), "{error}");
    }

    #[test]
    fn pattern_fill_repeats_all_eight_pattern_bytes() {
        let pattern = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let (_temporary, reader) =
            reader_for_chunk(&[], ChunkEncoding::Pattern(pattern), false, 18, 18);

        let page = reader.decompress_chunk(0).unwrap();
        assert_eq!(
            page,
            vec![
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                0x70, 0x80, 0x10, 0x20
            ]
        );
    }

    #[test]
    fn bzip2_chunk_uses_header_selected_decoder() {
        let compressed = [
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x56, 0x85, 0x00, 0xb2,
            0x00, 0x00, 0x00, 0x40, 0x00, 0x7f, 0xff, 0xa0, 0x00, 0x22, 0x8c, 0x98, 0x00, 0x14,
            0xc0, 0x01, 0x34, 0xcf, 0x00, 0xfc, 0x8d, 0x15, 0x9e, 0x26, 0xaf, 0x34, 0x5d, 0xc9,
            0x14, 0xe1, 0x42, 0x41, 0x5a, 0x14, 0x02, 0xc8,
        ];
        let (_temporary, reader) =
            reader_for_chunk(&compressed, ChunkEncoding::Bzip2, false, 16, 16);

        assert_eq!(
            reader.decompress_chunk(0).unwrap(),
            (0u8..16).collect::<Vec<_>>()
        );
    }

    #[test]
    fn raw_ewf2_chunk_adler32_is_verified() {
        let payload = (0u8..16).collect::<Vec<_>>();
        let mut stored = payload.clone();
        stored.extend_from_slice(&adler32(&payload).to_le_bytes());
        let (_temporary, reader) = reader_for_chunk(&stored, ChunkEncoding::Raw, true, 16, 16);
        assert_eq!(reader.decompress_chunk(0).unwrap(), payload);

        stored[16] ^= 0xff;
        let (_temporary, reader) = reader_for_chunk(&stored, ChunkEncoding::Raw, true, 16, 16);
        assert!(reader.decompress_chunk(0).is_err());
    }

    #[test]
    fn ewf2_table_first_chunk_must_be_contiguous() {
        let entry = ewf2::Ewf2TableEntry {
            chunk_data_offset: 0x0807_0605_0403_0201,
            chunk_data_size: 0,
            flags: ewf2::CHUNK_FLAG_COMPRESSED | ewf2::CHUNK_FLAG_PATTERNFILL,
        };
        let mut chunks = Vec::new();
        assert!(
            append_ewf2_chunks(&mut chunks, 1, &[entry], 0, ewf2::CompressionMethod::Zlib).is_err()
        );

        append_ewf2_chunks(&mut chunks, 0, &[entry], 0, ewf2::CompressionMethod::Zlib).unwrap();
        assert!(matches!(
            chunks[0].encoding,
            ChunkEncoding::Pattern([1, 2, 3, 4, 5, 6, 7, 8])
        ));
    }
}
