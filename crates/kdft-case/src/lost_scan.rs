//! Bounded-memory, sequential lost-partition candidate scanner.
//!
//! Scans every 512-byte sector start within caller-supplied gap ranges to detect
//! plausible NTFS, FAT12/16/32, ext2/3/4, or fixed-disk BitLocker boot/header
//! structures. These are discovery candidates, not proof that a lost partition
//! existed. The caller must still run the format parser and preserve that
//! distinction in any persisted finding.
//!
//! # Design
//!
//! * **Std-only**: no external dependencies beyond `std`.
//! * **Bounded memory**: reads in configurable (default 256 KiB) chunks with a
//!   fixed 2048-byte overlap to recognise headers that straddle a chunk boundary.
//! * **Checked arithmetic**: every offset computation uses checked/saturating
//!   arithmetic; short reads are handled gracefully.
//! * **Normalised coverage**: overlapping/adjacent input gaps are merged before
//!   scanning, preventing duplicate candidates and inflated progress totals.
//! * **Progress callback**: the caller can receive progress updates per chunk;
//!   the terminal outcome distinguishes complete coverage from callback stop.
//! * **Fallible candidate callback**: errors returned by the callback are
//!   propagated immediately.

use std::io::{self, Read, Seek, SeekFrom};

// ── Sector / header geometry ────────────────────────────────────────────────

/// Sector size in bytes – the minimum alignment for all candidate offsets.
const SECTOR_SIZE: u64 = 512;

/// Minimum read that covers an ext superblock (at offset 0x400 into the
/// volume, so 0x400 + 2 bytes of magic = 0x43A bytes from sector start).
/// We also need to read the BitLocker `-FVE-FS-` signature at offset 3 and
/// 0x55AA at bytes 510-511, so 2048 is the smallest power-of-two that
/// satisfies all probes.
const HEADER_SIZE: usize = 2048;

/// Default I/O chunk size (256 KiB).  Each chunk read covers this many
/// bytes *plus* an overlap equal to `HEADER_SIZE - SECTOR_SIZE` so that a
/// header starting in the last sector of one chunk is fully visible.
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// An examiner-controlled chunk must remain a bounded-memory setting. Larger
/// reads do not improve the 512-byte scan resolution and can otherwise turn a
/// malformed configuration into a multi-gigabyte allocation attempt.
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Defensive upper bound for caller-supplied gap records before normalisation.
/// Real partition maps contain orders of magnitude fewer ranges. This bounds
/// sort memory while still allowing highly fragmented synthetic sources.
const MAX_INPUT_GAPS: usize = 1_000_000;

/// Overlap appended to each chunk so that a header starting near the end of
/// the previous chunk is fully contained in the next.
const OVERLAP: usize = HEADER_SIZE - SECTOR_SIZE as usize;

// ── BitLocker FVE OEM signature ─────────────────────────────────────────────

const BITLOCKER_FVE_SIGNATURE: &[u8; 8] = b"-FVE-FS-";

// ── Public types ────────────────────────────────────────────────────────────

/// Filesystem hint returned alongside each candidate offset.
///
/// The variants intentionally do **not** carry payload; they exist only to
/// let the caller prioritise or dispatch validation without re-reading the
/// sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsHint {
    /// Sector 0 contains `NTFS    ` OEM ID + 0x55AA signature.
    Ntfs,
    /// Sector 0 contains coherent FAT12/16/32 BPB geometry + 0x55AA. The
    /// human-readable filesystem-type field is deliberately not trusted: it
    /// is informational and valid media need not contain `FAT` there.
    Fat,
    /// Superblock at +1024 bytes carries the ext2/3/4 magic 0xEF53.
    Ext,
    /// Sector 0 carries the `-FVE-FS-` BitLocker FVE OEM signature.
    BitLocker,
}

/// A single candidate detection reported to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Absolute byte offset within the underlying `Read + Seek` stream.
    pub offset: u64,
    /// Filesystem hint derived from the prefilter.
    pub hint: FsHint,
}

/// Progress information supplied to the optional progress callback.
#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    /// Number of bytes scanned so far across all gaps.
    pub bytes_scanned: u64,
    /// Total number of bytes to scan across all gaps.
    pub bytes_total: u64,
}

/// Why a successful scan call returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTerminalStatus {
    /// Every byte in every normalised gap was read and every eligible sector
    /// start was examined.
    Complete,
    /// The reader-aware candidate callback requested a clean early stop.
    /// Coverage is deliberately not reported as complete.
    StoppedByCallback,
}

/// Auditable terminal telemetry for a lost-partition discovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOutcome {
    pub status: ScanTerminalStatus,
    /// Bytes completely scanned before return. This is conservative when a
    /// callback stops in the middle of a buffered chunk.
    pub bytes_scanned: u64,
    /// Union length of the valid, normalised input gaps.
    pub bytes_total: u64,
    /// Candidates delivered to the callback, including the candidate whose
    /// callback requested a stop.
    pub candidates_reported: u64,
    /// Number of disjoint ranges after overlap/adjacency normalisation.
    pub normalized_gap_count: usize,
    /// Zero-width or inverted caller ranges excluded from coverage.
    pub ignored_gap_count: usize,
}

// ── Scanner configuration ───────────────────────────────────────────────────

/// Builder / configuration for [`scan_gaps`].
pub struct LostScanConfig {
    chunk_size: usize,
}

impl Default for LostScanConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl LostScanConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the I/O chunk size.  Must be ≥ `HEADER_SIZE` (2048).
    ///
    /// The scanner validates this value before allocating or reading so
    /// invalid examiner input is returned as `InvalidInput`, never a panic.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
}

#[derive(Debug)]
struct NormalizedGaps {
    ranges: Vec<(u64, u64)>,
    bytes_total: u64,
    ignored_count: usize,
}

/// Validate, sort and merge the caller's half-open byte ranges. Adjacent
/// ranges are merged too: splitting one continuous byte extent must not make
/// a header straddling that artificial boundary invisible.
fn normalize_gaps<G>(gaps: G) -> io::Result<NormalizedGaps>
where
    G: IntoIterator<Item = (u64, u64)>,
{
    let mut ranges = Vec::<(u64, u64)>::new();
    let mut ignored_count = 0usize;
    let mut input_count = 0usize;
    for (start, end) in gaps {
        input_count = input_count.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "input gap count overflow")
        })?;
        if input_count > MAX_INPUT_GAPS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("lost-partition scan accepts at most {MAX_INPUT_GAPS} input gap ranges"),
            ));
        }
        if end <= start {
            ignored_count = ignored_count.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "ignored gap count overflow")
            })?;
            continue;
        }
        if ranges.len() == ranges.capacity() {
            ranges.try_reserve(1024).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("gap normalisation buffer cannot be allocated: {error}"),
                )
            })?;
        }
        ranges.push((start, end));
    }

    ranges.sort_unstable();
    let mut merged = Vec::<(u64, u64)>::new();
    merged.try_reserve(ranges.len()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("normalised gap buffer cannot be allocated: {error}"),
        )
    })?;
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let bytes_total = merged.iter().try_fold(0_u64, |total, &(start, end)| {
        total
            .checked_add(end - start)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "gap byte total overflow"))
    })?;
    Ok(NormalizedGaps {
        ranges: merged,
        bytes_total,
        ignored_count,
    })
}

// ── Core scan implementation ────────────────────────────────────────────────

/// Scan every 512-byte-aligned sector start in the supplied `[gap_start,
/// gap_end)` ranges for plausible filesystem / BitLocker boot-sector
/// signatures.
///
/// * `reader` – seekable byte source (e.g. a disk image).
/// * `gaps`   – iterator of `(gap_start, gap_end)` byte ranges. Ranges may
///   overlap or be unordered; their valid union is scanned exactly once.
/// * `on_candidate` – fallible callback invoked once per plausible
///   detection.  Returning `Err` aborts the scan.
/// * `on_progress` – optional progress callback invoked after each chunk
///   read.  May be `None`.
/// * `config` – scanner configuration (chunk size, etc.).
///
/// Returns terminal coverage telemetry, or the first `Err` produced by
/// `on_candidate` or by I/O.
pub fn scan_gaps<R, G, F, P>(
    reader: &mut R,
    gaps: G,
    mut on_candidate: F,
    on_progress: Option<P>,
    config: &LostScanConfig,
) -> io::Result<ScanOutcome>
where
    R: Read + Seek + ?Sized,
    G: IntoIterator<Item = (u64, u64)>,
    F: FnMut(Candidate) -> io::Result<()>,
    P: FnMut(ScanProgress),
{
    scan_gaps_with_reader(
        reader,
        gaps,
        |_, candidate| {
            on_candidate(candidate)?;
            Ok(true)
        },
        on_progress,
        config,
    )
}

/// Reader-aware variant used when a candidate must be validated or consumed
/// immediately without retaining an unbounded candidate list. The callback
/// returns `Ok(true)` to continue scanning or `Ok(false)` to stop cleanly.
///
/// The scanner always seeks explicitly before its next chunk read, so the
/// callback may seek or read the shared source. Candidate classification uses
/// the already-buffered chunk and is unaffected by those reader operations.
pub fn scan_gaps_with_reader<R, G, F, P>(
    reader: &mut R,
    gaps: G,
    mut on_candidate: F,
    mut on_progress: Option<P>,
    config: &LostScanConfig,
) -> io::Result<ScanOutcome>
where
    R: Read + Seek + ?Sized,
    G: IntoIterator<Item = (u64, u64)>,
    F: FnMut(&mut R, Candidate) -> io::Result<bool>,
    P: FnMut(ScanProgress),
{
    // Validate public configuration before allocating. Invalid examiner input
    // must be reported as an error rather than panicking or wrapping.
    if !(HEADER_SIZE..=MAX_CHUNK_SIZE).contains(&config.chunk_size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "chunk_size must be between {HEADER_SIZE} and {MAX_CHUNK_SIZE} bytes, got {}",
                config.chunk_size,
            ),
        ));
    }

    let NormalizedGaps {
        ranges: gaps,
        bytes_total,
        ignored_count: ignored_gap_count,
    } = normalize_gaps(gaps)?;
    let normalized_gap_count = gaps.len();

    let chunk_data_size = config.chunk_size; // net new data per read
    let buf_capacity = chunk_data_size.checked_add(OVERLAP).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk_size plus scanner overlap exceeds this platform's address space",
        )
    })?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(buf_capacity).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("scanner chunk buffer cannot be allocated: {error}"),
        )
    })?;
    buf.resize(buf_capacity, 0);
    let mut bytes_scanned: u64 = 0;
    let mut candidates_reported: u64 = 0;

    for (gap_start, gap_end) in gaps {
        if gap_end <= gap_start {
            continue;
        }
        // Align the start down to SECTOR_SIZE boundary (should already be,
        // but be defensive).
        let aligned_start = gap_start / SECTOR_SIZE * SECTOR_SIZE;

        // `file_pos` is the absolute position of the *first new byte* in
        // each iteration.  For the first chunk of a gap there is no
        // preceding overlap to carry, so `file_pos == aligned_start`.
        let mut file_pos = aligned_start;

        // High-water mark: the highest absolute sector offset that had a
        // *complete* HEADER_SIZE window in a previous chunk iteration.
        // Sectors at or below this offset were definitively classified and
        // must not be reported again.  Initialised to "nothing classified
        // yet" by using a value below any possible sector.
        let mut fully_classified_up_to: Option<u64> = None;

        while file_pos < gap_end {
            // How many *new* data bytes to request this iteration.
            let remaining = gap_end.saturating_sub(file_pos);
            let want_new = remaining.min(chunk_data_size as u64) as usize;

            // The actual read length includes the overlap tail so that
            // headers starting in the last few sectors of the previous
            // chunk are fully visible.  On the very first read of a gap
            // we have no preceding data, so we just read from `file_pos`.
            // On subsequent reads we've already seen
            // `chunk_data_size` bytes and back up by `OVERLAP`.
            let is_first = file_pos == aligned_start;
            let (read_start, read_len) = if is_first {
                // First chunk – no prior data to overlap.
                let rl = want_new.min(buf.len());
                (file_pos, rl)
            } else {
                // Subsequent chunk – back up by OVERLAP bytes so the tail
                // of the previous chunk is re-read at the start of this
                // buffer.
                let backed_up = file_pos.saturating_sub(OVERLAP as u64);
                let rl = want_new
                    .checked_add(OVERLAP)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "chunk read length overflow")
                    })?
                    .min(buf.len());
                (backed_up, rl)
            };

            reader.seek(SeekFrom::Start(read_start))?;
            let filled = read_full(&mut *reader, &mut buf[..read_len])?;
            let premature_eof = filled < read_len;

            // Determine where to start scanning in the buffer.  On the
            // first chunk, respect the gap_start offset.  On subsequent
            // chunks, start from 0 (the overlap region) so that headers
            // which straddled the previous chunk boundary are now visible
            // in full.  The high-water mark prevents duplicate reports.
            let scan_buf_start = if is_first {
                (gap_start.saturating_sub(read_start)) as usize
            } else {
                0
            };

            let scan_buf_end = filled;
            let abs_buf_base = read_start;

            // Align buf_off upwards so that (abs_buf_base + buf_off) is
            // sector-aligned.
            let mut buf_off = scan_buf_start;
            let abs_off = abs_buf_base.checked_add(buf_off as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "absolute scan offset overflow")
            })?;
            let misalignment = abs_off % SECTOR_SIZE;
            if misalignment != 0 {
                let bump = (SECTOR_SIZE - misalignment) as usize;
                buf_off = buf_off.saturating_add(bump);
            }

            // Track the highest sector in *this* chunk that gets a full
            // HEADER_SIZE window, so we can set the high-water mark after
            // the loop.
            let mut this_chunk_classified_up_to: Option<u64> = None;

            while buf_off < scan_buf_end {
                let abs_sector = abs_buf_base.checked_add(buf_off as u64).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "absolute sector offset overflow",
                    )
                })?;

                // Skip sectors outside the gap.
                if abs_sector >= gap_end {
                    break;
                }

                if abs_sector >= gap_start {
                    let window_end =
                        filled.min(buf_off.checked_add(HEADER_SIZE).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "scan window offset overflow",
                            )
                        })?);
                    let window = &buf[buf_off..window_end];
                    let has_full_window = window.len() >= HEADER_SIZE;

                    // Skip sectors that were already definitively
                    // classified (had a full window) in a prior chunk.
                    let already_done = match fully_classified_up_to {
                        Some(hwm) => abs_sector <= hwm,
                        None => false,
                    };

                    // A partial window at an ordinary chunk boundary is
                    // deliberately deferred until the overlap read supplies
                    // the rest of it. At the actual end of the gap, the
                    // available partial window is final and may still contain
                    // enough bytes for NTFS/FAT/BitLocker classification.
                    let buffer_end = abs_buf_base.checked_add(filled as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "read end offset overflow")
                    })?;
                    let window_is_final = buffer_end.min(gap_end) == gap_end;

                    if !already_done && (has_full_window || window_is_final) {
                        if let Some(hint) = classify_sector(window) {
                            candidates_reported =
                                candidates_reported.checked_add(1).ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "lost-partition candidate count overflow",
                                    )
                                })?;
                            if !on_candidate(
                                reader,
                                Candidate {
                                    offset: abs_sector,
                                    hint,
                                },
                            )? {
                                return Ok(ScanOutcome {
                                    status: ScanTerminalStatus::StoppedByCallback,
                                    bytes_scanned,
                                    bytes_total,
                                    candidates_reported,
                                    normalized_gap_count,
                                    ignored_gap_count,
                                });
                            }
                        }
                    }

                    if has_full_window {
                        this_chunk_classified_up_to = Some(abs_sector);
                    }
                }

                buf_off = match buf_off.checked_add(SECTOR_SIZE as usize) {
                    Some(v) => v,
                    None => break,
                };
            }

            // Update the high-water mark.
            if let Some(tc) = this_chunk_classified_up_to {
                fully_classified_up_to = Some(match fully_classified_up_to {
                    Some(prev) => prev.max(tc),
                    None => tc,
                });
            }

            // Only count bytes that were actually read for the new portion of
            // this chunk and that lie inside the caller's exact gap. This is
            // important for non-sector-aligned starts and for a source that
            // ends before the declared gap does.
            let requested_end = file_pos.checked_add(want_new as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "gap offset overflow")
            })?;
            let filled_end = read_start.checked_add(filled as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "filled read offset overflow")
            })?;
            let actual_new_end = filled_end.min(requested_end);
            let progress_start = file_pos.max(gap_start);
            let advanced_in_gap = actual_new_end.saturating_sub(progress_start);
            bytes_scanned = bytes_scanned.saturating_add(advanced_in_gap);
            if let Some(ref mut cb) = on_progress {
                cb(ScanProgress {
                    bytes_scanned,
                    bytes_total,
                });
            }

            if premature_eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "source ended at byte {} before lost-partition gap end {}",
                        filled_end, gap_end
                    ),
                ));
            }

            file_pos = requested_end;
        }
    }

    Ok(ScanOutcome {
        status: ScanTerminalStatus::Complete,
        bytes_scanned,
        bytes_total,
        candidates_reported,
        normalized_gap_count,
        ignored_gap_count,
    })
}

// ── Prefilter classification ────────────────────────────────────────────────

/// Inspect the first `window.len()` bytes starting at a sector boundary and
/// return a hint if the sector looks like a plausible boot/header record.
///
/// These checks validate mutually-consistent header geometry while remaining
/// a prefilter. They deliberately do not claim that a filesystem is mountable
/// or that the header marks a former partition boundary.
fn classify_sector(window: &[u8]) -> Option<FsHint> {
    if plausible_primary_ext_superblock(window) {
        return Some(FsHint::Ext);
    }

    if plausible_bitlocker_header(window) {
        return Some(FsHint::BitLocker);
    }

    if plausible_ntfs_boot_sector(window) {
        return Some(FsHint::Ntfs);
    }

    if plausible_fat_boot_sector(window) {
        return Some(FsHint::Fat);
    }

    None
}

fn plausible_primary_ext_superblock(window: &[u8]) -> bool {
    // ext superblock begins 1024 bytes into the volume. Field offsets below
    // are therefore 0x400 + their documented struct ext4_super_block offset.
    if window.len() < 0x554 || le_u16(window, 0x438) != Some(0xEF53) {
        return false;
    }
    let Some(inodes_count) = le_u32(window, 0x400) else {
        return false;
    };
    let Some(blocks_low) = le_u32(window, 0x404) else {
        return false;
    };
    let Some(first_data_block) = le_u32(window, 0x414) else {
        return false;
    };
    let Some(log_block_size) = le_u32(window, 0x418) else {
        return false;
    };
    let Some(blocks_per_group) = le_u32(window, 0x420) else {
        return false;
    };
    let Some(inodes_per_group) = le_u32(window, 0x428) else {
        return false;
    };
    let Some(revision) = le_u32(window, 0x44C) else {
        return false;
    };
    let Some(inode_size) = le_u16(window, 0x458) else {
        return false;
    };
    let Some(block_group_number) = le_u16(window, 0x45A) else {
        return false;
    };
    let Some(feature_incompat) = le_u32(window, 0x460) else {
        return false;
    };
    let blocks_high = if feature_incompat & 0x80 != 0 {
        le_u32(window, 0x550).unwrap_or(0)
    } else {
        0
    };
    let blocks_count = u64::from(blocks_low) | (u64::from(blocks_high) << 32);

    if inodes_count == 0
        || blocks_count == 0
        || blocks_per_group == 0
        || inodes_per_group == 0
        || log_block_size > 6
        || block_group_number != 0
    {
        return false;
    }
    // Kernel ext geometry requires the first data block to be at least one
    // for 1 KiB blocks; for larger blocks it is normally zero. Accept one for
    // larger blocks too to avoid rejecting historical, otherwise-consistent
    // images, but never an arbitrary value.
    if (log_block_size == 0 && first_data_block == 0) || first_data_block > 1 {
        return false;
    }
    if revision == 0 {
        // Revision 0 implies a fixed 128-byte inode; images commonly leave the
        // later inode-size field zero, while some writers repeat 128.
        return inode_size == 0 || inode_size == 128;
    }
    let block_size = 1024_u32.checked_shl(log_block_size).unwrap_or(0);
    inode_size.is_power_of_two()
        && (128..=u16::try_from(block_size).unwrap_or(u16::MAX)).contains(&inode_size)
}

fn plausible_bitlocker_header(window: &[u8]) -> bool {
    if window.len() < 512
        || window.get(3..11) != Some(BITLOCKER_FVE_SIGNATURE.as_slice())
        || !has_boot_signature(window)
    {
        return false;
    }
    let Some(bytes_per_sector) = le_u16(window, 11) else {
        return false;
    };
    let sectors_per_cluster = window[13];
    let Some(total_sectors) = le_u64(window, 40) else {
        return false;
    };
    valid_ntfs_sector_size(bytes_per_sector)
        && valid_sectors_per_cluster(sectors_per_cluster)
        && total_sectors > 0
}

fn plausible_ntfs_boot_sector(window: &[u8]) -> bool {
    if window.len() < 512
        || window.get(3..11) != Some(b"NTFS    ".as_slice())
        || !has_boot_signature(window)
    {
        return false;
    }
    let Some(bytes_per_sector) = le_u16(window, 11) else {
        return false;
    };
    let sectors_per_cluster = window[13];
    let Some(total_sectors) = le_u64(window, 40) else {
        return false;
    };
    let Some(mft_lcn) = le_u64(window, 48) else {
        return false;
    };
    let Some(mft_mirror_lcn) = le_u64(window, 56) else {
        return false;
    };
    if !valid_ntfs_sector_size(bytes_per_sector)
        || !valid_sectors_per_cluster(sectors_per_cluster)
        || le_u16(window, 14) != Some(0)
        || total_sectors == 0
        || window[64] == 0
        || window[68] == 0
    {
        return false;
    }
    let total_clusters = total_sectors / u64::from(sectors_per_cluster);
    total_clusters > 0 && mft_lcn < total_clusters && mft_mirror_lcn < total_clusters
}

fn plausible_fat_boot_sector(window: &[u8]) -> bool {
    if window.len() < 512 || !has_boot_signature(window) {
        return false;
    }
    let Some(bytes_per_sector) = le_u16(window, 11) else {
        return false;
    };
    let sectors_per_cluster = window[13];
    let Some(reserved_sectors) = le_u16(window, 14) else {
        return false;
    };
    let fat_count = window[16];
    let Some(root_entries) = le_u16(window, 17) else {
        return false;
    };
    let Some(total_16) = le_u16(window, 19) else {
        return false;
    };
    let Some(fat_size_16) = le_u16(window, 22) else {
        return false;
    };
    let Some(total_32) = le_u32(window, 32) else {
        return false;
    };
    let Some(fat_size_32) = le_u32(window, 36) else {
        return false;
    };
    if !valid_fat_sector_size(bytes_per_sector)
        || !valid_sectors_per_cluster(sectors_per_cluster)
        || reserved_sectors == 0
        || !(1..=2).contains(&fat_count)
    {
        return false;
    }
    let total_sectors = if total_16 != 0 {
        u64::from(total_16)
    } else {
        u64::from(total_32)
    };
    let fat_size = if fat_size_16 != 0 {
        u64::from(fat_size_16)
    } else {
        u64::from(fat_size_32)
    };
    if total_sectors == 0 || fat_size == 0 {
        return false;
    }
    let root_dir_bytes = u64::from(root_entries) * 32;
    let root_dir_sectors = root_dir_bytes
        .checked_add(u64::from(bytes_per_sector) - 1)
        .map(|rounded| rounded / u64::from(bytes_per_sector));
    let Some(root_dir_sectors) = root_dir_sectors else {
        return false;
    };
    let Some(fat_region_sectors) = fat_size.checked_mul(u64::from(fat_count)) else {
        return false;
    };
    let Some(first_data_sector) = u64::from(reserved_sectors)
        .checked_add(fat_region_sectors)
        .and_then(|value| value.checked_add(root_dir_sectors))
    else {
        return false;
    };
    if first_data_sector >= total_sectors {
        return false;
    }
    let cluster_count = (total_sectors - first_data_sector) / u64::from(sectors_per_cluster);
    if cluster_count == 0 {
        return false;
    }

    let fat32_geometry = root_entries == 0 && fat_size_16 == 0 && fat_size_32 > 0;
    let legacy_geometry = root_entries > 0 && fat_size_16 > 0;
    if fat32_geometry {
        let Some(root_cluster) = le_u32(window, 44) else {
            return false;
        };
        root_cluster >= 2 && u64::from(root_cluster) < cluster_count.saturating_add(2)
    } else {
        legacy_geometry
    }
}

fn has_boot_signature(window: &[u8]) -> bool {
    window.get(510..512) == Some([0x55, 0xAA].as_slice())
}

fn valid_ntfs_sector_size(value: u16) -> bool {
    matches!(value, 256 | 512 | 1024 | 2048 | 4096)
}

fn valid_fat_sector_size(value: u16) -> bool {
    matches!(value, 512 | 1024 | 2048 | 4096)
}

fn valid_sectors_per_cluster(value: u8) -> bool {
    value != 0 && value.is_power_of_two() && value <= 128
}

fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Read exactly `buf.len()` bytes, retrying on short reads.  Returns the
/// total number of bytes actually read (may be less than `buf.len()` only
/// at EOF).
fn read_full<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

// ══════════════════════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Build a minimal NTFS boot sector at the given offset within `data`.
    fn place_ntfs(data: &mut [u8], offset: usize) {
        assert!(
            offset + 512 <= data.len(),
            "NTFS header doesn't fit at offset {offset}"
        );
        data[offset + 3..offset + 11].copy_from_slice(b"NTFS    ");
        data[offset + 11..offset + 13].copy_from_slice(&512_u16.to_le_bytes());
        data[offset + 13] = 8;
        data[offset + 40..offset + 48].copy_from_slice(&65_536_u64.to_le_bytes());
        data[offset + 48..offset + 56].copy_from_slice(&4_u64.to_le_bytes());
        data[offset + 56..offset + 64].copy_from_slice(&8_u64.to_le_bytes());
        data[offset + 64] = (-10_i8) as u8;
        data[offset + 68] = (-10_i8) as u8;
        data[offset + 510] = 0x55;
        data[offset + 511] = 0xAA;
    }

    /// Build a minimal FAT16 boot sector at the given offset.
    fn place_fat16(data: &mut [u8], offset: usize) {
        assert!(offset + 512 <= data.len());
        data[offset + 11..offset + 13].copy_from_slice(&512_u16.to_le_bytes());
        data[offset + 13] = 4;
        data[offset + 14..offset + 16].copy_from_slice(&1_u16.to_le_bytes());
        data[offset + 16] = 2;
        data[offset + 17..offset + 19].copy_from_slice(&512_u16.to_le_bytes());
        data[offset + 19..offset + 21].copy_from_slice(&32_768_u16.to_le_bytes());
        data[offset + 21] = 0xF8;
        data[offset + 22..offset + 24].copy_from_slice(&64_u16.to_le_bytes());
        data[offset + 54..offset + 62].copy_from_slice(b"FAT16   ");
        data[offset + 510] = 0x55;
        data[offset + 511] = 0xAA;
    }

    /// Build a minimal FAT32 boot sector at the given offset.
    fn place_fat32(data: &mut [u8], offset: usize) {
        assert!(offset + 512 <= data.len());
        data[offset + 11..offset + 13].copy_from_slice(&512_u16.to_le_bytes());
        data[offset + 13] = 8;
        data[offset + 14..offset + 16].copy_from_slice(&32_u16.to_le_bytes());
        data[offset + 16] = 2;
        data[offset + 32..offset + 36].copy_from_slice(&1_000_000_u32.to_le_bytes());
        data[offset + 36..offset + 40].copy_from_slice(&1_000_u32.to_le_bytes());
        data[offset + 44..offset + 48].copy_from_slice(&2_u32.to_le_bytes());
        data[offset + 82..offset + 90].copy_from_slice(b"FAT32   ");
        data[offset + 510] = 0x55;
        data[offset + 511] = 0xAA;
    }

    /// Place ext2/3/4 superblock magic at the correct offset (0x438 bytes
    /// from the volume start).
    fn place_ext(data: &mut [u8], offset: usize) {
        assert!(offset + HEADER_SIZE <= data.len());
        data[offset + 0x400..offset + 0x404].copy_from_slice(&1_024_u32.to_le_bytes());
        data[offset + 0x404..offset + 0x408].copy_from_slice(&8_192_u32.to_le_bytes());
        data[offset + 0x414..offset + 0x418].copy_from_slice(&1_u32.to_le_bytes());
        data[offset + 0x420..offset + 0x424].copy_from_slice(&8_192_u32.to_le_bytes());
        data[offset + 0x428..offset + 0x42C].copy_from_slice(&1_024_u32.to_le_bytes());
        let magic_off = offset + 0x438;
        data[magic_off] = 0x53; // 0xEF53 little-endian
        data[magic_off + 1] = 0xEF;
        data[offset + 0x44C..offset + 0x450].copy_from_slice(&1_u32.to_le_bytes());
        data[offset + 0x458..offset + 0x45A].copy_from_slice(&256_u16.to_le_bytes());
    }

    /// Place BitLocker FVE signature at the given offset.
    fn place_bitlocker(data: &mut [u8], offset: usize) {
        assert!(offset + 512 <= data.len());
        data[offset + 3..offset + 11].copy_from_slice(BITLOCKER_FVE_SIGNATURE);
        data[offset + 11..offset + 13].copy_from_slice(&512_u16.to_le_bytes());
        data[offset + 13] = 8;
        data[offset + 40..offset + 48].copy_from_slice(&262_144_u64.to_le_bytes());
        data[offset + 510] = 0x55;
        data[offset + 511] = 0xAA;
    }

    /// Collect all candidates from a scan into a Vec.
    fn collect_candidates(
        reader: &mut Cursor<Vec<u8>>,
        gaps: &[(u64, u64)],
        config: &LostScanConfig,
    ) -> io::Result<Vec<Candidate>> {
        let mut results = Vec::new();
        scan_gaps(
            reader,
            gaps.iter().copied(),
            |c| {
                results.push(c);
                Ok(())
            },
            None::<fn(ScanProgress)>,
            config,
        )?;
        Ok(results)
    }

    // ── Test: candidate beyond old 4096 MiB-aligned probe reach ─────────

    /// A candidate at an offset not reachable by the old 4096-entry,
    /// 1 MiB-aligned probing must be found when the gap itself begins at 0.
    ///
    /// Uses a sparse seekable reader – *not* a multi-GB allocation.
    #[test]
    fn candidate_beyond_4096_mib_aligned_probe() -> io::Result<()> {
        // SparseCursor simulates a very large stream without allocating GBs.
        let old_probe_reach = 4096_u64 * 1024 * 1024;
        let target_offset = old_probe_reach + 512;
        let sparse_len: u64 = target_offset + 2048;

        let mut sparse = SparseCursor::new(sparse_len);
        // Place an NTFS header at target_offset inside the sparse storage.
        let mut sector = vec![0u8; 512];
        place_ntfs(&mut sector, 0);
        sparse.write_at(target_offset, &sector);

        let config = LostScanConfig::new().chunk_size(8 * 1024 * 1024);
        let mut found = Vec::new();
        scan_gaps(
            &mut sparse,
            [(0, sparse_len)].iter().copied(),
            |c| {
                found.push(c);
                Ok(())
            },
            None::<fn(ScanProgress)>,
            &config,
        )?;

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, target_offset);
        assert_eq!(found[0].hint, FsHint::Ntfs);
        Ok(())
    }

    #[test]
    fn reports_more_than_4096_candidates_without_an_internal_cap() -> io::Result<()> {
        const CANDIDATE_COUNT: usize = 4097;
        let total = CANDIDATE_COUNT * SECTOR_SIZE as usize + HEADER_SIZE;
        let mut data = vec![0u8; total];
        for index in 0..CANDIDATE_COUNT {
            place_ntfs(&mut data, index * SECTOR_SIZE as usize);
        }

        let mut observed = 0usize;
        scan_gaps(
            &mut Cursor::new(data),
            [(0, total as u64)],
            |_| {
                observed += 1;
                Ok(())
            },
            None::<fn(ScanProgress)>,
            &LostScanConfig::new().chunk_size(64 * 1024),
        )?;

        assert_eq!(observed, CANDIDATE_COUNT);
        Ok(())
    }

    // ── Test: unaligned-to-1MiB but 512-aligned candidate ───────────────

    #[test]
    fn unaligned_to_1mib_but_512_aligned() -> io::Result<()> {
        // Place an NTFS header at offset 1536 (3 × 512, not 1 MiB aligned).
        let total = 8192usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 1536);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;

        assert!(
            candidates
                .iter()
                .any(|c| c.offset == 1536 && c.hint == FsHint::Ntfs),
            "expected candidate at offset 1536, got: {candidates:?}"
        );
        Ok(())
    }

    // ── Test: chunk-boundary header ─────────────────────────────────────

    /// An ext superblock header that spans a chunk boundary must still be
    /// detected thanks to the overlap region.
    #[test]
    fn chunk_boundary_header() -> io::Result<()> {
        // Use a chunk size of 2048 (minimum). The ext magic sits at
        // +0x438 from the sector start. We place the sector so that the
        // magic bytes land exactly at (or just beyond) the chunk boundary.
        let chunk = HEADER_SIZE; // 2048
                                 // Sector at offset `sector_off` means magic at `sector_off + 0x438`.
                                 // We want `sector_off + 0x438` to be >= chunk but < chunk + OVERLAP
                                 // so the magic straddles the boundary.
                                 // OVERLAP = HEADER_SIZE - 512 = 1536.
                                 // sector_off = chunk - 0x438 = 2048 - 1080 = 968.  Not sector-aligned.
                                 // Next 512-aligned: 1024.  magic at 1024 + 0x438 = 2104.
                                 // chunk boundary at 2048, so magic is in the overlap zone – perfect.
        let sector_off: usize = 1024;
        let total = chunk + HEADER_SIZE + 2048; // enough room
        let mut data = vec![0u8; total];
        place_ext(&mut data, sector_off);

        let config = LostScanConfig::new().chunk_size(chunk);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;

        assert!(
            candidates
                .iter()
                .any(|c| c.offset == sector_off as u64 && c.hint == FsHint::Ext),
            "expected ext candidate at {sector_off}, got: {candidates:?}"
        );
        Ok(())
    }

    // ── Test: ext magic detection ───────────────────────────────────────

    #[test]
    fn ext_magic_detected() -> io::Result<()> {
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_ext(&mut data, 0);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;

        assert!(
            candidates
                .iter()
                .any(|c| c.offset == 0 && c.hint == FsHint::Ext),
            "expected ext candidate at 0: {candidates:?}"
        );
        Ok(())
    }

    // ── Test: no duplicate offsets ───────────────────────────────────────

    #[test]
    fn no_duplicate_offsets() -> io::Result<()> {
        // Two NTFS headers at different, well-separated offsets.
        let total = 8192usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 0);
        place_ntfs(&mut data, 2048);

        // Use a very small chunk so the overlap exercises more iterations.
        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;

        // Check that each offset appears at most once.
        let mut seen = std::collections::HashSet::new();
        for c in &candidates {
            assert!(
                seen.insert(c.offset),
                "duplicate candidate at offset {}",
                c.offset
            );
        }
        // Both must be present.
        assert!(candidates.iter().any(|c| c.offset == 0));
        assert!(candidates.iter().any(|c| c.offset == 2048));
        Ok(())
    }

    #[test]
    fn unordered_overlapping_gaps_report_one_candidate_and_exact_progress() -> io::Result<()> {
        let total = 8192usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 2048);
        let mut candidates = Vec::new();
        let mut progress = Vec::new();
        let outcome = scan_gaps(
            &mut Cursor::new(data),
            [(4096, 8192), (0, 4096), (1024, 6144), (7, 7)],
            |candidate| {
                candidates.push(candidate);
                Ok(())
            },
            Some(|sample| progress.push(sample)),
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        )?;

        assert_eq!(
            candidates,
            vec![Candidate {
                offset: 2048,
                hint: FsHint::Ntfs
            }]
        );
        assert_eq!(outcome.status, ScanTerminalStatus::Complete);
        assert_eq!(outcome.bytes_scanned, total as u64);
        assert_eq!(outcome.bytes_total, total as u64);
        assert_eq!(outcome.candidates_reported, 1);
        assert_eq!(outcome.normalized_gap_count, 1);
        assert_eq!(outcome.ignored_gap_count, 1);
        assert_eq!(
            progress.last().map(|sample| sample.bytes_scanned),
            Some(total as u64)
        );
        Ok(())
    }

    #[test]
    fn adjacent_ranges_do_not_hide_a_header_crossing_their_boundary() -> io::Result<()> {
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_ext(&mut data, 1024);
        let candidates = collect_candidates(
            &mut Cursor::new(data),
            &[(0, 2048), (2048, total as u64)],
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        )?;
        assert_eq!(
            candidates,
            vec![Candidate {
                offset: 1024,
                hint: FsHint::Ext,
            }]
        );
        Ok(())
    }

    // ── Test: malformed / short input ───────────────────────────────────

    #[test]
    fn malformed_short_input() -> io::Result<()> {
        // Input shorter than a single sector – should produce no
        // candidates and no errors.
        let data = vec![0u8; 256];
        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, 256)], &config)?;
        assert!(candidates.is_empty(), "no candidates from short input");
        Ok(())
    }

    #[test]
    fn empty_gap_range() -> io::Result<()> {
        let data = vec![0u8; 4096];
        let config = LostScanConfig::default();
        let candidates = collect_candidates(
            &mut Cursor::new(data),
            &[(100, 100), (200, 50)], // zero-width and inverted
            &config,
        )?;
        assert!(candidates.is_empty());
        Ok(())
    }

    // ── Test: fallible callback propagation ─────────────────────────────

    #[test]
    fn fallible_callback_propagation() {
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 0);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let result = scan_gaps(
            &mut Cursor::new(data),
            [(0u64, total as u64)].iter().copied(),
            |_c| Err(io::Error::other("user abort")),
            None::<fn(ScanProgress)>,
            &config,
        );

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("user abort"),
            "expected 'user abort' in error, got: {msg}"
        );
    }

    // ── Test: progress callback fires ───────────────────────────────────

    #[test]
    fn reader_callback_may_seek_and_read_before_a_later_candidate() -> io::Result<()> {
        let total = 12 * 1024usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 0);
        place_fat32(&mut data, 8192);

        let mut offsets = Vec::new();
        scan_gaps_with_reader(
            &mut Cursor::new(data),
            [(0, total as u64)],
            |reader, candidate| {
                offsets.push(candidate.offset);
                if candidate.offset == 0 {
                    reader.seek(SeekFrom::Start(7000))?;
                    let mut scratch = [0u8; 37];
                    reader.read_exact(&mut scratch)?;
                }
                Ok(true)
            },
            None::<fn(ScanProgress)>,
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        )?;

        assert_eq!(offsets, vec![0, 8192]);
        Ok(())
    }

    #[test]
    fn reader_callback_can_stop_cleanly() -> io::Result<()> {
        let total = 8192usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 0);
        place_fat16(&mut data, 4096);

        let mut callbacks = 0usize;
        let outcome = scan_gaps_with_reader(
            &mut Cursor::new(data),
            [(0, total as u64)],
            |_reader, _candidate| {
                callbacks += 1;
                Ok(false)
            },
            None::<fn(ScanProgress)>,
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        )?;

        assert_eq!(callbacks, 1);
        assert_eq!(outcome.status, ScanTerminalStatus::StoppedByCallback);
        assert_eq!(outcome.bytes_scanned, 0);
        assert_eq!(outcome.bytes_total, total as u64);
        assert_eq!(outcome.candidates_reported, 1);
        Ok(())
    }

    #[test]
    fn premature_eof_is_an_error_and_never_reports_100_percent() {
        let actual_len = 4096usize;
        let declared_end = 8192u64;
        let mut samples = Vec::new();

        let result = scan_gaps(
            &mut Cursor::new(vec![0u8; actual_len]),
            [(0, declared_end)],
            |_| Ok(()),
            Some(|progress| samples.push(progress)),
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        );

        let error = result.expect_err("a source shorter than its gap must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(!samples.is_empty());
        assert!(samples
            .iter()
            .all(|sample| sample.bytes_scanned < sample.bytes_total));
        assert_eq!(samples.last().unwrap().bytes_scanned, actual_len as u64);
        assert_eq!(samples.last().unwrap().bytes_total, declared_end);
    }

    #[test]
    fn unaligned_gap_progress_is_exact() -> io::Result<()> {
        let gap_start = 300u64;
        let gap_end = 3901u64;
        let mut samples = Vec::new();

        scan_gaps(
            &mut Cursor::new(vec![0u8; gap_end as usize]),
            [(gap_start, gap_end)],
            |_| Ok(()),
            Some(|progress| samples.push(progress)),
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        )?;

        let expected = gap_end - gap_start;
        assert!(!samples.is_empty());
        assert!(samples
            .windows(2)
            .all(|pair| pair[0].bytes_scanned <= pair[1].bytes_scanned));
        assert!(samples
            .iter()
            .all(|sample| sample.bytes_scanned <= sample.bytes_total));
        assert_eq!(samples.last().unwrap().bytes_total, expected);
        assert_eq!(samples.last().unwrap().bytes_scanned, expected);
        Ok(())
    }

    #[test]
    fn progress_callback_fires() -> io::Result<()> {
        let total = 8192usize;
        let data = vec![0u8; total];
        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);

        let mut progress_calls = 0u32;
        let mut last_progress: Option<ScanProgress> = None;
        scan_gaps(
            &mut Cursor::new(data),
            [(0u64, total as u64)].iter().copied(),
            |_| Ok(()),
            Some(|p: ScanProgress| {
                progress_calls += 1;
                last_progress = Some(p);
            }),
            &config,
        )?;

        assert!(progress_calls > 0, "progress callback should have fired");
        let lp = last_progress.unwrap();
        assert_eq!(lp.bytes_total, total as u64);
        assert_eq!(lp.bytes_scanned, total as u64);
        Ok(())
    }

    // ── Test: FAT32 detection ───────────────────────────────────────────

    #[test]
    fn fat32_detected() -> io::Result<()> {
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_fat32(&mut data, 0);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;
        assert!(candidates
            .iter()
            .any(|c| c.offset == 0 && c.hint == FsHint::Fat));
        Ok(())
    }

    // ── Test: FAT16 detection ───────────────────────────────────────────

    #[test]
    fn fat16_detected() -> io::Result<()> {
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_fat16(&mut data, 0);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;
        assert!(candidates
            .iter()
            .any(|c| c.offset == 0 && c.hint == FsHint::Fat));
        Ok(())
    }

    // ── Test: BitLocker detection ───────────────────────────────────────

    #[test]
    fn bitlocker_detected() -> io::Result<()> {
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_bitlocker(&mut data, 0);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;
        assert!(candidates
            .iter()
            .any(|c| c.offset == 0 && c.hint == FsHint::BitLocker));
        Ok(())
    }

    // ── Test: multiple filesystem types in one scan ─────────────────────

    #[test]
    fn multiple_fs_types() -> io::Result<()> {
        let total = 16384usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 0);
        place_fat16(&mut data, 2048);
        place_ext(&mut data, 4096);
        place_bitlocker(&mut data, 6144);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, total as u64)], &config)?;

        assert!(candidates
            .iter()
            .any(|c| c.offset == 0 && c.hint == FsHint::Ntfs));
        assert!(candidates
            .iter()
            .any(|c| c.offset == 2048 && c.hint == FsHint::Fat));
        assert!(candidates
            .iter()
            .any(|c| c.offset == 4096 && c.hint == FsHint::Ext));
        assert!(candidates
            .iter()
            .any(|c| c.offset == 6144 && c.hint == FsHint::BitLocker));
        Ok(())
    }

    // ── Test: multiple gaps ─────────────────────────────────────────────

    #[test]
    fn multiple_gaps() -> io::Result<()> {
        let total = 16384usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 1024);
        place_fat32(&mut data, 8192);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates = collect_candidates(
            &mut Cursor::new(data),
            &[(1024, 2048), (8192, 12288)],
            &config,
        )?;

        assert!(candidates
            .iter()
            .any(|c| c.offset == 1024 && c.hint == FsHint::Ntfs));
        assert!(candidates
            .iter()
            .any(|c| c.offset == 8192 && c.hint == FsHint::Fat));
        // Nothing at offset 0 (outside gaps).
        assert!(!candidates.iter().any(|c| c.offset == 0));
        Ok(())
    }

    // ── Test: all zeros produces no candidates ──────────────────────────

    #[test]
    fn all_zeros_no_candidates() -> io::Result<()> {
        let data = vec![0u8; 65536];
        let config = LostScanConfig::default();
        let candidates = collect_candidates(&mut Cursor::new(data), &[(0, 65536)], &config)?;
        assert!(
            candidates.is_empty(),
            "all-zeros should not match: {candidates:?}"
        );
        Ok(())
    }

    // ── SparseCursor: fake seekable reader for multi-GB offsets ──────────

    /// A scanner-specific sparse `Read + Seek` implementation backed by a
    /// `BTreeMap` of written regions. It avoids materialising or repeatedly
    /// zero-filling the multi-gigabyte logical source: the scanner reuses one
    /// initially-zeroed buffer, so this helper only clears bytes dirtied by a
    /// previous patch and writes patches intersecting the current read.
    struct SparseCursor {
        len: u64,
        pos: u64,
        patches: std::collections::BTreeMap<u64, Vec<u8>>,
        dirty_indices: Vec<usize>,
        initialized_len: usize,
    }

    impl SparseCursor {
        fn new(len: u64) -> Self {
            Self {
                len,
                pos: 0,
                patches: std::collections::BTreeMap::new(),
                dirty_indices: Vec::new(),
                initialized_len: 0,
            }
        }

        fn write_at(&mut self, offset: u64, data: &[u8]) {
            self.patches.insert(offset, data.to_vec());
        }
    }

    impl Read for SparseCursor {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.len {
                return Ok(0);
            }
            let avail = (self.len - self.pos).min(usize::MAX as u64) as usize;
            let n = buf.len().min(avail);

            if self.initialized_len < n {
                buf[self.initialized_len..n].fill(0);
                self.initialized_len = n;
            }

            let mut dirty_indices = Vec::new();
            for index in self.dirty_indices.drain(..) {
                if index < n {
                    buf[index] = 0;
                } else {
                    dirty_indices.push(index);
                }
            }

            let read_start = self.pos;
            let read_end = read_start + n as u64;
            for (&patch_start, patch) in &self.patches {
                let patch_end = patch_start.saturating_add(patch.len() as u64);
                if patch_end <= read_start {
                    continue;
                }
                if patch_start >= read_end {
                    break;
                }

                let overlap_start = patch_start.max(read_start);
                let overlap_end = patch_end.min(read_end);
                let source_start = (overlap_start - patch_start) as usize;
                let destination_start = (overlap_start - read_start) as usize;
                let overlap_len = (overlap_end - overlap_start) as usize;
                let source = &patch[source_start..source_start + overlap_len];
                let destination = &mut buf[destination_start..destination_start + overlap_len];
                destination.copy_from_slice(source);
                dirty_indices.extend(
                    source
                        .iter()
                        .enumerate()
                        .filter(|(_, byte)| **byte != 0)
                        .map(|(index, _)| destination_start + index),
                );
            }
            self.dirty_indices = dirty_indices;
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for SparseCursor {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            let new_pos: i64 = match pos {
                SeekFrom::Start(p) => p as i64,
                SeekFrom::Current(d) => self.pos as i64 + d,
                SeekFrom::End(d) => self.len as i64 + d,
            };
            if new_pos < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seek before start",
                ));
            }
            self.pos = new_pos as u64;
            Ok(self.pos)
        }
    }

    // ── Test: classify_sector unit tests ────────────────────────────────

    #[test]
    fn classify_sector_empty() {
        assert_eq!(classify_sector(&[]), None);
    }

    #[test]
    fn classify_sector_too_short() {
        assert_eq!(classify_sector(&[0u8; 100]), None);
    }

    #[test]
    fn classify_sector_ntfs() {
        let mut sec = vec![0u8; 512];
        place_ntfs(&mut sec, 0);
        assert_eq!(classify_sector(&sec), Some(FsHint::Ntfs));
    }

    #[test]
    fn classify_sector_ext_priority_over_boot_sig() {
        // ext magic takes priority: even if 0x55AA is present, ext wins.
        let mut sec = vec![0u8; HEADER_SIZE];
        place_ext(&mut sec, 0);
        sec[510] = 0x55;
        sec[511] = 0xAA;
        assert_eq!(classify_sector(&sec), Some(FsHint::Ext));
    }

    #[test]
    fn classify_bitlocker_priority_over_ntfs() {
        // BitLocker FVE at same position as OEM ID – should not be NTFS.
        let mut sec = vec![0u8; 512];
        place_bitlocker(&mut sec, 0);
        assert_eq!(classify_sector(&sec), Some(FsHint::BitLocker));
    }

    #[test]
    fn magic_only_and_substring_lookalikes_are_rejected() {
        let mut ext = vec![0u8; HEADER_SIZE];
        ext[0x438..0x43A].copy_from_slice(&0xEF53_u16.to_le_bytes());
        assert_eq!(classify_sector(&ext), None);

        let mut ntfs = vec![0u8; 512];
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        ntfs[510..512].copy_from_slice(&[0x55, 0xAA]);
        assert_eq!(classify_sector(&ntfs), None);

        let mut fat = vec![0u8; 512];
        fat[54..62].copy_from_slice(b"XXFAT16 ");
        fat[510..512].copy_from_slice(&[0x55, 0xAA]);
        assert_eq!(classify_sector(&fat), None);

        let mut bitlocker = vec![0u8; 512];
        bitlocker[3..11].copy_from_slice(BITLOCKER_FVE_SIGNATURE);
        bitlocker[510..512].copy_from_slice(&[0x55, 0xAA]);
        assert_eq!(classify_sector(&bitlocker), None);
    }

    #[test]
    fn endian_swapped_geometry_is_rejected() {
        let mut ntfs = vec![0u8; 512];
        place_ntfs(&mut ntfs, 0);
        ntfs[11..13].copy_from_slice(&512_u16.to_be_bytes());
        assert_eq!(classify_sector(&ntfs), None);

        let mut ext = vec![0u8; HEADER_SIZE];
        place_ext(&mut ext, 0);
        ext[0x418..0x41C].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(classify_sector(&ext), None);
    }

    #[test]
    fn ext_backup_superblock_is_not_a_partition_start_candidate() {
        let mut ext = vec![0u8; HEADER_SIZE];
        place_ext(&mut ext, 0);
        ext[0x45A..0x45C].copy_from_slice(&7_u16.to_le_bytes());
        assert_eq!(classify_sector(&ext), None);
    }

    #[test]
    fn gap_boundary_truncation_never_promotes_a_partial_header() -> io::Result<()> {
        let mut data = vec![0u8; 512];
        place_ntfs(&mut data, 0);
        let candidates = collect_candidates(
            &mut Cursor::new(data),
            &[(0, 511)],
            &LostScanConfig::new().chunk_size(HEADER_SIZE),
        )?;
        assert!(candidates.is_empty());
        Ok(())
    }

    // ── Test: gap_start not sector-aligned is handled ───────────────────

    #[test]
    fn invalid_public_configuration_returns_errors_without_panicking() {
        for chunk_size in [0, HEADER_SIZE - 1, usize::MAX] {
            let mut source = Cursor::new(Vec::<u8>::new());
            let error = scan_gaps(
                &mut source,
                std::iter::empty(),
                |_| Ok(()),
                None::<fn(ScanProgress)>,
                &LostScanConfig::new().chunk_size(chunk_size),
            )
            .expect_err("invalid chunk size must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn overlapping_progress_ranges_use_union_length() -> io::Result<()> {
        let normalized = normalize_gaps([
            (4096, 8192),
            (0, 4096),
            (2048, 6144),
            (300, 300),
            (900, 100),
        ])?;
        assert_eq!(normalized.ranges, vec![(0, 8192)]);
        assert_eq!(normalized.bytes_total, 8192);
        assert_eq!(normalized.ignored_count, 2);
        Ok(())
    }

    #[test]
    fn non_sector_aligned_gap_start() -> io::Result<()> {
        // gap starts at 300, which isn't 512-aligned.  Scanner should
        // advance to the first 512-aligned sector within the gap (512).
        let total = 4096usize;
        let mut data = vec![0u8; total];
        place_ntfs(&mut data, 512);

        let config = LostScanConfig::new().chunk_size(HEADER_SIZE);
        let candidates =
            collect_candidates(&mut Cursor::new(data), &[(300, total as u64)], &config)?;

        assert!(
            candidates
                .iter()
                .any(|c| c.offset == 512 && c.hint == FsHint::Ntfs),
            "expected NTFS at 512 even though gap starts at 300: {candidates:?}"
        );
        // Nothing at offset 300 (not sector-aligned).
        assert!(!candidates.iter().any(|c| c.offset == 300));
        Ok(())
    }

    #[test]
    fn fat_geometry_does_not_require_informational_type_label() {
        let mut fat16 = vec![0_u8; 512];
        place_fat16(&mut fat16, 0);
        fat16[54..62].fill(b' ');
        assert_eq!(classify_sector(&fat16), Some(FsHint::Fat));

        let mut fat32 = vec![0_u8; 512];
        place_fat32(&mut fat32, 0);
        fat32[82..90].copy_from_slice(b"NOTAFS  ");
        assert_eq!(classify_sector(&fat32), Some(FsHint::Fat));
    }
}
