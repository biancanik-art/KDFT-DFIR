use std::convert::TryFrom;
use std::io;

use anyhow::ensure;
use anyhow::Error;
use positioned_io::ReadAt;

use crate::assumption_failed;
use crate::read_le16;
use crate::read_le32;

#[derive(Debug)]
struct Extent {
    /// The docs call this 'block' (like everything else). I've invented a different name.
    part: u32,
    start: u64,
    len: u16,
    initialized: bool,
}

pub struct TreeReader<R> {
    inner: R,
    pos: u64,
    len: u64,
    block_size: u32,
    extents: Vec<Extent>,
}

impl<R> TreeReader<R>
where
    R: ReadAt,
{
    pub fn new(
        inner: R,
        block_size: u32,
        size: u64,
        core: [u8; crate::INODE_CORE_SIZE],
        checksum_prefix: Option<u32>,
    ) -> Result<TreeReader<R>, Error> {
        let extents = load_extent_tree(
            &mut |block| crate::load_disc_bytes(&inner, block_size, block),
            core,
            checksum_prefix,
        )?;
        Ok(TreeReader::create(inner, block_size, size, extents))
    }

    fn create(inner: R, block_size: u32, size: u64, extents: Vec<Extent>) -> TreeReader<R> {
        TreeReader {
            pos: 0,
            len: size,
            inner,
            extents,
            block_size,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub(crate) fn first_extent_location(&self) -> Result<Option<(u64, u64, u64)>, Error> {
        let block_size = u64::from(self.block_size);
        for extent in self
            .extents
            .iter()
            .filter(|extent| extent.initialized && extent.len > 0)
        {
            let file_offset = u64::from(extent.part)
                .checked_mul(block_size)
                .ok_or_else(|| assumption_failed("extent file offset overflow"))?;
            if file_offset >= self.len {
                continue;
            }
            let filesystem_offset = extent
                .start
                .checked_mul(block_size)
                .ok_or_else(|| assumption_failed("extent filesystem offset overflow"))?;
            let extent_bytes = u64::from(extent.len)
                .checked_mul(block_size)
                .ok_or_else(|| assumption_failed("extent byte length overflow"))?;
            let contiguous_bytes = extent_bytes.min(self.len - file_offset);
            return Ok(Some((file_offset, filesystem_offset, contiguous_bytes)));
        }
        Ok(None)
    }
}

enum FoundPart<'a> {
    Actual(&'a Extent),
    Sparse(u32),
}

fn find_part(part: u32, extents: &[Extent]) -> FoundPart<'_> {
    for extent in extents {
        if part < extent.part {
            // we've gone past it
            return FoundPart::Sparse(extent.part - part);
        }

        let extent_end = extent.part.saturating_add(u32::from(extent.len));
        if part >= extent.part && part < extent_end {
            // we're inside it
            return if extent.initialized {
                FoundPart::Actual(extent)
            } else {
                FoundPart::Sparse(extent_end - part)
            };
        }
    }

    FoundPart::Sparse(u32::MAX)
}

impl<R> io::Read for TreeReader<R>
where
    R: ReadAt,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos == self.len {
            return Ok(0);
        }

        if self.pos > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ext4 reader position is beyond end of file",
            ));
        }

        let block_size = u64::from(self.block_size);
        if block_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ext4 block size cannot be zero",
            ));
        }

        let wanted_block = u32::try_from(self.pos / block_size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ext4 logical block number exceeds the extent format",
            )
        })?;
        let read_of_this_block = self.pos % block_size;

        match find_part(wanted_block, &self.extents) {
            FoundPart::Actual(extent) => {
                let bytes_through_extent =
                    (block_size * u64::from(wanted_block - extent.part)) + read_of_this_block;
                let remaining_bytes_in_extent =
                    (u64::from(extent.len) * block_size) - bytes_through_extent;
                let to_read = std::cmp::min(remaining_bytes_in_extent, buf.len() as u64) as usize;
                let to_read = std::cmp::min(to_read as u64, self.len - self.pos) as usize;
                let offset = extent
                    .start
                    .checked_mul(block_size)
                    .and_then(|start| start.checked_add(bytes_through_extent))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ext4 physical extent offset overflow",
                        )
                    })?;
                let read = self.inner.read_at(offset, &mut buf[0..to_read])?;
                self.pos = self
                    .pos
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("ext4 reader position overflow"))?;
                Ok(read)
            }
            FoundPart::Sparse(max) => {
                let max_bytes = u64::from(max) * block_size;
                let read = std::cmp::min(max_bytes, buf.len() as u64) as usize;
                let read = std::cmp::min(read as u64, self.len - self.pos) as usize;
                zero(&mut buf[0..read]);
                self.pos = self
                    .pos
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("ext4 reader position overflow"))?;
                Ok(read)
            }
        }
    }
}

impl<R> io::Seek for TreeReader<R>
where
    R: ReadAt,
{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let requested = match pos {
            io::SeekFrom::Start(set) => i128::from(set),
            io::SeekFrom::Current(diff) => i128::from(self.pos) + i128::from(diff),
            io::SeekFrom::End(diff) => i128::from(self.len) + i128::from(diff),
        };
        if requested < 0 || requested > i128::from(self.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek outside ext4 file bounds",
            ));
        }
        self.pos = requested as u64;
        Ok(self.pos)
    }
}

fn add_found_extents<F>(
    load_block: &mut F,
    data: &[u8],
    expected_depth: u16,
    extents: &mut Vec<Extent>,
    checksum_prefix: Option<u32>,
    first_level: bool,
) -> Result<(), Error>
where
    F: FnMut(u64) -> Result<Vec<u8>, Error>,
{
    ensure!(
        data.len() >= 12,
        assumption_failed(format!("extent node is too short: {} bytes", data.len()))
    );
    ensure!(
        0x0a == data[0] && 0xf3 == data[1],
        assumption_failed("invalid extent magic")
    );

    let extent_entries = read_le16(&data[2..]);
    let max_entries = read_le16(&data[4..]);
    let depth = read_le16(&data[6..]);
    // 8..: generation, not used in standard ext4

    ensure!(
        expected_depth == depth,
        assumption_failed(format!("depth incorrect: {} != {}", expected_depth, depth))
    );

    ensure!(
        extent_entries <= max_entries,
        assumption_failed(format!(
            "extent node has {extent_entries} entries but capacity is {max_entries}"
        ))
    );
    let checksum_bytes = usize::from(!first_level && checksum_prefix.is_some()) * 4;
    let usable_len = data.len().saturating_sub(checksum_bytes);
    let entries_end = 12usize
        .checked_add(
            usize::from(extent_entries)
                .checked_mul(12)
                .ok_or_else(|| assumption_failed("extent entry byte count overflow"))?,
        )
        .ok_or_else(|| assumption_failed("extent node byte count overflow"))?;
    ensure!(
        entries_end <= usable_len,
        assumption_failed(format!(
            "extent entries exceed node bounds: need {entries_end}, have {usable_len}"
        ))
    );

    if !first_level && checksum_prefix.is_some() {
        let end_of_entries = data.len() - 4;
        let on_disc = read_le32(&data[end_of_entries..(end_of_entries + 4)]);
        let computed = crate::parse::ext4_style_crc32c_le(
            checksum_prefix.ok_or_else(|| assumption_failed("missing extent checksum prefix"))?,
            &data[..end_of_entries],
        );

        ensure!(
            computed == on_disc,
            assumption_failed(format!(
                "extent checksum mismatch: {:08x} != {:08x} @ {}",
                on_disc,
                computed,
                data.len()
            ),)
        );
    }

    if 0 == depth {
        for en in 0..extent_entries {
            let raw_extent = &data[12 + usize::from(en) * 12..];
            let ee_block = read_le32(raw_extent);
            let encoded_len = read_le16(&raw_extent[4..]);
            let initialized = encoded_len <= 0x8000;
            let ee_len = if initialized {
                encoded_len
            } else {
                encoded_len - 0x8000
            };
            ensure!(
                ee_len != 0,
                assumption_failed("extent has a zero logical length")
            );
            let ee_start_hi = read_le16(&raw_extent[6..]);
            let ee_start_lo = read_le32(&raw_extent[8..]);
            let ee_start = u64::from(ee_start_lo) | (u64::from(ee_start_hi) << 32);

            extents.push(Extent {
                part: ee_block,
                start: ee_start,
                len: ee_len,
                initialized,
            });
        }

        return Ok(());
    }

    for en in 0..extent_entries {
        let extent_idx = &data[12 + usize::from(en) * 12..];
        //            let ei_block = as_u32(extent_idx);
        let ei_leaf_lo = read_le32(&extent_idx[4..]);
        let ei_leaf_hi = read_le16(&extent_idx[8..]);
        let ee_leaf: u64 = u64::from(ei_leaf_lo) + (u64::from(ei_leaf_hi) << 32);
        let data = load_block(ee_leaf)?;
        add_found_extents(
            load_block,
            &data,
            depth - 1,
            extents,
            checksum_prefix,
            false,
        )?;
    }

    Ok(())
}

fn load_extent_tree<F>(
    load_block: &mut F,
    core: [u8; crate::INODE_CORE_SIZE],
    checksum_prefix: Option<u32>,
) -> Result<Vec<Extent>, Error>
where
    F: FnMut(u64) -> Result<Vec<u8>, Error>,
{
    ensure!(
        0x0a == core[0] && 0xf3 == core[1],
        assumption_failed("invalid extent magic")
    );

    let extent_entries = read_le16(&core[2..]);
    // 4..: max; doesn't seem to be useful during read
    let depth = read_le16(&core[6..]);

    ensure!(
        depth <= 5,
        assumption_failed(format!("initial depth too high: {}", depth))
    );

    let mut extents = Vec::with_capacity(usize::from(extent_entries) + usize::from(depth) * 200);

    add_found_extents(
        load_block,
        &core,
        depth,
        &mut extents,
        checksum_prefix,
        true,
    )?;

    extents.sort_by_key(|e| e.part);

    for extent in &extents {
        extent
            .part
            .checked_add(u32::from(extent.len))
            .ok_or_else(|| assumption_failed("extent logical block range overflow"))?;
    }
    for pair in extents.windows(2) {
        let previous_end = pair[0].part + u32::from(pair[0].len);
        ensure!(
            previous_end <= pair[1].part,
            assumption_failed(format!(
                "overlapping extents at logical blocks {} and {}",
                pair[0].part, pair[1].part
            ))
        );
    }

    Ok(extents)
}

fn zero(buf: &mut [u8]) {
    buf.fill(0);
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::io::{self, Read, Seek};

    use crate::extents::Extent;
    use crate::extents::TreeReader;

    #[test]
    fn simple_tree() {
        let data = (0..255u8).collect::<Vec<u8>>();
        let size = 4 + 4 * 2;
        let mut reader = TreeReader::create(
            data,
            4,
            u64::try_from(size).expect("infallible u64 conversion"),
            vec![
                Extent {
                    part: 0,
                    start: 10,
                    len: 1,
                    initialized: true,
                },
                Extent {
                    part: 1,
                    start: 20,
                    len: 2,
                    initialized: true,
                },
            ],
        );

        let mut res = Vec::new();
        assert_eq!(size, reader.read_to_end(&mut res).unwrap());

        assert_eq!(vec![40, 41, 42, 43, 80, 81, 82, 83, 84, 85, 86, 87], res);
    }

    #[test]
    fn zero_buf() {
        let mut buf = [7u8; 5];
        assert_eq!(7, buf[0]);
        crate::extents::zero(&mut buf);
        for i in &buf {
            assert_eq!(0, *i);
        }
    }

    #[test]
    fn extent_physical_high_bits_are_shifted_by_32() {
        let mut core = [0u8; crate::INODE_CORE_SIZE];
        core[0..2].copy_from_slice(&0xf30au16.to_le_bytes());
        core[2..4].copy_from_slice(&1u16.to_le_bytes());
        core[4..6].copy_from_slice(&4u16.to_le_bytes());
        core[12..16].copy_from_slice(&3u32.to_le_bytes());
        core[16..18].copy_from_slice(&1u16.to_le_bytes());
        core[18..20].copy_from_slice(&2u16.to_le_bytes());
        core[20..24].copy_from_slice(&7u32.to_le_bytes());

        let extents = super::load_extent_tree(&mut |_| unreachable!(), core, None).unwrap();
        assert_eq!(extents[0].start, (2u64 << 32) | 7);
    }

    #[test]
    fn unwritten_extent_reads_as_zero_and_is_not_a_physical_source() {
        let data = (0..128u8).collect::<Vec<u8>>();
        let mut reader = TreeReader::create(
            data,
            4,
            8,
            vec![
                Extent {
                    part: 0,
                    start: 10,
                    len: 1,
                    initialized: false,
                },
                Extent {
                    part: 1,
                    start: 20,
                    len: 1,
                    initialized: true,
                },
            ],
        );

        assert_eq!(reader.first_extent_location().unwrap(), Some((4, 80, 4)));
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 80, 81, 82, 83]);
    }

    #[test]
    fn seek_rejects_positions_outside_file_without_panicking() {
        let mut reader = TreeReader::create(Vec::<u8>::new(), 4, 8, Vec::new());
        assert_eq!(
            reader.seek(io::SeekFrom::End(-1)).unwrap(),
            7,
            "standard negative seek from end should work"
        );
        assert_eq!(
            reader.seek(io::SeekFrom::Current(-8)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            reader.seek(io::SeekFrom::End(1)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn oversized_logical_block_returns_error_without_panicking() {
        let len = (u64::from(u32::MAX) + 2) * 4;
        let mut reader = TreeReader::create(Vec::<u8>::new(), 4, len, Vec::new());
        reader
            .seek(io::SeekFrom::Start((u64::from(u32::MAX) + 1) * 4))
            .unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn overflowing_physical_extent_offset_is_rejected() {
        let reader = TreeReader::create(
            Vec::<u8>::new(),
            u32::MAX,
            1,
            vec![Extent {
                part: 0,
                start: u64::MAX,
                len: 1,
                initialized: true,
            }],
        );
        assert!(reader.first_extent_location().is_err());
    }

    #[test]
    fn first_extent_location_is_limited_to_logical_file_size() {
        let reader = TreeReader::create(
            Vec::<u8>::new(),
            4,
            6,
            vec![Extent {
                part: 1,
                start: 10,
                len: 3,
                initialized: true,
            }],
        );
        assert_eq!(reader.first_extent_location().unwrap(), Some((4, 40, 2)));
    }

    #[test]
    fn extent_beyond_logical_end_is_not_reported_as_file_data() {
        let reader = TreeReader::create(
            Vec::<u8>::new(),
            4,
            4,
            vec![Extent {
                part: 1,
                start: 10,
                len: 1,
                initialized: true,
            }],
        );
        assert_eq!(reader.first_extent_location().unwrap(), None);
    }
}
