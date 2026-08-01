use std::convert::TryFrom;
use std::io;

use anyhow::ensure;
use anyhow::Error;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::assumption_failed;
use crate::not_found;

const EXT4_BLOCK_GROUP_INODES_UNUSED: u16 = 0b1;

#[derive(Debug)]
struct Entry {
    inode_table_block: u64,
    max_inode_number: u32,
}

#[derive(Debug)]
pub struct BlockGroups {
    groups: Vec<Entry>,
    inodes_per_group: u32,
    pub block_size: u32,
    pub inode_size: u16,
}

impl BlockGroups {
    pub fn new<R>(
        mut inner: R,
        blocks_count: u64,
        s_desc_size: u16,
        s_inodes_per_group: u32,
        block_size: u32,
        inode_size: u16,
        checksum_seed: Option<u32>,
    ) -> Result<BlockGroups, Error>
    where
        R: io::Read + io::Seek,
    {
        let blocks_count = usize::try_from(blocks_count)?;
        // A zero s_desc_size is the legacy on-disk encoding for a 32-byte
        // descriptor.  The 64-bit feature uses descriptors of at least 64
        // bytes; offsets in that extension are relative to byte 32, not to
        // the start of the next descriptor.
        let descriptor_size = if s_desc_size == 0 {
            32usize
        } else {
            usize::from(s_desc_size)
        };
        ensure!(
            descriptor_size >= 32,
            assumption_failed(format!(
                "block group descriptor is too short: {descriptor_size} bytes"
            ))
        );

        // Do not reserve from an untrusted superblock count up front. A
        // corrupt image can otherwise force a huge allocation before the
        // first descriptor has even been validated or read.
        let mut groups = Vec::new();
        groups
            .try_reserve(blocks_count.min(4096))
            .map_err(|_| assumption_failed("cannot allocate ext4 block group table"))?;

        for block in 0..blocks_count {
            let mut descriptor = vec![0u8; descriptor_size];
            inner.read_exact(&mut descriptor)?;
            if let Some(checksum_seed) = checksum_seed {
                let expected = u16::from_le_bytes([descriptor[0x1e], descriptor[0x1f]]);
                descriptor[0x1e] = 0;
                descriptor[0x1f] = 0;
                let group_number = u32::try_from(block)
                    .map_err(|_| assumption_failed("ext4 group number exceeds u32"))?;
                let prefix =
                    crate::parse::ext4_style_crc32c_le(checksum_seed, &group_number.to_le_bytes());
                let computed = crate::parse::ext4_style_crc32c_le(prefix, &descriptor) as u16;
                ensure!(
                    expected == computed,
                    assumption_failed(format!(
                        "block group {block} checksum mismatch: {expected:04x} != {computed:04x}"
                    ))
                );
            }
            let mut inner = io::Cursor::new(descriptor);

            //            let bg_block_bitmap_lo =
            inner.read_u32::<LittleEndian>()?; /* Blocks bitmap block */
            //            let bg_inode_bitmap_lo =
            inner.read_u32::<LittleEndian>()?; /* Inodes bitmap block */
            let bg_inode_table_lo = inner.read_u32::<LittleEndian>()?; /* Inodes table block */
            //            let bg_free_blocks_count_lo =
            inner.read_u16::<LittleEndian>()?; /* Free blocks count */
            let bg_free_inodes_count_lo = inner.read_u16::<LittleEndian>()?; /* Free inodes count */
            //            let bg_used_dirs_count_lo =
            inner.read_u16::<LittleEndian>()?; /* Directories count */
            let bg_flags = inner.read_u16::<LittleEndian>()?; /* EXT4_BG_flags (INODE_UNINIT, etc) */
            //            let bg_exclude_bitmap_lo =
            inner.read_u32::<LittleEndian>()?; /* Exclude bitmap for snapshots */
            //            let bg_block_bitmap_csum_lo =
            inner.read_u16::<LittleEndian>()?; /* crc32c(s_uuid+grp_num+bbitmap) LE */
            //            let bg_inode_bitmap_csum_lo =
            inner.read_u16::<LittleEndian>()?; /* crc32c(s_uuid+grp_num+ibitmap) LE */
            //            let bg_itable_unused_lo =
            inner.read_u16::<LittleEndian>()?; /* Unused inodes count */
            //            let bg_checksum =
            inner.read_u16::<LittleEndian>()?; /* crc16(sb_uuid+group+desc) */

            let (bg_inode_table_hi, bg_free_inodes_count_hi) = if descriptor_size >= 64 {
                //            let bg_block_bitmap_hi =
                inner.read_u32::<LittleEndian>()?; /* Blocks bitmap block MSB */
                //            let bg_inode_bitmap_hi =
                inner.read_u32::<LittleEndian>()?; /* Inodes bitmap block MSB */
                let inode_table_hi = inner.read_u32::<LittleEndian>()?; /* Inodes table block MSB */
                //            let bg_free_blocks_count_hi =
                inner.read_u16::<LittleEndian>()?; /* Free blocks count MSB */
                let free_inodes_count_hi = inner.read_u16::<LittleEndian>()?; /* Free inodes count MSB */
                (Some(inode_table_hi), Some(free_inodes_count_hi))
            } else {
                (None, None)
            };

            //          let bg_used_dirs_count_hi =
            //              inner.read_u16::<LittleEndian>()?; /* Directories count MSB */
            //          let bg_itable_unused_hi =
            //              inner.read_u16::<LittleEndian>()?; /* Unused inodes count MSB */
            //          let bg_exclude_bitmap_hi =
            //              inner.read_u32::<LittleEndian>()?; /* Exclude bitmap block MSB */
            //          let bg_block_bitmap_csum_hi =
            //              inner.read_u16::<LittleEndian>()?; /* crc32c(s_uuid+grp_num+bbitmap) BE */
            //          let bg_inode_bitmap_csum_hi =
            //              inner.read_u16::<LittleEndian>()?; /* crc32c(s_uuid+grp_num+ibitmap) BE */
            let inode_table_block =
                u64::from(bg_inode_table_lo) | ((u64::from(bg_inode_table_hi.unwrap_or(0))) << 32);
            let free_inodes_count = u32::from(bg_free_inodes_count_lo)
                | ((u32::from(bg_free_inodes_count_hi.unwrap_or(0))) << 16);

            // BLOCK_UNINIT says only that the block bitmap is uninitialized;
            // it does not make valid inodes in the group disappear.
            let unallocated = bg_flags & EXT4_BLOCK_GROUP_INODES_UNUSED != 0;

            if free_inodes_count > s_inodes_per_group {
                return Err(crate::parse_error(format!(
                    "too many free inodes in group {}: {} > {}",
                    block, free_inodes_count, s_inodes_per_group
                )));
            }

            let max_inode_number = if unallocated {
                0
            } else {
                // can't use free inodes here, as there can be unallocated ranges in the middle;
                // would have to parse the bitmap to work that out and it doesn't seem worth
                // the effort
                s_inodes_per_group
            };

            groups.push(Entry {
                inode_table_block,
                max_inode_number,
            });
        }

        Ok(BlockGroups {
            groups,
            inodes_per_group: s_inodes_per_group,
            block_size,
            inode_size,
        })
    }

    pub fn index_of(&self, inode: u32) -> Result<u64, Error> {
        ensure!(0 != inode, not_found("there is no inode zero"));

        let inode = inode - 1;
        let group_number = inode / self.inodes_per_group;
        let group = self
            .groups
            .get(usize::try_from(group_number)?)
            .ok_or_else(|| {
                not_found(format!(
                    "inode {inode} refers to missing group {group_number}"
                ))
            })?;
        let inode_index_in_group = inode % self.inodes_per_group;
        ensure!(
            inode_index_in_group < group.max_inode_number,
            assumption_failed(format!(
                "inode <{}> number must fit in group: {} is greater than {} for group {}",
                inode + 1,
                inode_index_in_group,
                group.max_inode_number,
                group_number
            ))
        );
        let table_offset = group
            .inode_table_block
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| assumption_failed("inode table byte offset overflow"))?;
        let inode_offset = u64::from(inode_index_in_group)
            .checked_mul(u64::from(self.inode_size))
            .ok_or_else(|| assumption_failed("inode byte offset overflow"))?;
        table_offset
            .checked_add(inode_offset)
            .ok_or_else(|| assumption_failed("inode absolute byte offset overflow").into())
    }
}

#[cfg(test)]
mod tests {
    use super::BlockGroups;
    use std::io::Cursor;

    fn descriptor(inode_table_lo: u32, free_inodes: u16, flags: u16) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[8..12].copy_from_slice(&inode_table_lo.to_le_bytes());
        bytes[14..16].copy_from_slice(&free_inodes.to_le_bytes());
        bytes[18..20].copy_from_slice(&flags.to_le_bytes());
        bytes
    }

    #[test]
    fn legacy_descriptors_stay_aligned_at_32_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&descriptor(10, 0, 0));
        bytes.extend_from_slice(&descriptor(20, 0, 0));

        let groups = BlockGroups::new(Cursor::new(bytes), 2, 32, 4, 1024, 256, None).unwrap();
        assert_eq!(groups.index_of(1).unwrap(), 10 * 1024);
        assert_eq!(groups.index_of(5).unwrap(), 20 * 1024);
    }

    #[test]
    fn sixty_four_byte_descriptor_uses_high_inode_table_bits() {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&descriptor(7, 0, 0));
        bytes[40..44].copy_from_slice(&2u32.to_le_bytes());

        let groups = BlockGroups::new(Cursor::new(bytes), 1, 64, 4, 1024, 256, None).unwrap();
        assert_eq!(groups.index_of(1).unwrap(), ((2u64 << 32) | 7) * 1024);
    }

    #[test]
    fn uninitialized_block_bitmap_does_not_hide_inodes() {
        let bytes = descriptor(11, 0, 0b10);
        let groups = BlockGroups::new(Cursor::new(bytes), 1, 32, 4, 1024, 256, None).unwrap();
        assert_eq!(groups.index_of(1).unwrap(), 11 * 1024);
    }

    #[test]
    fn overflowing_inode_table_offset_is_rejected() {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&descriptor(u32::MAX, 0, 0));
        bytes[40..44].copy_from_slice(&u32::MAX.to_le_bytes());

        let groups = BlockGroups::new(Cursor::new(bytes), 1, 64, 4, u32::MAX, 256, None).unwrap();
        assert!(groups.index_of(1).is_err());
    }

    #[test]
    fn metadata_checksum_rejects_corrupt_descriptor() {
        let bytes = descriptor(11, 0, 0);
        assert!(BlockGroups::new(Cursor::new(bytes), 1, 32, 4, 1024, 256, Some(7)).is_err());
    }
}
