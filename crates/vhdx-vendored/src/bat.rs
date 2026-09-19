use crate::bytes::le_u64;
use crate::error::{Result, VhdxError};
use crate::metadata::VhdxMetadata;

const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;

#[derive(Debug, Clone)]
pub struct Bat {
    entries: Vec<u64>,
    meta: VhdxMetadata,
    #[allow(dead_code)]
    region_offset: u64,
}

impl Bat {
    pub fn parse(data: &[u8], bat_offset: u64, bat_len: u32, meta: VhdxMetadata) -> Result<Self> {
        let start = bat_offset as usize;
        let end = start + bat_len as usize;
        if data.len() < end {
            return Err(VhdxError::BatRegionMissing);
        }
        let bat_bytes = &data[start..end];
        let entry_count = bat_bytes.len() / 8;
        let mut entries = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let e = le_u64(bat_bytes, i * 8);
            entries.push(e);
        }
        Ok(Self {
            entries,
            meta,
            region_offset: bat_offset,
        })
    }

    pub fn file_offset_for_byte(&self, virtual_byte: u64) -> Result<u64> {
        if virtual_byte >= self.meta.virtual_disk_size {
            return Err(VhdxError::SectorOutOfRange {
                sector: virtual_byte / u64::from(self.meta.logical_sector_size),
                size: self.meta.virtual_disk_size,
            });
        }
        let block_size = u64::from(self.meta.block_size);
        let data_block_index = virtual_byte / block_size;
        let offset_within_block = virtual_byte % block_size;
        let chunk_ratio = self.meta.chunk_ratio();

        let bat_index = data_block_index + data_block_index / chunk_ratio;

        let bat_entry = *self
            .entries
            .get(bat_index as usize)
            .ok_or(VhdxError::BlockNotPresent(data_block_index))?;

        let state = bat_entry & 0b111;
        if state == PAYLOAD_BLOCK_NOT_PRESENT {
            return Err(VhdxError::BlockNotPresent(data_block_index));
        }
        if state != PAYLOAD_BLOCK_FULLY_PRESENT {
            return Err(VhdxError::BlockNotPresent(data_block_index));
        }

        let file_offset_mb = bat_entry >> 20;
        let file_offset = file_offset_mb
            .checked_mul(0x0010_0000)
            .and_then(|o| o.checked_add(offset_within_block))
            .ok_or(VhdxError::AddressOverflow)?;
        Ok(file_offset)
    }
}
