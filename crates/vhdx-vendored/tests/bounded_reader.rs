#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Seek, SeekFrom, Write};

const MB: u64 = 0x0010_0000;
const BLOCK_SIZE: u32 = MB as u32;
const VIRTUAL_DISK_SIZE: u64 = 8 * MB;
const METADATA_OFFSET: u64 = 2 * MB;
const METADATA_LENGTH: u32 = MB as u32;
const BAT_OFFSET: u64 = 3 * MB;
const BAT_LENGTH: u32 = MB as u32;
const DATA_OFFSET: u64 = 4 * MB;

const BAT_GUID: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
const METADATA_GUID: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];
const FILE_PARAMETERS_GUID: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];
const VIRTUAL_DISK_SIZE_GUID: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5B, 0xE0, 0x7A, 0x6C, 0xE3, 0x2C,
];
const LOGICAL_SECTOR_SIZE_GUID: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];

fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ POLY
            };
        }
    }
    crc ^ u32::MAX
}

fn write_header(slot: &mut [u8], sequence: u64) {
    let header = &mut slot[..4096];
    header[0..4].copy_from_slice(b"head");
    header[8..16].copy_from_slice(&sequence.to_le_bytes());
    header[64..66].copy_from_slice(&1_u16.to_le_bytes());
    header[66..68].copy_from_slice(&1_u16.to_le_bytes());
    let checksum = crc32c(header);
    header[4..8].copy_from_slice(&checksum.to_le_bytes());
}

fn write_region_table(table: &mut [u8]) {
    table[0..4].copy_from_slice(b"regi");
    table[8..12].copy_from_slice(&2_u32.to_le_bytes());
    table[16..32].copy_from_slice(&BAT_GUID);
    table[32..40].copy_from_slice(&BAT_OFFSET.to_le_bytes());
    table[40..44].copy_from_slice(&BAT_LENGTH.to_le_bytes());
    table[44..48].copy_from_slice(&1_u32.to_le_bytes());
    table[48..64].copy_from_slice(&METADATA_GUID);
    table[64..72].copy_from_slice(&METADATA_OFFSET.to_le_bytes());
    table[72..76].copy_from_slice(&METADATA_LENGTH.to_le_bytes());
    table[76..80].copy_from_slice(&1_u32.to_le_bytes());
    let mut checked = table[..65_536].to_vec();
    checked[4..8].fill(0);
    table[4..8].copy_from_slice(&crc32c(&checked).to_le_bytes());
}

fn write_metadata(region: &mut [u8]) {
    const FILE_PARAMETERS_OFFSET: u32 = 0x200;
    const VIRTUAL_SIZE_OFFSET: u32 = 0x210;
    const SECTOR_SIZE_OFFSET: u32 = 0x220;

    region[0..8].copy_from_slice(b"metadata");
    region[10..12].copy_from_slice(&3_u16.to_le_bytes());
    for (entry, guid, offset, length) in [
        (0_usize, FILE_PARAMETERS_GUID, FILE_PARAMETERS_OFFSET, 8_u32),
        (1, VIRTUAL_DISK_SIZE_GUID, VIRTUAL_SIZE_OFFSET, 8),
        (2, LOGICAL_SECTOR_SIZE_GUID, SECTOR_SIZE_OFFSET, 4),
    ] {
        let base = 32 + entry * 32;
        region[base..base + 16].copy_from_slice(&guid);
        region[base + 16..base + 20].copy_from_slice(&offset.to_le_bytes());
        region[base + 20..base + 24].copy_from_slice(&length.to_le_bytes());
    }
    region[FILE_PARAMETERS_OFFSET as usize..FILE_PARAMETERS_OFFSET as usize + 4]
        .copy_from_slice(&BLOCK_SIZE.to_le_bytes());
    region[VIRTUAL_SIZE_OFFSET as usize..VIRTUAL_SIZE_OFFSET as usize + 8]
        .copy_from_slice(&VIRTUAL_DISK_SIZE.to_le_bytes());
    region[SECTOR_SIZE_OFFSET as usize..SECTOR_SIZE_OFFSET as usize + 4]
        .copy_from_slice(&512_u32.to_le_bytes());
}

fn write_test_vhdx(path: &std::path::Path) {
    let mut front = vec![0_u8; DATA_OFFSET as usize];
    front[0..8].copy_from_slice(b"vhdxfile");
    write_header(&mut front[0x10000..0x20000], 1);
    write_header(&mut front[0x20000..0x30000], 0);
    write_region_table(&mut front[0x30000..0x40000]);
    write_region_table(&mut front[0x40000..0x50000]);
    write_metadata(
        &mut front
            [METADATA_OFFSET as usize..(METADATA_OFFSET + u64::from(METADATA_LENGTH)) as usize],
    );
    let bat_entry = ((DATA_OFFSET >> 20) << 20) | 6;
    front[BAT_OFFSET as usize..BAT_OFFSET as usize + 8].copy_from_slice(&bat_entry.to_le_bytes());

    let mut file = std::fs::File::create(path).expect("create VHDX fixture");
    file.write_all(&front).expect("write VHDX front matter");
    let mut block = vec![0_u8; BLOCK_SIZE as usize];
    block[0] = 0x42;
    file.write_all(&block).expect("write VHDX payload block");
    file.flush().expect("flush VHDX fixture");
}

#[test]
fn path_open_keeps_file_backing_and_reads_blocks_on_demand() {
    let temp = tempfile::tempdir().expect("create test directory");
    let path = temp.path().join("bounded.vhdx");
    write_test_vhdx(&path);

    let mut reader = vhdx::VhdxReader::open(&path).expect("open VHDX using bounded reader");
    let debug = format!("{reader:?}");
    assert!(
        debug.contains("backing: File"),
        "unexpected reader: {debug}"
    );
    assert!(
        !debug.contains("backing: Mem"),
        "path open retained the image: {debug}"
    );
    assert_eq!(reader.virtual_disk_size(), VIRTUAL_DISK_SIZE);

    let mut byte = [0_u8; 1];
    reader.read_exact(&mut byte).expect("read present block");
    assert_eq!(byte[0], 0x42);
    reader
        .seek(SeekFrom::Start(u64::from(BLOCK_SIZE)))
        .expect("seek to absent block");
    reader.read_exact(&mut byte).expect("read absent block");
    assert_eq!(byte[0], 0, "absent dynamic block must be zero-filled");
}
