//! Bounded SRUM/ESE source recognition and table decoding.
//!
//! SRUDB.dat is an Extensible Storage Engine (ESE) database.  This module is
//! intentionally read-only and dependency-free: it implements only the ESE
//! page, B-tree, catalog, and record forms needed by the validated SRUM schema.
//! Every offset is checked before use, page checksums are verified, and tree
//! traversal is cycle/depth bounded.  Recognition alone must never be confused
//! with decoding rows; callers only receive rows after catalog and table-tree
//! validation succeeds.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const ESE_HEADER_CHECKSUM_BYTES: usize = 668;
const ESE_SIGNATURE: u32 = 0x89ab_cdef;
const ESE_CHECKSUM_SEED: u32 = 0x89ab_cdef;
const VALID_PAGE_SIZES: [u32; 5] = [2_048, 4_096, 8_192, 16_384, 32_768];
const ESE_PAGE_HEADER_SIZE: usize = 40;
const ESE_EXTENDED_PAGE_HEADER_SIZE: usize = 80;
const ESE_PAGE_FLAG_ROOT: u32 = 0x0000_0001;
const ESE_PAGE_FLAG_LEAF: u32 = 0x0000_0002;
const ESE_PAGE_FLAG_PARENT: u32 = 0x0000_0004;
const ESE_PAGE_FLAG_EMPTY: u32 = 0x0000_0008;
const ESE_PAGE_FLAG_SPACE_TREE: u32 = 0x0000_0020;
const ESE_PAGE_FLAG_INDEX: u32 = 0x0000_0040;
const ESE_PAGE_FLAG_LONG_VALUE: u32 = 0x0000_0080;
const ESE_PAGE_FLAG_NEW_CHECKSUM: u32 = 0x0000_2000;
const ESE_PAGE_TAG_FLAG_DEFUNCT: u8 = 0x02;
const ESE_PAGE_TAG_FLAG_COMMON_KEY: u8 = 0x04;
const ESE_REVISION_EXTENDED_PAGE_HEADER: u32 = 0x11;
const ESE_REVISION_RESERVED_TAG_COUNT_BITS: u32 = 0x122;
const ESE_CATALOG_ROOT_PAGE: u32 = 4;
const ESE_MAX_BTREE_DEPTH: usize = 64;
const ESE_MAX_CATALOG_RECORDS: usize = 65_536;
const ESE_MAX_SRUM_TABLE_RECORDS: usize = 1_000_000;

const SRUM_ID_MAP_TABLE: &str = "SruDbIdMapTable";
const SRUM_NETWORK_USAGE_TABLE: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
const SRUM_APPLICATION_RESOURCE_TABLE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
const SRUM_CONNECTIVITY_TABLE: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";

const SRUM_OFFSET_BASIS: &str =
    "byte offset within the recovered SRUDB.dat file stream; not an evidence-media offset";

const CATALOG_TYPE_TABLE: i16 = 1;
const CATALOG_TYPE_COLUMN: i16 = 2;

const COLUMN_FLAG_FIXED: u32 = 0x0000_0001;
const COLUMN_FLAG_TAGGED: u32 = 0x0000_0002;

const TAGGED_VALUE_FLAG_COMPRESSED: u8 = 0x02;
const TAGGED_VALUE_FLAG_LONG_VALUE: u8 = 0x04;
const TAGGED_VALUE_FLAG_MULTI_VALUE: u8 = 0x08;
const TAGGED_VALUE_FLAG_VARIABLE_SIZE: u8 = 0x01;
const TAGGED_VALUE_FLAG_MULTI_VALUE_SIZE: u8 = 0x10;
const TAGGED_VALUE_KNOWN_FLAG_MASK: u8 = TAGGED_VALUE_FLAG_VARIABLE_SIZE
    | TAGGED_VALUE_FLAG_COMPRESSED
    | TAGGED_VALUE_FLAG_LONG_VALUE
    | TAGGED_VALUE_FLAG_MULTI_VALUE
    | TAGGED_VALUE_FLAG_MULTI_VALUE_SIZE;

#[derive(Debug, Clone, Serialize)]
pub struct SrumEseHeaderProbe {
    pub signature_hex: String,
    pub format_version: u32,
    pub format_version_hex: String,
    pub format_revision: u32,
    pub format_revision_hex: String,
    pub file_type: u32,
    pub database_time: u64,
    pub database_state_code: u32,
    pub database_state: String,
    pub page_size: u32,
    pub page_count: u64,
    pub file_size: u64,
    pub file_size_page_aligned: bool,
    pub header_checksum_stored_hex: String,
    pub header_checksum_computed_hex: String,
    pub header_checksum_valid: bool,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u32,
    pub os_service_pack_number: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SrumLiveRowCounts {
    /// Live, non-defunct primary-table records.  These are deliberately kept
    /// separate from ESE AutoInc/high-water values, which can include deleted
    /// identifiers and are not table row counts.
    pub id_map: usize,
    pub network_usage: usize,
    pub application_resource_usage: usize,
    pub connectivity: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumRecordProvenance {
    pub table_name: String,
    pub table_object_id: u32,
    pub table_root_page: u32,
    pub page_number: u32,
    pub tag_index: u16,
    pub primary_key_hex: String,
    pub source_file_page_offset: u64,
    pub source_file_page_value_offset: u64,
    pub source_file_record_offset: u64,
    pub source_file_record_length: usize,
    pub offset_basis: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumIdMapRecord {
    pub id_type: u8,
    pub id_index: u32,
    pub value_kind: String,
    pub decoded_value: Option<String>,
    pub raw_value_hex: Option<String>,
    pub provenance: SrumRecordProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumIdentifierReference {
    pub id_index: u32,
    pub resolved: bool,
    pub id_type: Option<u8>,
    pub value_kind: Option<String>,
    pub decoded_value: Option<String>,
    pub raw_value_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumNetworkUsageRecord {
    pub auto_inc_id: u32,
    pub timestamp_ole_automation_days: Option<f64>,
    pub timestamp_utc: Option<String>,
    pub app: SrumIdentifierReference,
    pub user: SrumIdentifierReference,
    pub interface_luid: Option<u64>,
    pub l2_profile_id: Option<u32>,
    pub l2_profile_flags: Option<u32>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub wake_count: Option<u32>,
    pub provenance: SrumRecordProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumApplicationResourceRecord {
    pub auto_inc_id: u32,
    pub timestamp_ole_automation_days: Option<f64>,
    pub timestamp_utc: Option<String>,
    pub app: SrumIdentifierReference,
    pub user: SrumIdentifierReference,
    pub foreground_cycle_time_raw: Option<u64>,
    pub background_cycle_time_raw: Option<u64>,
    pub face_time_raw: Option<u64>,
    pub foreground_context_switches: Option<u32>,
    pub background_context_switches: Option<u32>,
    pub foreground_bytes_read: Option<u64>,
    pub foreground_bytes_written: Option<u64>,
    pub foreground_read_operations: Option<u32>,
    pub foreground_write_operations: Option<u32>,
    pub foreground_flushes: Option<u32>,
    pub background_bytes_read: Option<u64>,
    pub background_bytes_written: Option<u64>,
    pub background_read_operations: Option<u32>,
    pub background_write_operations: Option<u32>,
    pub background_flushes: Option<u32>,
    pub provenance: SrumRecordProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumConnectivityRecord {
    pub auto_inc_id: u32,
    pub timestamp_ole_automation_days: Option<f64>,
    pub timestamp_utc: Option<String>,
    pub app: SrumIdentifierReference,
    pub user: SrumIdentifierReference,
    pub interface_luid: Option<u64>,
    pub l2_profile_id: Option<u32>,
    pub connected_time_seconds: Option<u32>,
    pub connect_start_filetime: Option<u64>,
    pub connect_start_utc: Option<String>,
    pub l2_profile_flags: Option<u32>,
    pub provenance: SrumRecordProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SrumDecodeResult {
    pub header: SrumEseHeaderProbe,
    pub live_row_counts: SrumLiveRowCounts,
    pub id_map_records: Vec<SrumIdMapRecord>,
    pub network_usage_records: Vec<SrumNetworkUsageRecord>,
    pub application_resource_records: Vec<SrumApplicationResourceRecord>,
    pub connectivity_records: Vec<SrumConnectivityRecord>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EsePageHeader {
    page_number: u32,
    previous_page: u32,
    next_page: u32,
    father_data_page_object_id: u32,
    available_data_size: u16,
    available_uncommitted_data_size: u16,
    first_available_data_offset: u16,
    tag_count: u16,
    flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EsePageTag {
    index: u16,
    offset: usize,
    size: usize,
    flags: u8,
}

#[derive(Debug, Clone)]
struct EsePage {
    header: EsePageHeader,
    bytes: Vec<u8>,
    header_size: usize,
    tags: Vec<EsePageTag>,
}

impl EsePage {
    fn value(&self, tag: &EsePageTag) -> Result<&[u8]> {
        let start = self
            .header_size
            .checked_add(tag.offset)
            .context("ESE page-value start offset overflow")?;
        let end = start
            .checked_add(tag.size)
            .context("ESE page-value end offset overflow")?;
        self.bytes.get(start..end).with_context(|| {
            format!(
                "ESE page {} tag {} value range {start}..{end} is out of bounds",
                self.header.page_number, tag.index
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EseLeafRecord {
    page_number: u32,
    tag_index: u16,
    key: Vec<u8>,
    data: Vec<u8>,
    page_value_offset: usize,
    record_data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EseColumn {
    id: u32,
    name: String,
    column_type: u32,
    space_usage: u32,
    flags: u32,
    codepage: u32,
    record_offset: Option<u16>,
}

impl EseColumn {
    fn is_fixed(&self) -> bool {
        self.id < 128 || self.flags & COLUMN_FLAG_FIXED != 0
    }

    fn is_variable(&self) -> bool {
        (128..256).contains(&self.id) && self.flags & (COLUMN_FLAG_FIXED | COLUMN_FLAG_TAGGED) == 0
    }

    fn is_tagged(&self) -> bool {
        self.id >= 256 || self.flags & COLUMN_FLAG_TAGGED != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EseTable {
    object_id: u32,
    name: String,
    root_page: u32,
    columns: BTreeMap<u32, EseColumn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EseColumnValue {
    Inline(Vec<u8>),
    Null,
    Unsupported {
        flags: u8,
        reason: &'static str,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EseDecodedRow {
    page_number: u32,
    tag_index: u16,
    key: Vec<u8>,
    columns: BTreeMap<u32, EseColumnValue>,
    page_value_offset: usize,
    record_data_offset: usize,
    record_data_length: usize,
}

/// A bounded, read-only ESE reader.  The file handle is never exposed and the
/// only seek targets are validated database page numbers.
struct EseReader {
    source_path: PathBuf,
    file: File,
    page_size: usize,
    format_revision: u32,
    physical_page_count: u64,
}

impl EseReader {
    fn open(path: &Path) -> Result<(Self, SrumEseHeaderProbe)> {
        let probe = probe_ese_database(path)?;
        let page_size = usize::try_from(probe.page_size).context("ESE page size overflow")?;
        let file = File::open(path)
            .with_context(|| format!("opening read-only ESE source {}", path.display()))?;
        Ok((
            Self {
                source_path: path.to_path_buf(),
                file,
                page_size,
                format_revision: probe.format_revision,
                physical_page_count: probe.page_count,
            },
            probe,
        ))
    }

    fn maximum_page_number(&self) -> Result<u32> {
        // Physical pages 0 and 1 contain the primary and shadow database
        // headers. ESE page N is stored at physical page N + 1.
        let maximum = self
            .physical_page_count
            .checked_sub(2)
            .context("ESE source contains no database pages")?;
        u32::try_from(maximum).context("ESE page count exceeds u32")
    }

    fn read_page(&mut self, page_number: u32) -> Result<EsePage> {
        if page_number == 0 || page_number > self.maximum_page_number()? {
            bail!(
                "ESE page {page_number} is outside valid range 1..={}",
                self.maximum_page_number()?
            );
        }
        let physical_page = u64::from(page_number)
            .checked_add(1)
            .context("ESE physical page number overflow")?;
        let file_offset = physical_page
            .checked_mul(u64::try_from(self.page_size).context("ESE page size overflow")?)
            .context("ESE page file offset overflow")?;
        self.file
            .seek(SeekFrom::Start(file_offset))
            .with_context(|| {
                format!(
                    "seeking to ESE page {page_number} in {}",
                    self.source_path.display()
                )
            })?;
        let mut bytes = vec![0_u8; self.page_size];
        self.file.read_exact(&mut bytes).with_context(|| {
            format!(
                "reading ESE page {page_number} from {}",
                self.source_path.display()
            )
        })?;
        parse_ese_page(&bytes, page_number, self.format_revision)
    }

    fn read_table_tree(
        &mut self,
        root_page: u32,
        expected_object_id: u32,
        maximum_records: usize,
    ) -> Result<Vec<EseLeafRecord>> {
        if maximum_records == 0 {
            bail!("ESE table record limit must be non-zero");
        }
        let mut pending = vec![(root_page, 0_usize)];
        let mut visited = HashSet::new();
        let mut records = Vec::new();

        while let Some((page_number, depth)) = pending.pop() {
            if depth > ESE_MAX_BTREE_DEPTH {
                bail!(
                    "ESE B-tree rooted at page {root_page} exceeds maximum depth {ESE_MAX_BTREE_DEPTH}"
                );
            }
            if !visited.insert(page_number) {
                bail!(
                    "ESE B-tree rooted at page {root_page} contains a page cycle or duplicate reference at page {page_number}"
                );
            }
            let page = self.read_page(page_number)?;
            if page.header.father_data_page_object_id != expected_object_id {
                bail!(
                    "ESE page {page_number} belongs to FDP object {}, expected {expected_object_id}",
                    page.header.father_data_page_object_id
                );
            }
            if page.header.flags & ESE_PAGE_FLAG_EMPTY != 0 {
                continue;
            }
            if page.header.flags
                & (ESE_PAGE_FLAG_SPACE_TREE | ESE_PAGE_FLAG_INDEX | ESE_PAGE_FLAG_LONG_VALUE)
                != 0
            {
                bail!(
                    "ESE table tree page {page_number} has non-table flags 0x{:08x}",
                    page.header.flags
                );
            }
            let is_leaf = page.header.flags & ESE_PAGE_FLAG_LEAF != 0;
            let is_branch = page.header.flags & ESE_PAGE_FLAG_PARENT != 0 || !is_leaf;
            if is_leaf && page.header.flags & ESE_PAGE_FLAG_PARENT != 0 {
                bail!("ESE page {page_number} is marked as both leaf and parent");
            }

            if is_leaf {
                let mut page_records = parse_leaf_records(&page)?;
                if records.len().saturating_add(page_records.len()) > maximum_records {
                    bail!(
                        "ESE table rooted at page {root_page} exceeds bounded record limit {maximum_records}"
                    );
                }
                records.append(&mut page_records);
            } else if is_branch {
                let children = parse_branch_children(&page)?;
                if children.is_empty() {
                    bail!("ESE branch page {page_number} has no live children");
                }
                for child in children.into_iter().rev() {
                    pending.push((child, depth + 1));
                }
            }
        }
        validate_primary_key_order(root_page, &records)?;
        Ok(records)
    }

    fn read_catalog(&mut self) -> Result<BTreeMap<String, EseTable>> {
        let root = self.read_page(ESE_CATALOG_ROOT_PAGE)?;
        let catalog_object_id = root.header.father_data_page_object_id;
        let records = self.read_table_tree(
            ESE_CATALOG_ROOT_PAGE,
            catalog_object_id,
            ESE_MAX_CATALOG_RECORDS,
        )?;
        build_catalog(&records)
    }

    fn read_rows(
        &mut self,
        table: &EseTable,
        maximum_records: usize,
    ) -> Result<Vec<EseDecodedRow>> {
        let records = self.read_table_tree(table.root_page, table.object_id, maximum_records)?;
        records
            .into_iter()
            .map(|record| decode_table_record(&record, table, self.format_revision, self.page_size))
            .collect()
    }
}

fn validate_primary_key_order(root_page: u32, records: &[EseLeafRecord]) -> Result<()> {
    for adjacent in records.windows(2) {
        if adjacent[0].key >= adjacent[1].key {
            bail!(
                "ESE B-tree rooted at page {root_page} has non-increasing live primary keys: page {} tag {} key {} followed by page {} tag {} key {}",
                adjacent[0].page_number,
                adjacent[0].tag_index,
                encode_hex(&adjacent[0].key),
                adjacent[1].page_number,
                adjacent[1].tag_index,
                encode_hex(&adjacent[1].key)
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ExpectedColumn {
    id: u32,
    name: &'static str,
    column_type: u32,
    space_usage: u32,
    flags: u32,
    record_offset: Option<u16>,
}

const ID_MAP_SCHEMA: [ExpectedColumn; 3] = [
    ExpectedColumn {
        id: 1,
        name: "IdType",
        column_type: 2,
        space_usage: 1,
        flags: 0,
        record_offset: Some(4),
    },
    ExpectedColumn {
        id: 2,
        name: "IdIndex",
        column_type: 4,
        space_usage: 4,
        flags: 4,
        record_offset: Some(5),
    },
    ExpectedColumn {
        id: 256,
        name: "IdBlob",
        column_type: 11,
        space_usage: 0,
        flags: 0,
        record_offset: None,
    },
];

const NETWORK_USAGE_SCHEMA: [ExpectedColumn; 10] = [
    ExpectedColumn {
        id: 1,
        name: "AutoIncId",
        column_type: 4,
        space_usage: 4,
        flags: 4,
        record_offset: Some(4),
    },
    ExpectedColumn {
        id: 2,
        name: "TimeStamp",
        column_type: 8,
        space_usage: 8,
        flags: 0,
        record_offset: Some(8),
    },
    ExpectedColumn {
        id: 3,
        name: "AppId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(16),
    },
    ExpectedColumn {
        id: 4,
        name: "UserId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(20),
    },
    ExpectedColumn {
        id: 5,
        name: "InterfaceLuid",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(24),
    },
    ExpectedColumn {
        id: 6,
        name: "L2ProfileId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(32),
    },
    ExpectedColumn {
        id: 7,
        name: "L2ProfileFlags",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(36),
    },
    ExpectedColumn {
        id: 8,
        name: "BytesSent",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(40),
    },
    ExpectedColumn {
        id: 9,
        name: "BytesRecvd",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(48),
    },
    ExpectedColumn {
        id: 10,
        name: "WakeCount",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(56),
    },
];

const APPLICATION_RESOURCE_SCHEMA: [ExpectedColumn; 19] = [
    ExpectedColumn {
        id: 1,
        name: "AutoIncId",
        column_type: 4,
        space_usage: 4,
        flags: 4,
        record_offset: Some(4),
    },
    ExpectedColumn {
        id: 2,
        name: "TimeStamp",
        column_type: 8,
        space_usage: 8,
        flags: 0,
        record_offset: Some(8),
    },
    ExpectedColumn {
        id: 3,
        name: "AppId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(16),
    },
    ExpectedColumn {
        id: 4,
        name: "UserId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(20),
    },
    ExpectedColumn {
        id: 5,
        name: "ForegroundCycleTime",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(24),
    },
    ExpectedColumn {
        id: 6,
        name: "BackgroundCycleTime",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(32),
    },
    ExpectedColumn {
        id: 7,
        name: "FaceTime",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(40),
    },
    ExpectedColumn {
        id: 8,
        name: "ForegroundContextSwitches",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(48),
    },
    ExpectedColumn {
        id: 9,
        name: "BackgroundContextSwitches",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(52),
    },
    ExpectedColumn {
        id: 10,
        name: "ForegroundBytesRead",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(56),
    },
    ExpectedColumn {
        id: 11,
        name: "ForegroundBytesWritten",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(64),
    },
    ExpectedColumn {
        id: 12,
        name: "ForegroundNumReadOperations",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(72),
    },
    ExpectedColumn {
        id: 13,
        name: "ForegroundNumWriteOperations",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(76),
    },
    ExpectedColumn {
        id: 14,
        name: "ForegroundNumberOfFlushes",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(80),
    },
    ExpectedColumn {
        id: 15,
        name: "BackgroundBytesRead",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(84),
    },
    ExpectedColumn {
        id: 16,
        name: "BackgroundBytesWritten",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(92),
    },
    ExpectedColumn {
        id: 17,
        name: "BackgroundNumReadOperations",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(100),
    },
    ExpectedColumn {
        id: 18,
        name: "BackgroundNumWriteOperations",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(104),
    },
    ExpectedColumn {
        id: 19,
        name: "BackgroundNumberOfFlushes",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(108),
    },
];

const CONNECTIVITY_SCHEMA: [ExpectedColumn; 9] = [
    ExpectedColumn {
        id: 1,
        name: "AutoIncId",
        column_type: 4,
        space_usage: 4,
        flags: 4,
        record_offset: Some(4),
    },
    ExpectedColumn {
        id: 2,
        name: "TimeStamp",
        column_type: 8,
        space_usage: 8,
        flags: 0,
        record_offset: Some(8),
    },
    ExpectedColumn {
        id: 3,
        name: "AppId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(16),
    },
    ExpectedColumn {
        id: 4,
        name: "UserId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(20),
    },
    ExpectedColumn {
        id: 5,
        name: "InterfaceLuid",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(24),
    },
    ExpectedColumn {
        id: 6,
        name: "L2ProfileId",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(32),
    },
    ExpectedColumn {
        id: 7,
        name: "ConnectedTime",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(36),
    },
    ExpectedColumn {
        id: 8,
        name: "ConnectStartTime",
        column_type: 15,
        space_usage: 8,
        flags: 0,
        record_offset: Some(40),
    },
    ExpectedColumn {
        id: 9,
        name: "L2ProfileFlags",
        column_type: 4,
        space_usage: 4,
        flags: 0,
        record_offset: Some(48),
    },
];

pub(super) fn decode_srum_database(path: &Path) -> Result<SrumDecodeResult> {
    let (mut reader, header) = EseReader::open(path)?;
    if header.format_version != 0x620 || header.format_revision != 300 {
        bail!(
            "SRUM decoder is validated for ESE version 0x620 revision 300; source reports version {} revision {}",
            header.format_version_hex,
            header.format_revision
        );
    }
    let catalog = reader.read_catalog().context("decoding the ESE catalog")?;
    let id_map_table = validated_table(&catalog, SRUM_ID_MAP_TABLE, &ID_MAP_SCHEMA)?;
    let network_table = validated_table(&catalog, SRUM_NETWORK_USAGE_TABLE, &NETWORK_USAGE_SCHEMA)?;
    let application_table = validated_table(
        &catalog,
        SRUM_APPLICATION_RESOURCE_TABLE,
        &APPLICATION_RESOURCE_SCHEMA,
    )?;
    let connectivity_table =
        validated_table(&catalog, SRUM_CONNECTIVITY_TABLE, &CONNECTIVITY_SCHEMA)?;

    let id_rows = reader.read_rows(id_map_table, ESE_MAX_SRUM_TABLE_RECORDS)?;
    let mut id_map = BTreeMap::new();
    let mut id_map_records = Vec::with_capacity(id_rows.len());
    for row in &id_rows {
        let record = decode_id_map_record(row, id_map_table, reader.page_size)?;
        if id_map.insert(record.id_index, record.clone()).is_some() {
            bail!(
                "SRUM IdMap contains duplicate live IdIndex {}",
                record.id_index
            );
        }
        id_map_records.push(record);
    }

    let network_rows = reader.read_rows(network_table, ESE_MAX_SRUM_TABLE_RECORDS)?;
    let network_usage_records = network_rows
        .iter()
        .map(|row| decode_network_usage_record(row, network_table, reader.page_size, &id_map))
        .collect::<Result<Vec<_>>>()?;

    let application_rows = reader.read_rows(application_table, ESE_MAX_SRUM_TABLE_RECORDS)?;
    let application_resource_records = application_rows
        .iter()
        .map(|row| {
            decode_application_resource_record(row, application_table, reader.page_size, &id_map)
        })
        .collect::<Result<Vec<_>>>()?;

    let connectivity_rows = reader.read_rows(connectivity_table, ESE_MAX_SRUM_TABLE_RECORDS)?;
    let connectivity_records = connectivity_rows
        .iter()
        .map(|row| decode_connectivity_record(row, connectivity_table, reader.page_size, &id_map))
        .collect::<Result<Vec<_>>>()?;

    let unresolved_app_ids = network_usage_records
        .iter()
        .map(|row| &row.app)
        .chain(application_resource_records.iter().map(|row| &row.app))
        .chain(connectivity_records.iter().map(|row| &row.app))
        .filter(|reference| !reference.resolved)
        .count();
    let unresolved_user_ids = network_usage_records
        .iter()
        .map(|row| &row.user)
        .chain(application_resource_records.iter().map(|row| &row.user))
        .chain(connectivity_records.iter().map(|row| &row.user))
        .filter(|reference| !reference.resolved)
        .count();
    let null_id_blobs = id_map_records
        .iter()
        .filter(|record| record.value_kind == "null")
        .count();
    let unknown_id_types = id_map_records
        .iter()
        .filter(|record| record.value_kind.starts_with("unmapped_binary_id_type_"))
        .count();

    let live_row_counts = SrumLiveRowCounts {
        id_map: id_map_records.len(),
        network_usage: network_usage_records.len(),
        application_resource_usage: application_resource_records.len(),
        connectivity: connectivity_records.len(),
    };
    let diagnostics = vec![
        format!(
            "decoded live/non-defunct rows: IdMap={}, network_usage={}, application_resource_usage={}, connectivity={}; ESE AutoInc values are high-water identifiers and are not row counts",
            live_row_counts.id_map,
            live_row_counts.network_usage,
            live_row_counts.application_resource_usage,
            live_row_counts.connectivity
        ),
        format!(
            "IdMap resolution retained {unresolved_app_ids} unresolved application reference(s) and {unresolved_user_ids} unresolved user reference(s) explicitly"
        ),
        format!(
            "IdMap contained {null_id_blobs} null identifier blob(s) and {unknown_id_types} identifier(s) with unknown IdType values; unknown values are retained as raw hex rather than guessed"
        ),
        "SRUM row offsets are offsets within the recovered SRUDB.dat file stream, not evidence-media offsets".to_string(),
    ];
    Ok(SrumDecodeResult {
        header,
        live_row_counts,
        id_map_records,
        network_usage_records,
        application_resource_records,
        connectivity_records,
        diagnostics,
    })
}

fn validated_table<'a>(
    catalog: &'a BTreeMap<String, EseTable>,
    table_name: &str,
    expected: &[ExpectedColumn],
) -> Result<&'a EseTable> {
    let table = catalog
        .get(table_name)
        .with_context(|| format!("ESE catalog is missing required SRUM table {table_name}"))?;
    if table.columns.len() != expected.len() {
        bail!(
            "SRUM table {table_name} defines {} columns, expected exactly {}",
            table.columns.len(),
            expected.len()
        );
    }
    for expected in expected {
        let actual = table.columns.get(&expected.id).with_context(|| {
            format!(
                "SRUM table {table_name} is missing column {} ({})",
                expected.id, expected.name
            )
        })?;
        if actual.name != expected.name
            || actual.column_type != expected.column_type
            || actual.space_usage != expected.space_usage
            || actual.flags != expected.flags
            || actual.record_offset != expected.record_offset
            || actual.codepage != 0
        {
            bail!(
                "SRUM table {table_name} column {} schema mismatch: got name={} type={} size={} flags=0x{:x} offset={:?} codepage={}",
                expected.id,
                actual.name,
                actual.column_type,
                actual.space_usage,
                actual.flags,
                actual.record_offset,
                actual.codepage
            );
        }
    }
    Ok(table)
}

fn decode_id_map_record(
    row: &EseDecodedRow,
    table: &EseTable,
    page_size: usize,
) -> Result<SrumIdMapRecord> {
    let id_type = required_u8(row, 1, table)?;
    let id_index = required_u32(row, 2, table)?;
    let (value_kind, decoded_value, raw_value_hex) = match inline_value(row, 256, table)? {
        None => ("null".to_string(), None, None),
        Some(bytes) if id_type == 0 => (
            "application_identifier_utf16".to_string(),
            Some(decode_utf16_identifier(bytes).with_context(|| {
                format!("decoding SRUM application IdBlob for IdIndex {id_index}")
            })?),
            Some(encode_hex(bytes)),
        ),
        Some(bytes) if id_type == 3 => (
            "windows_sid".to_string(),
            Some(
                decode_binary_sid(bytes)
                    .with_context(|| format!("decoding SRUM SID IdBlob for IdIndex {id_index}"))?,
            ),
            Some(encode_hex(bytes)),
        ),
        Some(bytes) => (
            format!("unmapped_binary_id_type_{id_type}"),
            None,
            Some(encode_hex(bytes)),
        ),
    };
    Ok(SrumIdMapRecord {
        id_type,
        id_index,
        value_kind,
        decoded_value,
        raw_value_hex,
        provenance: record_provenance(row, table, page_size)?,
    })
}

fn decode_network_usage_record(
    row: &EseDecodedRow,
    table: &EseTable,
    page_size: usize,
    id_map: &BTreeMap<u32, SrumIdMapRecord>,
) -> Result<SrumNetworkUsageRecord> {
    let (timestamp_ole_automation_days, timestamp_utc) = row_ole_timestamp(row, 2, table)?;
    Ok(SrumNetworkUsageRecord {
        auto_inc_id: required_u32(row, 1, table)?,
        timestamp_ole_automation_days,
        timestamp_utc,
        app: resolve_identifier(required_u32(row, 3, table)?, id_map),
        user: resolve_identifier(required_u32(row, 4, table)?, id_map),
        interface_luid: optional_u64(row, 5, table)?,
        l2_profile_id: optional_u32(row, 6, table)?,
        l2_profile_flags: optional_u32(row, 7, table)?,
        bytes_sent: optional_u64(row, 8, table)?,
        bytes_received: optional_u64(row, 9, table)?,
        wake_count: optional_u32(row, 10, table)?,
        provenance: record_provenance(row, table, page_size)?,
    })
}

fn decode_application_resource_record(
    row: &EseDecodedRow,
    table: &EseTable,
    page_size: usize,
    id_map: &BTreeMap<u32, SrumIdMapRecord>,
) -> Result<SrumApplicationResourceRecord> {
    let (timestamp_ole_automation_days, timestamp_utc) = row_ole_timestamp(row, 2, table)?;
    Ok(SrumApplicationResourceRecord {
        auto_inc_id: required_u32(row, 1, table)?,
        timestamp_ole_automation_days,
        timestamp_utc,
        app: resolve_identifier(required_u32(row, 3, table)?, id_map),
        user: resolve_identifier(required_u32(row, 4, table)?, id_map),
        foreground_cycle_time_raw: optional_u64(row, 5, table)?,
        background_cycle_time_raw: optional_u64(row, 6, table)?,
        face_time_raw: optional_u64(row, 7, table)?,
        foreground_context_switches: optional_u32(row, 8, table)?,
        background_context_switches: optional_u32(row, 9, table)?,
        foreground_bytes_read: optional_u64(row, 10, table)?,
        foreground_bytes_written: optional_u64(row, 11, table)?,
        foreground_read_operations: optional_u32(row, 12, table)?,
        foreground_write_operations: optional_u32(row, 13, table)?,
        foreground_flushes: optional_u32(row, 14, table)?,
        background_bytes_read: optional_u64(row, 15, table)?,
        background_bytes_written: optional_u64(row, 16, table)?,
        background_read_operations: optional_u32(row, 17, table)?,
        background_write_operations: optional_u32(row, 18, table)?,
        background_flushes: optional_u32(row, 19, table)?,
        provenance: record_provenance(row, table, page_size)?,
    })
}

fn decode_connectivity_record(
    row: &EseDecodedRow,
    table: &EseTable,
    page_size: usize,
    id_map: &BTreeMap<u32, SrumIdMapRecord>,
) -> Result<SrumConnectivityRecord> {
    let (timestamp_ole_automation_days, timestamp_utc) = row_ole_timestamp(row, 2, table)?;
    let connect_start_filetime = optional_u64(row, 8, table)?;
    let connect_start_utc = connect_start_filetime
        .map(filetime_to_rfc3339)
        .transpose()
        .context("converting SRUM ConnectStartTime FILETIME")?
        .flatten();
    Ok(SrumConnectivityRecord {
        auto_inc_id: required_u32(row, 1, table)?,
        timestamp_ole_automation_days,
        timestamp_utc,
        app: resolve_identifier(required_u32(row, 3, table)?, id_map),
        user: resolve_identifier(required_u32(row, 4, table)?, id_map),
        interface_luid: optional_u64(row, 5, table)?,
        l2_profile_id: optional_u32(row, 6, table)?,
        connected_time_seconds: optional_u32(row, 7, table)?,
        connect_start_filetime,
        connect_start_utc,
        l2_profile_flags: optional_u32(row, 9, table)?,
        provenance: record_provenance(row, table, page_size)?,
    })
}

fn record_provenance(
    row: &EseDecodedRow,
    table: &EseTable,
    page_size: usize,
) -> Result<SrumRecordProvenance> {
    let page_size = u64::try_from(page_size).context("ESE page size exceeds u64")?;
    let source_file_page_offset = u64::from(row.page_number)
        .checked_add(1)
        .and_then(|page| page.checked_mul(page_size))
        .context("SRUM source-file page offset overflow")?;
    let source_file_page_value_offset = source_file_page_offset
        .checked_add(u64::try_from(row.page_value_offset).context("page-value offset exceeds u64")?)
        .context("SRUM source-file page-value offset overflow")?;
    let source_file_record_offset = source_file_page_offset
        .checked_add(
            u64::try_from(row.record_data_offset).context("record-data offset exceeds u64")?,
        )
        .context("SRUM source-file record offset overflow")?;
    Ok(SrumRecordProvenance {
        table_name: table.name.clone(),
        table_object_id: table.object_id,
        table_root_page: table.root_page,
        page_number: row.page_number,
        tag_index: row.tag_index,
        primary_key_hex: encode_hex(&row.key),
        source_file_page_offset,
        source_file_page_value_offset,
        source_file_record_offset,
        source_file_record_length: row.record_data_length,
        offset_basis: SRUM_OFFSET_BASIS,
    })
}

fn resolve_identifier(
    id_index: u32,
    id_map: &BTreeMap<u32, SrumIdMapRecord>,
) -> SrumIdentifierReference {
    match id_map.get(&id_index) {
        Some(value) => SrumIdentifierReference {
            id_index,
            resolved: true,
            id_type: Some(value.id_type),
            value_kind: Some(value.value_kind.clone()),
            decoded_value: value.decoded_value.clone(),
            raw_value_hex: value.raw_value_hex.clone(),
        },
        None => SrumIdentifierReference {
            id_index,
            resolved: false,
            id_type: None,
            value_kind: None,
            decoded_value: None,
            raw_value_hex: None,
        },
    }
}

fn inline_value<'a>(
    row: &'a EseDecodedRow,
    column_id: u32,
    table: &EseTable,
) -> Result<Option<&'a [u8]>> {
    match row.columns.get(&column_id) {
        Some(EseColumnValue::Inline(bytes)) => Ok(Some(bytes)),
        Some(EseColumnValue::Null) | None => Ok(None),
        Some(EseColumnValue::Unsupported { reason, flags, .. }) => bail!(
            "SRUM table {} page {} tag {} column {} uses unsupported {} flags 0x{flags:02x}",
            table.name,
            row.page_number,
            row.tag_index,
            column_id,
            reason
        ),
    }
}

fn required_u8(row: &EseDecodedRow, column_id: u32, table: &EseTable) -> Result<u8> {
    let bytes = inline_value(row, column_id, table)?.with_context(|| {
        format!(
            "SRUM table {} page {} tag {} required column {column_id} is null",
            table.name, row.page_number, row.tag_index
        )
    })?;
    if bytes.len() != 1 {
        bail!(
            "SRUM table {} column {column_id} is {} bytes, expected 1",
            table.name,
            bytes.len()
        );
    }
    Ok(bytes[0])
}

fn required_u32(row: &EseDecodedRow, column_id: u32, table: &EseTable) -> Result<u32> {
    optional_u32(row, column_id, table)?.with_context(|| {
        format!(
            "SRUM table {} page {} tag {} required column {column_id} is null",
            table.name, row.page_number, row.tag_index
        )
    })
}

fn optional_u32(row: &EseDecodedRow, column_id: u32, table: &EseTable) -> Result<Option<u32>> {
    let Some(bytes) = inline_value(row, column_id, table)? else {
        return Ok(None);
    };
    let array: [u8; 4] = bytes.try_into().with_context(|| {
        format!(
            "SRUM table {} column {column_id} is {} bytes, expected 4",
            table.name,
            bytes.len()
        )
    })?;
    Ok(Some(u32::from_le_bytes(array)))
}

fn optional_u64(row: &EseDecodedRow, column_id: u32, table: &EseTable) -> Result<Option<u64>> {
    let Some(bytes) = inline_value(row, column_id, table)? else {
        return Ok(None);
    };
    let array: [u8; 8] = bytes.try_into().with_context(|| {
        format!(
            "SRUM table {} column {column_id} is {} bytes, expected 8",
            table.name,
            bytes.len()
        )
    })?;
    Ok(Some(u64::from_le_bytes(array)))
}

fn row_ole_timestamp(
    row: &EseDecodedRow,
    column_id: u32,
    table: &EseTable,
) -> Result<(Option<f64>, Option<String>)> {
    let Some(bytes) = inline_value(row, column_id, table)? else {
        return Ok((None, None));
    };
    let array: [u8; 8] = bytes.try_into().with_context(|| {
        format!(
            "SRUM table {} timestamp column {column_id} is {} bytes, expected 8",
            table.name,
            bytes.len()
        )
    })?;
    let value = f64::from_le_bytes(array);
    let utc = ole_automation_to_rfc3339(value).with_context(|| {
        format!(
            "converting SRUM table {} page {} tag {} OLE Automation timestamp",
            table.name, row.page_number, row.tag_index
        )
    })?;
    Ok((Some(value), Some(utc)))
}

fn ole_automation_to_rfc3339(days: f64) -> Result<String> {
    if !days.is_finite() {
        bail!("OLE Automation timestamp is not finite");
    }
    let unix_seconds = (days - 25_569.0) * 86_400.0;
    if !unix_seconds.is_finite() || unix_seconds < i64::MIN as f64 || unix_seconds > i64::MAX as f64
    {
        bail!("OLE Automation timestamp is outside the supported UTC range");
    }
    let mut seconds = unix_seconds.floor() as i64;
    let mut nanoseconds = ((unix_seconds - seconds as f64) * 1_000_000_000.0).round() as i64;
    if nanoseconds >= 1_000_000_000 {
        seconds = seconds
            .checked_add(1)
            .context("OLE Automation timestamp second overflow")?;
        nanoseconds -= 1_000_000_000;
    }
    let nanoseconds = u32::try_from(nanoseconds).context("invalid OLE Automation nanoseconds")?;
    DateTime::<Utc>::from_timestamp(seconds, nanoseconds)
        .context("OLE Automation timestamp is outside chrono range")
        .map(|timestamp| timestamp.to_rfc3339())
}

fn filetime_to_rfc3339(filetime: u64) -> Result<Option<String>> {
    if filetime == 0 {
        return Ok(None);
    }
    const FILETIME_UNIX_EPOCH: i128 = 116_444_736_000_000_000;
    let unix_ticks = i128::from(filetime) - FILETIME_UNIX_EPOCH;
    let seconds = unix_ticks.div_euclid(10_000_000);
    let remaining_ticks = unix_ticks.rem_euclid(10_000_000);
    let seconds = i64::try_from(seconds).context("FILETIME seconds exceed i64")?;
    let nanoseconds = u32::try_from(remaining_ticks * 100).context("FILETIME nanos exceed u32")?;
    DateTime::<Utc>::from_timestamp(seconds, nanoseconds)
        .context("FILETIME is outside chrono range")
        .map(|timestamp| Some(timestamp.to_rfc3339()))
}

fn decode_utf16_identifier(bytes: &[u8]) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        bail!("UTF-16 identifier has odd byte length {}", bytes.len());
    }
    let mut units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.contains(&0) {
        bail!("UTF-16 identifier contains an embedded NUL");
    }
    char::decode_utf16(units)
        .map(|unit| unit.context("UTF-16 identifier contains an invalid surrogate"))
        .collect()
}

fn decode_binary_sid(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 8 {
        bail!("binary SID is only {} bytes", bytes.len());
    }
    let revision = bytes[0];
    if revision != 1 {
        bail!("binary SID revision {revision} is unsupported");
    }
    let subauthority_count = usize::from(bytes[1]);
    if subauthority_count > 15 {
        bail!("binary SID has invalid subauthority count {subauthority_count}");
    }
    let expected_length = 8_usize
        .checked_add(
            subauthority_count
                .checked_mul(4)
                .context("binary SID length overflow")?,
        )
        .context("binary SID length overflow")?;
    if bytes.len() != expected_length {
        bail!(
            "binary SID is {} bytes, expected {expected_length} for {subauthority_count} subauthorities",
            bytes.len()
        );
    }
    let identifier_authority = bytes[2..8]
        .iter()
        .fold(0_u64, |authority, byte| (authority << 8) | u64::from(*byte));
    let mut sid = format!("S-{revision}-{identifier_authority}");
    for chunk in bytes[8..].chunks_exact(4) {
        let subauthority = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        sid.push('-');
        sid.push_str(&subauthority.to_string());
    }
    Ok(sid)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn probe_ese_database(path: &Path) -> Result<SrumEseHeaderProbe> {
    let file_size = std::fs::metadata(path)
        .with_context(|| format!("reading SRUM source metadata {}", path.display()))?
        .len();
    let mut file = File::open(path)
        .with_context(|| format!("opening staged SRUM source {}", path.display()))?;
    let mut header = [0_u8; ESE_HEADER_CHECKSUM_BYTES];
    file.read_exact(&mut header).with_context(|| {
        format!(
            "reading the bounded {}-byte ESE header from {}",
            ESE_HEADER_CHECKSUM_BYTES,
            path.display()
        )
    })?;
    probe_ese_header(&header, file_size)
}

fn probe_ese_header(header: &[u8], file_size: u64) -> Result<SrumEseHeaderProbe> {
    if header.len() < ESE_HEADER_CHECKSUM_BYTES {
        bail!(
            "ESE header is truncated: need at least {ESE_HEADER_CHECKSUM_BYTES} bytes, got {}",
            header.len()
        );
    }
    let signature = le_u32(header, 4)?;
    if signature != ESE_SIGNATURE {
        bail!("invalid ESE signature 0x{signature:08x}");
    }

    let stored_checksum = le_u32(header, 0)?;
    let computed_checksum = ese_header_checksum(header)?;
    let database_state_code = le_u32(header, 52)?;
    let header_checksum_valid = stored_checksum == computed_checksum;
    // A dirty-shutdown ESE header can legitimately retain a stale checksum;
    // libesedb applies the same exception. Preserve that state explicitly
    // instead of rejecting the source or silently calling its header valid.
    if !header_checksum_valid && database_state_code != 2 {
        bail!(
            "ESE header checksum mismatch: stored 0x{stored_checksum:08x}, computed 0x{computed_checksum:08x}"
        );
    }

    let page_size = le_u32(header, 236)?;
    let page_size = if page_size == 0 { 4_096 } else { page_size };
    if !VALID_PAGE_SIZES.contains(&page_size) {
        bail!("unsupported or invalid ESE page size {page_size}");
    }
    let minimum_file_size = u64::from(page_size).saturating_mul(2);
    if file_size < minimum_file_size {
        bail!(
            "ESE source is truncated: file is {file_size} bytes but two {page_size}-byte header pages require at least {minimum_file_size} bytes"
        );
    }
    let file_size_page_aligned = file_size.is_multiple_of(u64::from(page_size));
    if !file_size_page_aligned {
        bail!("ESE source length {file_size} is not aligned to its {page_size}-byte page size");
    }

    let database_state = match database_state_code {
        1 => "just_created",
        2 => "dirty_shutdown",
        3 => "clean_shutdown",
        4 => "being_converted",
        5 => "force_detach",
        _ => "unknown",
    }
    .to_string();
    let format_version = le_u32(header, 8)?;
    let format_revision = le_u32(header, 232)?;

    Ok(SrumEseHeaderProbe {
        signature_hex: format!("0x{signature:08x}"),
        format_version,
        format_version_hex: format!("0x{format_version:x}"),
        format_revision,
        format_revision_hex: format!("0x{format_revision:x}"),
        file_type: le_u32(header, 12)?,
        database_time: le_u64(header, 16)?,
        database_state_code,
        database_state,
        page_size,
        page_count: file_size / u64::from(page_size),
        file_size,
        file_size_page_aligned,
        header_checksum_stored_hex: format!("0x{stored_checksum:08x}"),
        header_checksum_computed_hex: format!("0x{computed_checksum:08x}"),
        header_checksum_valid,
        os_major_version: le_u32(header, 216)?,
        os_minor_version: le_u32(header, 220)?,
        os_build_number: le_u32(header, 224)?,
        os_service_pack_number: le_u32(header, 228)?,
    })
}

fn parse_ese_page(bytes: &[u8], page_number: u32, format_revision: u32) -> Result<EsePage> {
    if bytes.len() < ESE_PAGE_HEADER_SIZE || !bytes.len().is_multiple_of(4) {
        bail!(
            "ESE page {page_number} has invalid byte length {}",
            bytes.len()
        );
    }
    let flags = le_u32(bytes, 36)?;
    verify_ese_page_checksum(bytes, page_number, flags)?;

    let header_size =
        if format_revision >= ESE_REVISION_EXTENDED_PAGE_HEADER && bytes.len() >= 16_384 {
            ESE_EXTENDED_PAGE_HEADER_SIZE
        } else {
            ESE_PAGE_HEADER_SIZE
        };
    let raw_tag_count = le_u16(bytes, 34)?;
    let tag_count = if format_revision >= ESE_REVISION_RESERVED_TAG_COUNT_BITS {
        raw_tag_count & 0x0fff
    } else {
        raw_tag_count
    };
    let tag_array_size = usize::from(tag_count)
        .checked_mul(4)
        .context("ESE page tag-array size overflow")?;
    let tag_array_start = bytes
        .len()
        .checked_sub(tag_array_size)
        .context("ESE page tag array exceeds page")?;
    if tag_array_start < header_size {
        bail!("ESE page {page_number} tag array overlaps its page header");
    }
    let values_capacity = tag_array_start - header_size;
    let first_available_data_offset = le_u16(bytes, 32)?;
    if usize::from(first_available_data_offset) > values_capacity {
        bail!(
            "ESE page {page_number} first-available data offset {} exceeds value area {values_capacity}",
            first_available_data_offset
        );
    }

    let extended_tags = header_size == ESE_EXTENDED_PAGE_HEADER_SIZE;
    let mut tags = Vec::with_capacity(usize::from(tag_count));
    let mut live_ranges = Vec::new();
    for index in 0..tag_count {
        let reverse_distance = usize::from(index)
            .checked_add(1)
            .and_then(|value| value.checked_mul(4))
            .context("ESE page tag offset overflow")?;
        let tag_offset = bytes
            .len()
            .checked_sub(reverse_distance)
            .context("ESE page tag offset underflow")?;
        // ESE stores each four-byte tag as size followed by offset.  Tags are
        // enumerated from the end of the page toward the front.
        let raw_size = le_u16(bytes, tag_offset)?;
        let raw_offset = le_u16(bytes, tag_offset + 2)?;
        let (offset, size, mut tag_flags) = if extended_tags {
            (
                usize::from(raw_offset & 0x7fff),
                usize::from(raw_size & 0x7fff),
                0_u8,
            )
        } else {
            (
                usize::from(raw_offset & 0x1fff),
                usize::from(raw_size & 0x1fff),
                u8::try_from(raw_offset >> 13)
                    .context("ESE page tag flags exceed their three-bit field")?,
            )
        };
        let end = offset
            .checked_add(size)
            .context("ESE page tag value range overflow")?;
        if offset > values_capacity || end > values_capacity {
            bail!(
                "ESE page {page_number} tag {index} value {offset}..{end} exceeds value area {values_capacity}"
            );
        }
        if extended_tags && size >= 2 {
            let entry_start = header_size + offset;
            tag_flags = u8::try_from(le_u16(bytes, entry_start)? >> 13)
                .context("ESE embedded tag flags exceed their three-bit field")?;
        }
        if size > 0 && tag_flags & ESE_PAGE_TAG_FLAG_DEFUNCT == 0 {
            live_ranges.push((offset, end, index));
        }
        tags.push(EsePageTag {
            index,
            offset,
            size,
            flags: tag_flags,
        });
    }
    live_ranges.sort_unstable_by_key(|range| (range.0, range.1));
    for adjacent in live_ranges.windows(2) {
        if adjacent[0].1 > adjacent[1].0 {
            bail!(
                "ESE page {page_number} live tags {} and {} overlap",
                adjacent[0].2,
                adjacent[1].2
            );
        }
    }

    Ok(EsePage {
        header: EsePageHeader {
            page_number,
            previous_page: le_u32(bytes, 16)?,
            next_page: le_u32(bytes, 20)?,
            father_data_page_object_id: le_u32(bytes, 24)?,
            available_data_size: le_u16(bytes, 28)?,
            available_uncommitted_data_size: le_u16(bytes, 30)?,
            first_available_data_offset,
            tag_count,
            flags,
        },
        bytes: bytes.to_vec(),
        header_size,
        tags,
    })
}

fn verify_ese_page_checksum(bytes: &[u8], page_number: u32, flags: u32) -> Result<()> {
    let stored_xor = le_u32(bytes, 0)?;
    if flags & ESE_PAGE_FLAG_NEW_CHECKSUM != 0 {
        let stored_ecc = le_u32(bytes, 4)?;
        let (computed_ecc, computed_xor) = ese_page_ecc32(bytes, 8, page_number)?;
        if stored_xor != computed_xor || stored_ecc != computed_ecc {
            bail!(
                "ESE page {page_number} checksum mismatch: stored XOR/ECC 0x{stored_xor:08x}/0x{stored_ecc:08x}, computed 0x{computed_xor:08x}/0x{computed_ecc:08x}"
            );
        }
    } else {
        let computed = bytes[4..]
            .chunks_exact(4)
            .fold(ESE_CHECKSUM_SEED, |checksum, chunk| {
                checksum ^ u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            });
        if stored_xor != computed {
            bail!(
                "ESE page {page_number} legacy checksum mismatch: stored 0x{stored_xor:08x}, computed 0x{computed:08x}"
            );
        }
    }
    Ok(())
}

/// Calculates the ESE little-endian ECC-32 and XOR-32 checksums.  This is a
/// direct implementation of the published ESE parity construction: parity is
/// accumulated per 16-byte stripe, then folded across the four 32-bit lanes.
fn ese_page_ecc32(bytes: &[u8], offset: usize, initial_xor: u32) -> Result<(u32, u32)> {
    if offset > bytes.len() || !offset.is_multiple_of(4) || !bytes.len().is_multiple_of(4) {
        bail!("invalid ESE ECC checksum range {offset}..{}", bytes.len());
    }
    let mut ecc = 0_u32;
    let mut vertical = [0_u32; 4];
    let mut stripe_xor = 0_u32;
    let mut bitmask = 0xff80_0000_u32;
    let mut lane = (offset % 16) / 4;

    for chunk in bytes[offset..].chunks_exact(4) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        vertical[lane] ^= value;
        stripe_xor ^= value;
        lane += 1;
        if lane == 4 {
            if byte_xor_parity(stripe_xor) {
                ecc ^= bitmask;
            }
            bitmask = bitmask.wrapping_sub(0x007f_ff80);
            stripe_xor = 0;
            lane = 0;
        }
    }
    if stripe_xor != 0 && byte_xor_parity(stripe_xor) {
        ecc ^= bitmask;
    }
    if byte_xor_parity(vertical[0] ^ vertical[1]) {
        ecc ^= 0x0040_0000;
    }
    if byte_xor_parity(vertical[0] ^ vertical[2]) {
        ecc ^= 0x0020_0000;
    }
    if byte_xor_parity(vertical[1] ^ vertical[3]) {
        ecc ^= 0x0000_0020;
    }
    if byte_xor_parity(vertical[2] ^ vertical[3]) {
        ecc ^= 0x0000_0040;
    }

    let vertical_xor = vertical.into_iter().fold(0_u32, |value, lane| value ^ lane);
    let mut final_bitmask = 0_u32;
    let mut fold_mask = 0xffff_0000_u32;
    let mut bit = 1_u32;
    loop {
        if vertical_xor & bit != 0 {
            final_bitmask ^= fold_mask;
        }
        fold_mask = fold_mask.wrapping_sub(0x0000_ffff);
        bit = bit.wrapping_shl(1);
        if bit == 0 {
            break;
        }
    }
    if bytes.len() < 8_192 {
        let size_mask = u32::try_from(bytes.len())
            .context("ESE page size exceeds u32")?
            .checked_shl(19)
            .unwrap_or(0);
        ecc &= !size_mask;
    }
    ecc ^= (ecc ^ final_bitmask) & 0x001f_001f;
    Ok((ecc, initial_xor ^ vertical_xor))
}

fn byte_xor_parity(value: u32) -> bool {
    let bytes = value.to_le_bytes();
    (bytes[0] ^ bytes[1] ^ bytes[2] ^ bytes[3]).count_ones() % 2 == 1
}

fn parse_branch_children(page: &EsePage) -> Result<Vec<u32>> {
    if page.header.flags & ESE_PAGE_FLAG_LEAF != 0 {
        bail!("ESE page {} is not a branch page", page.header.page_number);
    }
    let common_key = page_common_key(page)?;
    let mut children = Vec::new();
    for tag in page.tags.iter().skip(1) {
        if tag.flags & ESE_PAGE_TAG_FLAG_DEFUNCT != 0 {
            continue;
        }
        let value = page.value(tag)?;
        let (_, data) =
            split_btree_entry(value, tag.flags, common_key, true).with_context(|| {
                format!(
                    "decoding ESE branch page {} tag {}",
                    page.header.page_number, tag.index
                )
            })?;
        if data.len() != 4 {
            bail!(
                "ESE branch page {} tag {} child payload is {} bytes, expected 4",
                page.header.page_number,
                tag.index,
                data.len()
            );
        }
        let child = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if child == 0 {
            bail!(
                "ESE branch page {} tag {} references page zero",
                page.header.page_number,
                tag.index
            );
        }
        children.push(child);
    }
    Ok(children)
}

fn parse_leaf_records(page: &EsePage) -> Result<Vec<EseLeafRecord>> {
    if page.header.flags & ESE_PAGE_FLAG_LEAF == 0 {
        bail!("ESE page {} is not a leaf page", page.header.page_number);
    }
    let common_key = page_common_key(page)?;
    let mut records = Vec::new();
    for tag in page.tags.iter().skip(1) {
        if tag.flags & ESE_PAGE_TAG_FLAG_DEFUNCT != 0 {
            continue;
        }
        let value = page.value(tag)?;
        let (key, data) =
            split_btree_entry(value, tag.flags, common_key, false).with_context(|| {
                format!(
                    "decoding ESE leaf page {} tag {}",
                    page.header.page_number, tag.index
                )
            })?;
        if data.is_empty() {
            bail!(
                "ESE leaf page {} tag {} has no record data",
                page.header.page_number,
                tag.index
            );
        }
        let page_value_offset = page
            .header_size
            .checked_add(tag.offset)
            .context("ESE leaf page-value offset overflow")?;
        let entry_header_length = value
            .len()
            .checked_sub(data.len())
            .context("ESE leaf record data is not contained by its page value")?;
        let record_data_offset = page_value_offset
            .checked_add(entry_header_length)
            .context("ESE leaf record-data offset overflow")?;
        records.push(EseLeafRecord {
            page_number: page.header.page_number,
            tag_index: tag.index,
            key,
            data: data.to_vec(),
            page_value_offset,
            record_data_offset,
        });
    }
    Ok(records)
}

fn page_common_key(page: &EsePage) -> Result<&[u8]> {
    let Some(first_tag) = page.tags.first() else {
        return Ok(&[]);
    };
    if page.header.flags & ESE_PAGE_FLAG_ROOT != 0 {
        return Ok(&[]);
    }
    page.value(first_tag)
}

fn split_btree_entry<'a>(
    value: &'a [u8],
    tag_flags: u8,
    common_page_key: &[u8],
    branch: bool,
) -> Result<(Vec<u8>, &'a [u8])> {
    let mut cursor = 0_usize;
    let common_size = if tag_flags & ESE_PAGE_TAG_FLAG_COMMON_KEY != 0 {
        let size = usize::from(read_u16_at(value, cursor, "common-key size")?);
        cursor += 2;
        if size > common_page_key.len() {
            bail!(
                "ESE entry common-key length {size} exceeds page prefix {}",
                common_page_key.len()
            );
        }
        size
    } else {
        0
    };
    let local_size = usize::from(read_u16_at(value, cursor, "local-key size")? & 0x1fff);
    cursor += 2;
    let local_end = cursor
        .checked_add(local_size)
        .context("ESE local-key range overflow")?;
    let local_key = value
        .get(cursor..local_end)
        .context("ESE local key is truncated")?;
    let data = value
        .get(local_end..)
        .context("ESE entry data offset is out of bounds")?;
    if branch && data.len() != 4 {
        bail!("ESE branch entry contains {} trailing bytes", data.len());
    }
    let mut key = Vec::with_capacity(common_size.saturating_add(local_key.len()));
    key.extend_from_slice(&common_page_key[..common_size]);
    key.extend_from_slice(local_key);
    Ok((key, data))
}

#[derive(Debug)]
struct CatalogRecord {
    object_id: u32,
    catalog_type: i16,
    id: u32,
    column_type_or_root_page: u32,
    space_usage: u32,
    flags: u32,
    pages_or_codepage: u32,
    record_offset: Option<u16>,
    name: String,
}

fn build_catalog(records: &[EseLeafRecord]) -> Result<BTreeMap<String, EseTable>> {
    let decoded = records
        .iter()
        .map(decode_catalog_record)
        .collect::<Result<Vec<_>>>()?;
    let mut by_object = BTreeMap::new();
    for record in decoded
        .iter()
        .filter(|record| record.catalog_type == CATALOG_TYPE_TABLE)
    {
        if record.name.is_empty() || record.column_type_or_root_page == 0 {
            bail!("ESE catalog contains an unnamed table or a zero root page");
        }
        let table = EseTable {
            object_id: record.object_id,
            name: record.name.clone(),
            root_page: record.column_type_or_root_page,
            columns: BTreeMap::new(),
        };
        if by_object.insert(record.object_id, table).is_some() {
            bail!(
                "ESE catalog contains duplicate table object {}",
                record.object_id
            );
        }
    }
    for record in decoded
        .iter()
        .filter(|record| record.catalog_type == CATALOG_TYPE_COLUMN)
    {
        let table = by_object.get_mut(&record.object_id).with_context(|| {
            format!(
                "ESE catalog column {} references missing table object {}",
                record.name, record.object_id
            )
        })?;
        let column = EseColumn {
            id: record.id,
            name: record.name.clone(),
            column_type: record.column_type_or_root_page,
            space_usage: record.space_usage,
            flags: record.flags,
            codepage: record.pages_or_codepage,
            record_offset: record.record_offset,
        };
        if table.columns.insert(record.id, column).is_some() {
            bail!(
                "ESE table {} contains duplicate column identifier {}",
                table.name,
                record.id
            );
        }
    }

    let mut by_name = BTreeMap::new();
    for (_, table) in by_object {
        if by_name.insert(table.name.clone(), table).is_some() {
            bail!("ESE catalog contains duplicate table names");
        }
    }
    let catalog = by_name
        .get("MSysObjects")
        .context("ESE catalog does not define MSysObjects")?;
    if catalog.root_page != ESE_CATALOG_ROOT_PAGE {
        bail!(
            "ESE MSysObjects root page is {}, expected {}",
            catalog.root_page,
            ESE_CATALOG_ROOT_PAGE
        );
    }
    Ok(by_name)
}

fn decode_catalog_record(record: &EseLeafRecord) -> Result<CatalogRecord> {
    let data = &record.data;
    if data.len() < 4 {
        bail!(
            "ESE catalog page {} tag {} record header is truncated",
            record.page_number,
            record.tag_index
        );
    }
    let last_fixed = data[0];
    if last_fixed < 7 {
        bail!(
            "ESE catalog page {} tag {} only defines fixed columns through {last_fixed}",
            record.page_number,
            record.tag_index
        );
    }
    let variable = parse_variable_columns(data)?;
    let name_bytes = variable
        .values
        .get(&128)
        .and_then(|value| value.as_deref())
        .context("ESE catalog record has no Name column")?;
    let name = decode_ese_text(name_bytes, 0)?;
    Ok(CatalogRecord {
        object_id: read_u32_at(data, 4, "catalog ObjidTable")?,
        catalog_type: read_i16_at(data, 8, "catalog Type")?,
        id: read_u32_at(data, 10, "catalog Id")?,
        column_type_or_root_page: read_u32_at(data, 14, "catalog ColtypOrPgnoFDP")?,
        space_usage: read_u32_at(data, 18, "catalog SpaceUsage")?,
        flags: read_u32_at(data, 22, "catalog Flags")?,
        pages_or_codepage: read_u32_at(data, 26, "catalog PagesOrLocale")?,
        record_offset: if last_fixed >= 9 {
            Some(read_u16_at(data, 31, "catalog RecordOffset")?)
        } else {
            None
        },
        name,
    })
}

fn decode_table_record(
    record: &EseLeafRecord,
    table: &EseTable,
    format_revision: u32,
    page_size: usize,
) -> Result<EseDecodedRow> {
    if record.data.len() < 4 {
        bail!(
            "ESE table {} page {} tag {} record header is truncated",
            table.name,
            record.page_number,
            record.tag_index
        );
    }
    let last_fixed = u32::from(record.data[0]);
    let variable = parse_variable_columns(&record.data)?;
    let mut values = BTreeMap::new();

    for column in table.columns.values().filter(|column| column.is_fixed()) {
        if column.id > last_fixed {
            values.insert(column.id, EseColumnValue::Null);
            continue;
        }
        let offset = usize::from(column.record_offset.with_context(|| {
            format!(
                "ESE fixed column {}.{} lacks a record offset",
                table.name, column.name
            )
        })?);
        let size = fixed_column_size(column)?;
        let end = offset
            .checked_add(size)
            .context("ESE fixed-column range overflow")?;
        let bytes = record.data.get(offset..end).with_context(|| {
            format!(
                "ESE fixed column {}.{} range {offset}..{end} is truncated on page {} tag {}",
                table.name, column.name, record.page_number, record.tag_index
            )
        })?;
        values.insert(column.id, EseColumnValue::Inline(bytes.to_vec()));
    }
    for column in table.columns.values().filter(|column| column.is_variable()) {
        let value = match variable.values.get(&column.id) {
            Some(Some(bytes)) => EseColumnValue::Inline(bytes.clone()),
            Some(None) | None => EseColumnValue::Null,
        };
        values.insert(column.id, value);
    }
    let tagged = parse_tagged_columns(
        record
            .data
            .get(variable.tagged_start..)
            .context("ESE tagged-column start is out of bounds")?,
        format_revision,
        page_size,
    )?;
    for (column_id, value) in tagged {
        if !table
            .columns
            .get(&column_id)
            .is_some_and(EseColumn::is_tagged)
        {
            bail!(
                "ESE table {} record contains undefined tagged column {column_id}",
                table.name
            );
        }
        values.insert(column_id, value);
    }
    Ok(EseDecodedRow {
        page_number: record.page_number,
        tag_index: record.tag_index,
        key: record.key.clone(),
        columns: values,
        page_value_offset: record.page_value_offset,
        record_data_offset: record.record_data_offset,
        record_data_length: record.data.len(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EseVariableColumns {
    values: BTreeMap<u32, Option<Vec<u8>>>,
    tagged_start: usize,
}

fn parse_variable_columns(data: &[u8]) -> Result<EseVariableColumns> {
    if data.len() < 4 {
        bail!("ESE record header is truncated");
    }
    let last_variable = data[1];
    let variable_offset = usize::from(read_u16_at(data, 2, "variable-column offset")?);
    if variable_offset < 4 || variable_offset > data.len() {
        bail!(
            "ESE variable-column offset {variable_offset} is outside record length {}",
            data.len()
        );
    }
    let count = if last_variable >= 128 {
        usize::from(last_variable - 127)
    } else {
        0
    };
    let array_end = variable_offset
        .checked_add(
            count
                .checked_mul(2)
                .context("ESE variable array overflow")?,
        )
        .context("ESE variable array end overflow")?;
    if array_end > data.len() {
        bail!("ESE variable-column offset array is truncated");
    }
    let mut values = BTreeMap::new();
    let mut previous_end = 0_usize;
    for index in 0..count {
        let raw_end = read_u16_at(data, variable_offset + index * 2, "variable-column end")?;
        let is_null = raw_end & 0x8000 != 0;
        let end = usize::from(raw_end & 0x7fff);
        if end < previous_end {
            bail!("ESE variable-column offsets are not monotonic");
        }
        let absolute_end = array_end
            .checked_add(end)
            .context("ESE variable-column end overflow")?;
        if absolute_end > data.len() {
            bail!("ESE variable-column value exceeds record bounds");
        }
        let column_id = 128_u32 + u32::try_from(index).context("column id overflow")?;
        if is_null {
            values.insert(column_id, None);
        } else {
            let absolute_start = array_end + previous_end;
            values.insert(column_id, Some(data[absolute_start..absolute_end].to_vec()));
        }
        previous_end = end;
    }
    let tagged_start = array_end
        .checked_add(previous_end)
        .context("ESE tagged-column start overflow")?;
    Ok(EseVariableColumns {
        values,
        tagged_start,
    })
}

fn parse_tagged_columns(
    tagged: &[u8],
    format_revision: u32,
    page_size: usize,
) -> Result<BTreeMap<u32, EseColumnValue>> {
    let mut values = BTreeMap::new();
    if tagged.is_empty() {
        return Ok(values);
    }
    if tagged.len() < 4 {
        bail!("ESE tagged-column array is truncated");
    }
    if format_revision < 9 {
        bail!("ESE tagged columns before format revision 9 are unsupported");
    }
    if page_size >= 16_384 {
        bail!("ESE tagged columns on extended-page databases are not yet decoded");
    }
    let first_raw_offset = read_u16_at(tagged, 2, "first tagged-column offset")?;
    if first_raw_offset & 0x8000 != 0 {
        bail!("ESE tagged-column offset has unsupported high flag bit");
    }
    let array_size = usize::from(first_raw_offset & 0x3fff);
    if array_size == 0 || !array_size.is_multiple_of(4) || array_size > tagged.len() {
        bail!("ESE tagged-column array size {array_size} is invalid");
    }
    let count = array_size / 4;
    let mut entries = Vec::with_capacity(count);
    let mut previous_id = None;
    for index in 0..count {
        let base = index * 4;
        let column_id = u32::from(read_u16_at(tagged, base, "tagged-column id")?);
        if let Some(previous) = previous_id {
            if column_id <= previous {
                bail!("ESE tagged-column identifiers are not strictly increasing");
            }
        }
        previous_id = Some(column_id);
        let raw_offset = read_u16_at(tagged, base + 2, "tagged-column offset")?;
        if raw_offset & 0x8000 != 0 {
            bail!("ESE tagged-column {column_id} has unsupported high offset flag");
        }
        let offset = usize::from(raw_offset & 0x3fff);
        if offset < array_size || offset > tagged.len() {
            bail!("ESE tagged-column {column_id} offset {offset} is invalid");
        }
        entries.push((column_id, offset, raw_offset & 0x4000 != 0));
    }
    for pair in entries.windows(2) {
        if pair[0].1 > pair[1].1 {
            bail!("ESE tagged-column offsets are not monotonic");
        }
    }
    for (index, (column_id, start, has_flags)) in entries.iter().copied().enumerate() {
        let end = entries.get(index + 1).map_or(tagged.len(), |entry| entry.1);
        let mut raw = tagged
            .get(start..end)
            .context("ESE tagged-column range is out of bounds")?;
        let flags = if has_flags {
            let (&flags, remainder) = raw
                .split_first()
                .context("ESE tagged-column flags byte is missing")?;
            raw = remainder;
            flags
        } else {
            0
        };
        let unsupported = if flags & TAGGED_VALUE_FLAG_LONG_VALUE != 0 {
            Some("long-value reference")
        } else if flags & TAGGED_VALUE_FLAG_COMPRESSED != 0 {
            Some("compressed tagged value")
        } else if flags & TAGGED_VALUE_FLAG_MULTI_VALUE != 0 {
            Some("multi-valued tagged value")
        } else if flags & TAGGED_VALUE_FLAG_MULTI_VALUE_SIZE != 0 {
            Some("multi-value size-definition tagged value")
        } else if flags & !TAGGED_VALUE_KNOWN_FLAG_MASK != 0 {
            Some("unrecognized tagged-value flags")
        } else {
            None
        };
        values.insert(
            column_id,
            if let Some(reason) = unsupported {
                EseColumnValue::Unsupported {
                    flags,
                    reason,
                    raw: raw.to_vec(),
                }
            } else {
                EseColumnValue::Inline(raw.to_vec())
            },
        );
    }
    Ok(values)
}

fn fixed_column_size(column: &EseColumn) -> Result<usize> {
    let canonical = match column.column_type {
        1 | 2 => Some(1_usize),
        3 | 17 => Some(2),
        4 | 6 | 14 => Some(4),
        5 | 7 | 8 | 15 => Some(8),
        16 => Some(16),
        _ => None,
    };
    let declared = usize::try_from(column.space_usage).context("ESE column size overflow")?;
    match (canonical, declared) {
        (Some(size), 0) => Ok(size),
        (Some(size), declared) if size == declared => Ok(size),
        (Some(size), declared) => bail!(
            "ESE fixed column {} declares size {declared}, expected {size} for type {}",
            column.name,
            column.column_type
        ),
        (None, 1..=65_535) => Ok(declared),
        (None, _) => bail!(
            "ESE fixed column {} has unsupported type {} or size {declared}",
            column.name,
            column.column_type
        ),
    }
}

fn decode_ese_text(bytes: &[u8], codepage: u32) -> Result<String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    let looks_utf16 = bytes.len().is_multiple_of(2)
        && (codepage == 1_200
            || bytes
                .chunks_exact(2)
                .filter(|pair| pair[1] == 0)
                .count()
                .saturating_mul(2)
                >= bytes.len() / 2);
    if looks_utf16 {
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        return char::decode_utf16(units)
            .map(|value| value.context("invalid UTF-16 in ESE text value"))
            .collect();
    }
    std::str::from_utf8(bytes)
        .context("non-UTF-8 ESE text value is unsupported")
        .map(ToOwned::to_owned)
}

fn ese_header_checksum(header: &[u8]) -> Result<u32> {
    let checksum_bytes = header
        .get(4..ESE_HEADER_CHECKSUM_BYTES)
        .context("ESE header is shorter than its checksum-covered region")?;
    Ok(checksum_bytes
        .chunks_exact(4)
        .fold(ESE_CHECKSUM_SEED, |checksum, chunk| {
            checksum ^ u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        }))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .with_context(|| format!("ESE field at offset 0x{offset:x} is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .with_context(|| format!("ESE header field at offset 0x{offset:x} is truncated"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u16_at(bytes: &[u8], offset: usize, field: &str) -> Result<u16> {
    bytes
        .get(offset..offset.saturating_add(2))
        .with_context(|| format!("ESE {field} at offset {offset} is truncated"))
        .map(|value| u16::from_le_bytes([value[0], value[1]]))
}

fn read_i16_at(bytes: &[u8], offset: usize, field: &str) -> Result<i16> {
    bytes
        .get(offset..offset.saturating_add(2))
        .with_context(|| format!("ESE {field} at offset {offset} is truncated"))
        .map(|value| i16::from_le_bytes([value[0], value[1]]))
}

fn read_u32_at(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    bytes
        .get(offset..offset.saturating_add(4))
        .with_context(|| format!("ESE {field} at offset {offset} is truncated"))
        .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .with_context(|| format!("ESE header field at offset 0x{offset:x} is truncated"))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_header(revision: u32, state: u32, page_size: u32) -> Vec<u8> {
        let mut header = vec![0_u8; ESE_HEADER_CHECKSUM_BYTES];
        header[4..8].copy_from_slice(&ESE_SIGNATURE.to_le_bytes());
        header[8..12].copy_from_slice(&0x620_u32.to_le_bytes());
        header[12..16].copy_from_slice(&0_u32.to_le_bytes());
        header[16..24].copy_from_slice(&18_658_u64.to_le_bytes());
        header[52..56].copy_from_slice(&state.to_le_bytes());
        header[216..220].copy_from_slice(&10_u32.to_le_bytes());
        header[220..224].copy_from_slice(&0_u32.to_le_bytes());
        header[224..228].copy_from_slice(&26_200_u32.to_le_bytes());
        header[228..232].copy_from_slice(&0_u32.to_le_bytes());
        header[232..236].copy_from_slice(&revision.to_le_bytes());
        header[236..240].copy_from_slice(&page_size.to_le_bytes());
        let checksum = ese_header_checksum(&header).expect("checksum");
        header[0..4].copy_from_slice(&checksum.to_le_bytes());
        header
    }

    fn write_page_checksum(page: &mut [u8], page_number: u32) {
        page[0..8].fill(0);
        let flags = le_u32(page, 36).expect("page flags");
        if flags & ESE_PAGE_FLAG_NEW_CHECKSUM != 0 {
            let (ecc, xor) = ese_page_ecc32(page, 8, page_number).expect("ECC checksum");
            page[0..4].copy_from_slice(&xor.to_le_bytes());
            page[4..8].copy_from_slice(&ecc.to_le_bytes());
        } else {
            let checksum = page[4..]
                .chunks_exact(4)
                .fold(ESE_CHECKSUM_SEED, |checksum, chunk| {
                    checksum ^ u32::from_le_bytes(chunk.try_into().expect("four-byte word"))
                });
            page[0..4].copy_from_slice(&checksum.to_le_bytes());
        }
    }

    fn synthetic_page(
        page_number: u32,
        flags: u32,
        raw_tag_count: u16,
        tags: &[(u16, u16, u8)],
    ) -> Vec<u8> {
        assert_eq!(usize::from(raw_tag_count & 0x0fff), tags.len());
        let mut page = vec![0_u8; 4_096];
        page[24..28].copy_from_slice(&73_u32.to_le_bytes());
        let first_available = tags
            .iter()
            .map(|(offset, size, _)| offset.saturating_add(*size))
            .max()
            .unwrap_or(0);
        page[32..34].copy_from_slice(&first_available.to_le_bytes());
        page[34..36].copy_from_slice(&raw_tag_count.to_le_bytes());
        page[36..40].copy_from_slice(&flags.to_le_bytes());
        for (index, (offset, size, tag_flags)) in tags.iter().copied().enumerate() {
            assert!(tag_flags <= 7);
            let tag_offset = page.len() - (index + 1) * 4;
            let raw_offset = offset | (u16::from(tag_flags) << 13);
            page[tag_offset..tag_offset + 2].copy_from_slice(&size.to_le_bytes());
            page[tag_offset + 2..tag_offset + 4].copy_from_slice(&raw_offset.to_le_bytes());
        }
        write_page_checksum(&mut page, page_number);
        page
    }

    fn table_from_schema(name: &str, schema: &[ExpectedColumn]) -> EseTable {
        EseTable {
            object_id: 73,
            name: name.to_string(),
            root_page: 11,
            columns: schema
                .iter()
                .map(|column| {
                    (
                        column.id,
                        EseColumn {
                            id: column.id,
                            name: column.name.to_string(),
                            column_type: column.column_type,
                            space_usage: column.space_usage,
                            flags: column.flags,
                            codepage: 0,
                            record_offset: column.record_offset,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn clean_revision_300_header_is_recognized_with_provenance() {
        let header = synthetic_header(300, 3, 4_096);
        let parsed = probe_ese_header(&header, 4_096 * 656).expect("valid header");
        assert_eq!(parsed.format_version, 0x620);
        assert_eq!(parsed.format_revision, 300);
        assert_eq!(parsed.database_state, "clean_shutdown");
        assert_eq!(parsed.page_size, 4_096);
        assert_eq!(parsed.page_count, 656);
        assert_eq!(parsed.os_build_number, 26_200);
        assert!(parsed.header_checksum_valid);
        assert!(parsed.file_size_page_aligned);
    }

    #[test]
    fn dirty_shutdown_is_preserved_instead_of_hidden() {
        let mut header = synthetic_header(0x122, 2, 8_192);
        header[300] ^= 0x80;
        let parsed = probe_ese_header(&header, 8_192 * 3).expect("valid header");
        assert_eq!(parsed.database_state, "dirty_shutdown");
        assert_eq!(parsed.database_state_code, 2);
        assert!(!parsed.header_checksum_valid);
    }

    #[test]
    fn invalid_checksum_is_rejected() {
        let mut header = synthetic_header(300, 3, 4_096);
        header[300] ^= 0x80;
        let error = probe_ese_header(&header, 8_192).expect_err("checksum must fail");
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn short_and_unaligned_sources_are_rejected_boundedly() {
        let error = probe_ese_header(&[0_u8; 64], 64).expect_err("short header");
        assert!(error.to_string().contains("truncated"));

        let header = synthetic_header(300, 3, 4_096);
        let error = probe_ese_header(&header, 8_193).expect_err("unaligned source");
        assert!(error.to_string().contains("not aligned"));
    }

    #[test]
    fn reserved_tag_count_bits_are_masked_for_revision_300() {
        let page = synthetic_page(
            9,
            ESE_PAGE_FLAG_ROOT | ESE_PAGE_FLAG_LEAF,
            0xa001,
            &[(0, 0, 0)],
        );
        let parsed = parse_ese_page(&page, 9, 300).expect("valid page");
        assert_eq!(parsed.header.tag_count, 1);
        assert_eq!(parsed.tags.len(), 1);
    }

    #[test]
    fn page_checksum_corruption_is_rejected() {
        let mut legacy =
            synthetic_page(9, ESE_PAGE_FLAG_ROOT | ESE_PAGE_FLAG_LEAF, 1, &[(0, 0, 0)]);
        parse_ese_page(&legacy, 9, 300).expect("valid legacy checksum");
        legacy[128] ^= 0x40;
        let error = parse_ese_page(&legacy, 9, 300).expect_err("corrupt legacy page");
        assert!(error.to_string().contains("checksum mismatch"));

        let mut ecc = synthetic_page(
            9,
            ESE_PAGE_FLAG_ROOT | ESE_PAGE_FLAG_LEAF | ESE_PAGE_FLAG_NEW_CHECKSUM,
            1,
            &[(0, 0, 0)],
        );
        parse_ese_page(&ecc, 9, 300).expect("valid ECC checksum");
        ecc[256] ^= 0x04;
        let error = parse_ese_page(&ecc, 9, 300).expect_err("corrupt ECC page");
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn tag_bounds_and_live_overlap_are_rejected() {
        let out_of_bounds = synthetic_page(
            9,
            ESE_PAGE_FLAG_ROOT | ESE_PAGE_FLAG_LEAF,
            1,
            &[(0, 4_090, 0)],
        );
        let error = parse_ese_page(&out_of_bounds, 9, 300).expect_err("out-of-bounds tag");
        assert!(error.to_string().contains("exceeds value area"));

        let overlap = synthetic_page(
            9,
            ESE_PAGE_FLAG_ROOT | ESE_PAGE_FLAG_LEAF,
            2,
            &[(0, 10, 0), (5, 10, 0)],
        );
        let error = parse_ese_page(&overlap, 9, 300).expect_err("overlapping tags");
        assert!(error.to_string().contains("overlap"));
    }

    #[test]
    fn truncated_btree_keys_are_rejected() {
        let error =
            split_btree_entry(&[5, 0, 0xaa], 0, &[], false).expect_err("truncated local key");
        assert!(error.to_string().contains("local key is truncated"));

        let error = split_btree_entry(&[2, 0, 0, 0], ESE_PAGE_TAG_FLAG_COMMON_KEY, &[0xaa], false)
            .expect_err("oversized common key");
        assert!(error.to_string().contains("exceeds page prefix"));

        let error =
            split_btree_entry(&[0, 0, 1, 2, 3], 0, &[], true).expect_err("invalid branch payload");
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn variable_columns_are_bounded_and_monotonic() {
        let mut record = vec![0, 129, 4, 0, 3, 0, 5, 0];
        record.extend_from_slice(b"abcde");
        let variable = parse_variable_columns(&record).expect("variable values");
        assert_eq!(variable.values.get(&128), Some(&Some(b"abc".to_vec())));
        assert_eq!(variable.values.get(&129), Some(&Some(b"de".to_vec())));
        assert_eq!(variable.tagged_start, record.len());

        let mut with_null = record.clone();
        with_null[6..8].copy_from_slice(&0x8005_u16.to_le_bytes());
        let variable = parse_variable_columns(&with_null).expect("null variable value");
        assert_eq!(variable.values.get(&129), Some(&None));

        let mut nonmonotonic = record.clone();
        nonmonotonic[4..6].copy_from_slice(&4_u16.to_le_bytes());
        nonmonotonic[6..8].copy_from_slice(&3_u16.to_le_bytes());
        let error = parse_variable_columns(&nonmonotonic).expect_err("nonmonotonic offsets");
        assert!(error.to_string().contains("not monotonic"));

        let mut outside = record;
        outside[6..8].copy_from_slice(&10_u16.to_le_bytes());
        let error = parse_variable_columns(&outside).expect_err("out-of-bounds value");
        assert!(error.to_string().contains("exceeds record bounds"));
    }

    #[test]
    fn btree_live_primary_keys_must_increase() {
        let record = |page_number, tag_index, key| EseLeafRecord {
            page_number,
            tag_index,
            key,
            data: Vec::new(),
            page_value_offset: 0,
            record_data_offset: 0,
        };
        let increasing = [record(10, 1, vec![1]), record(11, 1, vec![2])];
        validate_primary_key_order(4, &increasing).expect("increasing keys");

        let duplicate = [record(10, 1, vec![2]), record(11, 1, vec![2])];
        let error = validate_primary_key_order(4, &duplicate).expect_err("duplicate key");
        assert!(error
            .to_string()
            .contains("non-increasing live primary keys"));

        let descending = [record(10, 1, vec![2]), record(11, 1, vec![1])];
        let error = validate_primary_key_order(4, &descending).expect_err("descending keys");
        assert!(error
            .to_string()
            .contains("non-increasing live primary keys"));
    }

    #[test]
    fn tagged_columns_preserve_unsupported_values_without_guessing() {
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&256_u16.to_le_bytes());
        tagged.extend_from_slice(&8_u16.to_le_bytes());
        tagged.extend_from_slice(&257_u16.to_le_bytes());
        tagged.extend_from_slice(&(0x4000_u16 | 10).to_le_bytes());
        tagged.extend_from_slice(&[0xaa, 0xbb, TAGGED_VALUE_FLAG_COMPRESSED, 0xcc]);
        let values = parse_tagged_columns(&tagged, 300, 4_096).expect("tagged values");
        assert_eq!(
            values.get(&256),
            Some(&EseColumnValue::Inline(vec![0xaa, 0xbb]))
        );
        assert_eq!(
            values.get(&257),
            Some(&EseColumnValue::Unsupported {
                flags: TAGGED_VALUE_FLAG_COMPRESSED,
                reason: "compressed tagged value",
                raw: vec![0xcc],
            })
        );

        tagged[4..6].copy_from_slice(&256_u16.to_le_bytes());
        let error =
            parse_tagged_columns(&tagged, 300, 4_096).expect_err("duplicate tagged identifier");
        assert!(error.to_string().contains("not strictly increasing"));
    }

    #[test]
    fn identifiers_and_time_values_are_strictly_normalized() {
        let utf16 = "application.exe"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode_utf16_identifier(&utf16).expect("UTF-16 identifier"),
            "application.exe"
        );
        assert!(decode_utf16_identifier(&[0x41]).is_err());
        assert!(decode_utf16_identifier(&[0x41, 0, 0, 0, 0x42, 0]).is_err());

        let sid = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
        assert_eq!(decode_binary_sid(&sid).expect("valid SID"), "S-1-5-32-545");
        assert!(decode_binary_sid(&sid[..15]).is_err());

        assert_eq!(
            ole_automation_to_rfc3339(25_569.0).expect("OLE epoch"),
            "1970-01-01T00:00:00+00:00"
        );
        assert_eq!(
            filetime_to_rfc3339(116_444_736_000_000_000).expect("FILETIME epoch"),
            Some("1970-01-01T00:00:00+00:00".to_string())
        );
        assert_eq!(filetime_to_rfc3339(0).expect("unset FILETIME"), None);
        assert_eq!(
            filetime_to_rfc3339(134_297_369_134_947_100).expect("gold FILETIME"),
            Some("2026-07-28T18:28:33.494710+00:00".to_string())
        );
        assert!(ole_automation_to_rfc3339(f64::NAN).is_err());
    }

    #[test]
    fn audited_schema_requires_exact_column_metadata() {
        let mut catalog = BTreeMap::new();
        catalog.insert(
            SRUM_NETWORK_USAGE_TABLE.to_string(),
            table_from_schema(SRUM_NETWORK_USAGE_TABLE, &NETWORK_USAGE_SCHEMA),
        );
        validated_table(&catalog, SRUM_NETWORK_USAGE_TABLE, &NETWORK_USAGE_SCHEMA)
            .expect("exact schema");

        catalog
            .get_mut(SRUM_NETWORK_USAGE_TABLE)
            .expect("table")
            .columns
            .get_mut(&8)
            .expect("BytesSent")
            .name = "BytesGuessed".to_string();
        let error = validated_table(&catalog, SRUM_NETWORK_USAGE_TABLE, &NETWORK_USAGE_SCHEMA)
            .expect_err("schema mismatch");
        assert!(error.to_string().contains("schema mismatch"));
    }

    #[test]
    #[ignore = "set KDFT_TEST_SRUM_PATH to validate an examiner-provided read-only source"]
    fn external_read_only_source_probe() {
        let path = std::env::var_os("KDFT_TEST_SRUM_PATH")
            .map(std::path::PathBuf::from)
            .expect("KDFT_TEST_SRUM_PATH must name a read-only SRUDB.dat copy");
        let (mut reader, parsed) = EseReader::open(&path).expect("valid ESE source");
        assert_eq!(parsed.format_version, 0x620);
        assert_eq!(parsed.format_revision, 300);
        assert!(parsed.header_checksum_valid);
        let catalog = reader.read_catalog().expect("validated ESE catalog");
        for table_name in [
            "SruDbIdMapTable",
            "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
            "{DD6636C4-8929-4683-974E-22C046A43763}",
        ] {
            let table = catalog.get(table_name).expect("expected SRUM table");
            let rows = reader
                .read_rows(table, 100_000)
                .expect("bounded SRUM table rows");
            let independently_observed_live_rows = match table_name {
                SRUM_ID_MAP_TABLE => 832,
                SRUM_NETWORK_USAGE_TABLE => 158,
                SRUM_APPLICATION_RESOURCE_TABLE => 533,
                SRUM_CONNECTIVITY_TABLE => 5,
                _ => unreachable!("fixed audited table list"),
            };
            assert_eq!(
                rows.len(),
                independently_observed_live_rows,
                "native table walk must match the independent Windows ESENT cursor live-row count"
            );
            if table_name == "SruDbIdMapTable" {
                let inline = rows
                    .iter()
                    .filter(|row| matches!(row.columns.get(&256), Some(EseColumnValue::Inline(_))))
                    .count();
                let null = rows
                    .iter()
                    .filter(|row| {
                        matches!(row.columns.get(&256), None | Some(EseColumnValue::Null))
                    })
                    .count();
                let unsupported = rows
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.columns.get(&256),
                            Some(EseColumnValue::Unsupported { .. })
                        )
                    })
                    .count();
                assert_eq!(inline, 830);
                assert_eq!(null, 2);
                assert_eq!(unsupported, 0);
            }
        }

        // These live-row counts and representative first-row values were
        // independently obtained from the Windows ESENT cursor API against
        // the same read-only source.  They intentionally do not use the ESE
        // table AutoInc/high-water values as row counts.
        let decoded = decode_srum_database(&path).expect("validated SRUM decode");
        assert_eq!(decoded.live_row_counts.id_map, 832);
        assert_eq!(decoded.live_row_counts.network_usage, 158);
        assert_eq!(decoded.live_row_counts.application_resource_usage, 533);
        assert_eq!(decoded.live_row_counts.connectivity, 5);

        let id_map_first = decoded.id_map_records.first().expect("IdMap first row");
        assert_eq!(id_map_first.id_type, 0);
        assert_eq!(id_map_first.id_index, 1);
        assert_eq!(id_map_first.value_kind, "null");

        let network_first = decoded
            .network_usage_records
            .first()
            .expect("network first row");
        assert_eq!(network_first.auto_inc_id, 1);
        assert_eq!(network_first.app.id_index, 398);
        assert_eq!(network_first.user.id_index, 4);
        assert_eq!(network_first.interface_luid, Some(0x0006_0080_0000_0000));
        assert_eq!(network_first.bytes_sent, Some(54_388));
        assert_eq!(network_first.bytes_received, Some(108_716));

        let application_first = decoded
            .application_resource_records
            .first()
            .expect("application-resource first row");
        assert_eq!(application_first.auto_inc_id, 51);
        assert_eq!(application_first.app.id_index, 440);
        assert_eq!(application_first.user.id_index, 191);

        let connectivity_first = decoded
            .connectivity_records
            .first()
            .expect("connectivity first row");
        assert_eq!(connectivity_first.auto_inc_id, 2);
        assert_eq!(connectivity_first.app.id_index, 1);
        assert_eq!(connectivity_first.user.id_index, 2);
        assert_eq!(connectivity_first.connected_time_seconds, Some(1_766));
        assert_eq!(
            connectivity_first.connect_start_filetime,
            Some(134_297_369_134_947_100)
        );
        assert_eq!(
            connectivity_first.provenance.offset_basis,
            SRUM_OFFSET_BASIS
        );
    }
}
