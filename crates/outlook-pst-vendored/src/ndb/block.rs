//! [Blocks](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/a9c1981d-d1ea-457c-b39e-dc7fb0eb95d4)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    collections::{btree_map, BTreeMap, VecDeque},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    iter,
};
use tracing::error;

use super::{block_id::*, block_ref::*, byte_index::*, node_id::*, page::*, read_write::*, *};
use crate::{AnsiPstFile, PstFile, PstFileReadWriteBlockBTree, PstReader, UnicodePstFile};

pub const MAX_BLOCK_SIZE: u16 = 8192;
pub const MAX_TREE_DEPTH: usize = 64;
pub const MAX_DATA_TREE_DEPTH: usize = 2;
pub const MAX_MATERIALIZED_NODE_BYTES: u32 = 256 * 1024 * 1024;
pub const MAX_DATA_TREE_BLOCKS: usize = 65_536;

pub const fn block_size(size: u16) -> u16 {
    assert!(size > 0);
    assert!(size <= MAX_BLOCK_SIZE);
    size.div_ceil(64) * 64
}

/// Round a data-plus-trailer length to its on-disk allocation size without
/// allowing untrusted metadata to overflow or trigger [`block_size`]'s
/// programmer-facing assertions.
pub fn checked_block_size(data_size: u16, trailer_size: u16) -> NdbResult<u16> {
    let combined = u32::from(data_size)
        .checked_add(u32::from(trailer_size))
        .ok_or(NdbError::InvalidBlockAllocationSize(u32::MAX))?;
    if combined == 0 || combined > u32::from(MAX_BLOCK_SIZE) {
        return Err(NdbError::InvalidBlockAllocationSize(combined));
    }

    let rounded = combined
        .checked_add(63)
        .ok_or(NdbError::InvalidBlockAllocationSize(combined))?
        / 64
        * 64;
    u16::try_from(rounded).map_err(|_| NdbError::InvalidBlockAllocationSize(rounded))
}

pub(crate) fn read_to_end_bounded<R: Read + ?Sized>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let probe_limit = u64::try_from(limit)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(NdbError::NodeDataTooLarge(u64::MAX))?;
    let mut data = Vec::new();
    reader.take(probe_limit).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(NdbError::NodeDataTooLarge(data.len() as u64).into());
    }
    Ok(data)
}

/// [BLOCKTRAILER](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/a14943ef-70c2-403f-898c-5bc3747117e1)
pub trait BlockTrailer {
    type BlockId: BlockId;

    fn size(&self) -> u16;
    fn signature(&self) -> u16;
    fn crc(&self) -> u32;
    fn block_id(&self) -> Self::BlockId;
    fn cyclic_key(&self) -> u32;
    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()>;
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeBlockTrailer {
    size: u16,
    signature: u16,
    crc: u32,
    block_id: UnicodeBlockId,
}

impl UnicodeBlockTrailer {
    pub fn new(size: u16, signature: u16, crc: u32, block_id: UnicodeBlockId) -> NdbResult<Self> {
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size));
        }

        Ok(Self {
            size,
            block_id,
            signature,
            crc,
        })
    }
}

impl BlockTrailer for UnicodeBlockTrailer {
    type BlockId = UnicodeBlockId;

    fn size(&self) -> u16 {
        self.size
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> UnicodeBlockId {
        self.block_id
    }

    fn cyclic_key(&self) -> u32 {
        self.block_id.search_key() as u32
    }

    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()> {
        if self.block_id.is_internal() != is_internal {
            return Err(NdbError::InvalidUnicodeBlockTrailerId(u64::from(
                self.block_id,
            )));
        }
        Ok(())
    }
}

impl BlockTrailerReadWrite for UnicodeBlockTrailer {
    const SIZE: u16 = 16;

    fn new(size: u16, signature: u16, crc: u32, block_id: UnicodeBlockId) -> NdbResult<Self> {
        Self::new(size, signature, crc, block_id)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u16::<LittleEndian>()?;
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size).into());
        }

        let signature = f.read_u16::<LittleEndian>()?;
        let crc = f.read_u32::<LittleEndian>()?;
        let block_id = UnicodeBlockId::read(f)?;

        Ok(Self {
            size,
            signature,
            crc,
            block_id,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.signature)?;
        f.write_u32::<LittleEndian>(self.crc)?;
        self.block_id.write(f)
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiBlockTrailer {
    size: u16,
    signature: u16,
    block_id: AnsiBlockId,
    crc: u32,
}

impl AnsiBlockTrailer {
    pub fn new(size: u16, signature: u16, crc: u32, block_id: AnsiBlockId) -> NdbResult<Self> {
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size));
        }

        Ok(Self {
            size,
            signature,
            block_id,
            crc,
        })
    }
}

impl BlockTrailer for AnsiBlockTrailer {
    type BlockId = AnsiBlockId;

    fn size(&self) -> u16 {
        self.size
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> AnsiBlockId {
        self.block_id
    }

    fn cyclic_key(&self) -> u32 {
        self.block_id.search_key()
    }

    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()> {
        if self.block_id.is_internal() != is_internal {
            return Err(NdbError::InvalidAnsiBlockTrailerId(u32::from(
                self.block_id,
            )));
        }
        Ok(())
    }
}

impl BlockTrailerReadWrite for AnsiBlockTrailer {
    const SIZE: u16 = 12;

    fn new(size: u16, signature: u16, crc: u32, block_id: AnsiBlockId) -> NdbResult<Self> {
        Self::new(size, signature, crc, block_id)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u16::<LittleEndian>()?;
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size).into());
        }

        let signature = f.read_u16::<LittleEndian>()?;
        let block_id = AnsiBlockId::read(f)?;
        let crc = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            size,
            signature,
            block_id,
            crc,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.signature)?;
        self.block_id.write(f)?;
        f.write_u32::<LittleEndian>(self.crc)
    }
}

/// [Data Blocks](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/d0e6fbaf-00e3-4d4d-bea8-8ab3cdb4fde6)
pub trait Block {
    type Trailer: BlockTrailer;

    fn encoding(&self) -> NdbCryptMethod;
    fn data(&self) -> &[u8];
    fn trailer(&self) -> &Self::Trailer;
}

#[derive(Clone, Default)]
pub struct UnicodeDataBlock {
    encoding: NdbCryptMethod,
    data: Vec<u8>,
    trailer: UnicodeBlockTrailer,
}

impl UnicodeDataBlock {
    pub fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            data,
            encoding,
            trailer,
        })
    }
}

impl Block for UnicodeDataBlock {
    type Trailer = UnicodeBlockTrailer;

    fn encoding(&self) -> NdbCryptMethod {
        self.encoding
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn trailer(&self) -> &UnicodeBlockTrailer {
        &self.trailer
    }
}

impl BlockReadWrite for UnicodeDataBlock {
    fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Self::new(encoding, data, trailer)
    }
}

impl From<UnicodeDataBlock> for Vec<u8> {
    fn from(value: UnicodeDataBlock) -> Self {
        value.data
    }
}

#[derive(Clone, Default)]
pub struct AnsiDataBlock {
    encoding: NdbCryptMethod,
    data: Vec<u8>,
    trailer: AnsiBlockTrailer,
}

impl AnsiDataBlock {
    pub fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: AnsiBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            data,
            encoding,
            trailer,
        })
    }
}

impl Block for AnsiDataBlock {
    type Trailer = AnsiBlockTrailer;

    fn encoding(&self) -> NdbCryptMethod {
        self.encoding
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn trailer(&self) -> &AnsiBlockTrailer {
        &self.trailer
    }
}

impl BlockReadWrite for AnsiDataBlock {
    fn new(encoding: NdbCryptMethod, data: Vec<u8>, trailer: AnsiBlockTrailer) -> NdbResult<Self> {
        Self::new(encoding, data, trailer)
    }
}

impl From<AnsiDataBlock> for Vec<u8> {
    fn from(value: AnsiDataBlock) -> Self {
        value.data
    }
}

pub trait IntermediateTreeHeader {
    fn level(&self) -> u8;
    fn entry_count(&self) -> u16;
}

pub trait IntermediateTreeEntry {}

pub trait IntermediateTreeBlock {
    type Header: IntermediateTreeHeader;
    type Entry: IntermediateTreeEntry;
    type Trailer: BlockTrailer;

    fn header(&self) -> &Self::Header;
    fn entries(&self) -> &[Self::Entry];
    fn trailer(&self) -> &Self::Trailer;
}

#[derive(Clone, Copy, Default)]
pub struct DataTreeBlockHeader {
    level: u8,
    entry_count: u16,
    total_size: u32,
}

impl DataTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16, total_size: u32) -> Self {
        Self {
            level,
            entry_count,
            total_size,
        }
    }

    pub fn total_size(&self) -> u32 {
        self.total_size
    }
}

impl IntermediateTreeHeader for DataTreeBlockHeader {
    fn level(&self) -> u8 {
        self.level
    }

    fn entry_count(&self) -> u16 {
        self.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for DataTreeBlockHeader {
    const HEADER_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x01 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;
        let total_size = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            level,
            entry_count,
            total_size,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x01)?;
        f.write_u8(self.level)?;
        f.write_u16::<LittleEndian>(self.entry_count)?;
        f.write_u32::<LittleEndian>(self.total_size)
    }
}

pub trait IntermediateDataTreeEntry<Pst>: IntermediateTreeEntry
where
    Pst: PstFile,
{
    fn new(block: <Pst as PstFile>::BlockId) -> Self;
    fn block(&self) -> <Pst as PstFile>::BlockId;
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeDataTreeEntry(UnicodeBlockId);

impl IntermediateTreeEntry for UnicodeDataTreeEntry {}

impl IntermediateDataTreeEntry<UnicodePstFile> for UnicodeDataTreeEntry {
    fn new(block: UnicodeBlockId) -> Self {
        Self(block)
    }

    fn block(&self) -> UnicodeBlockId {
        self.0
    }
}

impl IntermediateTreeEntryReadWrite for UnicodeDataTreeEntry {
    const ENTRY_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(UnicodeBlockId::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<UnicodeBlockId> for UnicodeDataTreeEntry {
    fn from(value: UnicodeBlockId) -> Self {
        Self::new(value)
    }
}

impl From<UnicodeDataTreeEntry> for UnicodeBlockId {
    fn from(value: UnicodeDataTreeEntry) -> Self {
        value.block()
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiDataTreeEntry(AnsiBlockId);

impl IntermediateTreeEntry for AnsiDataTreeEntry {}

impl IntermediateDataTreeEntry<AnsiPstFile> for AnsiDataTreeEntry {
    fn new(block: AnsiBlockId) -> Self {
        Self(block)
    }

    fn block(&self) -> AnsiBlockId {
        self.0
    }
}

impl IntermediateTreeEntryReadWrite for AnsiDataTreeEntry {
    const ENTRY_SIZE: u16 = 4;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(AnsiBlockId::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<AnsiBlockId> for AnsiDataTreeEntry {
    fn from(value: AnsiBlockId) -> Self {
        Self::new(value)
    }
}

impl From<AnsiDataTreeEntry> for AnsiBlockId {
    fn from(value: AnsiDataTreeEntry) -> Self {
        value.block()
    }
}

/// [XBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5b7a6935-e83d-4917-9f62-6ce3707f09e0)
/// / [XXBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/061b6ac4-d1da-468c-b75d-0303a0a8f468)
struct DataTreeBlockInner<Entry, Trailer>
where
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    header: DataTreeBlockHeader,
    entries: Vec<Entry>,
    trailer: Trailer,
}

impl<Entry, Trailer> DataTreeBlockInner<Entry, Trailer>
where
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    pub fn new(
        header: DataTreeBlockHeader,
        entries: Vec<Entry>,
        trailer: Trailer,
    ) -> NdbResult<Self> {
        trailer.verify_block_id(true)?;

        Ok(Self {
            header,
            entries,
            trailer,
        })
    }
}

pub struct UnicodeDataTreeBlock {
    inner: DataTreeBlockInner<UnicodeDataTreeEntry, UnicodeBlockTrailer>,
}

impl IntermediateTreeBlock for UnicodeDataTreeBlock {
    type Header = DataTreeBlockHeader;
    type Entry = UnicodeDataTreeEntry;
    type Trailer = UnicodeBlockTrailer;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.inner.entries
    }

    fn trailer(&self) -> &Self::Trailer {
        &self.inner.trailer
    }
}

impl IntermediateTreeBlockReadWrite for UnicodeDataTreeBlock {
    fn new(
        header: DataTreeBlockHeader,
        entries: Vec<UnicodeDataTreeEntry>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            inner: DataTreeBlockInner::new(header, entries, trailer)?,
        })
    }
}

pub struct AnsiDataTreeBlock {
    inner: DataTreeBlockInner<AnsiDataTreeEntry, AnsiBlockTrailer>,
}

impl IntermediateTreeBlock for AnsiDataTreeBlock {
    type Header = DataTreeBlockHeader;
    type Entry = AnsiDataTreeEntry;
    type Trailer = AnsiBlockTrailer;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.inner.entries
    }

    fn trailer(&self) -> &Self::Trailer {
        &self.inner.trailer
    }
}

impl IntermediateTreeBlockReadWrite for AnsiDataTreeBlock {
    fn new(
        header: DataTreeBlockHeader,
        entries: Vec<AnsiDataTreeEntry>,
        trailer: AnsiBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            inner: DataTreeBlockInner::new(header, entries, trailer)?,
        })
    }
}

pub type DataBlockCache<Pst> = BTreeMap<<Pst as PstFile>::BlockId, DataTree<Pst>>;

struct DataTreeTraversalState {
    depth: usize,
    remaining_bytes: usize,
    remaining_blocks: usize,
}

impl Default for DataTreeTraversalState {
    fn default() -> Self {
        Self {
            depth: 0,
            remaining_bytes: MAX_MATERIALIZED_NODE_BYTES as usize,
            remaining_blocks: MAX_DATA_TREE_BLOCKS,
        }
    }
}

pub enum DataTree<Pst>
where
    Pst: PstFile,
{
    Intermediate(Box<<Pst as PstFile>::DataTreeBlock>),
    Leaf(Box<<Pst as PstFile>::DataBlock>),
}

impl<Pst> DataTree<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite,
{
    pub fn declared_size(&self) -> u64 {
        match self {
            Self::Intermediate(block) => u64::from(block.header().total_size()),
            Self::Leaf(block) => block.data().len() as u64,
        }
    }

    pub fn ensure_materializable(&self) -> io::Result<()> {
        let size = self.declared_size();
        if size > u64::from(MAX_MATERIALIZED_NODE_BYTES) {
            return Err(NdbError::NodeDataTooLarge(size).into());
        }
        Ok(())
    }

    pub fn read<R>(
        f: &mut R,
        encoding: NdbCryptMethod,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<Self>
    where
        R: PstReader,
    {
        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        let block_size = checked_block_size(
            block.size(),
            <<Pst as PstFile>::BlockTrailer as BlockTrailerReadWrite>::SIZE,
        )?;
        let mut data = vec![0; block_size as usize];
        f.read_exact(&mut data)?;
        let mut cursor = Cursor::new(data);

        let block = if block.block().block().is_internal() {
            let header = DataTreeBlockHeader::read(&mut cursor)?;
            if !(1..=MAX_DATA_TREE_DEPTH as u8).contains(&header.level()) {
                return Err(NdbError::InvalidInternalBlockLevel(header.level()).into());
            }
            cursor.seek(SeekFrom::Start(0))?;
            let block = <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut cursor,
                header,
                block.size(),
            )?;
            Self::Intermediate(Box::new(block))
        } else {
            let block = <<Pst as PstFile>::DataBlock as BlockReadWrite>::read(
                &mut cursor,
                block.size(),
                encoding,
            )?;
            Self::Leaf(Box::new(block))
        };

        Ok(block)
    }

    pub fn write<W: Write + Seek>(
        &self,
        f: &mut W,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<()> {
        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        match self {
            Self::Intermediate(block, ..) => block.write(f),
            Self::Leaf(block) => block.write(f),
        }
    }

    pub fn blocks<'a, R>(
        &'a self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::DataBlock>>>
    where
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        self.ensure_materializable()?;
        let mut state = DataTreeTraversalState::default();
        self.blocks_with_depth(
            f,
            encoding,
            block_btree,
            page_cache,
            block_cache,
            &mut state,
        )
    }

    fn blocks_with_depth<'a, R>(
        &'a self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
        state: &mut DataTreeTraversalState,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::DataBlock>>>
    where
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block, ..) => {
                if state.depth >= MAX_DATA_TREE_DEPTH {
                    return Err(NdbError::TreeTraversalDepthExceeded.into());
                }
                let mut blocks = Vec::with_capacity(block.entries().len());
                for entry in block.entries() {
                    let data_tree = match block_cache.remove(&entry.block()) {
                        Some(entry) => entry,
                        None => {
                            let data_block = block_btree.find_entry(
                                f,
                                entry.block().search_key(),
                                page_cache,
                            )?;
                            Self::read(&mut *f, encoding, &data_block)?
                        }
                    };
                    if let Self::Intermediate(child) = &data_tree {
                        if child.header().level() >= block.header().level() {
                            return Err(NdbError::InvalidInternalBlockLevel(
                                child.header().level(),
                            )
                            .into());
                        }
                    }
                    state.depth += 1;
                    let entries = data_tree
                        .blocks_with_depth(f, encoding, block_btree, page_cache, block_cache, state)
                        .map(|blocks| blocks.collect::<Vec<_>>());
                    state.depth -= 1;
                    block_cache.insert(entry.block(), data_tree);
                    blocks.push(entries?);
                }
                Ok(Box::new(blocks.into_iter().flatten()))
            }
            Self::Leaf(block) => {
                let size = block.data().len();
                if size > state.remaining_bytes {
                    return Err(NdbError::NodeDataTooLarge(
                        u64::from(MAX_MATERIALIZED_NODE_BYTES) + 1,
                    )
                    .into());
                }
                if state.remaining_blocks == 0 {
                    return Err(NdbError::DataTreeBlockLimitExceeded.into());
                }
                state.remaining_bytes -= size;
                state.remaining_blocks -= 1;
                Ok(Box::new(Some(block.as_ref()).cloned().into_iter()))
            }
        }
    }

    pub fn nth<R>(
        &self,
        n: usize,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &mut DataBlockCache<Pst>,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        Ok(Some(match self {
            Self::Intermediate(_) => {
                let Some(data_block) = self
                    .sub_entries(f, encoding, block_btree, page_cache, block_cache)?
                    .nth(n)
                else {
                    return Ok(None);
                };

                let data_tree = match block_cache.entry(data_block.block().block()) {
                    btree_map::Entry::Vacant(entry) => {
                        entry.insert(Self::read(&mut *f, encoding, &data_block)?)
                    }
                    btree_map::Entry::Occupied(entry) => entry.into_mut(),
                };

                let Self::Leaf(block) = data_tree else {
                    error!(
                        name: "PstInvalidDataTreeIntermediateBlock",
                        "Data tree intermediate block has non-leaf sub-entry"
                    );

                    return Err(NdbError::InvalidInternalBlockLevel(0).into());
                };

                block.data().to_vec()
            }
            Self::Leaf(block) => {
                if n != 0 {
                    return Ok(None);
                }

                block.data().to_vec()
            }
        }))
    }

    pub fn reader<'a, R>(
        &self,
        f: &'a mut R,
        encoding: NdbCryptMethod,
        block_btree: &'a PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Box<dyn 'a + Read>>
    where
        Pst: 'a,
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let reader: DataTreeReader<'a, Pst, R> =
            DataTreeReader::new(self, f, encoding, block_btree, page_cache, block_cache)?;
        let reader: Box<dyn 'a + Read> = Box::new(reader);
        Ok(reader)
    }

    fn sub_entries<'a, R>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::BlockBTreeEntry>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockBTreeEntry: 'a,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        self.ensure_materializable()?;
        let mut state = DataTreeTraversalState::default();
        self.sub_entries_with_depth(
            f,
            encoding,
            block_btree,
            page_cache,
            block_cache,
            &mut state,
        )
    }

    fn sub_entries_with_depth<'a, R>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
        state: &mut DataTreeTraversalState,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::BlockBTreeEntry>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockBTreeEntry: 'a,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block, ..) => {
                if state.depth >= MAX_DATA_TREE_DEPTH {
                    return Err(NdbError::TreeTraversalDepthExceeded.into());
                }
                let mut blocks = Vec::with_capacity(block.entries().len());
                for entry in block.entries() {
                    if entry.block().is_internal() {
                        let data_tree = match block_cache.remove(&entry.block()) {
                            Some(entry) => entry,
                            None => {
                                let data_block = block_btree.find_entry(
                                    f,
                                    entry.block().search_key(),
                                    page_cache,
                                )?;
                                Self::read(&mut *f, encoding, &data_block)?
                            }
                        };
                        let Self::Intermediate(child) = &data_tree else {
                            return Err(NdbError::InvalidInternalBlockLevel(0).into());
                        };
                        if child.header().level() >= block.header().level() {
                            return Err(NdbError::InvalidInternalBlockLevel(
                                child.header().level(),
                            )
                            .into());
                        }
                        state.depth += 1;
                        let entries = data_tree
                            .sub_entries_with_depth(
                                f,
                                encoding,
                                block_btree,
                                page_cache,
                                block_cache,
                                state,
                            )
                            .map(|entries| entries.collect::<Vec<_>>());
                        state.depth -= 1;
                        block_cache.insert(entry.block(), data_tree);
                        blocks.push(entries?);
                    } else {
                        if state.remaining_blocks == 0 {
                            return Err(NdbError::DataTreeBlockLimitExceeded.into());
                        }
                        state.remaining_blocks -= 1;
                        let data_block =
                            block_btree.find_entry(f, entry.block().search_key(), page_cache)?;
                        blocks.push(vec![data_block]);
                    }
                }
                Ok(Box::new(blocks.into_iter().flatten()))
            }
            Self::Leaf(_) => Ok(Box::new(iter::empty())),
        }
    }
}

struct DataTreeCursor<Pst>
where
    Pst: PstFile,
{
    current: Cursor<Vec<u8>>,
    next: VecDeque<<Pst as PstFile>::BlockBTreeEntry>,
}

struct DataTreeReader<'a, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
{
    file: &'a mut R,
    encoding: NdbCryptMethod,
    cursor: DataTreeCursor<Pst>,
}

impl<'a, Pst, R> DataTreeReader<'a, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
{
    fn new(
        data_tree: &DataTree<Pst>,
        file: &'a mut R,
        encoding: NdbCryptMethod,
        block_btree: &'a PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Self>
    where
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
        <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
        <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
        <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
            IntermediateTreeEntryReadWrite,
        <Pst as PstFile>::DataBlock: BlockReadWrite,
    {
        let cursor = match data_tree {
            DataTree::Intermediate(_) => {
                let next = data_tree
                    .sub_entries(file, encoding, block_btree, page_cache, block_cache)?
                    .collect();

                DataTreeCursor {
                    current: Default::default(),
                    next,
                }
            }
            DataTree::Leaf(block) => DataTreeCursor {
                current: Cursor::new(block.data().to_vec()),
                next: Default::default(),
            },
        };

        Ok(Self {
            cursor,
            file,
            encoding,
        })
    }
}

impl<Pst, R> Read for DataTreeReader<'_, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
    <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<
            Pst,
            <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
            <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
        >,
    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
        RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total_read = self.cursor.current.read(buf)?;

        while total_read < buf.len() {
            let Some(next) = self.cursor.next.pop_front() else {
                break;
            };

            let next: DataTree<Pst> = DataTree::read(self.file, self.encoding, &next)?;
            let DataTree::Leaf(next) = next else {
                error!(
                    name: "PstInvalidDataTreeIntermediateBlock",
                    "Data tree intermediate block has non-leaf sub-entry"
                );

                return Err(NdbError::InvalidInternalBlockLevel(0).into());
            };
            self.cursor.current = Cursor::new(next.data().to_vec());

            let buf = &mut buf[total_read..];
            total_read += self.cursor.current.read(buf)?;
        }

        Ok(total_read)
    }
}

pub type UnicodeDataTree = DataTree<UnicodePstFile>;
pub type AnsiDataTree = DataTree<AnsiPstFile>;

#[derive(Clone, Copy, Default)]
struct SubNodeTreeBlockHeader {
    level: u8,
    entry_count: u16,
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeSubNodeTreeBlockHeader(SubNodeTreeBlockHeader);

impl UnicodeSubNodeTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16) -> Self {
        Self(SubNodeTreeBlockHeader { level, entry_count })
    }
}

impl IntermediateTreeHeader for UnicodeSubNodeTreeBlockHeader {
    fn level(&self) -> u8 {
        self.0.level
    }

    fn entry_count(&self) -> u16 {
        self.0.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for UnicodeSubNodeTreeBlockHeader {
    const HEADER_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x02 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;

        let padding = f.read_u32::<LittleEndian>()?;
        if padding != 0 {
            return Err(NdbError::InvalidSubNodeBlockPadding(padding).into());
        }

        Ok(Self::new(level, entry_count))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x02)?;
        f.write_u8(self.level())?;
        f.write_u16::<LittleEndian>(self.entry_count())?;
        f.write_u32::<LittleEndian>(0)
    }
}

impl SubNodeTreeBlockHeaderReadWrite for UnicodeSubNodeTreeBlockHeader {
    fn new(level: u8, entry_count: u16) -> Self {
        Self::new(level, entry_count)
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiSubNodeTreeBlockHeader(SubNodeTreeBlockHeader);

impl AnsiSubNodeTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16) -> Self {
        Self(SubNodeTreeBlockHeader { level, entry_count })
    }
}

impl IntermediateTreeHeader for AnsiSubNodeTreeBlockHeader {
    fn level(&self) -> u8 {
        self.0.level
    }

    fn entry_count(&self) -> u16 {
        self.0.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for AnsiSubNodeTreeBlockHeader {
    const HEADER_SIZE: u16 = 4;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x02 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;

        Ok(Self::new(level, entry_count))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x02)?;
        f.write_u8(self.level())?;
        f.write_u16::<LittleEndian>(self.entry_count())
    }
}

impl SubNodeTreeBlockHeaderReadWrite for AnsiSubNodeTreeBlockHeader {
    fn new(level: u8, entry_count: u16) -> Self {
        Self::new(level, entry_count)
    }
}

/// [SLENTRY (Leaf Block Entry)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/85c4d943-0779-43c5-bd98-61dc9bb5dfd6)
#[derive(Clone, Copy, Default)]
pub struct LeafSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    inner: IntermediateSubNodeTreeEntry<Block>,
    sub_node: Option<Block>,
}

impl<Block> LeafSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    pub fn new(node: NodeId, block: Block, sub_node: Option<Block>) -> Self {
        Self {
            inner: IntermediateSubNodeTreeEntry::new(node, block),
            sub_node,
        }
    }

    pub fn node(&self) -> NodeId {
        self.inner.node()
    }

    pub fn block(&self) -> Block {
        self.inner.block()
    }

    pub fn sub_node(&self) -> Option<Block> {
        self.sub_node
    }
}

pub type UnicodeLeafSubNodeTreeEntry = LeafSubNodeTreeEntry<UnicodeBlockId>;
pub type AnsiLeafSubNodeTreeEntry = LeafSubNodeTreeEntry<AnsiBlockId>;

impl IntermediateTreeEntry for UnicodeLeafSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for UnicodeLeafSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 24;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let inner = UnicodeIntermediateSubNodeTreeEntry::read(f)?;
        let sub_node = UnicodeBlockId::read(f)?;
        let sub_node = if sub_node.search_key() != 0 {
            Some(sub_node)
        } else {
            None
        };

        Ok(Self::new(inner.node(), inner.block(), sub_node))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.inner.write(f)?;
        self.sub_node.unwrap_or_default().write(f)
    }
}

impl IntermediateTreeEntry for AnsiLeafSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for AnsiLeafSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 12;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let inner = AnsiIntermediateSubNodeTreeEntry::read(f)?;
        let sub_node = AnsiBlockId::read(f)?;
        let sub_node = if sub_node.search_key() != 0 {
            Some(sub_node)
        } else {
            None
        };

        Ok(Self::new(inner.node(), inner.block(), sub_node))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.inner.write(f)?;
        self.sub_node.unwrap_or_default().write(f)
    }
}

/// [SIENTRY (Intermediate Block Entry)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/9e79c673-d2f4-49fb-a00b-51b08fd2d1e4)
#[derive(Clone, Copy, Default)]
pub struct IntermediateSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    node: NodeId,
    block: Block,
}

impl<Block> IntermediateSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    pub fn new(node: NodeId, block: Block) -> Self {
        Self { node, block }
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn block(&self) -> Block {
        self.block
    }
}

pub type UnicodeIntermediateSubNodeTreeEntry = IntermediateSubNodeTreeEntry<UnicodeBlockId>;
pub type AnsiIntermediateSubNodeTreeEntry = IntermediateSubNodeTreeEntry<AnsiBlockId>;

impl IntermediateTreeEntry for UnicodeIntermediateSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for UnicodeIntermediateSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 16;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let node = NodeId::from(f.read_u64::<LittleEndian>()? as u32);
        let block = UnicodeBlockId::read(f)?;
        Ok(Self::new(node, block))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u64::<LittleEndian>(u64::from(u32::from(self.node)))?;
        self.block.write(f)
    }
}

impl IntermediateTreeEntry for AnsiIntermediateSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for AnsiIntermediateSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let node = NodeId::read(f)?;
        let block = AnsiBlockId::read(f)?;
        Ok(Self::new(node, block))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.node.write(f)?;
        self.block.write(f)
    }
}

/// [SLBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5182eb24-4b0b-4816-aa3f-719cc6e6b018)
/// / [SIBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/729fb9bd-060a-4bbc-9b3b-8f014b487dad)
pub struct SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    header: Header,
    entries: Vec<Entry>,
    trailer: Trailer,
}

impl<Header, Entry, Trailer> SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    pub fn new(header: Header, entries: Vec<Entry>, trailer: Trailer) -> NdbResult<Self> {
        trailer.verify_block_id(true)?;

        Ok(Self {
            header,
            entries,
            trailer,
        })
    }
}

impl<Header, Entry, Trailer> IntermediateTreeBlock for SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    type Header = Header;
    type Entry = Entry;
    type Trailer = Trailer;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.entries
    }

    fn trailer(&self) -> &Trailer {
        &self.trailer
    }
}

impl<Header, Entry, Trailer> IntermediateTreeBlockReadWrite
    for SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeaderReadWrite,
    Entry: IntermediateTreeEntryReadWrite,
    Trailer: BlockTrailerReadWrite,
{
    fn new(header: Header, entries: Vec<Entry>, trailer: Trailer) -> NdbResult<Self> {
        Self::new(header, entries, trailer)
    }
}

pub type UnicodeIntermediateSubNodeTreeBlock = SubNodeTreeBlock<
    UnicodeSubNodeTreeBlockHeader,
    UnicodeIntermediateSubNodeTreeEntry,
    UnicodeBlockTrailer,
>;
pub type AnsiIntermediateSubNodeTreeBlock = SubNodeTreeBlock<
    AnsiSubNodeTreeBlockHeader,
    AnsiIntermediateSubNodeTreeEntry,
    AnsiBlockTrailer,
>;

pub type UnicodeLeafSubNodeTreeBlock = SubNodeTreeBlock<
    UnicodeSubNodeTreeBlockHeader,
    UnicodeLeafSubNodeTreeEntry,
    UnicodeBlockTrailer,
>;
pub type AnsiLeafSubNodeTreeBlock =
    SubNodeTreeBlock<AnsiSubNodeTreeBlockHeader, AnsiLeafSubNodeTreeEntry, AnsiBlockTrailer>;

pub enum SubNodeTree<Pst>
where
    Pst: PstFile,
{
    Intermediate(Box<<Pst as PstFile>::SubNodeTreeBlock>),
    Leaf(Box<<Pst as PstFile>::SubNodeBlock>),
}

impl<Pst> SubNodeTree<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::SubNodeTreeBlockHeader: IntermediateTreeHeaderReadWrite,
    <Pst as PstFile>::SubNodeTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::SubNodeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
{
    pub fn read<R: PstReader>(
        f: &mut R,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<Self> {
        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        let block_size = checked_block_size(
            block.size(),
            <<Pst as PstFile>::BlockTrailer as BlockTrailerReadWrite>::SIZE,
        )?;
        let mut data = vec![0; block_size as usize];
        f.read_exact(&mut data)?;
        let mut cursor = Cursor::new(data);
        let header =
            <<Pst as PstFile>::SubNodeTreeBlockHeader as IntermediateTreeHeaderReadWrite>::read(
                &mut cursor,
            )?;
        cursor.seek(SeekFrom::Start(0))?;

        if header.level() > 0 {
            let block =
                <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlockReadWrite>::read(
                    &mut cursor,
                    header,
                    block.size(),
                )?;
            Ok(Self::Intermediate(Box::new(block)))
        } else {
            let block = <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut cursor,
                header,
                block.size(),
            )?;
            Ok(Self::Leaf(Box::new(block)))
        }
    }

    pub fn write<W: Write + Seek>(
        &self,
        f: &mut W,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<()> {
        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        match self {
            Self::Intermediate(block) => block.write(f),
            Self::Leaf(block) => block.write(f),
        }
    }

    pub fn find_entry<R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        node: NodeId,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
    ) -> io::Result<<Pst as PstFile>::BlockId>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        self.find_entry_with_depth(f, block_btree, node, page_cache, 0)
    }

    fn find_entry_with_depth<R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        node: NodeId,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        depth: usize,
    ) -> io::Result<<Pst as PstFile>::BlockId>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block) => {
                if depth >= MAX_TREE_DEPTH {
                    return Err(NdbError::TreeTraversalDepthExceeded.into());
                }
                let parent_level = block.header().level();
                let entries = block.entries();
                let index =
                    entries.partition_point(|entry| u32::from(entry.node()) <= u32::from(node));
                let entry = index
                    .checked_sub(1)
                    .and_then(|index| entries.get(index))
                    .ok_or(NdbError::SubNodeNotFound(node))?;
                let block = block_btree.find_entry(f, entry.block().search_key(), page_cache)?;
                let page = Self::read(f, &block)?;
                if let Self::Intermediate(child) = &page {
                    if child.header().level() >= parent_level {
                        return Err(
                            NdbError::InvalidInternalBlockLevel(child.header().level()).into()
                        );
                    }
                }
                page.find_entry_with_depth(f, block_btree, node, page_cache, depth + 1)
            }
            Self::Leaf(block) => {
                let entry = block
                    .entries()
                    .iter()
                    .find(|entry| u32::from(entry.node()) == u32::from(node))
                    .map(|entry| entry.block())
                    .ok_or(NdbError::SubNodeNotFound(node))?;
                Ok(entry)
            }
        }
    }

    pub fn entries<'a, R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId:
            'a + BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        self.entries_with_depth(f, block_btree, page_cache, 0)
    }

    fn entries_with_depth<'a, R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        depth: usize,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId:
            'a + BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block) => {
                if depth >= MAX_TREE_DEPTH {
                    return Err(NdbError::TreeTraversalDepthExceeded.into());
                }
                let parent_level = block.header().level();
                let entries = block
                    .entries()
                    .iter()
                    .map(|entry| {
                        let block =
                            block_btree.find_entry(f, entry.block().search_key(), page_cache)?;
                        let sub_nodes = Self::read(f, &block)?;
                        if let Self::Intermediate(child) = &sub_nodes {
                            if child.header().level() >= parent_level {
                                return Err(NdbError::InvalidInternalBlockLevel(
                                    child.header().level(),
                                )
                                .into());
                            }
                        }
                        sub_nodes.entries_with_depth(f, block_btree, page_cache, depth + 1)
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                Ok(Box::new(entries.into_iter().flatten()))
            }
            Self::Leaf(block) => {
                let entries = block.entries().to_vec();
                Ok(Box::new(entries.into_iter()))
            }
        }
    }
}

pub type UnicodeSubNodeTree = SubNodeTree<UnicodePstFile>;
pub type AnsiSubNodeTree = SubNodeTree<AnsiPstFile>;

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn checked_block_size_accepts_exact_maximum() {
        assert_eq!(checked_block_size(8176, 16).unwrap(), MAX_BLOCK_SIZE);
    }

    #[test]
    fn checked_block_size_rejects_overflowing_metadata() {
        assert!(checked_block_size(8177, 16).is_err());
        assert!(checked_block_size(u16::MAX, u16::MAX).is_err());
    }

    #[test]
    fn bounded_read_never_materializes_beyond_limit() {
        let mut exact = Cursor::new(vec![0_u8; 8]);
        assert_eq!(read_to_end_bounded(&mut exact, 8).unwrap().len(), 8);

        let mut oversized = Cursor::new(vec![0_u8; 9]);
        let error = read_to_end_bounded(&mut oversized, 8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
