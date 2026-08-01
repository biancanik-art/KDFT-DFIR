//! Read-only WordprocessingML text extraction for DOCX evidence.
//!
//! This module never extracts package members to the filesystem. It assumes
//! these dependency APIs:
//!
//! ```toml
//! zip = { version = "2.4.2", default-features = false, features = ["deflate"] }
//! quick-xml = "0.41"
//! ```
//!
//! `max_segment_bytes` is a storage chunk size, not a total-work limit. The
//! parser creates as many segments as needed and always flushes the tail.

use quick_xml::encoding::Decoder;
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use quick_xml::XmlVersion;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::io::{self, BufReader, Read, Seek};
use zip::ZipArchive;

const CONTENT_TYPES_PART: &str = "[Content_Types].xml";
const MAIN_DOCUMENT_PART: &str = "word/document.xml";

const CONTENT_TYPES_NS: &[u8] = b"http://schemas.openxmlformats.org/package/2006/content-types";
const RELATIONSHIPS_NS: &[u8] = b"http://schemas.openxmlformats.org/package/2006/relationships";
const WORD_NS_TRANSITIONAL: &[u8] = b"http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const WORD_NS_STRICT: &[u8] = b"http://purl.oclc.org/ooxml/wordprocessingml/main";
const CORE_PROPERTIES_NS: &[u8] =
    b"http://schemas.openxmlformats.org/package/2006/metadata/core-properties";
const CUSTOM_PROPERTIES_NS: &[u8] =
    b"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties";
const CUSTOM_PROPERTIES_NS_STRICT: &[u8] =
    b"http://purl.oclc.org/ooxml/officeDocument/customProperties";
const EXTENDED_PROPERTIES_NS: &[u8] =
    b"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties";
const EXTENDED_PROPERTIES_NS_STRICT: &[u8] =
    b"http://purl.oclc.org/ooxml/officeDocument/extendedProperties";

const MAIN_DOCUMENT_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
const HEADER_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml";
const FOOTER_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml";
const FOOTNOTES_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml";
const ENDNOTES_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml";
const COMMENTS_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml";
const CORE_PROPERTIES_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-package.core-properties+xml";
const CUSTOM_PROPERTIES_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.custom-properties+xml";
const EXTENDED_PROPERTIES_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.extended-properties+xml";
const CUSTOM_XML_PROPERTIES_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.customXmlProperties+xml";
const RELATIONSHIPS_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.relationships+xml";

/// Default chunk size for parsed text. There is deliberately no total text
/// limit; a document larger than this produces multiple ordered segments.
pub const DEFAULT_MAX_SEGMENT_BYTES: usize = 64 * 1024;
/// Defensive package-structure bound. Crossing it is an explicit parse error,
/// never a successful partial result.
pub const DEFAULT_MAX_ARCHIVE_ENTRIES: usize = 16 * 1024;
/// Part names are retained for provenance and duplicate detection.
pub const DEFAULT_MAX_PART_NAME_BYTES: usize = 4 * 1024;
/// Maximum raw bytes in one XML lexical token before parsing aborts.
pub const DEFAULT_MAX_XML_TOKEN_BYTES: usize = 1024 * 1024;
/// Maximum Default/Override rules retained from `[Content_Types].xml`.
pub const DEFAULT_MAX_CONTENT_TYPE_RULES: usize = 4 * 1024;
/// Aggregate declared uncompressed package size accepted by default. This is
/// a protective ZIP-bomb failure threshold, not a successful parse cutoff.
pub const DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlParseOptions {
    pub max_segment_bytes: usize,
}

impl Default for OoxmlParseOptions {
    fn default() -> Self {
        Self {
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OoxmlPartKind {
    MainDocument,
    Header,
    Footer,
    Footnotes,
    Endnotes,
    Comments,
    CoreProperties,
    CustomProperties,
    ExtendedProperties,
    CustomXml,
    Relationships,
}

impl OoxmlPartKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MainDocument => "main_document",
            Self::Header => "header",
            Self::Footer => "footer",
            Self::Footnotes => "footnotes",
            Self::Endnotes => "endnotes",
            Self::Comments => "comments",
            Self::CoreProperties => "core_properties",
            Self::CustomProperties => "custom_properties",
            Self::ExtendedProperties => "extended_properties",
            Self::CustomXml => "custom_xml",
            Self::Relationships => "relationships",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::MainDocument => 0,
            Self::Header => 10,
            Self::Footer => 20,
            Self::Footnotes => 30,
            Self::Endnotes => 31,
            Self::Comments => 32,
            Self::CoreProperties => 40,
            Self::CustomProperties => 41,
            Self::ExtendedProperties => 42,
            Self::CustomXml => 43,
            Self::Relationships => 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlTextSegment {
    /// Monotonic across the whole parse result, after semantic part ordering.
    pub ordinal: usize,
    pub part_name: String,
    pub part_kind: OoxmlPartKind,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OoxmlUnsupportedReason {
    FormattingOrLayout,
    Media,
    EmbeddedObject,
    MacroOrActiveContent,
    PackageInfrastructure,
    PotentialTextContent,
    UnknownPart,
}

impl OoxmlUnsupportedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FormattingOrLayout => "formatting_or_layout",
            Self::Media => "media",
            Self::EmbeddedObject => "embedded_object",
            Self::MacroOrActiveContent => "macro_or_active_content",
            Self::PackageInfrastructure => "package_infrastructure",
            Self::PotentialTextContent => "potential_text_content",
            Self::UnknownPart => "unknown_part",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlUnsupportedPart {
    pub part_name: String,
    pub reason: OoxmlUnsupportedReason,
    /// True when the unparsed member could contain examiner-searchable text.
    pub may_contain_text: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OoxmlParseStats {
    pub archive_entries: usize,
    pub file_parts: usize,
    pub text_parts_selected: usize,
    pub text_parts_parsed: usize,
    pub segments_emitted: usize,
    pub text_bytes: u64,
    pub text_chars: u64,
    pub hyperlink_targets: usize,
    pub unsupported_parts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlParseResult {
    pub segments: Vec<OoxmlTextSegment>,
    pub stats: OoxmlParseStats,
    pub unsupported_parts: Vec<OoxmlUnsupportedPart>,
    /// False only when a disclosed unsupported member may itself contain text.
    pub supported_scope_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OoxmlErrorKind {
    InvalidOptions,
    InvalidZip,
    UnsafePartName,
    DuplicatePart,
    EncryptedPart,
    UnsupportedZipFeature,
    MissingContentTypes,
    InvalidContentTypes,
    NotWordprocessingDocument,
    MissingMainDocument,
    UnexpectedContentType,
    MalformedXml,
    InvalidRelationship,
    ZipBombSuspected,
    XmlTokenTooLarge,
    SinkFailure,
}

impl OoxmlErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidOptions => "invalid_options",
            Self::InvalidZip => "invalid_zip",
            Self::UnsafePartName => "unsafe_part_name",
            Self::DuplicatePart => "duplicate_part",
            Self::EncryptedPart => "encrypted_part",
            Self::UnsupportedZipFeature => "unsupported_zip_feature",
            Self::MissingContentTypes => "missing_content_types",
            Self::InvalidContentTypes => "invalid_content_types",
            Self::NotWordprocessingDocument => "not_wordprocessing_document",
            Self::MissingMainDocument => "missing_main_document",
            Self::UnexpectedContentType => "unexpected_content_type",
            Self::MalformedXml => "malformed_xml",
            Self::InvalidRelationship => "invalid_relationship",
            Self::ZipBombSuspected => "zip_bomb_suspected",
            Self::XmlTokenTooLarge => "xml_token_too_large",
            Self::SinkFailure => "sink_failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlParseError {
    pub kind: OoxmlErrorKind,
    pub part_name: Option<String>,
    pub message: String,
}

impl OoxmlParseError {
    fn new(
        kind: OoxmlErrorKind,
        part_name: Option<impl Into<String>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            part_name: part_name.map(Into::into),
            message: message.into(),
        }
    }

    fn package(kind: OoxmlErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, None::<String>, message)
    }

    fn part(kind: OoxmlErrorKind, part_name: &str, message: impl Into<String>) -> Self {
        Self::new(kind, Some(part_name), message)
    }
}

impl fmt::Display for OoxmlParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(part_name) = &self.part_name {
            write!(
                formatter,
                "OOXML {} error in {}: {}",
                self.kind.as_str(),
                part_name,
                self.message
            )
        } else {
            write!(
                formatter,
                "OOXML {} error: {}",
                self.kind.as_str(),
                self.message
            )
        }
    }
}

impl Error for OoxmlParseError {}

#[derive(Debug, Clone)]
struct ArchivePart {
    index: usize,
    name: String,
    compressed_size: u64,
    uncompressed_size: u64,
}

#[derive(Default)]
struct ContentTypes {
    defaults: HashMap<String, String>,
    overrides: HashMap<String, String>,
}

impl ContentTypes {
    fn for_part(&self, part_name: &str) -> Option<&str> {
        let absolute = format!("/{part_name}");
        self.overrides
            .get(&absolute)
            .map(String::as_str)
            .or_else(|| {
                let extension = part_name.rsplit_once('.')?.1.to_ascii_lowercase();
                self.defaults.get(&extension).map(String::as_str)
            })
    }
}

struct PartParseOutcome {
    segments: Vec<OoxmlTextSegment>,
    hyperlink_targets: usize,
}

/// Callback sink for streaming OOXML text extraction.
/// Segments are delivered in semantic part order. The sink
/// may return Err to abort parsing early.
pub trait OoxmlSink {
    type Error: fmt::Display;
    fn segment(&mut self, segment: &OoxmlTextSegment) -> Result<(), Self::Error>;
    fn unsupported_part(&mut self, part: &OoxmlUnsupportedPart) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlStreamOptions {
    pub max_segment_bytes: usize,
    /// Maximum declared uncompressed size for any single ZIP entry.
    /// Default: 256 MiB. Entries exceeding this are rejected as potential zip bombs.
    pub max_entry_uncompressed_bytes: u64,
    /// Maximum ratio of uncompressed/compressed size for any single entry.
    /// Default: 100. Entries exceeding this ratio are rejected.
    pub max_compression_ratio: u64,
    /// Maximum sum of declared uncompressed sizes across regular members.
    pub max_total_uncompressed_bytes: u64,
    /// Maximum ZIP members inventoried. This bounds provenance and duplicate
    /// detection memory; exceeding it is reported as a protective error.
    pub max_archive_entries: usize,
    /// Maximum UTF-8 byte length retained for a package member name.
    pub max_part_name_bytes: usize,
    /// Maximum bytes permitted in any individual XML lexical token.
    pub max_xml_token_bytes: usize,
    /// Maximum retained content-type rules.
    pub max_content_type_rules: usize,
}

impl Default for OoxmlStreamOptions {
    fn default() -> Self {
        Self {
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_entry_uncompressed_bytes: 256 * 1024 * 1024,
            max_compression_ratio: 100,
            max_total_uncompressed_bytes: DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES,
            max_archive_entries: DEFAULT_MAX_ARCHIVE_ENTRIES,
            max_part_name_bytes: DEFAULT_MAX_PART_NAME_BYTES,
            max_xml_token_bytes: DEFAULT_MAX_XML_TOKEN_BYTES,
            max_content_type_rules: DEFAULT_MAX_CONTENT_TYPE_RULES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OoxmlStreamResult {
    pub stats: OoxmlParseStats,
    pub supported_scope_complete: bool,
}

/// Compatibility sink for the legacy collecting API and unit tests. The case
/// ingestion path uses a transactional SQLite sink and never accumulates all
/// extracted segments or unsupported-part disclosures in memory.
struct LegacyCollectingSink {
    segments: Vec<OoxmlTextSegment>,
    unsupported_parts: Vec<OoxmlUnsupportedPart>,
}

impl OoxmlSink for LegacyCollectingSink {
    type Error = std::convert::Infallible;
    fn segment(&mut self, segment: &OoxmlTextSegment) -> Result<(), Self::Error> {
        self.segments.push(segment.clone());
        Ok(())
    }
    fn unsupported_part(&mut self, part: &OoxmlUnsupportedPart) -> Result<(), Self::Error> {
        self.unsupported_parts.push(part.clone());
        Ok(())
    }
}

/// Collecting compatibility API. New production ingestion should use
/// [`parse_docx_streaming`] with a bounded or durable sink.
pub fn parse_docx<R: Read + Seek>(reader: R) -> Result<OoxmlParseResult, OoxmlParseError> {
    parse_docx_with_options(reader, OoxmlParseOptions::default())
}

/// Collecting compatibility API with custom segment sizing. Package members
/// are never materialized as filesystem paths, but all emitted segments are
/// retained; new production ingestion should use [`parse_docx_streaming`].
pub fn parse_docx_with_options<R: Read + Seek>(
    reader: R,
    options: OoxmlParseOptions,
) -> Result<OoxmlParseResult, OoxmlParseError> {
    let stream_options = OoxmlStreamOptions {
        max_segment_bytes: options.max_segment_bytes,
        ..Default::default()
    };
    let mut sink = LegacyCollectingSink {
        segments: Vec::new(),
        unsupported_parts: Vec::new(),
    };
    let result = parse_docx_streaming(reader, stream_options, &mut sink)?;
    Ok(OoxmlParseResult {
        segments: sink.segments,
        stats: result.stats,
        unsupported_parts: sink.unsupported_parts,
        supported_scope_complete: result.supported_scope_complete,
    })
}

/// Legacy implementation
pub fn parse_docx_with_options_legacy<R: Read + Seek>(
    reader: R,
    options: OoxmlParseOptions,
) -> Result<OoxmlParseResult, OoxmlParseError> {
    if options.max_segment_bytes < 4 {
        return Err(OoxmlParseError::package(
            OoxmlErrorKind::InvalidOptions,
            "max_segment_bytes must be at least four so one UTF-8 scalar always fits",
        ));
    }

    let mut archive = ZipArchive::new(reader)
        .map_err(|error| OoxmlParseError::package(OoxmlErrorKind::InvalidZip, error.to_string()))?;
    let archive_entries = archive.len();
    let parts = inventory_archive(&mut archive)?;
    let file_parts = parts.len();

    let content_types_part = parts
        .iter()
        .find(|part| part.name == CONTENT_TYPES_PART)
        .ok_or_else(|| {
            OoxmlParseError::package(
                OoxmlErrorKind::MissingContentTypes,
                "package has no [Content_Types].xml part",
            )
        })?;
    let content_types = {
        let file = archive
            .by_index(content_types_part.index)
            .map_err(|error| zip_part_access_error(CONTENT_TYPES_PART, error))?;
        parse_content_types(file, CONTENT_TYPES_PART)?
    };

    let main_part = parts
        .iter()
        .find(|part| part.name == MAIN_DOCUMENT_PART)
        .ok_or_else(|| {
            OoxmlParseError::package(
                OoxmlErrorKind::MissingMainDocument,
                "package has no word/document.xml part",
            )
        })?;
    let main_content_type = content_types.for_part(&main_part.name).ok_or_else(|| {
        OoxmlParseError::part(
            OoxmlErrorKind::NotWordprocessingDocument,
            &main_part.name,
            "[Content_Types].xml does not assign a content type to the main part",
        )
    })?;
    if main_content_type != MAIN_DOCUMENT_CONTENT_TYPE {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::NotWordprocessingDocument,
            &main_part.name,
            format!(
                "main part content type is {main_content_type:?}, expected {MAIN_DOCUMENT_CONTENT_TYPE:?}"
            ),
        ));
    }

    let mut selected = parts
        .iter()
        .filter_map(|part| classify_supported_part(&part.name).map(|kind| (kind, part)))
        .collect::<Vec<_>>();
    selected.sort_by(|(left_kind, left), (right_kind, right)| {
        left_kind
            .priority()
            .cmp(&right_kind.priority())
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.index.cmp(&right.index))
    });

    let mut selected_indices = HashSet::new();
    selected_indices.insert(content_types_part.index);
    let mut all_segments = Vec::new();
    let mut hyperlink_targets = 0_usize;
    for (kind, part) in &selected {
        selected_indices.insert(part.index);
        validate_supported_part_content_type(&content_types, part, *kind)?;
        let file = archive
            .by_index(part.index)
            .map_err(|error| zip_part_access_error(&part.name, error))?;
        let outcome = parse_supported_part(file, &part.name, *kind, options.max_segment_bytes)?;
        hyperlink_targets = hyperlink_targets.saturating_add(outcome.hyperlink_targets);
        all_segments.extend(outcome.segments);
    }
    for (ordinal, segment) in all_segments.iter_mut().enumerate() {
        segment.ordinal = ordinal;
    }

    let unsupported_parts = parts
        .iter()
        .filter(|part| !selected_indices.contains(&part.index))
        .map(unsupported_part_disclosure)
        .collect::<Vec<_>>();
    let supported_scope_complete = unsupported_parts.iter().all(|part| !part.may_contain_text);
    let text_bytes = all_segments.iter().fold(0_u64, |total, segment| {
        total.saturating_add(segment.text.len() as u64)
    });
    let text_chars = all_segments.iter().fold(0_u64, |total, segment| {
        total.saturating_add(segment.text.chars().count() as u64)
    });
    let stats = OoxmlParseStats {
        archive_entries,
        file_parts,
        text_parts_selected: selected.len(),
        text_parts_parsed: selected.len(),
        segments_emitted: all_segments.len(),
        text_bytes,
        text_chars,
        hyperlink_targets,
        unsupported_parts: unsupported_parts.len(),
    };

    Ok(OoxmlParseResult {
        segments: all_segments,
        stats,
        unsupported_parts,
        supported_scope_complete,
    })
}

fn inventory_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<ArchivePart>, OoxmlParseError> {
    inventory_archive_with_limits(
        archive,
        DEFAULT_MAX_ARCHIVE_ENTRIES,
        DEFAULT_MAX_PART_NAME_BYTES,
    )
}

#[cfg(test)]
type CollectingSink = LegacyCollectingSink;

fn inventory_archive_with_limits<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    max_archive_entries: usize,
    max_part_name_bytes: usize,
) -> Result<Vec<ArchivePart>, OoxmlParseError> {
    if archive.len() > max_archive_entries {
        return Err(OoxmlParseError::package(
            OoxmlErrorKind::ZipBombSuspected,
            format!(
                "archive has {} entries, exceeding the protective limit of {max_archive_entries}",
                archive.len()
            ),
        ));
    }
    let mut parts = Vec::with_capacity(archive.len());
    let mut seen_names: HashMap<String, String> = HashMap::new();
    for index in 0..archive.len() {
        let file = archive.by_index_raw(index).map_err(|error| {
            OoxmlParseError::package(
                OoxmlErrorKind::InvalidZip,
                format!("could not inspect archive member {index}: {error}"),
            )
        })?;
        let name = file.name().to_string();
        if name.len() > max_part_name_bytes {
            let prefix_len = utf8_prefix_len(&name, max_part_name_bytes);
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::ZipBombSuspected,
                &name[..prefix_len],
                format!(
                    "package member name is {} bytes, exceeding the protective limit of {max_part_name_bytes}",
                    name.len()
                ),
            ));
        }
        validate_archive_part_name(&name, file.enclosed_name().is_some())?;
        if file.encrypted() {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::EncryptedPart,
                &name,
                "encrypted package members are not parsed without an examiner-supplied decryption workflow",
            ));
        }
        if file.is_dir() {
            continue;
        }
        if !file.is_file() {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::UnsafePartName,
                &name,
                "OOXML package contains a non-regular ZIP member",
            ));
        }
        let folded = name.to_ascii_lowercase();
        if let Some(previous) = seen_names.insert(folded, name.clone()) {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::DuplicatePart,
                &name,
                format!("part collides with earlier package member {previous:?}"),
            ));
        }
        parts.push(ArchivePart {
            index,
            name,
            compressed_size: file.compressed_size(),
            uncompressed_size: file.size(),
        });
    }
    Ok(parts)
}

fn validate_archive_part_name(name: &str, enclosed: bool) -> Result<(), OoxmlParseError> {
    // A trailing slash is the conventional representation of a directory
    // member. Validate the path components before inventory skips it.
    let components_name = name.strip_suffix('/').unwrap_or(name);
    let unsafe_name = components_name.is_empty()
        || !enclosed
        || name.contains('\0')
        || name.contains('\\')
        || name.starts_with('/')
        || components_name
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        || name.as_bytes().get(1).is_some_and(|second| *second == b':');
    if unsafe_name {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::UnsafePartName,
            name,
            "package member name is absolute, ambiguous, empty, or contains traversal syntax",
        ));
    }
    Ok(())
}

fn zip_part_access_error(part_name: &str, error: zip::result::ZipError) -> OoxmlParseError {
    let kind = match &error {
        zip::result::ZipError::UnsupportedArchive(_) => OoxmlErrorKind::UnsupportedZipFeature,
        _ => OoxmlErrorKind::InvalidZip,
    };
    OoxmlParseError::part(kind, part_name, error.to_string())
}

fn parse_content_types<R: Read>(
    input: R,
    part_name: &str,
) -> Result<ContentTypes, OoxmlParseError> {
    parse_content_types_with_limits(
        input,
        part_name,
        DEFAULT_MAX_XML_TOKEN_BYTES,
        DEFAULT_MAX_CONTENT_TYPE_RULES,
        DEFAULT_MAX_PART_NAME_BYTES,
    )
}

fn parse_content_types_with_limits<R: Read>(
    input: R,
    part_name: &str,
    max_xml_token_bytes: usize,
    max_content_type_rules: usize,
    max_rule_value_bytes: usize,
) -> Result<ContentTypes, OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut result = ContentTypes::default();
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut folded_overrides = HashSet::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        let opens_element = matches!(&event, Event::Start(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                if opens_element {
                    element_depth = element_depth.saturating_add(1);
                }
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if !root_seen {
                    if local != b"Types" || !namespace_matches(&namespace, &[CONTENT_TYPES_NS]) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidContentTypes,
                            part_name,
                            "root element is not package content-types Types",
                        ));
                    }
                    root_seen = true;
                } else if namespace_matches(&namespace, &[CONTENT_TYPES_NS]) && local == b"Default"
                {
                    let extension =
                        required_attribute(&start, b"Extension", reader.decoder(), part_name)?
                            .to_ascii_lowercase();
                    let content_type =
                        required_attribute(&start, b"ContentType", reader.decoder(), part_name)?;
                    validate_content_type_rule_value_lengths(
                        part_name,
                        &extension,
                        &content_type,
                        max_rule_value_bytes,
                    )?;
                    if extension.is_empty() || extension.contains('.') || extension.contains('/') {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidContentTypes,
                            part_name,
                            format!("invalid Default extension {extension:?}"),
                        ));
                    }
                    if result
                        .defaults
                        .insert(extension.clone(), content_type)
                        .is_some()
                    {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidContentTypes,
                            part_name,
                            format!("duplicate Default content type for extension {extension:?}"),
                        ));
                    }
                    if result.defaults.len().saturating_add(result.overrides.len())
                        > max_content_type_rules
                    {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::ZipBombSuspected,
                            part_name,
                            format!(
                                "content-type rule count exceeds the protective limit of {max_content_type_rules}"
                            ),
                        ));
                    }
                } else if namespace_matches(&namespace, &[CONTENT_TYPES_NS]) && local == b"Override"
                {
                    let override_name =
                        required_attribute(&start, b"PartName", reader.decoder(), part_name)?;
                    validate_override_part_name(&override_name, part_name)?;
                    let content_type =
                        required_attribute(&start, b"ContentType", reader.decoder(), part_name)?;
                    validate_content_type_rule_value_lengths(
                        part_name,
                        &override_name,
                        &content_type,
                        max_rule_value_bytes,
                    )?;
                    if !folded_overrides.insert(override_name.to_ascii_lowercase())
                        || result
                            .overrides
                            .insert(override_name.clone(), content_type)
                            .is_some()
                    {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidContentTypes,
                            part_name,
                            format!("duplicate or case-colliding Override for {override_name:?}"),
                        ));
                    }
                    if result.defaults.len().saturating_add(result.overrides.len())
                        > max_content_type_rules
                    {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::ZipBombSuspected,
                            part_name,
                            format!(
                                "content-type rule count exceeds the protective limit of {max_content_type_rules}"
                            ),
                        ));
                    }
                }
            }
            Event::End(_) => {
                if element_depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "content-types XML contains an unexpected closing element",
                    ));
                }
                element_depth -= 1;
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidContentTypes,
            part_name,
            "content-types XML is empty",
        ));
    }
    if element_depth != 0 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!("content-types XML ended with {element_depth} unclosed element(s)"),
        ));
    }
    Ok(result)
}

fn validate_content_type_rule_value_lengths(
    part_name: &str,
    key: &str,
    content_type: &str,
    max_rule_value_bytes: usize,
) -> Result<(), OoxmlParseError> {
    if key.len() > max_rule_value_bytes || content_type.len() > max_rule_value_bytes {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::ZipBombSuspected,
            part_name,
            format!(
                "content-type rule value exceeds the protective limit of {max_rule_value_bytes} bytes"
            ),
        ));
    }
    Ok(())
}

fn validate_override_part_name(
    override_name: &str,
    content_types_part: &str,
) -> Result<(), OoxmlParseError> {
    let Some(relative) = override_name.strip_prefix('/') else {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidContentTypes,
            content_types_part,
            format!("Override PartName is not absolute: {override_name:?}"),
        ));
    };
    if relative.is_empty()
        || relative.contains('\\')
        || relative.contains('\0')
        || relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidContentTypes,
            content_types_part,
            format!("unsafe Override PartName {override_name:?}"),
        ));
    }
    Ok(())
}

fn classify_supported_part(name: &str) -> Option<OoxmlPartKind> {
    if name == MAIN_DOCUMENT_PART {
        return Some(OoxmlPartKind::MainDocument);
    }
    if numbered_word_part(name, "word/header") {
        return Some(OoxmlPartKind::Header);
    }
    if numbered_word_part(name, "word/footer") {
        return Some(OoxmlPartKind::Footer);
    }
    match name {
        "word/footnotes.xml" => Some(OoxmlPartKind::Footnotes),
        "word/endnotes.xml" => Some(OoxmlPartKind::Endnotes),
        "word/comments.xml" => Some(OoxmlPartKind::Comments),
        "docProps/core.xml" => Some(OoxmlPartKind::CoreProperties),
        "docProps/custom.xml" => Some(OoxmlPartKind::CustomProperties),
        "docProps/app.xml" => Some(OoxmlPartKind::ExtendedProperties),
        _ if name.starts_with("customXml/")
            && name.ends_with(".xml")
            && !name.split('/').any(|component| component == "_rels") =>
        {
            Some(OoxmlPartKind::CustomXml)
        }
        _ if is_word_relationship_part(name) => Some(OoxmlPartKind::Relationships),
        _ => None,
    }
}

fn numbered_word_part(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_suffix(".xml"))
        .is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_word_relationship_part(name: &str) -> bool {
    name.starts_with("word/")
        && name.ends_with(".rels")
        && name.split('/').any(|component| component == "_rels")
}

fn expected_content_type(kind: OoxmlPartKind) -> &'static str {
    match kind {
        OoxmlPartKind::MainDocument => MAIN_DOCUMENT_CONTENT_TYPE,
        OoxmlPartKind::Header => HEADER_CONTENT_TYPE,
        OoxmlPartKind::Footer => FOOTER_CONTENT_TYPE,
        OoxmlPartKind::Footnotes => FOOTNOTES_CONTENT_TYPE,
        OoxmlPartKind::Endnotes => ENDNOTES_CONTENT_TYPE,
        OoxmlPartKind::Comments => COMMENTS_CONTENT_TYPE,
        OoxmlPartKind::CoreProperties => CORE_PROPERTIES_CONTENT_TYPE,
        OoxmlPartKind::CustomProperties => CUSTOM_PROPERTIES_CONTENT_TYPE,
        OoxmlPartKind::ExtendedProperties => EXTENDED_PROPERTIES_CONTENT_TYPE,
        OoxmlPartKind::CustomXml => "application/xml",
        OoxmlPartKind::Relationships => RELATIONSHIPS_CONTENT_TYPE,
    }
}

fn validate_supported_part_content_type(
    content_types: &ContentTypes,
    part: &ArchivePart,
    kind: OoxmlPartKind,
) -> Result<(), OoxmlParseError> {
    let actual = content_types.for_part(&part.name);
    let valid = if kind == OoxmlPartKind::CustomXml {
        matches!(
            actual,
            Some("application/xml" | "text/xml") | Some(CUSTOM_XML_PROPERTIES_CONTENT_TYPE)
        ) || actual.is_some_and(|value| value.ends_with("+xml"))
    } else {
        actual == Some(expected_content_type(kind))
    };
    if !valid {
        let expected = if kind == OoxmlPartKind::CustomXml {
            "an XML content type"
        } else {
            expected_content_type(kind)
        };
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::UnexpectedContentType,
            &part.name,
            format!("content type is {actual:?}, expected {expected:?}"),
        ));
    }
    Ok(())
}

fn parse_supported_part<R: Read>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
) -> Result<PartParseOutcome, OoxmlParseError> {
    match kind {
        OoxmlPartKind::MainDocument
        | OoxmlPartKind::Header
        | OoxmlPartKind::Footer
        | OoxmlPartKind::Footnotes
        | OoxmlPartKind::Endnotes
        | OoxmlPartKind::Comments => {
            let segments = parse_word_part(input, part_name, kind, max_segment_bytes)?;
            Ok(PartParseOutcome {
                segments,
                hyperlink_targets: 0,
            })
        }
        OoxmlPartKind::CoreProperties
        | OoxmlPartKind::CustomProperties
        | OoxmlPartKind::ExtendedProperties => {
            let segments = parse_property_part(input, part_name, kind, max_segment_bytes)?;
            Ok(PartParseOutcome {
                segments,
                hyperlink_targets: 0,
            })
        }
        OoxmlPartKind::CustomXml => {
            let segments = parse_generic_xml_part(input, part_name, kind, max_segment_bytes)?;
            Ok(PartParseOutcome {
                segments,
                hyperlink_targets: 0,
            })
        }
        OoxmlPartKind::Relationships => {
            parse_relationship_part(input, part_name, kind, max_segment_bytes)
        }
    }
}

/// Extract searchable values from arbitrary custom XML without interpreting
/// its application-specific schema. Element names, attribute names/values,
/// text, and CDATA are retained in document order. Namespace declarations are
/// package syntax rather than evidence values and are omitted.
fn parse_generic_xml_part<R: Read>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
) -> Result<Vec<OoxmlTextSegment>, OoxmlParseError> {
    let mut reader = NsReader::from_reader(BufReader::new(input));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = Segmenter::new(part_name, kind, max_segment_bytes);
    let mut root_seen = false;
    let mut pending_text = String::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        match event {
            Event::Start(start) | Event::Empty(start) => {
                flush_generic_text(&mut segmenter, &mut pending_text);
                root_seen = true;
                append_generic_xml_element(&mut segmenter, &start, reader.decoder(), part_name)?;
            }
            Event::Text(value) => {
                pending_text.push_str(&decode_xml_text(&value, part_name)?);
            }
            Event::GeneralRef(reference) => {
                pending_text.push_str(&decode_xml_reference(&reference, part_name)?);
            }
            Event::CData(value) => {
                let decoded = value
                    .decode()
                    .map_err(|error| xml_error(part_name, error))?;
                pending_text.push_str(&decoded);
            }
            Event::End(_) => flush_generic_text(&mut segmenter, &mut pending_text),
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => {
                flush_generic_text(&mut segmenter, &mut pending_text);
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "custom XML part is empty",
        ));
    }
    Ok(segmenter.finish())
}

fn append_generic_xml_element(
    segmenter: &mut Segmenter,
    start: &BytesStart<'_>,
    decoder: Decoder,
    part_name: &str,
) -> Result<(), OoxmlParseError> {
    let element_name = start.name();
    let element = decoder
        .decode(element_name.as_ref())
        .map_err(|error| xml_error(part_name, error))?;
    segmenter.append("element: ");
    segmenter.append(&element);
    segmenter.separator('\n');
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| xml_error(part_name, error))?;
        let key = attribute.key.as_ref();
        if key == b"xmlns" || key.starts_with(b"xmlns:") {
            continue;
        }
        let key = decoder
            .decode(key)
            .map_err(|error| xml_error(part_name, error))?;
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|error| xml_error(part_name, error))?;
        segmenter.append("attribute ");
        segmenter.append(&key);
        segmenter.append(": ");
        segmenter.append(&value);
        segmenter.separator('\n');
    }
    Ok(())
}

fn expected_word_root(kind: OoxmlPartKind) -> &'static [u8] {
    match kind {
        OoxmlPartKind::MainDocument => b"document",
        OoxmlPartKind::Header => b"hdr",
        OoxmlPartKind::Footer => b"ftr",
        OoxmlPartKind::Footnotes => b"footnotes",
        OoxmlPartKind::Endnotes => b"endnotes",
        OoxmlPartKind::Comments => b"comments",
        _ => b"",
    }
}

fn parse_word_part<R: Read>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
) -> Result<Vec<OoxmlTextSegment>, OoxmlParseError> {
    let mut reader = NsReader::from_reader(BufReader::new(input));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = Segmenter::new(part_name, kind, max_segment_bytes);
    let mut root_seen = false;
    let mut text_depth = 0_usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        match event {
            Event::Start(start) => {
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                let is_word =
                    namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]);
                if !root_seen {
                    if !is_word || local != expected_word_root(kind) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            format!(
                                "root element is not the expected WordprocessingML {:?} element",
                                String::from_utf8_lossy(expected_word_root(kind))
                            ),
                        ));
                    }
                    root_seen = true;
                }
                if is_word {
                    if is_word_text_element(local) {
                        text_depth = text_depth.saturating_add(1);
                    }
                    append_word_record_prefix(
                        &mut segmenter,
                        &start,
                        local,
                        reader.decoder(),
                        part_name,
                    )?;
                }
            }
            Event::Empty(empty) => {
                let qname = empty.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]) {
                    append_word_empty_element(
                        &mut segmenter,
                        &empty,
                        local,
                        reader.decoder(),
                        part_name,
                    )?;
                }
            }
            Event::End(end) => {
                let qname = end.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]) {
                    if is_word_text_element(local) {
                        text_depth = text_depth.saturating_sub(1);
                    }
                    match local {
                        b"tc" => segmenter.separator('\t'),
                        b"p" | b"tr" | b"comment" | b"footnote" | b"endnote" => {
                            segmenter.separator('\n')
                        }
                        _ => {}
                    }
                }
            }
            Event::Text(text) if text_depth > 0 => {
                let decoded = decode_xml_text(&text, part_name)?;
                segmenter.append(&decoded);
            }
            Event::GeneralRef(reference) if text_depth > 0 => {
                segmenter.append(&decode_xml_reference(&reference, part_name)?);
            }
            Event::CData(text) if text_depth > 0 => {
                let decoded = text.decode().map_err(|error| xml_error(part_name, error))?;
                segmenter.append(&decoded);
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "WordprocessingML part is empty",
        ));
    }
    Ok(segmenter.finish())
}

fn is_word_text_element(local: &[u8]) -> bool {
    matches!(local, b"t" | b"delText" | b"instrText")
}

fn append_word_record_prefix(
    segmenter: &mut Segmenter,
    start: &BytesStart<'_>,
    local: &[u8],
    decoder: Decoder,
    part_name: &str,
) -> Result<(), OoxmlParseError> {
    match local {
        b"comment" => {
            segmenter.separator('\n');
            let id = optional_attribute(start, b"id", decoder, part_name)?;
            let author = optional_attribute(start, b"author", decoder, part_name)?;
            let date = optional_attribute(start, b"date", decoder, part_name)?;
            segmenter.append("[comment");
            append_labeled_attribute(segmenter, "id", id.as_deref());
            append_labeled_attribute(segmenter, "author", author.as_deref());
            append_labeled_attribute(segmenter, "date", date.as_deref());
            segmenter.append("] ");
        }
        b"footnote" | b"endnote" => {
            segmenter.separator('\n');
            let id = optional_attribute(start, b"id", decoder, part_name)?;
            segmenter.append(if local == b"footnote" {
                "[footnote"
            } else {
                "[endnote"
            });
            append_labeled_attribute(segmenter, "id", id.as_deref());
            segmenter.append("] ");
        }
        _ => {}
    }
    Ok(())
}

fn append_labeled_attribute(segmenter: &mut Segmenter, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        segmenter.append(" ");
        segmenter.append(label);
        segmenter.append("=");
        segmenter.append(value);
    }
}

fn append_word_empty_element(
    segmenter: &mut Segmenter,
    empty: &BytesStart<'_>,
    local: &[u8],
    decoder: Decoder,
    part_name: &str,
) -> Result<(), OoxmlParseError> {
    match local {
        b"tab" | b"ptab" => segmenter.separator('\t'),
        b"br" | b"cr" => segmenter.separator('\n'),
        b"noBreakHyphen" => segmenter.append("\u{2011}"),
        b"softHyphen" => segmenter.append("\u{00ad}"),
        b"sym" => {
            if let Some(value) = optional_attribute(empty, b"char", decoder, part_name)? {
                let value = value.trim_start_matches("0x");
                let scalar = u32::from_str_radix(value, 16).map_err(|_| {
                    OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        format!("invalid w:sym hexadecimal character {value:?}"),
                    )
                })?;
                let character = char::from_u32(scalar).ok_or_else(|| {
                    OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        format!("w:sym value is not a Unicode scalar: {value:?}"),
                    )
                })?;
                segmenter.append(&character.to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_property_part<R: Read>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
) -> Result<Vec<OoxmlTextSegment>, OoxmlParseError> {
    let mut reader = NsReader::from_reader(BufReader::new(input));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = Segmenter::new(part_name, kind, max_segment_bytes);
    let mut root_seen = false;
    let mut depth = 0_usize;
    let mut property: Option<(usize, String, bool)> = None;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        match event {
            Event::Start(start) => {
                depth = depth.saturating_add(1);
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if !root_seen {
                    if !property_root_matches(kind, namespace, local) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "property part has an unexpected root element or namespace",
                        ));
                    }
                    root_seen = true;
                } else if property.is_none() {
                    let label = if kind == OoxmlPartKind::CustomProperties && local == b"property" {
                        required_attribute(&start, b"name", reader.decoder(), part_name)?
                    } else if depth == 2 {
                        String::from_utf8_lossy(local).into_owned()
                    } else {
                        String::new()
                    };
                    if !label.is_empty() {
                        property = Some((depth, label, false));
                    }
                }
            }
            Event::Empty(start) => {
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                if !root_seen {
                    if !property_root_matches(kind, namespace, local_name.as_ref()) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "property part has an unexpected empty root element",
                        ));
                    }
                    root_seen = true;
                }
            }
            Event::Text(text) => {
                if let Some((_, label, emitted)) = property.as_mut() {
                    let decoded = decode_xml_text(&text, part_name)?;
                    if !decoded.chars().all(char::is_whitespace) {
                        if !*emitted {
                            segmenter.append(label);
                            segmenter.append(": ");
                            *emitted = true;
                        }
                        segmenter.append(&decoded);
                    }
                }
            }
            Event::GeneralRef(reference) => {
                if let Some((_, label, emitted)) = property.as_mut() {
                    let decoded = decode_xml_reference(&reference, part_name)?;
                    if !decoded.chars().all(char::is_whitespace) {
                        if !*emitted {
                            segmenter.append(label);
                            segmenter.append(": ");
                            *emitted = true;
                        }
                        segmenter.append(&decoded);
                    }
                }
            }
            Event::CData(text) => {
                if let Some((_, label, emitted)) = property.as_mut() {
                    let decoded = text.decode().map_err(|error| xml_error(part_name, error))?;
                    if !decoded.chars().all(char::is_whitespace) {
                        if !*emitted {
                            segmenter.append(label);
                            segmenter.append(": ");
                            *emitted = true;
                        }
                        segmenter.append(&decoded);
                    }
                }
            }
            Event::End(_) => {
                if property
                    .as_ref()
                    .is_some_and(|(property_depth, _, _)| *property_depth == depth)
                {
                    if let Some((_, _, emitted)) = property.take() {
                        if emitted {
                            segmenter.separator('\n');
                        }
                    }
                }
                depth = depth.saturating_sub(1);
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "property XML part is empty",
        ));
    }
    Ok(segmenter.finish())
}

fn property_root_matches(kind: OoxmlPartKind, namespace: ResolveResult<'_>, local: &[u8]) -> bool {
    match kind {
        OoxmlPartKind::CoreProperties => {
            local == b"coreProperties" && namespace_matches(&namespace, &[CORE_PROPERTIES_NS])
        }
        OoxmlPartKind::CustomProperties => {
            local == b"Properties"
                && namespace_matches(
                    &namespace,
                    &[CUSTOM_PROPERTIES_NS, CUSTOM_PROPERTIES_NS_STRICT],
                )
        }
        OoxmlPartKind::ExtendedProperties => {
            local == b"Properties"
                && namespace_matches(
                    &namespace,
                    &[EXTENDED_PROPERTIES_NS, EXTENDED_PROPERTIES_NS_STRICT],
                )
        }
        _ => false,
    }
}

fn parse_relationship_part<R: Read>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
) -> Result<PartParseOutcome, OoxmlParseError> {
    let mut reader = NsReader::from_reader(BufReader::new(input));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = Segmenter::new(part_name, kind, max_segment_bytes);
    let mut root_seen = false;
    let mut hyperlink_targets = 0_usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                let is_relationship_ns = namespace_matches(&namespace, &[RELATIONSHIPS_NS]);
                if !root_seen {
                    if local != b"Relationships" || !is_relationship_ns {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "relationship part has an unexpected root element or namespace",
                        ));
                    }
                    root_seen = true;
                } else if is_relationship_ns && local == b"Relationship" {
                    let relation_type =
                        required_attribute(&start, b"Type", reader.decoder(), part_name)?;
                    if relation_type.ends_with("/hyperlink") {
                        let target =
                            required_attribute(&start, b"Target", reader.decoder(), part_name)?;
                        let id = optional_attribute(&start, b"Id", reader.decoder(), part_name)?;
                        let mode =
                            optional_attribute(&start, b"TargetMode", reader.decoder(), part_name)?;
                        if target.is_empty() {
                            return Err(OoxmlParseError::part(
                                OoxmlErrorKind::InvalidRelationship,
                                part_name,
                                "hyperlink relationship has an empty Target",
                            ));
                        }
                        segmenter.append("hyperlink");
                        append_labeled_attribute(&mut segmenter, "id", id.as_deref());
                        append_labeled_attribute(&mut segmenter, "mode", mode.as_deref());
                        segmenter.append(": ");
                        segmenter.append(&target);
                        segmenter.separator('\n');
                        hyperlink_targets = hyperlink_targets.saturating_add(1);
                    }
                }
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "relationship XML part is empty",
        ));
    }
    Ok(PartParseOutcome {
        segments: segmenter.finish(),
        hyperlink_targets,
    })
}

fn unsupported_part_disclosure(part: &ArchivePart) -> OoxmlUnsupportedPart {
    let lower = part.name.to_ascii_lowercase();
    let (reason, may_contain_text) = if lower.contains("vbaproject")
        || lower.ends_with(".vba")
        || lower.starts_with("word/activex/")
    {
        (OoxmlUnsupportedReason::MacroOrActiveContent, true)
    } else if lower.starts_with("word/media/") || lower.starts_with("docprops/thumbnail") {
        (OoxmlUnsupportedReason::Media, false)
    } else if lower.starts_with("word/embeddings/") {
        (OoxmlUnsupportedReason::EmbeddedObject, true)
    } else if lower.starts_with("word/theme/")
        || matches!(
            lower.as_str(),
            "word/styles.xml"
                | "word/styleswitheffects.xml"
                | "word/numbering.xml"
                | "word/settings.xml"
                | "word/fonttable.xml"
                | "word/websettings.xml"
        )
    {
        (OoxmlUnsupportedReason::FormattingOrLayout, false)
    } else if lower.starts_with("_rels/")
        || lower.starts_with("docprops/")
        || lower.ends_with(".rels")
    {
        (OoxmlUnsupportedReason::PackageInfrastructure, false)
    } else if lower.starts_with("customxml/")
        || lower.contains("altchunk")
        || lower.contains("afchunk")
        || lower.ends_with(".xml")
        || lower.ends_with(".html")
        || lower.ends_with(".htm")
        || lower.ends_with(".rtf")
        || lower.ends_with(".txt")
    {
        (OoxmlUnsupportedReason::PotentialTextContent, true)
    } else {
        (OoxmlUnsupportedReason::UnknownPart, false)
    };
    OoxmlUnsupportedPart {
        part_name: part.name.clone(),
        reason,
        may_contain_text,
        compressed_size: part.compressed_size,
        uncompressed_size: part.uncompressed_size,
    }
}

fn namespace_matches(namespace: &ResolveResult<'_>, accepted: &[&[u8]]) -> bool {
    match namespace {
        ResolveResult::Bound(Namespace(value)) => accepted.contains(value),
        ResolveResult::Unbound | ResolveResult::Unknown(_) => false,
    }
}

fn required_attribute(
    start: &BytesStart<'_>,
    local_name: &[u8],
    decoder: Decoder,
    part_name: &str,
) -> Result<String, OoxmlParseError> {
    optional_attribute(start, local_name, decoder, part_name)?.ok_or_else(|| {
        OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!(
                "element {:?} is missing required attribute {:?}",
                String::from_utf8_lossy(start.name().as_ref()),
                String::from_utf8_lossy(local_name)
            ),
        )
    })
}

fn optional_attribute(
    start: &BytesStart<'_>,
    local_name: &[u8],
    decoder: Decoder,
    part_name: &str,
) -> Result<Option<String>, OoxmlParseError> {
    let mut value = None;
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| xml_error(part_name, error))?;
        if attribute.key.local_name().as_ref() != local_name {
            continue;
        }
        if value.is_some() {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::MalformedXml,
                part_name,
                format!(
                    "element {:?} repeats attribute local name {:?}",
                    String::from_utf8_lossy(start.name().as_ref()),
                    String::from_utf8_lossy(local_name)
                ),
            ));
        }
        value = Some(
            attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
                .map_err(|error| xml_error(part_name, error))?
                .into_owned(),
        );
    }
    Ok(value)
}

const XML_TOKEN_LIMIT_SENTINEL: &str = "kdft_xml_token_limit_exceeded";

#[derive(Debug)]
enum XmlLexicalState {
    Text,
    UnknownMarkup {
        prefix: [u8; 9],
        len: usize,
    },
    Tag {
        quote: Option<u8>,
    },
    Comment {
        tail: [u8; 2],
    },
    Cdata {
        tail: [u8; 2],
    },
    ProcessingInstruction {
        previous: u8,
    },
    Doctype {
        quote: Option<u8>,
        subset_depth: usize,
    },
}

/// Limits the raw bytes quick-xml can retain for one lexical token. This sits
/// below quick-xml's event buffer, so an adversarial text node, attribute,
/// comment, CDATA section, processing instruction, or DOCTYPE cannot make the
/// parser grow an event buffer without bound.
struct XmlTokenLimitReader<R> {
    inner: R,
    max_token_bytes: usize,
    token_bytes: usize,
    state: XmlLexicalState,
}

impl<R> XmlTokenLimitReader<R> {
    fn new(inner: R, max_token_bytes: usize) -> Self {
        Self {
            inner,
            max_token_bytes,
            token_bytes: 0,
            state: XmlLexicalState::Text,
        }
    }

    fn consume(&mut self, byte: u8) -> io::Result<()> {
        if matches!(self.state, XmlLexicalState::Text) && byte == b'<' {
            let mut prefix = [0_u8; 9];
            prefix[0] = byte;
            self.state = XmlLexicalState::UnknownMarkup { prefix, len: 1 };
            self.token_bytes = 1;
            return self.enforce_limit();
        }

        self.token_bytes = self.token_bytes.saturating_add(1);
        self.enforce_limit()?;
        if matches!(self.state, XmlLexicalState::Text) {
            return Ok(());
        }

        let state = std::mem::replace(&mut self.state, XmlLexicalState::Text);
        match Self::advance_markup(state, byte) {
            Some(state) => self.state = state,
            None => self.token_bytes = 0,
        }
        Ok(())
    }

    fn enforce_limit(&self) -> io::Result<()> {
        if self.token_bytes <= self.max_token_bytes {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{XML_TOKEN_LIMIT_SENTINEL}: XML lexical token exceeds the protective limit of {} bytes",
                self.max_token_bytes
            ),
        ))
    }

    fn advance_markup(state: XmlLexicalState, byte: u8) -> Option<XmlLexicalState> {
        match state {
            XmlLexicalState::Text => Some(XmlLexicalState::Text),
            XmlLexicalState::UnknownMarkup {
                mut prefix,
                mut len,
            } => {
                if len < prefix.len() {
                    prefix[len] = byte;
                    len += 1;
                }
                let candidate = &prefix[..len];
                if candidate == b"<?" {
                    return Some(XmlLexicalState::ProcessingInstruction { previous: 0 });
                }
                if candidate == b"<!--" {
                    return Some(XmlLexicalState::Comment { tail: [0, 0] });
                }
                if candidate == b"<![CDATA[" {
                    return Some(XmlLexicalState::Cdata { tail: [0, 0] });
                }
                if candidate == b"<!DOCTYPE" {
                    return Some(XmlLexicalState::Doctype {
                        quote: None,
                        subset_depth: 0,
                    });
                }
                let remains_special = [b"<?".as_slice(), b"<!--", b"<![CDATA[", b"<!DOCTYPE"]
                    .iter()
                    .any(|special| special.starts_with(candidate));
                if remains_special {
                    return Some(XmlLexicalState::UnknownMarkup { prefix, len });
                }
                Self::advance_markup(XmlLexicalState::Tag { quote: None }, byte)
            }
            XmlLexicalState::Tag { mut quote } => {
                if let Some(expected) = quote {
                    if byte == expected {
                        quote = None;
                    }
                    Some(XmlLexicalState::Tag { quote })
                } else if matches!(byte, b'\'' | b'"') {
                    Some(XmlLexicalState::Tag { quote: Some(byte) })
                } else if byte == b'>' {
                    None
                } else {
                    Some(XmlLexicalState::Tag { quote: None })
                }
            }
            XmlLexicalState::Comment { tail } => {
                if tail == *b"--" && byte == b'>' {
                    None
                } else {
                    Some(XmlLexicalState::Comment {
                        tail: [tail[1], byte],
                    })
                }
            }
            XmlLexicalState::Cdata { tail } => {
                if tail == *b"]]" && byte == b'>' {
                    None
                } else {
                    Some(XmlLexicalState::Cdata {
                        tail: [tail[1], byte],
                    })
                }
            }
            XmlLexicalState::ProcessingInstruction { previous } => {
                if previous == b'?' && byte == b'>' {
                    None
                } else {
                    Some(XmlLexicalState::ProcessingInstruction { previous: byte })
                }
            }
            XmlLexicalState::Doctype {
                mut quote,
                mut subset_depth,
            } => {
                if let Some(expected) = quote {
                    if byte == expected {
                        quote = None;
                    }
                } else {
                    match byte {
                        b'\'' | b'"' => quote = Some(byte),
                        b'[' => subset_depth = subset_depth.saturating_add(1),
                        b']' => subset_depth = subset_depth.saturating_sub(1),
                        b'>' if subset_depth == 0 => return None,
                        _ => {}
                    }
                }
                Some(XmlLexicalState::Doctype {
                    quote,
                    subset_depth,
                })
            }
        }
    }
}

impl<R: Read> Read for XmlTokenLimitReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        for byte in buffer[..read].iter().copied() {
            self.consume(byte)?;
        }
        Ok(read)
    }
}

fn xml_error(part_name: &str, error: impl fmt::Display) -> OoxmlParseError {
    let message = error.to_string();
    let kind = if message.contains(XML_TOKEN_LIMIT_SENTINEL) {
        OoxmlErrorKind::XmlTokenTooLarge
    } else {
        OoxmlErrorKind::MalformedXml
    };
    OoxmlParseError::part(kind, part_name, message)
}

fn decode_xml_text(text: &BytesText<'_>, part_name: &str) -> Result<String, OoxmlParseError> {
    text.xml10_content()
        .map(|value| value.into_owned())
        .map_err(|error| xml_error(part_name, error))
}

fn decode_xml_reference(
    reference: &BytesRef<'_>,
    part_name: &str,
) -> Result<String, OoxmlParseError> {
    if let Some(value) = reference
        .resolve_char_ref()
        .map_err(|error| xml_error(part_name, error))?
    {
        return Ok(value.to_string());
    }
    let name = reference
        .decode()
        .map_err(|error| xml_error(part_name, error))?;
    resolve_xml_entity(&name).map(str::to_owned).ok_or_else(|| {
        OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!("unsupported XML entity reference &{name};"),
        )
    })
}

fn doctype_error(part_name: &str) -> OoxmlParseError {
    OoxmlParseError::part(
        OoxmlErrorKind::MalformedXml,
        part_name,
        "DOCTYPE declarations are rejected; OOXML parts must not depend on external or custom entities",
    )
}

struct Segmenter {
    part_name: String,
    part_kind: OoxmlPartKind,
    max_bytes: usize,
    current: String,
    segments: Vec<OoxmlTextSegment>,
    last_char: Option<char>,
}

impl Segmenter {
    fn new(part_name: &str, part_kind: OoxmlPartKind, max_bytes: usize) -> Self {
        Self {
            part_name: part_name.to_string(),
            part_kind,
            max_bytes,
            current: String::new(),
            segments: Vec::new(),
            last_char: None,
        }
    }

    fn append(&mut self, mut text: &str) {
        if text.is_empty() {
            return;
        }
        self.last_char = text.chars().next_back();
        while !text.is_empty() {
            if self.current.len() == self.max_bytes {
                self.flush();
            }
            let capacity = self.max_bytes - self.current.len();
            let split = utf8_prefix_len(text, capacity);
            if split == 0 {
                self.flush();
                continue;
            }
            self.current.push_str(&text[..split]);
            text = &text[split..];
            if self.current.len() == self.max_bytes {
                self.flush();
            }
        }
    }

    fn separator(&mut self, separator: char) {
        if self.last_char == Some(separator) {
            return;
        }
        let mut encoded = [0_u8; 4];
        self.append(separator.encode_utf8(&mut encoded));
    }

    fn flush(&mut self) {
        if self.current.is_empty() {
            return;
        }
        self.segments.push(OoxmlTextSegment {
            ordinal: 0,
            part_name: self.part_name.clone(),
            part_kind: self.part_kind,
            text: std::mem::take(&mut self.current),
        });
    }

    fn finish(mut self) -> Vec<OoxmlTextSegment> {
        self.flush();
        self.segments
    }
}

fn flush_generic_text(segmenter: &mut Segmenter, pending: &mut String) {
    if !pending.chars().all(char::is_whitespace) {
        segmenter.append(pending);
        segmenter.separator('\n');
    }
    pending.clear();
}

fn utf8_prefix_len(text: &str, max_bytes: usize) -> usize {
    if text.len() <= max_bytes {
        return text.len();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

// --- STREAMING API IMPLEMENTATION ---

pub fn parse_docx_streaming<R: Read + Seek, S: OoxmlSink>(
    mut reader: R,
    options: OoxmlStreamOptions,
    sink: &mut S,
) -> Result<OoxmlStreamResult, OoxmlParseError> {
    if options.max_segment_bytes < 4 {
        return Err(OoxmlParseError::package(
            OoxmlErrorKind::InvalidOptions,
            "max_segment_bytes must be at least four so one UTF-8 scalar always fits",
        ));
    }
    if options.max_entry_uncompressed_bytes == 0
        || options.max_compression_ratio == 0
        || options.max_total_uncompressed_bytes == 0
        || options.max_archive_entries == 0
        || options.max_part_name_bytes == 0
        || options.max_xml_token_bytes == 0
        || options.max_content_type_rules == 0
    {
        return Err(OoxmlParseError::package(
            OoxmlErrorKind::InvalidOptions,
            "all OOXML protective limits must be greater than zero",
        ));
    }

    let mut archive = ZipArchive::new(&mut reader)
        .map_err(|error| OoxmlParseError::package(OoxmlErrorKind::InvalidZip, error.to_string()))?;
    let archive_entries = archive.len();
    let parts = inventory_archive_with_limits(
        &mut archive,
        options.max_archive_entries,
        options.max_part_name_bytes,
    )?;
    let file_parts = parts.len();

    // The package inventory, semantic selection vector, and duplicate/index
    // maps are all bounded by max_archive_entries. Extracted text is not held
    // here; it is delivered one bounded segment at a time to the caller sink.
    let mut total_uncompressed_bytes = 0_u64;
    for part in &parts {
        total_uncompressed_bytes = total_uncompressed_bytes
            .checked_add(part.uncompressed_size)
            .ok_or_else(|| {
                OoxmlParseError::part(
                    OoxmlErrorKind::ZipBombSuspected,
                    &part.name,
                    "aggregate declared uncompressed ZIP size overflows u64",
                )
            })?;
        if total_uncompressed_bytes > options.max_total_uncompressed_bytes {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::ZipBombSuspected,
                &part.name,
                format!(
                    "aggregate declared uncompressed size exceeds {} bytes",
                    options.max_total_uncompressed_bytes
                ),
            ));
        }
        if part.uncompressed_size > options.max_entry_uncompressed_bytes {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::ZipBombSuspected,
                &part.name,
                format!(
                    "uncompressed size exceeds {} bytes",
                    options.max_entry_uncompressed_bytes
                ),
            ));
        }
        if part.compressed_size == 0 && part.uncompressed_size > 0 {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::ZipBombSuspected,
                &part.name,
                "non-empty ZIP member declares a zero compressed size",
            ));
        }
        if part.compressed_size > 0
            && part.uncompressed_size
                > part
                    .compressed_size
                    .saturating_mul(options.max_compression_ratio)
        {
            return Err(OoxmlParseError::part(
                    OoxmlErrorKind::ZipBombSuspected,
                    &part.name,
                    format!(
                        "declared uncompressed size {} exceeds compressed size {} times the ratio limit of {}",
                        part.uncompressed_size,
                        part.compressed_size,
                        options.max_compression_ratio
                    ),
                ));
        }
    }

    let content_types_part = parts
        .iter()
        .find(|part| part.name == CONTENT_TYPES_PART)
        .ok_or_else(|| {
            OoxmlParseError::package(
                OoxmlErrorKind::MissingContentTypes,
                "package has no [Content_Types].xml part",
            )
        })?;
    let content_types = {
        let file = archive
            .by_index(content_types_part.index)
            .map_err(|error| zip_part_access_error(CONTENT_TYPES_PART, error))?;
        parse_content_types_with_limits(
            file,
            CONTENT_TYPES_PART,
            options.max_xml_token_bytes,
            options.max_content_type_rules,
            options.max_part_name_bytes,
        )?
    };

    let main_part = parts
        .iter()
        .find(|part| part.name == MAIN_DOCUMENT_PART)
        .ok_or_else(|| {
            OoxmlParseError::package(
                OoxmlErrorKind::MissingMainDocument,
                "package has no word/document.xml part",
            )
        })?;
    let main_content_type = content_types.for_part(&main_part.name).ok_or_else(|| {
        OoxmlParseError::part(
            OoxmlErrorKind::NotWordprocessingDocument,
            &main_part.name,
            "[Content_Types].xml does not assign a content type to the main part",
        )
    })?;
    if main_content_type != MAIN_DOCUMENT_CONTENT_TYPE {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::NotWordprocessingDocument,
            &main_part.name,
            format!(
                "main part content type is {main_content_type:?}, expected {MAIN_DOCUMENT_CONTENT_TYPE:?}"
            ),
        ));
    }

    let mut selected = parts
        .iter()
        .filter_map(|part| classify_supported_part(&part.name).map(|kind| (kind, part)))
        .collect::<Vec<_>>();
    selected.sort_by(|(left_kind, left), (right_kind, right)| {
        left_kind
            .priority()
            .cmp(&right_kind.priority())
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.index.cmp(&right.index))
    });

    let mut selected_indices = HashSet::new();
    selected_indices.insert(content_types_part.index);
    let mut hyperlink_targets = 0_usize;
    let mut text_bytes = 0_u64;
    let mut text_chars = 0_u64;
    let mut segments_emitted = 0_usize;

    for (kind, part) in &selected {
        selected_indices.insert(part.index);
        validate_supported_part_content_type(&content_types, part, *kind)?;
        let file = archive
            .by_index(part.index)
            .map_err(|error| zip_part_access_error(&part.name, error))?;

        let outcome = parse_supported_part_streaming(
            file,
            &part.name,
            *kind,
            options.max_segment_bytes,
            options.max_xml_token_bytes,
            sink,
            &mut segments_emitted,
        )?;
        hyperlink_targets = hyperlink_targets.saturating_add(outcome.hyperlink_targets);
        text_bytes = text_bytes.saturating_add(outcome.text_bytes);
        text_chars = text_chars.saturating_add(outcome.text_chars);
    }

    let mut unsupported_parts_count = 0;
    let mut supported_scope_complete = true;
    for part in &parts {
        if !selected_indices.contains(&part.index) {
            let unsupported = unsupported_part_disclosure(part);
            if unsupported.may_contain_text {
                supported_scope_complete = false;
            }
            sink.unsupported_part(&unsupported).map_err(|error| {
                OoxmlParseError::part(OoxmlErrorKind::SinkFailure, &part.name, error.to_string())
            })?;
            unsupported_parts_count += 1;
        }
    }

    let stats = OoxmlParseStats {
        archive_entries,
        file_parts,
        text_parts_selected: selected.len(),
        text_parts_parsed: selected.len(),
        segments_emitted,
        text_bytes,
        text_chars,
        hyperlink_targets,
        unsupported_parts: unsupported_parts_count,
    };

    Ok(OoxmlStreamResult {
        stats,
        supported_scope_complete,
    })
}

struct StreamingOutcome {
    hyperlink_targets: usize,
    text_bytes: u64,
    text_chars: u64,
}

fn parse_supported_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<StreamingOutcome, OoxmlParseError> {
    match kind {
        OoxmlPartKind::MainDocument
        | OoxmlPartKind::Header
        | OoxmlPartKind::Footer
        | OoxmlPartKind::Footnotes
        | OoxmlPartKind::Endnotes
        | OoxmlPartKind::Comments => {
            let (bytes, chars) = parse_word_part_streaming(
                input,
                part_name,
                kind,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: 0,
                text_bytes: bytes,
                text_chars: chars,
            })
        }
        OoxmlPartKind::CoreProperties
        | OoxmlPartKind::CustomProperties
        | OoxmlPartKind::ExtendedProperties => {
            let (bytes, chars) = parse_property_part_streaming(
                input,
                part_name,
                kind,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: 0,
                text_bytes: bytes,
                text_chars: chars,
            })
        }
        OoxmlPartKind::CustomXml => {
            let (bytes, chars) = parse_generic_xml_part_streaming(
                input,
                part_name,
                kind,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: 0,
                text_bytes: bytes,
                text_chars: chars,
            })
        }
        OoxmlPartKind::Relationships => {
            let (bytes, chars, targets) = parse_relationship_part_streaming(
                input,
                part_name,
                kind,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: targets,
                text_bytes: bytes,
                text_chars: chars,
            })
        }
    }
}

struct StreamingSegmenter<'a, S: OoxmlSink> {
    part_name: String,
    part_kind: OoxmlPartKind,
    max_bytes: usize,
    current: String,
    sink: &'a mut S,
    segments_emitted: &'a mut usize,
    text_bytes: u64,
    text_chars: u64,
    last_char: Option<char>,
}

impl<'a, S: OoxmlSink> StreamingSegmenter<'a, S> {
    fn new(
        part_name: &str,
        part_kind: OoxmlPartKind,
        max_bytes: usize,
        sink: &'a mut S,
        segments_emitted: &'a mut usize,
    ) -> Self {
        Self {
            part_name: part_name.to_string(),
            part_kind,
            max_bytes,
            current: String::new(),
            sink,
            segments_emitted,
            text_bytes: 0,
            text_chars: 0,
            last_char: None,
        }
    }

    fn append(&mut self, mut text: &str) -> Result<(), OoxmlParseError> {
        if text.is_empty() {
            return Ok(());
        }
        self.last_char = text.chars().next_back();
        while !text.is_empty() {
            if self.current.len() == self.max_bytes {
                self.flush()?;
            }
            let capacity = self.max_bytes - self.current.len();
            let split = utf8_prefix_len(text, capacity);
            if split == 0 {
                self.flush()?;
                continue;
            }
            self.current.push_str(&text[..split]);
            text = &text[split..];
            if self.current.len() == self.max_bytes {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn separator(&mut self, separator: char) -> Result<(), OoxmlParseError> {
        if self.last_char == Some(separator) {
            return Ok(());
        }
        let mut encoded = [0_u8; 4];
        self.append(separator.encode_utf8(&mut encoded))
    }

    fn flush(&mut self) -> Result<(), OoxmlParseError> {
        if self.current.is_empty() {
            return Ok(());
        }
        let text = std::mem::take(&mut self.current);
        self.text_bytes = self.text_bytes.saturating_add(text.len() as u64);
        self.text_chars = self.text_chars.saturating_add(text.chars().count() as u64);

        let segment = OoxmlTextSegment {
            ordinal: *self.segments_emitted,
            part_name: self.part_name.clone(),
            part_kind: self.part_kind,
            text,
        };
        *self.segments_emitted += 1;

        self.sink.segment(&segment).map_err(|error| {
            OoxmlParseError::part(
                OoxmlErrorKind::SinkFailure,
                &self.part_name,
                error.to_string(),
            )
        })?;
        Ok(())
    }

    fn finish(mut self) -> Result<(u64, u64), OoxmlParseError> {
        self.flush()?;
        Ok((self.text_bytes, self.text_chars))
    }
}

fn flush_generic_text_streaming<S: OoxmlSink>(
    segmenter: &mut StreamingSegmenter<'_, S>,
    pending: &mut String,
) -> Result<(), OoxmlParseError> {
    if !pending.chars().all(char::is_whitespace) {
        segmenter.append(pending)?;
        segmenter.separator('\n')?;
    }
    pending.clear();
    Ok(())
}

// Streaming counterparts retain the same validation and extraction rules while
// emitting bounded segments directly to the sink.
fn parse_word_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter =
        StreamingSegmenter::new(part_name, kind, max_segment_bytes, sink, segments_emitted);
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut text_depth = 0_usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        match event {
            Event::Start(start) => {
                element_depth = element_depth.saturating_add(1);
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                let is_word =
                    namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]);
                if !root_seen {
                    if !is_word || local != expected_word_root(kind) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            format!(
                                "root element is not the expected WordprocessingML {:?} element",
                                String::from_utf8_lossy(expected_word_root(kind))
                            ),
                        ));
                    }
                    root_seen = true;
                }
                if is_word {
                    if is_word_text_element(local) {
                        text_depth = text_depth.saturating_add(1);
                    }
                    // Inlined append_word_record_prefix for StreamingSegmenter
                    match local {
                        b"comment" => {
                            segmenter.separator('\n')?;
                            let id =
                                optional_attribute(&start, b"id", reader.decoder(), part_name)?;
                            let author =
                                optional_attribute(&start, b"author", reader.decoder(), part_name)?;
                            let date =
                                optional_attribute(&start, b"date", reader.decoder(), part_name)?;
                            segmenter.append("[comment")?;
                            if let Some(v) = id {
                                segmenter.append(" id=")?;
                                segmenter.append(&v)?;
                            }
                            if let Some(v) = author {
                                segmenter.append(" author=")?;
                                segmenter.append(&v)?;
                            }
                            if let Some(v) = date {
                                segmenter.append(" date=")?;
                                segmenter.append(&v)?;
                            }
                            segmenter.append("] ")?;
                        }
                        b"footnote" | b"endnote" => {
                            segmenter.separator('\n')?;
                            let id =
                                optional_attribute(&start, b"id", reader.decoder(), part_name)?;
                            segmenter.append(if local == b"footnote" {
                                "[footnote"
                            } else {
                                "[endnote"
                            })?;
                            if let Some(v) = id {
                                segmenter.append(" id=")?;
                                segmenter.append(&v)?;
                            }
                            segmenter.append("] ")?;
                        }
                        _ => {}
                    }
                }
            }
            Event::Empty(empty) => {
                let qname = empty.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]) {
                    // Inlined append_word_empty_element for StreamingSegmenter
                    match local {
                        b"tab" | b"ptab" => segmenter.separator('\t')?,
                        b"br" | b"cr" => segmenter.separator('\n')?,
                        b"noBreakHyphen" => segmenter.append("\u{2011}")?,
                        b"softHyphen" => segmenter.append("\u{00ad}")?,
                        b"sym" => {
                            if let Some(value) =
                                optional_attribute(&empty, b"char", reader.decoder(), part_name)?
                            {
                                let value = value.trim_start_matches("0x");
                                let scalar = u32::from_str_radix(value, 16).map_err(|_| {
                                    OoxmlParseError::part(
                                        OoxmlErrorKind::MalformedXml,
                                        part_name,
                                        format!("invalid w:sym hexadecimal character {value:?}"),
                                    )
                                })?;
                                let character = char::from_u32(scalar).ok_or_else(|| {
                                    OoxmlParseError::part(
                                        OoxmlErrorKind::MalformedXml,
                                        part_name,
                                        format!("w:sym value is not a Unicode scalar: {value:?}"),
                                    )
                                })?;
                                segmenter.append(&character.to_string())?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::End(end) => {
                if element_depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "WordprocessingML part contains an unexpected closing element",
                    ));
                }
                let qname = end.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]) {
                    if is_word_text_element(local) {
                        text_depth = text_depth.saturating_sub(1);
                    }
                    match local {
                        b"tc" => segmenter.separator('\t')?,
                        b"p" | b"tr" | b"comment" | b"footnote" | b"endnote" => {
                            segmenter.separator('\n')?
                        }
                        _ => {}
                    }
                }
                element_depth -= 1;
            }
            Event::Text(text) if text_depth > 0 => {
                let decoded = decode_xml_text(&text, part_name)?;
                segmenter.append(&decoded)?;
            }
            Event::GeneralRef(reference) if text_depth > 0 => {
                segmenter.append(&decode_xml_reference(&reference, part_name)?)?;
            }
            Event::CData(text) if text_depth > 0 => {
                let decoded = text.decode().map_err(|error| xml_error(part_name, error))?;
                segmenter.append(&decoded)?;
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "WordprocessingML part is empty",
        ));
    }
    if element_depth != 0 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!("WordprocessingML part ended with {element_depth} unclosed element(s)"),
        ));
    }
    segmenter.finish()
}

fn parse_property_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter =
        StreamingSegmenter::new(part_name, kind, max_segment_bytes, sink, segments_emitted);
    let mut root_seen = false;
    let mut depth = 0_usize;
    let mut property: Option<(usize, String, bool)> = None;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        match event {
            Event::Start(start) => {
                depth = depth.saturating_add(1);
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if !root_seen {
                    if !property_root_matches(kind, namespace, local) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "property part has an unexpected root element or namespace",
                        ));
                    }
                    root_seen = true;
                } else if property.is_none() {
                    let label = if kind == OoxmlPartKind::CustomProperties && local == b"property" {
                        required_attribute(&start, b"name", reader.decoder(), part_name)?
                    } else if depth == 2 {
                        String::from_utf8_lossy(local).into_owned()
                    } else {
                        String::new()
                    };
                    if !label.is_empty() {
                        property = Some((depth, label, false));
                    }
                }
            }
            Event::Empty(start) => {
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                if !root_seen {
                    if !property_root_matches(kind, namespace, local_name.as_ref()) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "property part has an unexpected empty root element",
                        ));
                    }
                    root_seen = true;
                }
            }
            Event::Text(text) => {
                if let Some((_, label, emitted)) = property.as_mut() {
                    let decoded = decode_xml_text(&text, part_name)?;
                    if !decoded.chars().all(char::is_whitespace) {
                        if !*emitted {
                            segmenter.append(label)?;
                            segmenter.append(": ")?;
                            *emitted = true;
                        }
                        segmenter.append(&decoded)?;
                    }
                }
            }
            Event::GeneralRef(reference) => {
                if let Some((_, label, emitted)) = property.as_mut() {
                    let decoded = decode_xml_reference(&reference, part_name)?;
                    if !decoded.chars().all(char::is_whitespace) {
                        if !*emitted {
                            segmenter.append(label)?;
                            segmenter.append(": ")?;
                            *emitted = true;
                        }
                        segmenter.append(&decoded)?;
                    }
                }
            }
            Event::CData(text) => {
                if let Some((_, label, emitted)) = property.as_mut() {
                    let decoded = text.decode().map_err(|error| xml_error(part_name, error))?;
                    if !decoded.chars().all(char::is_whitespace) {
                        if !*emitted {
                            segmenter.append(label)?;
                            segmenter.append(": ")?;
                            *emitted = true;
                        }
                        segmenter.append(&decoded)?;
                    }
                }
            }
            Event::End(_) => {
                if depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "property XML contains an unexpected closing element",
                    ));
                }
                if property
                    .as_ref()
                    .is_some_and(|(property_depth, _, _)| *property_depth == depth)
                {
                    if let Some((_, _, emitted)) = property.take() {
                        if emitted {
                            segmenter.separator('\n')?;
                        }
                    }
                }
                depth -= 1;
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "property XML part is empty",
        ));
    }
    if depth != 0 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!("property XML ended with {depth} unclosed element(s)"),
        ));
    }
    segmenter.finish()
}

fn parse_generic_xml_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter =
        StreamingSegmenter::new(part_name, kind, max_segment_bytes, sink, segments_emitted);
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut pending_text = String::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        let opens_element = matches!(&event, Event::Start(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                flush_generic_text_streaming(&mut segmenter, &mut pending_text)?;
                if opens_element {
                    element_depth = element_depth.saturating_add(1);
                }
                root_seen = true;
                let element_name = start.name();
                let element = reader
                    .decoder()
                    .decode(element_name.as_ref())
                    .map_err(|error| xml_error(part_name, error))?;
                segmenter.append("element: ")?;
                segmenter.append(&element)?;
                segmenter.separator('\n')?;
                for attribute in start.attributes().with_checks(true) {
                    let attribute = attribute.map_err(|error| xml_error(part_name, error))?;
                    let key = attribute.key.as_ref();
                    if key == b"xmlns" || key.starts_with(b"xmlns:") {
                        continue;
                    }
                    let key = reader
                        .decoder()
                        .decode(key)
                        .map_err(|error| xml_error(part_name, error))?;
                    let value = attribute
                        .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                        .map_err(|error| xml_error(part_name, error))?;
                    segmenter.append("attribute ")?;
                    segmenter.append(&key)?;
                    segmenter.append(": ")?;
                    segmenter.append(&value)?;
                    segmenter.separator('\n')?;
                }
            }
            Event::Text(value) => {
                pending_text.push_str(&decode_xml_text(&value, part_name)?);
            }
            Event::GeneralRef(reference) => {
                pending_text.push_str(&decode_xml_reference(&reference, part_name)?);
            }
            Event::CData(value) => {
                let decoded = value
                    .decode()
                    .map_err(|error| xml_error(part_name, error))?;
                pending_text.push_str(&decoded);
            }
            Event::End(_) => {
                flush_generic_text_streaming(&mut segmenter, &mut pending_text)?;
                if element_depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "custom XML contains an unexpected closing element",
                    ));
                }
                element_depth -= 1;
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => {
                flush_generic_text_streaming(&mut segmenter, &mut pending_text)?;
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "custom XML part is empty",
        ));
    }
    if element_depth != 0 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!("custom XML ended with {element_depth} unclosed element(s)"),
        ));
    }
    segmenter.finish()
}

fn parse_relationship_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64, usize), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter =
        StreamingSegmenter::new(part_name, kind, max_segment_bytes, sink, segments_emitted);
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut hyperlink_targets = 0_usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        let opens_element = matches!(&event, Event::Start(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                if opens_element {
                    element_depth = element_depth.saturating_add(1);
                }
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                let is_relationship_ns = namespace_matches(&namespace, &[RELATIONSHIPS_NS]);
                if !root_seen {
                    if local != b"Relationships" || !is_relationship_ns {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "relationship part has an unexpected root element or namespace",
                        ));
                    }
                    root_seen = true;
                } else if is_relationship_ns && local == b"Relationship" {
                    let relation_type =
                        required_attribute(&start, b"Type", reader.decoder(), part_name)?;
                    if relation_type.ends_with("/hyperlink") {
                        let target =
                            required_attribute(&start, b"Target", reader.decoder(), part_name)?;
                        let id = optional_attribute(&start, b"Id", reader.decoder(), part_name)?;
                        let mode =
                            optional_attribute(&start, b"TargetMode", reader.decoder(), part_name)?;
                        if target.is_empty() {
                            return Err(OoxmlParseError::part(
                                OoxmlErrorKind::InvalidRelationship,
                                part_name,
                                "hyperlink relationship has an empty Target",
                            ));
                        }
                        segmenter.append("hyperlink")?;
                        if let Some(v) = id {
                            segmenter.append(" id=")?;
                            segmenter.append(&v)?;
                        }
                        if let Some(v) = mode {
                            segmenter.append(" mode=")?;
                            segmenter.append(&v)?;
                        }
                        segmenter.append(": ")?;
                        segmenter.append(&target)?;
                        segmenter.separator('\n')?;
                        hyperlink_targets = hyperlink_targets.saturating_add(1);
                    }
                }
            }
            Event::End(_) => {
                if element_depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "relationship XML contains an unexpected closing element",
                    ));
                }
                element_depth -= 1;
            }
            Event::DocType(_) => return Err(doctype_error(part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "relationship XML part is empty",
        ));
    }
    if element_depth != 0 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            format!("relationship XML ended with {element_depth} unclosed element(s)"),
        ));
    }
    let (bytes, chars) = segmenter.finish()?;
    Ok((bytes, chars, hyperlink_targets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const CONTENT_TYPES_PREFIX: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
"#;

    fn content_types(overrides: &[(&str, &str)]) -> String {
        let mut xml = CONTENT_TYPES_PREFIX.to_string();
        for (part_name, content_type) in overrides {
            xml.push_str(&format!(
                "  <Override PartName=\"/{part_name}\" ContentType=\"{content_type}\"/>\n"
            ));
        }
        xml.push_str("</Types>");
        xml
    }

    fn make_zip(parts: &[(&str, &str)]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in parts {
            writer.start_file(*name, options).expect("start ZIP member");
            writer.write_all(data.as_bytes()).expect("write ZIP member");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn minimal_document_xml(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{body}</w:body>
</w:document>"#
        )
    }

    fn minimal_docx(body: &str) -> Vec<u8> {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml(body);
        make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
        ])
    }

    fn text_for_kind(result: &OoxmlParseResult, kind: OoxmlPartKind) -> String {
        result
            .segments
            .iter()
            .filter(|segment| segment.part_kind == kind)
            .map(|segment| segment.text.as_str())
            .collect()
    }

    #[test]
    fn parses_split_runs_unicode_entities_and_tables() {
        let package = minimal_docx(
            r#"<w:p><w:r><w:t>split</w:t></w:r><w:r><w:t>run &amp; Привет 😀</w:t></w:r></w:p>
<w:tbl><w:tr><w:tc><w:p><w:r><w:t>A</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>B</w:t></w:r></w:p></w:tc></w:tr></w:tbl>"#,
        );
        let parsed = parse_docx(Cursor::new(package)).expect("parse DOCX");
        let text = text_for_kind(&parsed, OoxmlPartKind::MainDocument);
        assert!(text.contains("splitrun & Привет 😀"));
        assert!(text.contains('A'));
        assert!(text.contains('B'));
        assert!(text.contains('\t'));
        assert_eq!(parsed.stats.text_parts_parsed, 1);
    }

    #[test]
    fn parses_auxiliary_parts_properties_and_hyperlink_targets_in_order() {
        let overrides = [
            (MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE),
            ("word/header1.xml", HEADER_CONTENT_TYPE),
            ("word/footer1.xml", FOOTER_CONTENT_TYPE),
            ("word/footnotes.xml", FOOTNOTES_CONTENT_TYPE),
            ("word/endnotes.xml", ENDNOTES_CONTENT_TYPE),
            ("word/comments.xml", COMMENTS_CONTENT_TYPE),
            ("docProps/core.xml", CORE_PROPERTIES_CONTENT_TYPE),
            ("docProps/custom.xml", CUSTOM_PROPERTIES_CONTENT_TYPE),
        ];
        let types = content_types(&overrides);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let header = r#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Header</w:t></w:r></w:p></w:hdr>"#;
        let footer = r#"<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Footer</w:t></w:r></w:p></w:ftr>"#;
        let footnotes = r#"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:footnote w:id="1"><w:p><w:r><w:t>Footnote</w:t></w:r></w:p></w:footnote></w:footnotes>"#;
        let endnotes = r#"<w:endnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:endnote w:id="2"><w:p><w:r><w:t>Endnote</w:t></w:r></w:p></w:endnote></w:endnotes>"#;
        let comments = r#"<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="3" w:author="Alice"><w:p><w:r><w:t>Comment text</w:t></w:r></w:p></w:comment></w:comments>"#;
        let core = r#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Case &amp; Evidence</dc:title><dc:creator>Examiner</dc:creator></cp:coreProperties>"#;
        let custom = r#"<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property name="Matter"><vt:lpwstr>Gold</vt:lpwstr></property></Properties>"#;
        let relationships = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.test/?a=1&amp;b=2" TargetMode="External"/></Relationships>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("word/footer1.xml", footer),
            (MAIN_DOCUMENT_PART, &document),
            ("word/header1.xml", header),
            ("word/footnotes.xml", footnotes),
            ("word/endnotes.xml", endnotes),
            ("word/comments.xml", comments),
            ("docProps/core.xml", core),
            ("docProps/custom.xml", custom),
            ("word/_rels/document.xml.rels", relationships),
        ]);

        let parsed = parse_docx(Cursor::new(package)).expect("parse rich DOCX");
        let kinds = parsed
            .segments
            .iter()
            .map(|segment| segment.part_kind)
            .collect::<Vec<_>>();
        assert_eq!(kinds.first(), Some(&OoxmlPartKind::MainDocument));
        assert!(text_for_kind(&parsed, OoxmlPartKind::Header).contains("Header"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::Footer).contains("Footer"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::Footnotes).contains("Footnote"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::Endnotes).contains("Endnote"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::Comments).contains("Alice"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::CoreProperties)
            .contains("title: Case & Evidence"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::CustomProperties).contains("Matter: Gold"));
        assert!(text_for_kind(&parsed, OoxmlPartKind::Relationships)
            .contains("https://example.test/?a=1&b=2"));
        assert_eq!(parsed.stats.hyperlink_targets, 1);
    }

    #[test]
    fn segments_long_text_without_dropping_the_tail() {
        let payload = format!("{}TAIL😀", "abc".repeat(80));
        let package = minimal_docx(&format!("<w:p><w:r><w:t>{payload}</w:t></w:r></w:p>"));
        let parsed = parse_docx_with_options(
            Cursor::new(package),
            OoxmlParseOptions {
                max_segment_bytes: 17,
            },
        )
        .expect("parse segmented DOCX");
        assert!(parsed.segments.len() > 3);
        assert!(parsed
            .segments
            .iter()
            .all(|segment| segment.text.len() <= 17));
        let reconstructed = text_for_kind(&parsed, OoxmlPartKind::MainDocument);
        assert_eq!(reconstructed, format!("{payload}\n"));
    }

    #[test]
    fn discloses_unparsed_parts_and_text_risk() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
            ("word/media/image1.png", "png"),
            ("word/afchunk1.html", "<p>hidden text</p>"),
        ]);
        let parsed = parse_docx(Cursor::new(package)).expect("parse DOCX");
        assert_eq!(parsed.unsupported_parts.len(), 2);
        assert!(parsed.unsupported_parts.iter().any(|part| {
            part.part_name == "word/media/image1.png"
                && part.reason == OoxmlUnsupportedReason::Media
                && !part.may_contain_text
        }));
        assert!(parsed.unsupported_parts.iter().any(|part| {
            part.part_name == "word/afchunk1.html"
                && part.reason == OoxmlUnsupportedReason::PotentialTextContent
                && part.may_contain_text
        }));
        assert!(!parsed.supported_scope_complete);
    }

    #[test]
    fn parses_custom_xml_text_and_attributes_without_renaming_parts() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let custom = r#"<b:Sources xmlns:b="urn:test" SelectedStyle="/APA.XSL"><b:Source id="gold">tail marker</b:Source></b:Sources>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
            ("customXml/item1.xml", custom),
        ]);

        let parsed = parse_docx(Cursor::new(package)).expect("parse custom XML");
        let segments = parsed
            .segments
            .iter()
            .filter(|segment| segment.part_kind == OoxmlPartKind::CustomXml)
            .collect::<Vec<_>>();
        let text = segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<String>();
        assert!(text.contains("SelectedStyle"));
        assert!(text.contains("/APA.XSL"));
        assert!(text.contains("tail marker"));
        assert!(segments
            .iter()
            .all(|segment| segment.part_name == "customXml/item1.xml"));
        assert!(parsed.supported_scope_complete);
    }

    #[test]
    fn rejects_corrupt_zip_and_non_docx_package_explicitly() {
        let corrupt = parse_docx(Cursor::new(b"not a zip".to_vec())).expect_err("corrupt ZIP");
        assert_eq!(corrupt.kind, OoxmlErrorKind::InvalidZip);

        let spreadsheet_type =
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
        let types = content_types(&[(MAIN_DOCUMENT_PART, spreadsheet_type)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
        ]);
        let not_docx = parse_docx(Cursor::new(package)).expect_err("wrong main content type");
        assert_eq!(not_docx.kind, OoxmlErrorKind::NotWordprocessingDocument);
    }

    #[test]
    fn rejects_malformed_xml_and_doctype() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let malformed = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, "<w:document>"),
        ]);
        let malformed_error =
            parse_docx(Cursor::new(malformed)).expect_err("malformed document XML");
        assert_eq!(malformed_error.kind, OoxmlErrorKind::MalformedXml);
        assert_eq!(
            malformed_error.part_name.as_deref(),
            Some(MAIN_DOCUMENT_PART)
        );

        let document = r#"<!DOCTYPE w:document [<!ENTITY x "unsafe">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>"#;
        let doctype_package =
            make_zip(&[(CONTENT_TYPES_PART, &types), (MAIN_DOCUMENT_PART, document)]);
        let doctype_error =
            parse_docx(Cursor::new(doctype_package)).expect_err("DOCTYPE must be rejected");
        assert_eq!(doctype_error.kind, OoxmlErrorKind::MalformedXml);
        assert!(doctype_error.message.contains("DOCTYPE"));
    }
    #[test]
    fn streaming_sink_receives_many_segments() {
        let payload = format!("{}TAIL😀", "abc".repeat(80));
        let package = minimal_docx(&format!("<w:p><w:r><w:t>{payload}</w:t></w:r></w:p>"));
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let options = OoxmlStreamOptions {
            max_segment_bytes: 17,
            ..Default::default()
        };
        parse_docx_streaming(Cursor::new(package), options, &mut sink).expect("parse DOCX");
        assert!(sink.segments.len() > 3);
        let text: String = sink.segments.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(
            text,
            format!(
                "{payload}
"
            )
        );
    }

    #[test]
    fn streaming_bounded_diagnostics() {
        let package = minimal_docx("<w:p><w:r><w:t>Hello</w:t></w:r></w:p>");
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let result = parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect("parse DOCX");
        assert_eq!(result.stats.text_parts_parsed, 1);
        assert_eq!(result.stats.segments_emitted, 1);
        assert_eq!(sink.segments.len(), 1);
        assert_eq!(
            sink.segments[0].text,
            "Hello
"
        );
    }

    #[test]
    fn streaming_custom_xml_extraction() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let custom = r#"<b:Sources xmlns:b="urn:test" SelectedStyle="/APA.XSL"><b:Source id="gold">tail marker</b:Source></b:Sources>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
            ("customXml/item1.xml", custom),
        ]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect("parse DOCX");
        let segments: Vec<_> = sink
            .segments
            .into_iter()
            .filter(|s| s.part_kind == OoxmlPartKind::CustomXml)
            .collect();
        assert!(!segments.is_empty());
        let text: String = segments.iter().map(|s| s.text.as_str()).collect();
        assert!(text.contains("tail marker"));
    }

    #[test]
    fn streaming_unknown_part_marks_scope_incomplete() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
            ("word/afchunk1.html", "<p>hidden text</p>"),
        ]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let result = parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect("parse DOCX");
        assert!(!result.supported_scope_complete);
        assert_eq!(sink.unsupported_parts.len(), 1);
        assert_eq!(sink.unsupported_parts[0].part_name, "word/afchunk1.html");
    }

    #[test]
    fn streaming_malformed_part_error() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let malformed = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, "<w:document>"),
        ]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let error = parse_docx_streaming(
            Cursor::new(malformed),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect_err("malformed");
        assert_eq!(error.kind, OoxmlErrorKind::MalformedXml);
    }

    #[test]
    fn streaming_unclosed_xml_fails_after_a_segment_was_emitted() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut state = 0x71a9_04d3_u32;
        let mut body = String::with_capacity(DEFAULT_MAX_SEGMENT_BYTES + 512);
        for _ in 0..(DEFAULT_MAX_SEGMENT_BYTES + 257) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            body.push(alphabet[(state as usize) % alphabet.len()] as char);
        }
        let document = format!(
            r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p>"#
        );
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
        ]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let error = parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect_err("unclosed WordprocessingML must not be reported complete");
        assert_eq!(error.kind, OoxmlErrorKind::MalformedXml);
        assert!(error.message.contains("unclosed element"));
        assert_eq!(sink.segments.len(), 1);
    }

    struct FailingSink {
        count: usize,
    }
    impl OoxmlSink for FailingSink {
        type Error = std::io::Error;
        fn segment(&mut self, _segment: &OoxmlTextSegment) -> Result<(), Self::Error> {
            self.count += 1;
            if self.count > 1 {
                Err(std::io::Error::other("sink error"))
            } else {
                Ok(())
            }
        }
        fn unsupported_part(&mut self, _part: &OoxmlUnsupportedPart) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn streaming_sink_failure_aborts_early() {
        let payload = format!("{}TAIL😀", "abc".repeat(80));
        let package = minimal_docx(&format!("<w:p><w:r><w:t>{payload}</w:t></w:r></w:p>"));
        let mut sink = FailingSink { count: 0 };
        let options = OoxmlStreamOptions {
            max_segment_bytes: 17,
            ..Default::default()
        };
        let error = parse_docx_streaming(Cursor::new(package), options, &mut sink)
            .expect_err("should abort");
        assert_eq!(error.kind, OoxmlErrorKind::SinkFailure);
        assert_eq!(error.part_name.as_deref(), Some(MAIN_DOCUMENT_PART));
        assert!(error.message.contains("sink error"));
    }

    #[test]
    fn streaming_rejects_oversized_xml_token_before_event_collection() {
        let package = minimal_docx(&format!(
            "<w:p><w:r><w:t>{}</w:t></w:r></w:p>",
            "x".repeat(2_048)
        ));
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let options = OoxmlStreamOptions {
            max_xml_token_bytes: 512,
            ..Default::default()
        };
        let error = parse_docx_streaming(Cursor::new(package), options, &mut sink)
            .expect_err("oversized XML text token must be rejected");
        assert_eq!(error.kind, OoxmlErrorKind::XmlTokenTooLarge);
        assert_eq!(error.part_name.as_deref(), Some(MAIN_DOCUMENT_PART));
        assert!(error.message.contains("512 bytes"));
        assert!(sink.segments.is_empty());
    }

    #[test]
    fn streaming_archive_inventory_limit_is_an_explicit_failure() {
        let package = minimal_docx("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let options = OoxmlStreamOptions {
            max_archive_entries: 1,
            ..Default::default()
        };
        let error = parse_docx_streaming(Cursor::new(package), options, &mut sink)
            .expect_err("inventory limit must not produce a false complete parse");
        assert_eq!(error.kind, OoxmlErrorKind::ZipBombSuspected);
        assert!(error.message.contains("protective limit"));
    }

    #[test]
    fn streaming_zip_bomb_rejected() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            (MAIN_DOCUMENT_PART, &document),
        ]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let options = OoxmlStreamOptions {
            max_entry_uncompressed_bytes: 10,
            ..Default::default()
        };
        let error = parse_docx_streaming(Cursor::new(package), options, &mut sink)
            .expect_err("should reject");
        assert_eq!(error.kind, OoxmlErrorKind::ZipBombSuspected);
    }

    #[test]
    fn streaming_doctype_rejected() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = r#"<!DOCTYPE w:document [<!ENTITY x "unsafe">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>"#;
        let package = make_zip(&[(CONTENT_TYPES_PART, &types), (MAIN_DOCUMENT_PART, document)]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let error = parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect_err("DOCTYPE must be rejected");
        assert_eq!(error.kind, OoxmlErrorKind::MalformedXml);
    }
}
