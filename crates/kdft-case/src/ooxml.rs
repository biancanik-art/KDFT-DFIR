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
use std::collections::{BTreeMap, HashMap, HashSet};
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
const MARKUP_COMPATIBILITY_NS: &[u8] =
    b"http://schemas.openxmlformats.org/markup-compatibility/2006";
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
const MAIN_DOCUMENT_MACRO_ENABLED_CONTENT_TYPE: &str =
    "application/vnd.ms-word.document.macroEnabled.main+xml";
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
const OFFICE_DOCUMENT_RELATIONSHIP_SUFFIX: &str = "/officeDocument";
const HEADER_RELATIONSHIP_SUFFIX: &str = "/header";
const FOOTER_RELATIONSHIP_SUFFIX: &str = "/footer";

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
/// Maximum relationships retained across the package. This bounds relationship
/// graph validation before any text is committed to the sink.
pub const DEFAULT_MAX_RELATIONSHIPS: usize = 64 * 1024;
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

/// Examiner-facing semantic role of the raw text in one homogeneous segment.
///
/// The parser deliberately retains deleted and field-instruction text for
/// forensic search, but never merges either into an ordinary visible-text
/// segment. `hidden` and `in_text_box` below are orthogonal properties because
/// a deleted/field run can also be hidden or live inside a text box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OoxmlTextRole {
    #[default]
    Visible,
    Deleted,
    FieldInstruction,
    DeletedFieldInstruction,
    DocumentProperty,
    CustomXml,
    RelationshipTarget,
}

impl OoxmlTextRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible_text",
            Self::Deleted => "deleted_text",
            Self::FieldInstruction => "field_instruction",
            Self::DeletedFieldInstruction => "deleted_field_instruction",
            Self::DocumentProperty => "document_property",
            Self::CustomXml => "custom_xml",
            Self::RelationshipTarget => "relationship_target",
        }
    }
}

fn default_text_role(part_kind: OoxmlPartKind) -> OoxmlTextRole {
    match part_kind {
        OoxmlPartKind::CoreProperties
        | OoxmlPartKind::CustomProperties
        | OoxmlPartKind::ExtendedProperties => OoxmlTextRole::DocumentProperty,
        OoxmlPartKind::CustomXml => OoxmlTextRole::CustomXml,
        OoxmlPartKind::Relationships => OoxmlTextRole::RelationshipTarget,
        _ => OoxmlTextRole::Visible,
    }
}

/// ZIP-member provenance shared by every segment emitted from a package part.
///
/// The offsets are relative to the DOCX/ZIP package. `zip_data_offset` is the
/// beginning of the member's *compressed* data. It is not an XML-text offset
/// and, for compressed members, cannot be converted 1:1 into a logical XML or
/// evidence-image physical offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlPartProvenance {
    pub archive_index: usize,
    pub crc32: u32,
    pub compression_method: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub zip_local_header_offset: u64,
    pub zip_data_offset: u64,
    pub zip_central_header_offset: u64,
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
    pub text_role: OoxmlTextRole,
    /// Direct `w:vanish`/`w:webHidden` run formatting was observed. Style-
    /// inherited visibility is reported separately in parse statistics.
    pub hidden: bool,
    /// The text occurred under `w:txbxContent`.
    pub in_text_box: bool,
    /// Source-derived structural context for this exact text value. Keys are
    /// parser vocabulary; values come from the OOXML source or are explicit
    /// derived booleans. They are never concatenated into `text`.
    pub source_fields: BTreeMap<String, String>,
    pub part_provenance: Option<OoxmlPartProvenance>,
    /// Decoded source text only. No parser labels, field names, identifiers,
    /// explanatory prefixes, or synthetic record separators are added.
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
    pub crc32: u32,
    pub compression_method: String,
    pub zip_local_header_offset: u64,
    pub zip_data_offset: u64,
    pub zip_central_header_offset: u64,
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
    pub visible_text_chars: u64,
    pub deleted_text_chars: u64,
    pub field_instruction_chars: u64,
    pub directly_hidden_text_chars: u64,
    pub text_box_chars: u64,
    pub run_or_paragraph_style_references: usize,
    pub alternate_content_blocks: usize,
    /// WordprocessingML control elements whose rendered character is not a
    /// literal XML text value (`w:tab`, `w:br`, soft/no-break hyphens, etc.).
    /// They are disclosed instead of injecting synthesized characters.
    pub non_text_control_elements: usize,
    pub internal_relationships: usize,
    pub external_relationships: usize,
    pub dangling_internal_relationships: usize,
    pub relationship_cycles: usize,
    pub unreferenced_story_parts: usize,
    pub opc_start_relationship_present: bool,
    pub orphan_relationship_parts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OoxmlParseResult {
    pub segments: Vec<OoxmlTextSegment>,
    pub stats: OoxmlParseStats,
    pub unsupported_parts: Vec<OoxmlUnsupportedPart>,
    /// False only when a disclosed unsupported member may itself contain text.
    pub supported_scope_complete: bool,
    /// False when style inheritance or Markup Compatibility branches prevent
    /// an exact visible/deleted/hidden role classification. Raw text is still
    /// retained in bounded homogeneous segments.
    pub semantic_scope_complete: bool,
    pub relationship_scope_complete: bool,
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
    crc32: u32,
    compression_method: String,
    header_start: u64,
    data_start: u64,
    central_header_start: u64,
}

impl ArchivePart {
    fn provenance(&self) -> OoxmlPartProvenance {
        OoxmlPartProvenance {
            archive_index: self.index,
            crc32: self.crc32,
            compression_method: self.compression_method.clone(),
            compressed_size: self.compressed_size,
            uncompressed_size: self.uncompressed_size,
            zip_local_header_offset: self.header_start,
            zip_data_offset: self.data_start,
            zip_central_header_offset: self.central_header_start,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpcRelationship {
    ordinal: usize,
    id: String,
    relationship_type: String,
    target: String,
    external: bool,
    resolved_target: Option<String>,
}

#[derive(Debug, Clone)]
struct RelationshipPartInventory {
    part: ArchivePart,
    source_part: Option<String>,
    relationships: Vec<OpcRelationship>,
}

fn relationship_source_part(part_name: &str) -> Result<Option<String>, OoxmlParseError> {
    if part_name == "_rels/.rels" {
        return Ok(None);
    }
    let Some((directory, file_name)) = part_name.rsplit_once('/') else {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            part_name,
            "relationship part is not stored in an _rels directory",
        ));
    };
    let Some(source_file) = file_name.strip_suffix(".rels") else {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            part_name,
            "relationship part does not end in .rels",
        ));
    };
    if source_file.is_empty() {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            part_name,
            "relationship part names an empty source part",
        ));
    }
    let source_directory = directory.strip_suffix("/_rels").or_else(|| {
        if directory == "_rels" {
            Some("")
        } else {
            None
        }
    });
    let Some(source_directory) = source_directory else {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            part_name,
            "relationship part is not stored in the source part's _rels directory",
        ));
    };
    Ok(Some(if source_directory.is_empty() {
        source_file.to_string()
    } else {
        format!("{source_directory}/{source_file}")
    }))
}

fn relationship_part_for_source(source_part: &str) -> String {
    if let Some((directory, file_name)) = source_part.rsplit_once('/') {
        format!("{directory}/_rels/{file_name}.rels")
    } else {
        format!("_rels/{source_part}.rels")
    }
}

fn resolve_internal_relationship_target(
    source_part: Option<&str>,
    target: &str,
    relationship_part: &str,
    max_part_name_bytes: usize,
) -> Result<String, OoxmlParseError> {
    if target.is_empty() {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            relationship_part,
            "internal relationship has an empty Target",
        ));
    }
    if target.contains('\0')
        || target.contains('\\')
        || target.contains('?')
        || target.starts_with("//")
        || target.contains("://")
    {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            relationship_part,
            format!("unsafe internal relationship Target {target:?}"),
        ));
    }
    let folded = target.to_ascii_lowercase();
    if ["%00", "%2e", "%2f", "%5c"]
        .iter()
        .any(|escape| folded.contains(escape))
    {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            relationship_part,
            format!("ambiguous percent-encoded internal relationship Target {target:?}"),
        ));
    }

    let path = target.split_once('#').map_or(target, |(path, _)| path);
    if path.is_empty() {
        return source_part.map(str::to_owned).ok_or_else(|| {
            OoxmlParseError::part(
                OoxmlErrorKind::InvalidRelationship,
                relationship_part,
                "package-root relationship cannot use a fragment-only Target",
            )
        });
    }

    let mut components = Vec::new();
    if !path.starts_with('/') {
        if let Some(source) = source_part {
            if let Some((directory, _)) = source.rsplit_once('/') {
                components.extend(directory.split('/').map(str::to_owned));
            }
        }
    }
    for component in path.trim_start_matches('/').split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::InvalidRelationship,
                        relationship_part,
                        format!(
                            "internal relationship Target escapes the package root: {target:?}"
                        ),
                    ));
                }
            }
            value => components.push(value.to_string()),
        }
    }
    let resolved = components.join("/");
    if resolved.is_empty() || resolved.len() > max_part_name_bytes {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            relationship_part,
            format!(
                "resolved internal relationship Target is empty or exceeds {max_part_name_bytes} bytes"
            ),
        ));
    }
    Ok(resolved)
}

fn parse_relationship_records<R: Read>(
    input: R,
    part_name: &str,
    source_part: Option<&str>,
    max_xml_token_bytes: usize,
    max_relationships: usize,
    max_part_name_bytes: usize,
) -> Result<Vec<OpcRelationship>, OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut seen_ids = HashSet::new();
    let mut relationships = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(part_name, error))?;
        let opens_element = matches!(&event, Event::Start(_));
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
                    if element_depth != 1 {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "Relationship element is not a direct child of Relationships",
                        ));
                    }
                    if relationships.len() == max_relationships {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::ZipBombSuspected,
                            part_name,
                            format!(
                                "relationship count exceeds the protective limit of {max_relationships}"
                            ),
                        ));
                    }
                    let id = required_attribute(&start, b"Id", reader.decoder(), part_name)?;
                    let relationship_type =
                        required_attribute(&start, b"Type", reader.decoder(), part_name)?;
                    let target =
                        required_attribute(&start, b"Target", reader.decoder(), part_name)?;
                    if id.is_empty() || relationship_type.is_empty() || target.is_empty() {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidRelationship,
                            part_name,
                            "relationship Id, Type, and Target must be non-empty",
                        ));
                    }
                    if !seen_ids.insert(id.clone()) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidRelationship,
                            part_name,
                            format!("relationship Id {id:?} is duplicated"),
                        ));
                    }
                    let mode =
                        optional_attribute(&start, b"TargetMode", reader.decoder(), part_name)?;
                    let external = match mode.as_deref() {
                        None | Some("Internal") => false,
                        Some("External") => true,
                        Some(value) => {
                            return Err(OoxmlParseError::part(
                                OoxmlErrorKind::InvalidRelationship,
                                part_name,
                                format!("unsupported relationship TargetMode {value:?}"),
                            ));
                        }
                    };
                    let resolved_target = if external {
                        None
                    } else {
                        Some(resolve_internal_relationship_target(
                            source_part,
                            &target,
                            part_name,
                            max_part_name_bytes,
                        )?)
                    };
                    relationships.push(OpcRelationship {
                        ordinal: relationships.len(),
                        id,
                        relationship_type,
                        target,
                        external,
                        resolved_target,
                    });
                } else if is_relationship_ns {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        format!(
                            "unexpected relationship element {:?}",
                            String::from_utf8_lossy(local)
                        ),
                    ));
                }
                if opens_element {
                    element_depth = element_depth.saturating_add(1);
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
    Ok(relationships)
}

fn count_relationship_cycles(inventories: &[RelationshipPartInventory]) -> usize {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    for inventory in inventories {
        let source = inventory.source_part.clone().unwrap_or_default();
        for relationship in &inventory.relationships {
            if let Some(target) = &relationship.resolved_target {
                graph
                    .entry(source.clone())
                    .or_default()
                    .push(target.clone());
            }
        }
    }

    fn visit(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        colors: &mut HashMap<String, u8>,
        cycles: &mut usize,
    ) {
        colors.insert(node.to_string(), 1);
        if let Some(targets) = graph.get(node) {
            for target in targets {
                match colors.get(target).copied().unwrap_or(0) {
                    0 => visit(target, graph, colors, cycles),
                    1 => *cycles = cycles.saturating_add(1),
                    _ => {}
                }
            }
        }
        colors.insert(node.to_string(), 2);
    }

    let mut colors = HashMap::new();
    let mut cycles = 0_usize;
    for node in graph.keys() {
        if colors.get(node).copied().unwrap_or(0) == 0 {
            visit(node, &graph, &mut colors, &mut cycles);
        }
    }
    cycles
}

fn parse_story_reference_order<R: Read>(
    input: R,
    main_part_name: &str,
    relationships: Option<&RelationshipPartInventory>,
    package_part_names: &HashSet<&str>,
    max_xml_token_bytes: usize,
) -> Result<Vec<String>, OoxmlParseError> {
    let relation_by_id = relationships
        .map(|inventory| {
            inventory
                .relationships
                .iter()
                .map(|relationship| (relationship.id.as_str(), relationship))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut seen_targets = HashSet::new();
    let mut ordered_targets = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| xml_error(main_part_name, error))?;
        let opens_element = matches!(&event, Event::Start(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let qname = start.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                let is_word =
                    namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]);
                if !root_seen {
                    if !is_word || local != b"document" {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            main_part_name,
                            "main part root is not a WordprocessingML document element",
                        ));
                    }
                    root_seen = true;
                } else if is_word && matches!(local, b"headerReference" | b"footerReference") {
                    let relationship_id =
                        required_attribute(&start, b"id", reader.decoder(), main_part_name)?;
                    let relationship =
                        relation_by_id
                            .get(relationship_id.as_str())
                            .ok_or_else(|| {
                                OoxmlParseError::part(
                                    OoxmlErrorKind::InvalidRelationship,
                                    main_part_name,
                                    format!(
                                "story reference uses missing relationship Id {relationship_id:?}"
                            ),
                                )
                            })?;
                    let expected_suffix = if local == b"headerReference" {
                        HEADER_RELATIONSHIP_SUFFIX
                    } else {
                        FOOTER_RELATIONSHIP_SUFFIX
                    };
                    if relationship.external
                        || !relationship.relationship_type.ends_with(expected_suffix)
                    {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidRelationship,
                            main_part_name,
                            format!(
                                "story reference {relationship_id:?} is not an internal {expected_suffix} relationship"
                            ),
                        ));
                    }
                    let target = relationship.resolved_target.as_ref().ok_or_else(|| {
                        OoxmlParseError::part(
                            OoxmlErrorKind::InvalidRelationship,
                            main_part_name,
                            format!(
                                "story relationship {relationship_id:?} has no resolved target"
                            ),
                        )
                    })?;
                    if !package_part_names.contains(target.as_str()) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidRelationship,
                            main_part_name,
                            format!(
                                "story relationship {relationship_id:?} targets missing package part {target:?}"
                            ),
                        ));
                    }
                    if seen_targets.insert(target.clone()) {
                        ordered_targets.push(target.clone());
                    }
                }
                if opens_element {
                    element_depth = element_depth.saturating_add(1);
                }
            }
            Event::End(_) => {
                if element_depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        main_part_name,
                        "main document contains an unexpected closing element",
                    ));
                }
                element_depth -= 1;
            }
            Event::DocType(_) => return Err(doctype_error(main_part_name)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen || element_depth != 0 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            main_part_name,
            "main WordprocessingML document is empty or structurally unbalanced",
        ));
    }
    Ok(ordered_targets)
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
    /// Maximum relationships retained across all `.rels` parts.
    pub max_relationships: usize,
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
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OoxmlStreamResult {
    pub stats: OoxmlParseStats,
    pub supported_scope_complete: bool,
    pub semantic_scope_complete: bool,
    pub relationship_scope_complete: bool,
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
        semantic_scope_complete: result.semantic_scope_complete,
        relationship_scope_complete: result.relationship_scope_complete,
    })
}

/// Backward-compatible name retained for callers that used the former
/// collecting parser. It intentionally delegates to the same streaming
/// implementation as [`parse_docx_with_options`] so there is only one
/// forensic extraction contract.
#[deprecated(
    since = "1.0.1",
    note = "use parse_docx_with_options; both now use the bounded streaming parser"
)]
pub fn parse_docx_with_options_legacy<R: Read + Seek>(
    reader: R,
    options: OoxmlParseOptions,
) -> Result<OoxmlParseResult, OoxmlParseError> {
    parse_docx_with_options(reader, options)
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
            crc32: file.crc32(),
            compression_method: file.compression().to_string(),
            header_start: file.header_start(),
            data_start: file.data_start(),
            central_header_start: file.central_header_start(),
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

fn classify_supported_part_from_package(
    part: &ArchivePart,
    main_part_name: &str,
    content_types: &ContentTypes,
) -> Option<OoxmlPartKind> {
    if part.name == main_part_name {
        return Some(OoxmlPartKind::MainDocument);
    }
    match content_types.for_part(&part.name) {
        Some(HEADER_CONTENT_TYPE) => Some(OoxmlPartKind::Header),
        Some(FOOTER_CONTENT_TYPE) => Some(OoxmlPartKind::Footer),
        Some(FOOTNOTES_CONTENT_TYPE) => Some(OoxmlPartKind::Footnotes),
        Some(ENDNOTES_CONTENT_TYPE) => Some(OoxmlPartKind::Endnotes),
        Some(COMMENTS_CONTENT_TYPE) => Some(OoxmlPartKind::Comments),
        Some(CORE_PROPERTIES_CONTENT_TYPE) => Some(OoxmlPartKind::CoreProperties),
        Some(CUSTOM_PROPERTIES_CONTENT_TYPE) => Some(OoxmlPartKind::CustomProperties),
        Some(EXTENDED_PROPERTIES_CONTENT_TYPE) => Some(OoxmlPartKind::ExtendedProperties),
        Some(RELATIONSHIPS_CONTENT_TYPE) if part.name.ends_with(".rels") => {
            Some(OoxmlPartKind::Relationships)
        }
        actual
            if part.name.starts_with("customXml/")
                && part.name.ends_with(".xml")
                && !part.name.split('/').any(|component| component == "_rels")
                && (matches!(actual, Some("application/xml" | "text/xml"))
                    || actual == Some(CUSTOM_XML_PROPERTIES_CONTENT_TYPE)
                    || actual.is_some_and(|value| value.ends_with("+xml"))) =>
        {
            Some(OoxmlPartKind::CustomXml)
        }
        _ => None,
    }
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
    let valid = if kind == OoxmlPartKind::MainDocument {
        matches!(
            actual,
            Some(MAIN_DOCUMENT_CONTENT_TYPE | MAIN_DOCUMENT_MACRO_ENABLED_CONTENT_TYPE)
        )
    } else if kind == OoxmlPartKind::CustomXml {
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

fn is_word_text_element(local: &[u8]) -> bool {
    matches!(local, b"t" | b"delText" | b"instrText" | b"delInstrText")
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
        // Styles, numbering labels, and settings can contain examiner-created
        // names or other searchable strings. They are not silently treated as
        // covered merely because they primarily describe presentation.
        (OoxmlUnsupportedReason::FormattingOrLayout, true)
    } else if lower.starts_with("_rels/") || lower.ends_with(".rels") {
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
        // Unknown members are conservative by default. A binary member may be
        // an embedded container or contain strings; only specifically known
        // non-text classes above may claim `may_contain_text = false`.
        (OoxmlUnsupportedReason::UnknownPart, true)
    };
    OoxmlUnsupportedPart {
        part_name: part.name.clone(),
        reason,
        may_contain_text,
        compressed_size: part.compressed_size,
        uncompressed_size: part.uncompressed_size,
        crc32: part.crc32,
        compression_method: part.compression_method.clone(),
        zip_local_header_offset: part.header_start,
        zip_data_offset: part.data_start,
        zip_central_header_offset: part.central_header_start,
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
    let folded = message.to_ascii_lowercase();
    let kind = if message.contains(XML_TOKEN_LIMIT_SENTINEL) {
        OoxmlErrorKind::XmlTokenTooLarge
    } else if folded.contains("checksum") || folded.contains("crc") {
        // ZIP member readers validate the member CRC while the XML reader is
        // consuming the stream. Preserve that as a package-integrity failure,
        // rather than misleadingly reporting syntactically malformed XML.
        OoxmlErrorKind::InvalidZip
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
        || options.max_relationships == 0
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

    let part_names = parts
        .iter()
        .map(|part| part.name.as_str())
        .collect::<HashSet<_>>();
    let mut relationship_inventories = Vec::new();
    let mut total_relationships = 0_usize;
    for part in parts.iter().filter(|part| part.name.ends_with(".rels")) {
        if content_types.for_part(&part.name) != Some(RELATIONSHIPS_CONTENT_TYPE) {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::UnexpectedContentType,
                &part.name,
                "relationship part is not assigned the OPC relationships content type",
            ));
        }
        let source_part = relationship_source_part(&part.name)?;
        let file = archive
            .by_index(part.index)
            .map_err(|error| zip_part_access_error(&part.name, error))?;
        let remaining = options
            .max_relationships
            .checked_sub(total_relationships)
            .ok_or_else(|| {
                OoxmlParseError::part(
                    OoxmlErrorKind::ZipBombSuspected,
                    &part.name,
                    format!(
                        "package relationship count exceeds the protective limit of {}",
                        options.max_relationships
                    ),
                )
            })?;
        let relationships = parse_relationship_records(
            file,
            &part.name,
            source_part.as_deref(),
            options.max_xml_token_bytes,
            remaining,
            options.max_part_name_bytes,
        )?;
        total_relationships = total_relationships
            .checked_add(relationships.len())
            .ok_or_else(|| {
                OoxmlParseError::part(
                    OoxmlErrorKind::ZipBombSuspected,
                    &part.name,
                    "package relationship count overflows usize",
                )
            })?;
        relationship_inventories.push(RelationshipPartInventory {
            part: part.clone(),
            source_part,
            relationships,
        });
    }

    let root_relationships = relationship_inventories
        .iter()
        .find(|inventory| inventory.part.name == "_rels/.rels");
    let office_document_relationships = root_relationships
        .into_iter()
        .flat_map(|inventory| inventory.relationships.iter())
        .filter(|relationship| {
            relationship
                .relationship_type
                .ends_with(OFFICE_DOCUMENT_RELATIONSHIP_SUFFIX)
        })
        .collect::<Vec<_>>();
    if office_document_relationships.len() > 1 {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::InvalidRelationship,
            "_rels/.rels",
            "package has multiple officeDocument start-part relationships",
        ));
    }
    let opc_start_relationship_present = office_document_relationships.len() == 1;
    let main_part_name = if let Some(relationship) = office_document_relationships.first() {
        if relationship.external {
            return Err(OoxmlParseError::part(
                OoxmlErrorKind::InvalidRelationship,
                "_rels/.rels",
                "officeDocument start-part relationship must be internal",
            ));
        }
        relationship.resolved_target.clone().ok_or_else(|| {
            OoxmlParseError::part(
                OoxmlErrorKind::InvalidRelationship,
                "_rels/.rels",
                "officeDocument relationship has no resolved package target",
            )
        })?
    } else {
        MAIN_DOCUMENT_PART.to_string()
    };
    let main_part = parts
        .iter()
        .find(|part| part.name == main_part_name)
        .ok_or_else(|| {
            OoxmlParseError::package(
                OoxmlErrorKind::MissingMainDocument,
                format!("package has no resolved WordprocessingML main part {main_part_name:?}"),
            )
        })?;
    let main_content_type = content_types.for_part(&main_part.name).ok_or_else(|| {
        OoxmlParseError::part(
            OoxmlErrorKind::NotWordprocessingDocument,
            &main_part.name,
            "[Content_Types].xml does not assign a content type to the main part",
        )
    })?;
    if !matches!(
        main_content_type,
        MAIN_DOCUMENT_CONTENT_TYPE | MAIN_DOCUMENT_MACRO_ENABLED_CONTENT_TYPE
    ) {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::NotWordprocessingDocument,
            &main_part.name,
            format!(
                "main part content type is {main_content_type:?}, expected a WordprocessingML document main content type"
            ),
        ));
    }

    let internal_relationships = relationship_inventories
        .iter()
        .flat_map(|inventory| inventory.relationships.iter())
        .filter(|relationship| !relationship.external)
        .count();
    let external_relationships = relationship_inventories
        .iter()
        .flat_map(|inventory| inventory.relationships.iter())
        .filter(|relationship| relationship.external)
        .count();
    let orphan_relationship_parts = relationship_inventories
        .iter()
        .filter(|inventory| {
            inventory
                .source_part
                .as_deref()
                .is_some_and(|source| !part_names.contains(source))
        })
        .count();
    let dangling_internal_relationships = relationship_inventories
        .iter()
        .flat_map(|inventory| inventory.relationships.iter())
        .filter_map(|relationship| relationship.resolved_target.as_deref())
        .filter(|target| !part_names.contains(*target))
        .count();
    let relationship_cycles = count_relationship_cycles(&relationship_inventories);
    let relationship_graph_complete = opc_start_relationship_present
        && orphan_relationship_parts == 0
        && dangling_internal_relationships == 0
        && relationship_cycles == 0;

    let main_relationship_part_name = relationship_part_for_source(&main_part_name);
    let main_relationships = relationship_inventories
        .iter()
        .find(|inventory| inventory.part.name == main_relationship_part_name);
    let story_order = {
        let file = archive
            .by_index(main_part.index)
            .map_err(|error| zip_part_access_error(&main_part.name, error))?;
        parse_story_reference_order(
            file,
            &main_part.name,
            main_relationships,
            &part_names,
            options.max_xml_token_bytes,
        )?
    };
    let story_position = story_order
        .iter()
        .enumerate()
        .map(|(ordinal, name)| (name.as_str(), ordinal))
        .collect::<HashMap<_, _>>();

    let mut selected = parts
        .iter()
        .filter_map(|part| {
            classify_supported_part_from_package(part, &main_part_name, &content_types)
                .map(|kind| (kind, part))
        })
        .collect::<Vec<_>>();
    selected.sort_by(|(left_kind, left), (right_kind, right)| {
        let left_priority = if matches!(left_kind, OoxmlPartKind::Header | OoxmlPartKind::Footer) {
            10
        } else {
            left_kind.priority()
        };
        let right_priority = if matches!(right_kind, OoxmlPartKind::Header | OoxmlPartKind::Footer)
        {
            10
        } else {
            right_kind.priority()
        };
        left_priority
            .cmp(&right_priority)
            .then_with(|| {
                story_position
                    .get(left.name.as_str())
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(
                        &story_position
                            .get(right.name.as_str())
                            .copied()
                            .unwrap_or(usize::MAX),
                    )
            })
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.index.cmp(&right.index))
    });
    let unreferenced_story_parts = selected
        .iter()
        .filter(|(kind, part)| {
            matches!(kind, OoxmlPartKind::Header | OoxmlPartKind::Footer)
                && !story_position.contains_key(part.name.as_str())
        })
        .count();
    let relationship_scope_complete = relationship_graph_complete && unreferenced_story_parts == 0;

    let mut selected_indices = HashSet::new();
    selected_indices.insert(content_types_part.index);
    let mut hyperlink_targets = 0_usize;
    let mut text_bytes = 0_u64;
    let mut text_chars = 0_u64;
    let mut segments_emitted = 0_usize;
    let mut word_semantics = WordSemanticStats::default();

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
            &part.provenance(),
            options.max_segment_bytes,
            options.max_xml_token_bytes,
            sink,
            &mut segments_emitted,
        )?;
        hyperlink_targets = hyperlink_targets.saturating_add(outcome.hyperlink_targets);
        text_bytes = text_bytes.saturating_add(outcome.text_bytes);
        text_chars = text_chars.saturating_add(outcome.text_chars);
        word_semantics.visible_text_chars = word_semantics
            .visible_text_chars
            .saturating_add(outcome.word_semantics.visible_text_chars);
        word_semantics.deleted_text_chars = word_semantics
            .deleted_text_chars
            .saturating_add(outcome.word_semantics.deleted_text_chars);
        word_semantics.field_instruction_chars = word_semantics
            .field_instruction_chars
            .saturating_add(outcome.word_semantics.field_instruction_chars);
        word_semantics.directly_hidden_text_chars = word_semantics
            .directly_hidden_text_chars
            .saturating_add(outcome.word_semantics.directly_hidden_text_chars);
        word_semantics.text_box_chars = word_semantics
            .text_box_chars
            .saturating_add(outcome.word_semantics.text_box_chars);
        word_semantics.run_or_paragraph_style_references = word_semantics
            .run_or_paragraph_style_references
            .saturating_add(outcome.word_semantics.run_or_paragraph_style_references);
        word_semantics.alternate_content_blocks = word_semantics
            .alternate_content_blocks
            .saturating_add(outcome.word_semantics.alternate_content_blocks);
        word_semantics.non_text_control_elements = word_semantics
            .non_text_control_elements
            .saturating_add(outcome.word_semantics.non_text_control_elements);
        word_semantics.late_run_visibility_properties = word_semantics
            .late_run_visibility_properties
            .saturating_add(outcome.word_semantics.late_run_visibility_properties);
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
        visible_text_chars: word_semantics.visible_text_chars,
        deleted_text_chars: word_semantics.deleted_text_chars,
        field_instruction_chars: word_semantics.field_instruction_chars,
        directly_hidden_text_chars: word_semantics.directly_hidden_text_chars,
        text_box_chars: word_semantics.text_box_chars,
        run_or_paragraph_style_references: word_semantics.run_or_paragraph_style_references,
        alternate_content_blocks: word_semantics.alternate_content_blocks,
        non_text_control_elements: word_semantics.non_text_control_elements,
        internal_relationships,
        external_relationships,
        dangling_internal_relationships,
        relationship_cycles,
        unreferenced_story_parts,
        opc_start_relationship_present,
        orphan_relationship_parts,
    };

    let semantic_scope_complete = word_semantics.run_or_paragraph_style_references == 0
        && word_semantics.alternate_content_blocks == 0
        && word_semantics.late_run_visibility_properties == 0
        && word_semantics.non_text_control_elements == 0;

    Ok(OoxmlStreamResult {
        stats,
        supported_scope_complete,
        semantic_scope_complete,
        relationship_scope_complete,
    })
}

struct StreamingOutcome {
    hyperlink_targets: usize,
    text_bytes: u64,
    text_chars: u64,
    word_semantics: WordSemanticStats,
}

#[derive(Debug, Default)]
struct WordSemanticStats {
    visible_text_chars: u64,
    deleted_text_chars: u64,
    field_instruction_chars: u64,
    directly_hidden_text_chars: u64,
    text_box_chars: u64,
    run_or_paragraph_style_references: usize,
    alternate_content_blocks: usize,
    late_run_visibility_properties: usize,
    non_text_control_elements: usize,
}

fn parse_supported_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    part_provenance: &OoxmlPartProvenance,
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
            let (bytes, chars, word_semantics) = parse_word_part_streaming(
                input,
                part_name,
                kind,
                part_provenance,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: 0,
                text_bytes: bytes,
                text_chars: chars,
                word_semantics,
            })
        }
        OoxmlPartKind::CoreProperties
        | OoxmlPartKind::CustomProperties
        | OoxmlPartKind::ExtendedProperties => {
            let (bytes, chars) = parse_property_part_streaming(
                input,
                part_name,
                kind,
                part_provenance,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: 0,
                text_bytes: bytes,
                text_chars: chars,
                word_semantics: WordSemanticStats::default(),
            })
        }
        OoxmlPartKind::CustomXml => {
            let (bytes, chars) = parse_generic_xml_part_streaming(
                input,
                part_name,
                kind,
                part_provenance,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: 0,
                text_bytes: bytes,
                text_chars: chars,
                word_semantics: WordSemanticStats::default(),
            })
        }
        OoxmlPartKind::Relationships => {
            let (bytes, chars, targets) = parse_relationship_part_streaming(
                input,
                part_name,
                kind,
                part_provenance,
                max_segment_bytes,
                max_xml_token_bytes,
                sink,
                segments_emitted,
            )?;
            Ok(StreamingOutcome {
                hyperlink_targets: targets,
                text_bytes: bytes,
                text_chars: chars,
                word_semantics: WordSemanticStats::default(),
            })
        }
    }
}

struct StreamingSegmenter<'a, S: OoxmlSink> {
    part_name: String,
    part_kind: OoxmlPartKind,
    part_provenance: OoxmlPartProvenance,
    text_role: OoxmlTextRole,
    hidden: bool,
    in_text_box: bool,
    source_fields: BTreeMap<String, String>,
    max_bytes: usize,
    current: String,
    sink: &'a mut S,
    segments_emitted: &'a mut usize,
    text_bytes: u64,
    text_chars: u64,
}

impl<'a, S: OoxmlSink> StreamingSegmenter<'a, S> {
    fn new(
        part_name: &str,
        part_kind: OoxmlPartKind,
        part_provenance: &OoxmlPartProvenance,
        max_bytes: usize,
        sink: &'a mut S,
        segments_emitted: &'a mut usize,
    ) -> Self {
        Self {
            part_name: part_name.to_string(),
            part_kind,
            part_provenance: part_provenance.clone(),
            text_role: default_text_role(part_kind),
            hidden: false,
            in_text_box: false,
            source_fields: BTreeMap::new(),
            max_bytes,
            current: String::new(),
            sink,
            segments_emitted,
            text_bytes: 0,
            text_chars: 0,
        }
    }

    fn emit_source_text(
        &mut self,
        text_role: OoxmlTextRole,
        hidden: bool,
        in_text_box: bool,
        source_fields: BTreeMap<String, String>,
        text: &str,
    ) -> Result<(), OoxmlParseError> {
        if text.is_empty() {
            return Ok(());
        }
        self.flush()?;
        self.text_role = text_role;
        self.hidden = hidden;
        self.in_text_box = in_text_box;
        self.source_fields = source_fields;
        self.append(text)?;
        self.flush()
    }

    fn append(&mut self, mut text: &str) -> Result<(), OoxmlParseError> {
        if text.is_empty() {
            return Ok(());
        }
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
            text_role: self.text_role,
            hidden: self.hidden,
            in_text_box: self.in_text_box,
            source_fields: self.source_fields.clone(),
            part_provenance: Some(self.part_provenance.clone()),
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

// Streaming counterparts retain the same validation and extraction rules while
// emitting bounded segments directly to the sink.
#[derive(Debug, Clone, Copy)]
struct WordTextContext {
    role: OoxmlTextRole,
    hidden: bool,
    in_text_box: bool,
    xml_element: &'static str,
}

fn word_text_context(
    local: &[u8],
    deleted: bool,
    hidden: bool,
    in_text_box: bool,
) -> WordTextContext {
    let role = match (local, deleted) {
        (b"instrText" | b"delInstrText", true) | (b"delInstrText", false) => {
            OoxmlTextRole::DeletedFieldInstruction
        }
        (b"instrText", false) => OoxmlTextRole::FieldInstruction,
        (b"delText", _) | (_, true) => OoxmlTextRole::Deleted,
        _ => OoxmlTextRole::Visible,
    };
    WordTextContext {
        role,
        hidden,
        in_text_box,
        xml_element: match local {
            b"t" => "w:t",
            b"delText" => "w:delText",
            b"instrText" => "w:instrText",
            b"delInstrText" => "w:delInstrText",
            _ => "w:text",
        },
    }
}

fn word_source_fields(
    context: WordTextContext,
    record_fields: Option<&BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    let mut fields = record_fields.cloned().unwrap_or_default();
    fields.insert("xml_element".to_string(), context.xml_element.to_string());
    fields
}

fn record_word_text(stats: &mut WordSemanticStats, context: WordTextContext, text: &str) {
    let chars = text.chars().count() as u64;
    match context.role {
        OoxmlTextRole::Visible => {
            stats.visible_text_chars = stats.visible_text_chars.saturating_add(chars)
        }
        OoxmlTextRole::Deleted => {
            stats.deleted_text_chars = stats.deleted_text_chars.saturating_add(chars)
        }
        OoxmlTextRole::FieldInstruction => {
            stats.field_instruction_chars = stats.field_instruction_chars.saturating_add(chars)
        }
        OoxmlTextRole::DeletedFieldInstruction => {
            stats.deleted_text_chars = stats.deleted_text_chars.saturating_add(chars);
            stats.field_instruction_chars = stats.field_instruction_chars.saturating_add(chars);
        }
        OoxmlTextRole::DocumentProperty
        | OoxmlTextRole::CustomXml
        | OoxmlTextRole::RelationshipTarget => {}
    }
    if context.hidden {
        stats.directly_hidden_text_chars = stats.directly_hidden_text_chars.saturating_add(chars);
    }
    if context.in_text_box {
        stats.text_box_chars = stats.text_box_chars.saturating_add(chars);
    }
}

fn word_boolean_property_enabled(
    start: &BytesStart<'_>,
    decoder: Decoder,
    part_name: &str,
) -> Result<bool, OoxmlParseError> {
    let Some(value) = optional_attribute(start, b"val", decoder, part_name)? else {
        return Ok(true);
    };
    Ok(!matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    ))
}

fn parse_word_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    part_provenance: &OoxmlPartProvenance,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64, WordSemanticStats), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = StreamingSegmenter::new(
        part_name,
        kind,
        part_provenance,
        max_segment_bytes,
        sink,
        segments_emitted,
    );
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut deleted_depth = 0_usize;
    let mut text_box_depth = 0_usize;
    let mut text_contexts = Vec::new();
    let mut record_contexts: Vec<BTreeMap<String, String>> = Vec::new();
    let mut run_hidden = Vec::new();
    let mut run_text_seen = Vec::new();
    let mut semantic_stats = WordSemanticStats::default();

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
                if namespace_matches(&namespace, &[MARKUP_COMPATIBILITY_NS])
                    && local == b"AlternateContent"
                {
                    semantic_stats.alternate_content_blocks =
                        semantic_stats.alternate_content_blocks.saturating_add(1);
                }
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
                    match local {
                        b"r" => {
                            run_hidden.push(false);
                            run_text_seen.push(false);
                        }
                        b"del" | b"moveFrom" => deleted_depth = deleted_depth.saturating_add(1),
                        b"txbxContent" => text_box_depth = text_box_depth.saturating_add(1),
                        b"rStyle" | b"pStyle" => {
                            semantic_stats.run_or_paragraph_style_references = semantic_stats
                                .run_or_paragraph_style_references
                                .saturating_add(1);
                        }
                        b"vanish" | b"webHidden" => {
                            if word_boolean_property_enabled(&start, reader.decoder(), part_name)? {
                                if run_text_seen.last().copied().unwrap_or(false) {
                                    semantic_stats.late_run_visibility_properties = semantic_stats
                                        .late_run_visibility_properties
                                        .saturating_add(1);
                                }
                                if let Some(hidden) = run_hidden.last_mut() {
                                    *hidden = true;
                                }
                            }
                        }
                        b"fldSimple" => {
                            if let Some(instruction) =
                                optional_attribute(&start, b"instr", reader.decoder(), part_name)?
                            {
                                let context = word_text_context(
                                    b"instrText",
                                    deleted_depth > 0,
                                    run_hidden.last().copied().unwrap_or(false),
                                    text_box_depth > 0,
                                );
                                record_word_text(&mut semantic_stats, context, &instruction);
                                let mut fields =
                                    word_source_fields(context, record_contexts.last());
                                fields.insert("xml_element".to_string(), "w:fldSimple".to_string());
                                fields.insert("xml_attribute".to_string(), "w:instr".to_string());
                                segmenter.emit_source_text(
                                    context.role,
                                    context.hidden,
                                    context.in_text_box,
                                    fields,
                                    &instruction,
                                )?;
                            }
                        }
                        _ => {}
                    }
                    if is_word_text_element(local) {
                        let context = word_text_context(
                            local,
                            deleted_depth > 0,
                            run_hidden.last().copied().unwrap_or(false),
                            text_box_depth > 0,
                        );
                        text_contexts.push(context);
                        if let Some(seen) = run_text_seen.last_mut() {
                            *seen = true;
                        }
                    }
                    match local {
                        b"comment" => {
                            let mut fields = BTreeMap::new();
                            fields.insert("record_element".to_string(), "w:comment".to_string());
                            let id =
                                optional_attribute(&start, b"id", reader.decoder(), part_name)?;
                            let author =
                                optional_attribute(&start, b"author", reader.decoder(), part_name)?;
                            let date =
                                optional_attribute(&start, b"date", reader.decoder(), part_name)?;
                            if let Some(v) = id {
                                fields.insert("comment_id".to_string(), v);
                            }
                            if let Some(v) = author {
                                fields.insert("comment_author".to_string(), v);
                            }
                            if let Some(v) = date {
                                fields.insert("comment_date".to_string(), v);
                            }
                            record_contexts.push(fields);
                        }
                        b"footnote" | b"endnote" => {
                            let mut fields = BTreeMap::new();
                            fields.insert(
                                "record_element".to_string(),
                                if local == b"footnote" {
                                    "w:footnote"
                                } else {
                                    "w:endnote"
                                }
                                .to_string(),
                            );
                            let id =
                                optional_attribute(&start, b"id", reader.decoder(), part_name)?;
                            if let Some(v) = id {
                                fields.insert("note_id".to_string(), v);
                            }
                            record_contexts.push(fields);
                        }
                        _ => {}
                    }
                }
            }
            Event::Empty(empty) => {
                let qname = empty.name();
                let (namespace, local_name) = reader.resolver().resolve_element(qname);
                let local = local_name.as_ref();
                if namespace_matches(&namespace, &[MARKUP_COMPATIBILITY_NS])
                    && local == b"AlternateContent"
                {
                    semantic_stats.alternate_content_blocks =
                        semantic_stats.alternate_content_blocks.saturating_add(1);
                }
                if namespace_matches(&namespace, &[WORD_NS_TRANSITIONAL, WORD_NS_STRICT]) {
                    match local {
                        b"rStyle" | b"pStyle" => {
                            semantic_stats.run_or_paragraph_style_references = semantic_stats
                                .run_or_paragraph_style_references
                                .saturating_add(1);
                        }
                        b"vanish" | b"webHidden" => {
                            if word_boolean_property_enabled(&empty, reader.decoder(), part_name)? {
                                if run_text_seen.last().copied().unwrap_or(false) {
                                    semantic_stats.late_run_visibility_properties = semantic_stats
                                        .late_run_visibility_properties
                                        .saturating_add(1);
                                }
                                if let Some(hidden) = run_hidden.last_mut() {
                                    *hidden = true;
                                }
                            }
                        }
                        b"fldSimple" => {
                            if let Some(instruction) =
                                optional_attribute(&empty, b"instr", reader.decoder(), part_name)?
                            {
                                let context = word_text_context(
                                    b"instrText",
                                    deleted_depth > 0,
                                    run_hidden.last().copied().unwrap_or(false),
                                    text_box_depth > 0,
                                );
                                record_word_text(&mut semantic_stats, context, &instruction);
                                let mut fields =
                                    word_source_fields(context, record_contexts.last());
                                fields.insert("xml_element".to_string(), "w:fldSimple".to_string());
                                fields.insert("xml_attribute".to_string(), "w:instr".to_string());
                                segmenter.emit_source_text(
                                    context.role,
                                    context.hidden,
                                    context.in_text_box,
                                    fields,
                                    &instruction,
                                )?;
                            }
                        }
                        _ => {}
                    }
                    match local {
                        b"tab" | b"ptab" | b"br" | b"cr" | b"noBreakHyphen" | b"softHyphen" => {
                            semantic_stats.non_text_control_elements =
                                semantic_stats.non_text_control_elements.saturating_add(1);
                        }
                        b"sym" => {
                            if let Some(value) =
                                optional_attribute(&empty, b"char", reader.decoder(), part_name)?
                            {
                                let normalized = value.trim_start_matches("0x");
                                let scalar = u32::from_str_radix(normalized, 16).map_err(|_| {
                                    OoxmlParseError::part(
                                        OoxmlErrorKind::MalformedXml,
                                        part_name,
                                        format!(
                                            "invalid w:sym hexadecimal character {normalized:?}"
                                        ),
                                    )
                                })?;
                                char::from_u32(scalar).ok_or_else(|| {
                                    OoxmlParseError::part(
                                        OoxmlErrorKind::MalformedXml,
                                        part_name,
                                        format!(
                                            "w:sym value is not a Unicode scalar: {normalized:?}"
                                        ),
                                    )
                                })?;
                            }
                            semantic_stats.non_text_control_elements =
                                semantic_stats.non_text_control_elements.saturating_add(1);
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
                    if is_word_text_element(local) && text_contexts.pop().is_none() {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::MalformedXml,
                            part_name,
                            "WordprocessingML text element closed without an open text context",
                        ));
                    }
                    match local {
                        b"r" => {
                            if run_hidden.pop().is_none() || run_text_seen.pop().is_none() {
                                return Err(OoxmlParseError::part(
                                    OoxmlErrorKind::MalformedXml,
                                    part_name,
                                    "WordprocessingML run closed without an open run",
                                ));
                            }
                        }
                        b"del" | b"moveFrom" => deleted_depth = deleted_depth.saturating_sub(1),
                        b"txbxContent" => text_box_depth = text_box_depth.saturating_sub(1),
                        b"comment" | b"footnote" | b"endnote"
                            if record_contexts.pop().is_none() =>
                        {
                            return Err(OoxmlParseError::part(
                                OoxmlErrorKind::MalformedXml,
                                part_name,
                                "WordprocessingML record closed without an open source context",
                            ));
                        }
                        _ => {}
                    }
                }
                element_depth -= 1;
            }
            Event::Text(text) if !text_contexts.is_empty() => {
                let decoded = decode_xml_text(&text, part_name)?;
                let Some(&context) = text_contexts.last() else {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "WordprocessingML text appeared without a source context",
                    ));
                };
                record_word_text(&mut semantic_stats, context, &decoded);
                segmenter.emit_source_text(
                    context.role,
                    context.hidden,
                    context.in_text_box,
                    word_source_fields(context, record_contexts.last()),
                    &decoded,
                )?;
            }
            Event::GeneralRef(reference) if !text_contexts.is_empty() => {
                let decoded = decode_xml_reference(&reference, part_name)?;
                let Some(&context) = text_contexts.last() else {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "WordprocessingML reference appeared without a source context",
                    ));
                };
                record_word_text(&mut semantic_stats, context, &decoded);
                segmenter.emit_source_text(
                    context.role,
                    context.hidden,
                    context.in_text_box,
                    word_source_fields(context, record_contexts.last()),
                    &decoded,
                )?;
            }
            Event::CData(text) if !text_contexts.is_empty() => {
                let decoded = text.decode().map_err(|error| xml_error(part_name, error))?;
                let Some(&context) = text_contexts.last() else {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "WordprocessingML CDATA appeared without a source context",
                    ));
                };
                record_word_text(&mut semantic_stats, context, &decoded);
                segmenter.emit_source_text(
                    context.role,
                    context.hidden,
                    context.in_text_box,
                    word_source_fields(context, record_contexts.last()),
                    &decoded,
                )?;
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
    if !text_contexts.is_empty()
        || !record_contexts.is_empty()
        || !run_hidden.is_empty()
        || !run_text_seen.is_empty()
    {
        return Err(OoxmlParseError::part(
            OoxmlErrorKind::MalformedXml,
            part_name,
            "WordprocessingML semantic state ended unbalanced",
        ));
    }
    let (bytes, chars) = segmenter.finish()?;
    Ok((bytes, chars, semantic_stats))
}

fn parse_property_part_streaming<R: Read, S: OoxmlSink>(
    input: R,
    part_name: &str,
    kind: OoxmlPartKind,
    part_provenance: &OoxmlPartProvenance,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = StreamingSegmenter::new(
        part_name,
        kind,
        part_provenance,
        max_segment_bytes,
        sink,
        segments_emitted,
    );
    let mut root_seen = false;
    let mut depth = 0_usize;
    let mut property: Option<(usize, String)> = None;

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
                        property = Some((depth, label));
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
                if let Some((_, label)) = property.as_ref() {
                    let decoded = decode_xml_text(&text, part_name)?;
                    if !decoded.chars().all(char::is_whitespace) {
                        let mut fields = BTreeMap::new();
                        fields.insert("property_name".to_string(), label.clone());
                        fields.insert("xml_node_kind".to_string(), "text".to_string());
                        segmenter.emit_source_text(
                            OoxmlTextRole::DocumentProperty,
                            false,
                            false,
                            fields,
                            &decoded,
                        )?;
                    }
                }
            }
            Event::GeneralRef(reference) => {
                if let Some((_, label)) = property.as_ref() {
                    let decoded = decode_xml_reference(&reference, part_name)?;
                    if !decoded.chars().all(char::is_whitespace) {
                        let mut fields = BTreeMap::new();
                        fields.insert("property_name".to_string(), label.clone());
                        fields.insert("xml_node_kind".to_string(), "entity_reference".to_string());
                        segmenter.emit_source_text(
                            OoxmlTextRole::DocumentProperty,
                            false,
                            false,
                            fields,
                            &decoded,
                        )?;
                    }
                }
            }
            Event::CData(text) => {
                if let Some((_, label)) = property.as_ref() {
                    let decoded = text.decode().map_err(|error| xml_error(part_name, error))?;
                    if !decoded.chars().all(char::is_whitespace) {
                        let mut fields = BTreeMap::new();
                        fields.insert("property_name".to_string(), label.clone());
                        fields.insert("xml_node_kind".to_string(), "cdata".to_string());
                        segmenter.emit_source_text(
                            OoxmlTextRole::DocumentProperty,
                            false,
                            false,
                            fields,
                            &decoded,
                        )?;
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
                    .is_some_and(|(property_depth, _)| *property_depth == depth)
                {
                    property.take();
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
    part_provenance: &OoxmlPartProvenance,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = StreamingSegmenter::new(
        part_name,
        kind,
        part_provenance,
        max_segment_bytes,
        sink,
        segments_emitted,
    );
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut element_stack: Vec<String> = Vec::new();

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
                root_seen = true;
                let element_name = start.name();
                let element = reader
                    .decoder()
                    .decode(element_name.as_ref())
                    .map_err(|error| xml_error(part_name, error))?
                    .into_owned();
                if opens_element {
                    element_stack.push(element.clone());
                }
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
                        .map_err(|error| xml_error(part_name, error))?
                        .into_owned();
                    let mut fields = BTreeMap::new();
                    fields.insert("xml_element".to_string(), element.clone());
                    fields.insert("xml_attribute".to_string(), key.into_owned());
                    fields.insert("xml_node_kind".to_string(), "attribute_value".to_string());
                    segmenter.emit_source_text(
                        OoxmlTextRole::CustomXml,
                        false,
                        false,
                        fields,
                        &value,
                    )?;
                }
            }
            Event::Text(value) => {
                let decoded = decode_xml_text(&value, part_name)?;
                if !decoded.chars().all(char::is_whitespace) {
                    let mut fields = BTreeMap::new();
                    if let Some(element) = element_stack.last() {
                        fields.insert("xml_element".to_string(), element.clone());
                    }
                    fields.insert("xml_node_kind".to_string(), "text".to_string());
                    segmenter.emit_source_text(
                        OoxmlTextRole::CustomXml,
                        false,
                        false,
                        fields,
                        &decoded,
                    )?;
                }
            }
            Event::GeneralRef(reference) => {
                let decoded = decode_xml_reference(&reference, part_name)?;
                if !decoded.chars().all(char::is_whitespace) {
                    let mut fields = BTreeMap::new();
                    if let Some(element) = element_stack.last() {
                        fields.insert("xml_element".to_string(), element.clone());
                    }
                    fields.insert("xml_node_kind".to_string(), "entity_reference".to_string());
                    segmenter.emit_source_text(
                        OoxmlTextRole::CustomXml,
                        false,
                        false,
                        fields,
                        &decoded,
                    )?;
                }
            }
            Event::CData(value) => {
                let decoded = value
                    .decode()
                    .map_err(|error| xml_error(part_name, error))?;
                if !decoded.chars().all(char::is_whitespace) {
                    let mut fields = BTreeMap::new();
                    if let Some(element) = element_stack.last() {
                        fields.insert("xml_element".to_string(), element.clone());
                    }
                    fields.insert("xml_node_kind".to_string(), "cdata".to_string());
                    segmenter.emit_source_text(
                        OoxmlTextRole::CustomXml,
                        false,
                        false,
                        fields,
                        &decoded,
                    )?;
                }
            }
            Event::End(_) => {
                if element_depth == 0 {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "custom XML contains an unexpected closing element",
                    ));
                }
                element_depth -= 1;
                if element_stack.pop().is_none() {
                    return Err(OoxmlParseError::part(
                        OoxmlErrorKind::MalformedXml,
                        part_name,
                        "custom XML element stack is unbalanced",
                    ));
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
            "custom XML part is empty",
        ));
    }
    if element_depth != 0 || !element_stack.is_empty() {
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
    part_provenance: &OoxmlPartProvenance,
    max_segment_bytes: usize,
    max_xml_token_bytes: usize,
    sink: &mut S,
    segments_emitted: &mut usize,
) -> Result<(u64, u64, usize), OoxmlParseError> {
    let bounded = XmlTokenLimitReader::new(input, max_xml_token_bytes);
    let mut reader = NsReader::from_reader(BufReader::new(bounded));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut segmenter = StreamingSegmenter::new(
        part_name,
        kind,
        part_provenance,
        max_segment_bytes,
        sink,
        segments_emitted,
    );
    let mut root_seen = false;
    let mut element_depth = 0_usize;
    let mut hyperlink_targets = 0_usize;
    let mut seen_ids = HashSet::new();

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
                    let target =
                        required_attribute(&start, b"Target", reader.decoder(), part_name)?;
                    let id = required_attribute(&start, b"Id", reader.decoder(), part_name)?;
                    if !seen_ids.insert(id.clone()) {
                        return Err(OoxmlParseError::part(
                            OoxmlErrorKind::InvalidRelationship,
                            part_name,
                            format!("relationship Id {id:?} is duplicated"),
                        ));
                    }
                    let mode =
                        optional_attribute(&start, b"TargetMode", reader.decoder(), part_name)?;
                    let external = match mode.as_deref() {
                        None | Some("Internal") => false,
                        Some("External") => true,
                        Some(value) => {
                            return Err(OoxmlParseError::part(
                                OoxmlErrorKind::InvalidRelationship,
                                part_name,
                                format!("unsupported relationship TargetMode {value:?}"),
                            ));
                        }
                    };
                    let is_hyperlink = relation_type.ends_with("/hyperlink");
                    if is_hyperlink || external {
                        let mut fields = BTreeMap::new();
                        fields.insert("xml_element".to_string(), "Relationship".to_string());
                        fields.insert("xml_attribute".to_string(), "Target".to_string());
                        fields.insert("relationship_id".to_string(), id.clone());
                        fields.insert("relationship_type".to_string(), relation_type.clone());
                        fields.insert("relationship_target".to_string(), target.clone());
                        if let Some(mode) = &mode {
                            fields.insert("relationship_target_mode".to_string(), mode.clone());
                        }
                        fields.insert("relationship_external".to_string(), external.to_string());
                        segmenter.emit_source_text(
                            OoxmlTextRole::RelationshipTarget,
                            false,
                            false,
                            fields,
                            &target,
                        )?;
                    }
                    if is_hyperlink {
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
        make_zip_with_method(parts, CompressionMethod::Deflated)
    }

    fn make_zip_with_method(parts: &[(&str, &str)], method: CompressionMethod) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default().compression_method(method);
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

    fn root_relationships(main_part: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdOfficeDocument" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{main_part}"/>
</Relationships>"#
        )
    }

    fn minimal_docx(body: &str) -> Vec<u8> {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml(body);
        let relationships = root_relationships(MAIN_DOCUMENT_PART);
        make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", &relationships),
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
        let values = parsed
            .segments
            .iter()
            .filter(|segment| segment.part_kind == OoxmlPartKind::MainDocument)
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(values.concat(), "splitrun & Привет 😀AB");
        assert!(values.iter().all(|value| !value.contains(['\t', '\n'])));
        assert_eq!(parsed.stats.text_parts_parsed, 2);
        assert!(parsed.stats.opc_start_relationship_present);
    }

    #[test]
    fn preserves_raw_text_in_homogeneous_semantic_segments() {
        let package = minimal_docx(
            r#"<w:p>
<w:r><w:t>Visible</w:t></w:r>
<w:r><w:rPr><w:vanish/></w:rPr><w:t>Hidden</w:t></w:r>
<w:del><w:r><w:delText>Deleted</w:delText></w:r></w:del>
<w:r><w:instrText>HYPERLINK &quot;x&quot;</w:instrText></w:r>
<w:del><w:r><w:delInstrText>DELETEDFIELD</w:delInstrText></w:r></w:del>
<w:r><w:txbxContent><w:p><w:r><w:t>Textbox</w:t></w:r></w:p></w:txbxContent></w:r>
</w:p>"#,
        );
        let parsed = parse_docx(Cursor::new(package)).expect("parse semantic DOCX");

        let find = |needle: &str| {
            parsed
                .segments
                .iter()
                .find(|segment| segment.text.contains(needle))
                .unwrap_or_else(|| panic!("missing semantic segment for {needle:?}"))
        };
        assert_eq!(find("Visible").text_role, OoxmlTextRole::Visible);
        assert!(!find("Visible").hidden);
        assert_eq!(find("Hidden").text_role, OoxmlTextRole::Visible);
        assert!(find("Hidden").hidden);
        assert_eq!(find("Deleted").text_role, OoxmlTextRole::Deleted);
        assert_eq!(find("HYPERLINK").text_role, OoxmlTextRole::FieldInstruction);
        assert_eq!(
            find("DELETEDFIELD").text_role,
            OoxmlTextRole::DeletedFieldInstruction
        );
        assert_eq!(find("Textbox").text_role, OoxmlTextRole::Visible);
        assert!(find("Textbox").in_text_box);
        assert!(parsed
            .segments
            .iter()
            .all(|segment| !segment.text.contains("[role=")));
        assert_eq!(parsed.stats.directly_hidden_text_chars, 6);
        assert_eq!(parsed.stats.text_box_chars, 7);
        assert!(parsed.stats.deleted_text_chars >= 7);
        assert!(parsed.stats.field_instruction_chars >= 13);
        assert!(parsed.semantic_scope_complete);
        assert!(parsed.relationship_scope_complete);
    }

    #[test]
    fn style_and_markup_compatibility_uncertainty_is_disclosed_without_text_loss() {
        let body = r#"<w:p xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
<w:pPr><w:pStyle w:val="ForensicStyle"/></w:pPr>
<w:r><w:rPr><w:rStyle w:val="PossiblyHidden"/></w:rPr><w:t>Styled text</w:t></w:r>
<mc:AlternateContent><mc:Choice Requires="w14"><w:r><w:t>Choice text</w:t></w:r></mc:Choice><mc:Fallback><w:r><w:t>Fallback text</w:t></w:r></mc:Fallback></mc:AlternateContent>
</w:p>"#;
        let parsed = parse_docx(Cursor::new(minimal_docx(body))).expect("parse semantic DOCX");
        let text = text_for_kind(&parsed, OoxmlPartKind::MainDocument);
        assert!(text.contains("Styled text"));
        assert!(text.contains("Choice text"));
        assert!(text.contains("Fallback text"));
        assert!(parsed.stats.run_or_paragraph_style_references >= 2);
        assert_eq!(parsed.stats.alternate_content_blocks, 1);
        assert!(!parsed.semantic_scope_complete);
    }

    #[test]
    fn resolves_nonstandard_opc_main_part_without_assuming_word_document_xml() {
        let main = "custom/story.xml";
        let types = content_types(&[(main, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Nonstandard main</w:t></w:r></w:p>");
        let relationships = root_relationships("/custom/story.xml");
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", &relationships),
            (main, &document),
        ]);

        let parsed = parse_docx(Cursor::new(package)).expect("parse OPC start part");
        let main_segment = parsed
            .segments
            .iter()
            .find(|segment| segment.part_kind == OoxmlPartKind::MainDocument)
            .expect("main document segment");
        assert_eq!(main_segment.part_name, main);
        assert!(main_segment.text.contains("Nonstandard main"));
        assert!(parsed.stats.opc_start_relationship_present);
        assert!(parsed.relationship_scope_complete);
    }

    #[test]
    fn relationship_references_order_stories_and_external_targets_are_not_dereferenced() {
        let types = content_types(&[
            (MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE),
            ("word/header1.xml", HEADER_CONTENT_TYPE),
            ("word/footer1.xml", FOOTER_CONTENT_TYPE),
        ]);
        let document = r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>Body</w:t></w:r></w:p><w:sectPr><w:footerReference r:id="rFooter"/><w:headerReference r:id="rHeader"/></w:sectPr></w:body></w:document>"#;
        let root = root_relationships(MAIN_DOCUMENT_PART);
        let document_relationships = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rHeader" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>
<Relationship Id="rFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
<Relationship Id="rExternal" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://examiner.invalid/do-not-fetch" TargetMode="External"/>
</Relationships>"#;
        let header = r#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Header</w:t></w:r></w:p></w:hdr>"#;
        let footer = r#"<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Footer</w:t></w:r></w:p></w:ftr>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", &root),
            (MAIN_DOCUMENT_PART, document),
            ("word/_rels/document.xml.rels", document_relationships),
            ("word/header1.xml", header),
            ("word/footer1.xml", footer),
        ]);

        let parsed = parse_docx(Cursor::new(package)).expect("parse related stories");
        let story_kinds = parsed
            .segments
            .iter()
            .filter_map(|segment| match segment.part_kind {
                OoxmlPartKind::MainDocument | OoxmlPartKind::Header | OoxmlPartKind::Footer => {
                    Some(segment.part_kind)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            story_kinds,
            vec![
                OoxmlPartKind::MainDocument,
                OoxmlPartKind::Footer,
                OoxmlPartKind::Header
            ]
        );
        let target = parsed
            .segments
            .iter()
            .find(|segment| segment.text.contains("https://examiner.invalid"))
            .expect("external target disclosure");
        assert_eq!(target.text_role, OoxmlTextRole::RelationshipTarget);
        assert_eq!(parsed.stats.external_relationships, 1);
        assert_eq!(parsed.stats.unreferenced_story_parts, 0);
        assert!(parsed.relationship_scope_complete);
    }

    #[test]
    fn unreferenced_story_part_is_extracted_but_relationship_scope_is_incomplete() {
        let types = content_types(&[
            (MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE),
            ("word/header1.xml", HEADER_CONTENT_TYPE),
        ]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let root = root_relationships(MAIN_DOCUMENT_PART);
        let header = r#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Unreferenced header</w:t></w:r></w:p></w:hdr>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", &root),
            (MAIN_DOCUMENT_PART, &document),
            ("word/header1.xml", header),
        ]);

        let parsed = parse_docx(Cursor::new(package)).expect("parse unreferenced story");
        assert!(parsed
            .segments
            .iter()
            .any(|segment| segment.text.contains("Unreferenced header")));
        assert_eq!(parsed.stats.unreferenced_story_parts, 1);
        assert!(!parsed.relationship_scope_complete);
    }

    #[test]
    fn rejects_duplicate_and_root_escaping_relationship_targets() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let duplicate = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="same" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="same" Type="urn:test" Target="word/document.xml"/></Relationships>"#;
        let duplicate_package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", duplicate),
            (MAIN_DOCUMENT_PART, &document),
        ]);
        let error = parse_docx(Cursor::new(duplicate_package)).expect_err("duplicate Id");
        assert_eq!(error.kind, OoxmlErrorKind::InvalidRelationship);
        assert!(error.message.contains("duplicated"));

        let traversal = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="../../word/document.xml"/></Relationships>"#;
        let traversal_package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", traversal),
            (MAIN_DOCUMENT_PART, &document),
        ]);
        let error = parse_docx(Cursor::new(traversal_package)).expect_err("root traversal");
        assert_eq!(error.kind, OoxmlErrorKind::InvalidRelationship);
        assert!(error.message.contains("escapes the package root"));
    }

    #[test]
    fn reports_relationship_cycles_and_dangling_targets_as_incomplete() {
        let types = content_types(&[
            (MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE),
            ("word/header1.xml", HEADER_CONTENT_TYPE),
        ]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let root = root_relationships(MAIN_DOCUMENT_PART);
        let document_relationships = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rCycleA" Type="urn:test" Target="header1.xml"/><Relationship Id="rMissing" Type="urn:test" Target="missing.xml"/></Relationships>"#;
        let header_relationships = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rCycleB" Type="urn:test" Target="document.xml"/></Relationships>"#;
        let header = r#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Header</w:t></w:r></w:p></w:hdr>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", &root),
            (MAIN_DOCUMENT_PART, &document),
            ("word/_rels/document.xml.rels", document_relationships),
            ("word/header1.xml", header),
            ("word/_rels/header1.xml.rels", header_relationships),
        ]);
        let parsed = parse_docx(Cursor::new(package)).expect("parse relationship graph");
        assert_eq!(parsed.stats.dangling_internal_relationships, 1);
        assert!(parsed.stats.relationship_cycles >= 1);
        assert!(!parsed.relationship_scope_complete);
    }

    #[test]
    fn relationship_count_limit_is_a_hard_preflight_failure() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>Body</w:t></w:r></w:p>");
        let root = root_relationships(MAIN_DOCUMENT_PART);
        let document_relationships = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid" TargetMode="External"/></Relationships>"#;
        let package = make_zip(&[
            (CONTENT_TYPES_PART, &types),
            ("_rels/.rels", &root),
            (MAIN_DOCUMENT_PART, &document),
            ("word/_rels/document.xml.rels", document_relationships),
        ]);
        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let error = parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions {
                max_relationships: 1,
                ..Default::default()
            },
            &mut sink,
        )
        .expect_err("relationship limit");
        assert_eq!(error.kind, OoxmlErrorKind::ZipBombSuspected);
        assert!(sink.segments.is_empty());
    }

    #[test]
    fn corrupt_member_crc_is_a_zip_integrity_failure_before_sink_mutation() {
        let types = content_types(&[(MAIN_DOCUMENT_PART, MAIN_DOCUMENT_CONTENT_TYPE)]);
        let document = minimal_document_xml("<w:p><w:r><w:t>CRC-CHECK-BODY</w:t></w:r></w:p>");
        let root = root_relationships(MAIN_DOCUMENT_PART);
        let mut package = make_zip_with_method(
            &[
                (CONTENT_TYPES_PART, &types),
                ("_rels/.rels", &root),
                (MAIN_DOCUMENT_PART, &document),
            ],
            CompressionMethod::Stored,
        );
        let needle = b"CRC-CHECK-BODY";
        let position = package
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("stored document marker");
        package[position] = b'X';

        let mut sink = CollectingSink {
            segments: Vec::new(),
            unsupported_parts: Vec::new(),
        };
        let error = parse_docx_streaming(
            Cursor::new(package),
            OoxmlStreamOptions::default(),
            &mut sink,
        )
        .expect_err("CRC mismatch");
        assert_eq!(error.kind, OoxmlErrorKind::InvalidZip);
        assert_eq!(error.part_name.as_deref(), Some(MAIN_DOCUMENT_PART));
        assert!(sink.segments.is_empty());
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
        let comment = parsed
            .segments
            .iter()
            .find(|segment| segment.part_kind == OoxmlPartKind::Comments)
            .expect("comment text segment");
        assert_eq!(comment.text, "Comment text");
        assert_eq!(
            comment
                .source_fields
                .get("comment_author")
                .map(String::as_str),
            Some("Alice")
        );
        assert_eq!(
            text_for_kind(&parsed, OoxmlPartKind::CoreProperties),
            "Case & EvidenceExaminer"
        );
        let custom_property = parsed
            .segments
            .iter()
            .find(|segment| segment.part_kind == OoxmlPartKind::CustomProperties)
            .expect("custom property segment");
        assert_eq!(custom_property.text, "Gold");
        assert_eq!(
            custom_property
                .source_fields
                .get("property_name")
                .map(String::as_str),
            Some("Matter")
        );
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
        assert_eq!(reconstructed, payload);
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
        assert!(text.contains("/APA.XSL"));
        assert!(text.contains("tail marker"));
        assert!(!text.contains("SelectedStyle"));
        let style_value = segments
            .iter()
            .find(|segment| segment.text == "/APA.XSL")
            .expect("custom XML attribute value");
        assert_eq!(
            style_value
                .source_fields
                .get("xml_attribute")
                .map(String::as_str),
            Some("SelectedStyle")
        );
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
        assert_eq!(text, payload);
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
        assert_eq!(result.stats.text_parts_parsed, 2);
        assert_eq!(result.stats.segments_emitted, 1);
        assert_eq!(sink.segments.len(), 1);
        assert_eq!(sink.segments[0].text, "Hello");
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
    fn streaming_unclosed_xml_fails_during_preflight_before_sink_mutation() {
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
        assert!(!error.message.is_empty());
        assert!(sink.segments.is_empty());
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
