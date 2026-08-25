//! Bounded parser for Windows Task Scheduler XML definitions.

use anyhow::{bail, Context, Result};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;
use quick_xml::XmlVersion;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{BufRead, Read};

const MAX_FIELD_CHARS: usize = 65_536;
const MAX_XML_DECLARATION_CHARS: usize = 1_024;
pub(crate) const MAX_SCHEDULED_TASK_SOURCE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScheduledTaskRecord {
    pub source_encoding: String,
    pub source_had_byte_order_mark: bool,
    pub task_version: Option<String>,
    pub registration: BTreeMap<String, String>,
    pub principals: Vec<BTreeMap<String, String>>,
    pub settings: BTreeMap<String, String>,
    pub triggers: Vec<BTreeMap<String, String>>,
    pub actions: Vec<BTreeMap<String, String>>,
}

#[derive(Debug)]
struct Component {
    start_depth: usize,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
enum Utf16ByteOrder {
    LittleEndian,
    BigEndian,
}

#[derive(Debug)]
struct DecodedTaskXml {
    text: String,
    encoding: &'static str,
    had_byte_order_mark: bool,
}

pub fn parse_scheduled_task<R: BufRead>(input: R) -> Result<ScheduledTaskRecord> {
    let decoded = decode_task_xml(input)?;
    let mut reader = Reader::from_reader(decoded.text.as_bytes());
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut text_stack = Vec::<String>::new();
    let mut record = ScheduledTaskRecord {
        source_encoding: decoded.encoding.to_string(),
        source_had_byte_order_mark: decoded.had_byte_order_mark,
        ..ScheduledTaskRecord::default()
    };
    let mut saw_task = false;
    let mut principal: Option<Component> = None;
    let mut trigger: Option<Component> = None;
    let mut action: Option<Component> = None;

    loop {
        match reader
            .read_event_into(&mut buffer)
            .context("reading scheduled-task XML")?
        {
            Event::Start(start) => {
                let element = local_name(start.name().as_ref());
                let parent = stack.last().cloned().unwrap_or_default();
                stack.push(element.clone());
                text_stack.push(String::new());
                if stack.len() == 1 && element == "task" {
                    saw_task = true;
                    record.task_version = attribute(&reader, &start, "version")?;
                } else if parent == "principals" && element == "principal" {
                    let mut component = new_component(stack.len(), "principal");
                    insert_attribute(&reader, &start, "id", &mut component.fields)?;
                    principal = Some(component);
                } else if parent == "triggers" && element.ends_with("trigger") {
                    let mut component = new_component(stack.len(), &element);
                    insert_attribute(&reader, &start, "id", &mut component.fields)?;
                    trigger = Some(component);
                } else if parent == "actions"
                    && matches!(
                        element.as_str(),
                        "exec" | "comhandler" | "sendemail" | "showmessage"
                    )
                {
                    let mut component = new_component(stack.len(), &element);
                    insert_attribute(&reader, &start, "id", &mut component.fields)?;
                    action = Some(component);
                }
            }
            Event::Empty(start) => {
                let element = local_name(start.name().as_ref());
                let parent = stack.last().map(String::as_str).unwrap_or("");
                if parent == "triggers" && element.ends_with("trigger") {
                    let mut component = new_component(stack.len() + 1, &element);
                    insert_attribute(&reader, &start, "id", &mut component.fields)?;
                    record.triggers.push(component.fields);
                } else if parent == "actions"
                    && matches!(
                        element.as_str(),
                        "exec" | "comhandler" | "sendemail" | "showmessage"
                    )
                {
                    let mut component = new_component(stack.len() + 1, &element);
                    insert_attribute(&reader, &start, "id", &mut component.fields)?;
                    record.actions.push(component.fields);
                }
            }
            Event::Text(text) => {
                let decoded = decode_xml_text(&text)?;
                let value = decoded.trim();
                if !value.is_empty() && text_stack.is_empty() {
                    bail!("scheduled-task XML contains text outside the root element");
                }
                if let Some(pending) = text_stack.last_mut() {
                    pending.push_str(&decoded);
                }
            }
            Event::GeneralRef(reference) => {
                let decoded = decode_xml_reference(&reference)?;
                let Some(pending) = text_stack.last_mut() else {
                    bail!("scheduled-task XML contains a reference outside the root element");
                };
                pending.push_str(&decoded);
            }
            Event::CData(text) => {
                let decoded = text.decode().context("decoding scheduled-task XML CDATA")?;
                let Some(pending) = text_stack.last_mut() else {
                    bail!("scheduled-task XML contains CDATA outside the root element");
                };
                pending.push_str(&decoded);
            }
            Event::End(_) => {
                let Some(decoded) = text_stack.pop() else {
                    bail!("scheduled-task XML contains an unexpected closing element");
                };
                let value = decoded.trim();
                if !value.is_empty() {
                    let value = bounded(value);
                    let leaf = stack.last().cloned().unwrap_or_default();
                    if let Some(component) = action.as_mut() {
                        insert_repeated(
                            &mut component.fields,
                            &relative_key(&stack, component.start_depth),
                            &value,
                        );
                    } else if let Some(component) = trigger.as_mut() {
                        insert_repeated(
                            &mut component.fields,
                            &relative_key(&stack, component.start_depth),
                            &value,
                        );
                    } else if let Some(component) = principal.as_mut() {
                        insert_repeated(
                            &mut component.fields,
                            &relative_key(&stack, component.start_depth),
                            &value,
                        );
                    } else if stack.starts_with(&["task".into(), "registrationinfo".into()]) {
                        insert_repeated(&mut record.registration, &leaf, &value);
                    } else if stack.starts_with(&["task".into(), "settings".into()]) {
                        insert_repeated(&mut record.settings, &relative_key(&stack, 2), &value);
                    }
                }
                if action
                    .as_ref()
                    .is_some_and(|component| stack.len() == component.start_depth)
                {
                    if let Some(component) = action.take() {
                        record.actions.push(component.fields);
                    }
                }
                if trigger
                    .as_ref()
                    .is_some_and(|component| stack.len() == component.start_depth)
                {
                    if let Some(component) = trigger.take() {
                        record.triggers.push(component.fields);
                    }
                }
                if principal
                    .as_ref()
                    .is_some_and(|component| stack.len() == component.start_depth)
                {
                    if let Some(component) = principal.take() {
                        record.principals.push(component.fields);
                    }
                }
                stack.pop();
            }
            Event::DocType(_) => bail!("scheduled-task XML document types are not supported"),
            Event::Eof => {
                if !stack.is_empty() || !text_stack.is_empty() {
                    bail!("scheduled-task XML ended with unclosed elements");
                }
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    if !saw_task {
        bail!("XML root is not a Windows Task element");
    }
    Ok(record)
}

fn decode_task_xml<R: BufRead>(input: R) -> Result<DecodedTaskXml> {
    let mut bytes = Vec::new();
    let mut limited = input.take((MAX_SCHEDULED_TASK_SOURCE_BYTES as u64) + 1);
    limited
        .read_to_end(&mut bytes)
        .context("reading scheduled-task XML within the source-size limit")?;
    if bytes.len() > MAX_SCHEDULED_TASK_SOURCE_BYTES {
        bail!(
            "scheduled-task XML exceeds the {}-byte safety limit",
            MAX_SCHEDULED_TASK_SOURCE_BYTES
        );
    }

    // Test UTF-32 signatures before UTF-16LE because the UTF-32LE BOM begins
    // with the UTF-16LE BOM. Task Scheduler XML is defined in UTF-8/UTF-16;
    // silently interpreting UTF-32 as UTF-16 would corrupt provenance.
    if bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) || bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00])
    {
        bail!("UTF-32 scheduled-task XML is not supported");
    }

    if let Some(payload) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return Ok(DecodedTaskXml {
            text: std::str::from_utf8(payload)
                .context("scheduled-task XML after the UTF-8 BOM is not valid UTF-8")?
                .to_owned(),
            encoding: "utf-8",
            had_byte_order_mark: true,
        });
    }
    if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16_task_xml(payload, Utf16ByteOrder::LittleEndian, true);
    }
    if let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16_task_xml(payload, Utf16ByteOrder::BigEndian, true);
    }
    if looks_like_bomless_utf16(&bytes, Utf16ByteOrder::LittleEndian) {
        return decode_utf16_task_xml(&bytes, Utf16ByteOrder::LittleEndian, false);
    }
    if looks_like_bomless_utf16(&bytes, Utf16ByteOrder::BigEndian) {
        return decode_utf16_task_xml(&bytes, Utf16ByteOrder::BigEndian, false);
    }

    Ok(DecodedTaskXml {
        text: std::str::from_utf8(&bytes)
            .context("scheduled-task XML is neither valid UTF-8 nor recognizable UTF-16")?
            .to_owned(),
        encoding: "utf-8",
        had_byte_order_mark: false,
    })
}

fn decode_utf16_task_xml(
    bytes: &[u8],
    byte_order: Utf16ByteOrder,
    had_byte_order_mark: bool,
) -> Result<DecodedTaskXml> {
    let encoding = match byte_order {
        Utf16ByteOrder::LittleEndian => "utf-16le",
        Utf16ByteOrder::BigEndian => "utf-16be",
    };
    if !bytes.len().is_multiple_of(2) {
        bail!(
            "scheduled-task {encoding} XML has an odd byte length ({})",
            bytes.len()
        );
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| match byte_order {
            Utf16ByteOrder::LittleEndian => u16::from_le_bytes([pair[0], pair[1]]),
            Utf16ByteOrder::BigEndian => u16::from_be_bytes([pair[0], pair[1]]),
        })
        .collect::<Vec<_>>();
    let mut text = String::from_utf16(&units)
        .with_context(|| format!("scheduled-task {encoding} XML contains invalid UTF-16"))?;

    // quick-xml receives the normalized UTF-8 representation below. Remove
    // only the XML declaration so a truthful source declaration such as
    // encoding="UTF-16" cannot make the reader reinterpret normalized bytes.
    // The declaration carries no Task Scheduler artifact data.
    strip_xml_declaration(&mut text)?;

    Ok(DecodedTaskXml {
        text,
        encoding,
        had_byte_order_mark,
    })
}

fn looks_like_bomless_utf16(bytes: &[u8], byte_order: Utf16ByteOrder) -> bool {
    bytes.chunks_exact(2).take(64).find_map(|pair| {
        let unit = match byte_order {
            Utf16ByteOrder::LittleEndian => u16::from_le_bytes([pair[0], pair[1]]),
            Utf16ByteOrder::BigEndian => u16::from_be_bytes([pair[0], pair[1]]),
        };
        match unit {
            0x0009 | 0x000A | 0x000D | 0x0020 => None,
            0x003C => Some(true),
            _ => Some(false),
        }
    }) == Some(true)
}

fn strip_xml_declaration(text: &mut String) -> Result<()> {
    if !text.starts_with("<?xml") {
        return Ok(());
    }
    let search_end = text.floor_char_boundary(MAX_XML_DECLARATION_CHARS.min(text.len()));
    let Some(relative_end) = text[..search_end].find("?>") else {
        bail!(
            "scheduled-task XML declaration is not closed within {} characters",
            MAX_XML_DECLARATION_CHARS
        );
    };
    text.drain(..relative_end + 2);
    Ok(())
}

fn decode_xml_text(text: &BytesText<'_>) -> Result<String> {
    text.xml10_content()
        .map(|value| value.into_owned())
        .context("decoding scheduled-task XML text")
}

fn decode_xml_reference(reference: &BytesRef<'_>) -> Result<String> {
    if let Some(value) = reference
        .resolve_char_ref()
        .context("decoding scheduled-task XML character reference")?
    {
        return Ok(value.to_string());
    }
    let name = reference
        .decode()
        .context("decoding scheduled-task XML entity name")?;
    resolve_xml_entity(&name)
        .map(str::to_owned)
        .with_context(|| format!("unsupported scheduled-task XML entity reference &{name};"))
}

fn local_name(raw: &[u8]) -> String {
    let name = String::from_utf8_lossy(raw);
    name.rsplit(':')
        .next()
        .unwrap_or(&name)
        .to_ascii_lowercase()
}

fn attribute<R: BufRead>(
    reader: &Reader<R>,
    start: &BytesStart<'_>,
    wanted: &str,
) -> Result<Option<String>> {
    for attribute in start.attributes().with_checks(false) {
        let attribute = attribute.context("reading scheduled-task XML attribute")?;
        if local_name(attribute.key.as_ref()) == wanted {
            return Ok(Some(
                attribute
                    .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                    .context("decoding scheduled-task XML attribute")?
                    .into_owned(),
            ));
        }
    }
    Ok(None)
}

fn insert_attribute<R: BufRead>(
    reader: &Reader<R>,
    start: &BytesStart<'_>,
    name: &str,
    fields: &mut BTreeMap<String, String>,
) -> Result<()> {
    if let Some(value) = attribute(reader, start, name)? {
        fields.insert(name.to_string(), bounded(&value));
    }
    Ok(())
}

fn new_component(start_depth: usize, kind: &str) -> Component {
    let mut fields = BTreeMap::new();
    fields.insert("type".to_string(), kind.to_string());
    Component {
        start_depth,
        fields,
    }
}

fn relative_key(stack: &[String], start_depth: usize) -> String {
    stack
        .iter()
        .skip(start_depth)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(".")
}

fn insert_repeated(fields: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if key.is_empty() {
        return;
    }
    fields
        .entry(key.to_string())
        .and_modify(|existing| {
            if existing != value {
                existing.push_str(" | ");
                existing.push_str(value);
                existing.truncate(existing.floor_char_boundary(MAX_FIELD_CHARS));
            }
        })
        .or_insert_with(|| value.to_string());
}

fn bounded(value: &str) -> String {
    value[..value.floor_char_boundary(MAX_FIELD_CHARS.min(value.len()))].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODING_TEST_AUTHOR: &str = "ACME\\Ștefan 東京";

    fn encoding_test_xml(declared_encoding: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="{declared_encoding}"?>
              <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                <RegistrationInfo><Author>{ENCODING_TEST_AUTHOR}</Author><Description>Δοκιμή</Description></RegistrationInfo>
                <Actions><Exec><Command>powershell.exe</Command></Exec></Actions>
              </Task>"#
        )
    }

    fn utf16_bytes(xml: &str, byte_order: Utf16ByteOrder, with_bom: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if with_bom {
            bytes.extend_from_slice(match byte_order {
                Utf16ByteOrder::LittleEndian => &[0xFF, 0xFE],
                Utf16ByteOrder::BigEndian => &[0xFE, 0xFF],
            });
        }
        for unit in xml.encode_utf16() {
            bytes.extend_from_slice(&match byte_order {
                Utf16ByteOrder::LittleEndian => unit.to_le_bytes(),
                Utf16ByteOrder::BigEndian => unit.to_be_bytes(),
            });
        }
        bytes
    }

    fn assert_encoding_parse(
        bytes: &[u8],
        expected_encoding: &str,
        expected_byte_order_mark: bool,
    ) {
        let record = parse_scheduled_task(bytes).unwrap();
        assert_eq!(record.source_encoding, expected_encoding);
        assert_eq!(record.source_had_byte_order_mark, expected_byte_order_mark);
        assert_eq!(record.registration["author"], ENCODING_TEST_AUTHOR);
        assert_eq!(record.registration["description"], "Δοκιμή");
        assert_eq!(record.actions[0]["command"], "powershell.exe");
    }

    #[test]
    fn parses_principal_trigger_and_exec_action() {
        let xml = br#"<?xml version="1.0"?>
          <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo><Author>ACME\Alice</Author><URI>\Demo\Collect</URI></RegistrationInfo>
            <Principals><Principal id="Author"><UserId>S-1-5-21-1</UserId><LogonType>Password</LogonType></Principal></Principals>
            <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>ACME\Alice</UserId></LogonTrigger></Triggers>
            <Settings><Hidden>false</Hidden><Enabled>true</Enabled></Settings>
            <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-File collect.ps1</Arguments></Exec></Actions>
          </Task>"#;
        let record = parse_scheduled_task(xml.as_slice()).unwrap();
        assert_eq!(record.task_version.as_deref(), Some("1.4"));
        assert_eq!(record.registration["author"], "ACME\\Alice");
        assert_eq!(record.principals[0]["userid"], "S-1-5-21-1");
        assert_eq!(record.triggers[0]["type"], "logontrigger");
        assert_eq!(record.actions[0]["command"], "powershell.exe");
        assert_eq!(record.settings["hidden"], "false");
    }

    #[test]
    fn preserves_entity_references_as_one_field_value() {
        let xml = br#"<?xml version="1.0"?>
          <Task version="1.4">
            <RegistrationInfo><Description>Collect &amp; Review &#x41;</Description></RegistrationInfo>
            <Actions><Exec><Arguments>one&amp;two</Arguments></Exec></Actions>
          </Task>"#;
        let record = parse_scheduled_task(xml.as_slice()).unwrap();
        assert_eq!(record.registration["description"], "Collect & Review A");
        assert_eq!(record.actions[0]["arguments"], "one&two");
    }

    #[test]
    fn rejects_document_type_declarations() {
        let xml = br#"<!DOCTYPE Task [<!ENTITY secret "unsafe">]><Task/>"#;
        let error = parse_scheduled_task(xml.as_slice()).unwrap_err();
        assert!(error.to_string().contains("document types"));
    }

    #[test]
    fn parses_utf8_without_bom() {
        let xml = encoding_test_xml("UTF-8");
        assert_encoding_parse(xml.as_bytes(), "utf-8", false);
    }

    #[test]
    fn parses_utf8_with_bom() {
        let xml = encoding_test_xml("UTF-8");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(xml.as_bytes());
        assert_encoding_parse(&bytes, "utf-8", true);
    }

    #[test]
    fn parses_utf16le_with_bom() {
        let xml = encoding_test_xml("UTF-16");
        let bytes = utf16_bytes(&xml, Utf16ByteOrder::LittleEndian, true);
        assert_encoding_parse(&bytes, "utf-16le", true);
    }

    #[test]
    fn parses_utf16le_without_bom() {
        let xml = encoding_test_xml("UTF-16LE");
        let bytes = utf16_bytes(&xml, Utf16ByteOrder::LittleEndian, false);
        assert_encoding_parse(&bytes, "utf-16le", false);
    }

    #[test]
    fn parses_utf16be_with_bom() {
        let xml = encoding_test_xml("UTF-16");
        let bytes = utf16_bytes(&xml, Utf16ByteOrder::BigEndian, true);
        assert_encoding_parse(&bytes, "utf-16be", true);
    }

    #[test]
    fn parses_utf16be_without_bom() {
        let xml = encoding_test_xml("UTF-16BE");
        let bytes = utf16_bytes(&xml, Utf16ByteOrder::BigEndian, false);
        assert_encoding_parse(&bytes, "utf-16be", false);
    }

    #[test]
    fn rejects_odd_length_utf16() {
        let xml = encoding_test_xml("UTF-16LE");
        let mut bytes = utf16_bytes(&xml, Utf16ByteOrder::LittleEndian, false);
        bytes.pop();
        let error = parse_scheduled_task(bytes.as_slice()).unwrap_err();
        assert!(error.to_string().contains("odd byte length"));
    }

    #[test]
    fn rejects_unpaired_utf16_surrogate() {
        let bytes = [0x3C, 0x00, 0x00, 0xD8];
        let error = parse_scheduled_task(bytes.as_slice()).unwrap_err();
        assert!(error.to_string().contains("invalid UTF-16"));
    }
}
