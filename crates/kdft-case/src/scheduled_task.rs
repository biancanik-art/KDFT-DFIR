//! Bounded parser for Windows Task Scheduler XML definitions.

use anyhow::{bail, Context, Result};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;
use quick_xml::XmlVersion;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::BufRead;

const MAX_FIELD_CHARS: usize = 65_536;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScheduledTaskRecord {
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

pub fn parse_scheduled_task<R: BufRead>(input: R) -> Result<ScheduledTaskRecord> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut text_stack = Vec::<String>::new();
    let mut record = ScheduledTaskRecord::default();
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
}
