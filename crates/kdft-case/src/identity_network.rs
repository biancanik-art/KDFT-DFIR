//! High-confidence identity and network derivation shared by embedded Registry
//! and WLAN-profile processing. These helpers never infer an account, address,
//! network, or secret from a loose filename keyword: every finding carries a
//! structured source path and the original source entry remains the authority.

use anyhow::{anyhow, bail, Context, Result};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, BytesText, Event};
use quick_xml::Reader;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

pub(crate) const MAX_WIFI_PROFILE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_STRUCTURED_SECRET_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_XML_DEPTH: usize = 64;
const MAX_XML_EVENTS: usize = 100_000;

#[derive(Debug, Clone)]
pub(crate) struct RegistryObservation {
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub value_data_truncated: bool,
    pub value_file_relative_offset: Option<u64>,
    pub value_size_bytes: Option<u64>,
    pub last_write_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StructuredLead {
    pub artifact_kind: &'static str,
    pub lead_type: &'static str,
    pub label: String,
    pub value: String,
    pub source_key: String,
    pub source_value_name: String,
    pub source_value_file_relative_offset: Option<u64>,
    pub source_value_size_bytes: Option<u64>,
    pub coordinate_space: &'static str,
    pub artifact_time_utc: Option<String>,
}

pub(crate) fn derive_registry_leads(
    hive_name: &str,
    observations: &[RegistryObservation],
) -> Vec<StructuredLead> {
    let hive = hive_name.to_ascii_lowercase();
    let mut seen = HashSet::new();
    let mut leads = Vec::new();
    for observation in observations {
        if observation.value_data_truncated {
            continue;
        }
        let key = observation.key_path.replace('\\', "/");
        let key_lower = key.to_ascii_lowercase();
        let name_lower = observation.value_name.to_ascii_lowercase();
        let value = observation.value_data.trim();
        if !reasonable_registry_text(value) {
            continue;
        }

        let classification = if hive == "system"
            && key_lower.contains("/control/computername/computername")
            && name_lower == "computername"
        {
            Some(("host_identity", "computer_name", "Computer name"))
        } else if hive == "system"
            && key_lower.contains("/services/tcpip/parameters")
            && matches!(
                name_lower.as_str(),
                "hostname" | "nv hostname" | "domain" | "dhcpdomain" | "searchlist"
            )
        {
            Some(("host_identity", "host_or_domain_name", "Host/domain name"))
        } else if hive == "system"
            && key_lower.contains("/services/tcpip/parameters")
            && matches!(
                name_lower.as_str(),
                "ipaddress"
                    | "dhcpipaddress"
                    | "defaultgateway"
                    | "dhcpdefaultgateway"
                    | "nameserver"
                    | "dhcpnameserver"
                    | "dhcpserver"
            )
        {
            Some((
                "network_configuration",
                "ip_dns_gateway_or_dhcp",
                "IP/network configuration",
            ))
        } else if hive == "software"
            && key_lower.contains("/microsoft/windows nt/currentversion/networklist/profiles/")
            && matches!(
                name_lower.as_str(),
                "profilename" | "description" | "dnssuffixname"
            )
        {
            Some((
                "network_configuration",
                "windows_network_profile",
                "Windows network profile",
            ))
        } else if hive == "software"
            && key_lower.contains("/microsoft/windows nt/currentversion")
            && matches!(
                name_lower.as_str(),
                "registeredowner" | "registeredorganization"
            )
        {
            Some(("host_identity", "registered_owner", "Registered owner"))
        } else {
            None
        };

        let Some((artifact_kind, lead_type, label)) = classification else {
            continue;
        };
        if lead_type == "ip_dns_gateway_or_dhcp" && !valid_network_value(value) {
            continue;
        }
        let dedupe = format!(
            "{}\u{1f}{}\u{1f}{}",
            lead_type,
            observation.value_name.to_ascii_lowercase(),
            value.to_ascii_lowercase()
        );
        if !seen.insert(dedupe) {
            continue;
        }
        leads.push(StructuredLead {
            artifact_kind,
            lead_type,
            label: format!("{label}: {value}"),
            value: value.to_string(),
            source_key: observation.key_path.clone(),
            source_value_name: observation.value_name.clone(),
            source_value_file_relative_offset: observation.value_file_relative_offset,
            source_value_size_bytes: observation.value_size_bytes,
            coordinate_space: "Registry hive file-relative cell offset; not decoded-media or acquisition-container physical offset",
            artifact_time_utc: observation.last_write_utc.clone(),
        });
    }
    leads
}

fn reasonable_registry_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16_384
        && !value.chars().any(|character| {
            character == '\0' || (character.is_control() && !character.is_whitespace())
        })
}

fn valid_network_value(value: &str) -> bool {
    let values = value
        .split([',', ';', '|', ' ', '\t', '\r', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    !values.is_empty()
        && values.iter().all(|value| {
            value.parse::<IpAddr>().is_ok()
                || value.eq_ignore_ascii_case("dhcp")
                || value.eq_ignore_ascii_case("none")
        })
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DomainAccountLead {
    pub account_name: String,
    pub domain_name: String,
    pub qualified_account: String,
    pub source_key: String,
    pub source_user_value: String,
    pub source_domain_value: String,
    pub source_user_value_file_relative_offset: Option<u64>,
    pub source_domain_value_file_relative_offset: Option<u64>,
    pub coordinate_space: &'static str,
    pub artifact_time_utc: Option<String>,
}

/// Recovers only explicitly paired Winlogon domain/user fields. A bare
/// username or a path containing an account-looking token is not enough to
/// create a domain-account record, and the output discloses that this is a
/// configured logon identity rather than proof of current AD membership.
pub(crate) fn derive_registry_domain_accounts(
    hive_name: &str,
    observations: &[RegistryObservation],
) -> Vec<DomainAccountLead> {
    if !hive_name.eq_ignore_ascii_case("software") {
        return Vec::new();
    }

    #[derive(Default)]
    struct Pair {
        key: String,
        username: Option<(String, String, Option<String>, Option<u64>)>,
        domain: Option<(String, String, Option<String>, Option<u64>)>,
        alt_username: Option<(String, String, Option<String>, Option<u64>)>,
        alt_domain: Option<(String, String, Option<String>, Option<u64>)>,
    }

    let mut pairs: BTreeMap<String, Pair> = BTreeMap::new();
    for observation in observations {
        if observation.value_data_truncated {
            continue;
        }
        let key = observation.key_path.replace('\\', "/");
        let key_lower = key.to_ascii_lowercase();
        if !key_lower.ends_with("/microsoft/windows nt/currentversion/winlogon") {
            continue;
        }
        let value = observation.value_data.trim();
        if !reasonable_account_component(value) {
            continue;
        }
        let field = (
            value.to_string(),
            observation.value_name.clone(),
            observation.last_write_utc.clone(),
            observation.value_file_relative_offset,
        );
        let pair = pairs.entry(key_lower).or_default();
        pair.key = key;
        match observation.value_name.to_ascii_lowercase().as_str() {
            "defaultusername" => pair.username = Some(field),
            "defaultdomainname" => pair.domain = Some(field),
            "altdefaultusername" => pair.alt_username = Some(field),
            "altdefaultdomainname" => pair.alt_domain = Some(field),
            _ => {}
        }
    }

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for pair in pairs.into_values() {
        for (username, domain) in [
            (pair.username.as_ref(), pair.domain.as_ref()),
            (pair.alt_username.as_ref(), pair.alt_domain.as_ref()),
        ] {
            let (
                Some((username, username_field, username_time, username_offset)),
                Some((domain, domain_field, domain_time, domain_offset)),
            ) = (username, domain)
            else {
                continue;
            };
            if domain == "." || domain.eq_ignore_ascii_case("localhost") {
                continue;
            }
            let dedupe = format!(
                "{}\\{}",
                domain.to_ascii_lowercase(),
                username.to_ascii_lowercase()
            );
            if !seen.insert(dedupe) {
                continue;
            }
            results.push(DomainAccountLead {
                account_name: username.clone(),
                domain_name: domain.clone(),
                qualified_account: format!("{domain}\\{username}"),
                source_key: pair.key.clone(),
                source_user_value: username_field.clone(),
                source_domain_value: domain_field.clone(),
                source_user_value_file_relative_offset: *username_offset,
                source_domain_value_file_relative_offset: *domain_offset,
                coordinate_space: "Registry hive file-relative cell offsets; not decoded-media or acquisition-container physical offsets",
                artifact_time_utc: username_time.clone().or_else(|| domain_time.clone()),
            });
        }
    }
    results
}

fn reasonable_account_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains(['\\', '/'])
        && !value
            .chars()
            .any(|character| character == '\0' || character.is_control())
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct WifiProfile {
    pub profile_name: Option<String>,
    pub ssid: Option<String>,
    pub authentication: Option<String>,
    pub encryption: Option<String>,
    pub key_type: Option<String>,
    pub key_protected: Option<String>,
    pub key_material: Option<String>,
}

pub(crate) fn parse_wifi_profile_xml(bytes: &[u8]) -> Result<WifiProfile> {
    if bytes.len() > MAX_WIFI_PROFILE_BYTES {
        bail!(
            "WLAN profile XML exceeds the {} byte parser limit",
            MAX_WIFI_PROFILE_BYTES
        );
    }
    let text = decode_xml_document(bytes).context("decoding WLAN profile XML")?;
    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<String> = Vec::new();
    let mut text_stack: Vec<String> = Vec::new();
    let mut profile = WifiProfile::default();
    let mut buffer = Vec::new();
    let mut event_count = 0_usize;
    let mut root_seen = false;
    let mut root_closed = false;

    loop {
        event_count = event_count.saturating_add(1);
        if event_count > MAX_XML_EVENTS {
            bail!("WLAN profile XML exceeds the parser event limit");
        }
        match reader
            .read_event_into(&mut buffer)
            .context("reading WLAN profile XML")?
        {
            Event::Start(start) => {
                if root_closed {
                    bail!("WLAN profile XML contains multiple root elements");
                }
                let raw = String::from_utf8_lossy(start.name().as_ref()).to_string();
                let local = raw.rsplit(':').next().unwrap_or(&raw).to_ascii_lowercase();
                if stack.is_empty() {
                    if root_seen || local != "wlanprofile" {
                        bail!("WLAN profile XML root element is not WLANProfile");
                    }
                    root_seen = true;
                }
                if stack.len() >= MAX_XML_DEPTH {
                    bail!("WLAN profile XML exceeds the parser depth limit");
                }
                stack.push(local);
                text_stack.push(String::new());
            }
            Event::End(_) => {
                let Some(value) = text_stack.pop() else {
                    bail!("WLAN profile XML contains an unexpected closing element");
                };
                let value = value.trim();
                if !value.is_empty() {
                    let path = stack.join("/");
                    match path.as_str() {
                        "wlanprofile/name" => set_unique_wifi_field(
                            &mut profile.profile_name,
                            value,
                            "WLANProfile/name",
                        )?,
                        "wlanprofile/ssidconfig/ssid/name" => set_unique_wifi_field(
                            &mut profile.ssid,
                            value,
                            "WLANProfile/SSIDConfig/SSID/name",
                        )?,
                        "wlanprofile/msm/security/authencryption/authentication" => {
                            set_unique_wifi_field(
                                &mut profile.authentication,
                                value,
                                "WLANProfile/MSM/security/authEncryption/authentication",
                            )?
                        }
                        "wlanprofile/msm/security/authencryption/encryption" => {
                            set_unique_wifi_field(
                                &mut profile.encryption,
                                value,
                                "WLANProfile/MSM/security/authEncryption/encryption",
                            )?
                        }
                        "wlanprofile/msm/security/sharedkey/keytype" => set_unique_wifi_field(
                            &mut profile.key_type,
                            value,
                            "WLANProfile/MSM/security/sharedKey/keyType",
                        )?,
                        "wlanprofile/msm/security/sharedkey/protected" => set_unique_wifi_field(
                            &mut profile.key_protected,
                            value,
                            "WLANProfile/MSM/security/sharedKey/protected",
                        )?,
                        "wlanprofile/msm/security/sharedkey/keymaterial" => set_unique_wifi_field(
                            &mut profile.key_material,
                            value,
                            "WLANProfile/MSM/security/sharedKey/keyMaterial",
                        )?,
                        _ => {}
                    }
                    if let Some(parent) = text_stack.last_mut() {
                        parent.push_str(value);
                    }
                }
                stack.pop();
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                let decoded = decode_xml_text(&text)?;
                if let Some(value) = text_stack.last_mut() {
                    value.push_str(&decoded);
                } else if !decoded.chars().all(char::is_whitespace) {
                    bail!("WLAN profile XML contains text outside the root element");
                }
            }
            Event::GeneralRef(reference) => {
                let Some(value) = text_stack.last_mut() else {
                    bail!("WLAN profile XML contains a reference outside the root element");
                };
                value.push_str(&decode_xml_reference(&reference)?);
            }
            Event::CData(text) => {
                let Some(value) = text_stack.last_mut() else {
                    bail!("WLAN profile XML contains CDATA outside the root element");
                };
                value.push_str(&text.decode().context("decoding WLAN profile XML CDATA")?);
            }
            Event::DocType(_) => {
                bail!("WLAN profile XML document types are not supported");
            }
            Event::Eof => {
                if !stack.is_empty() || !text_stack.is_empty() {
                    bail!("WLAN profile XML ended with unclosed elements");
                }
                if !root_seen || !root_closed {
                    bail!("WLAN profile XML has no complete WLANProfile root element");
                }
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    Ok(profile)
}

fn set_unique_wifi_field(target: &mut Option<String>, value: &str, field: &str) -> Result<()> {
    if target.is_some() {
        bail!("WLAN profile XML contains duplicate {field} elements");
    }
    *target = Some(value.to_string());
    Ok(())
}

fn decode_xml_document(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        bail!("XML document is empty");
    }
    if bytes.starts_with(&[0x00, 0x00, 0xfe, 0xff])
        || bytes.starts_with(&[0xff, 0xfe, 0x00, 0x00])
        || bytes.starts_with(&[0x00, 0x00, 0x00, b'<'])
        || bytes.starts_with(&[b'<', 0x00, 0x00, 0x00])
    {
        bail!("UTF-32 XML is recognized but unsupported");
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[b'<', 0x00, b'?', 0x00]) {
        return decode_utf16_xml(
            &bytes[usize::from(bytes.starts_with(&[0xff, 0xfe])) * 2..],
            true,
        );
    }
    if bytes.starts_with(&[0xfe, 0xff]) || bytes.starts_with(&[0x00, b'<', 0x00, b'?']) {
        return decode_utf16_xml(
            &bytes[usize::from(bytes.starts_with(&[0xfe, 0xff])) * 2..],
            false,
        );
    }

    let body = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let declared = declared_xml_encoding(body);
    if declared
        .as_deref()
        .is_none_or(|encoding| matches!(encoding, "utf-8" | "utf8" | "us-ascii"))
    {
        return std::str::from_utf8(body)
            .map(str::to_owned)
            .context("XML is not valid UTF-8");
    }
    let label = declared.context("XML encoding declaration disappeared during validation")?;
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())
        .ok_or_else(|| anyhow!("unsupported XML encoding declaration {label}"))?;
    if matches!(encoding.name(), "UTF-16LE" | "UTF-16BE") {
        bail!("UTF-16 XML without a byte-order mark or recognizable byte order is unsupported");
    }
    let (decoded, _, had_errors) = encoding.decode(body);
    if had_errors {
        bail!("XML contains invalid bytes for declared encoding {label}");
    }
    Ok(decoded.into_owned())
}

fn decode_utf16_xml(bytes: &[u8], little_endian: bool) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        bail!("UTF-16 XML has an odd byte length");
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16(&units).context("XML contains malformed UTF-16")
}

fn declared_xml_encoding(bytes: &[u8]) -> Option<String> {
    let preview = bytes.get(..bytes.len().min(512))?;
    // Only the XML declaration is required to be ASCII-compatible. Decoding a
    // fixed preview as UTF-8 incorrectly rejected valid legacy-encoded XML when
    // a non-ASCII body byte happened to occur inside that preview.
    let declaration_end = preview.windows(2).position(|window| window == b"?>")?;
    let declaration = std::str::from_utf8(preview.get(..declaration_end)?)
        .ok()?
        .trim_start();
    if !declaration.starts_with("<?xml") {
        return None;
    }
    let lower = declaration.to_ascii_lowercase();
    let mut search_from = 0_usize;
    let start = loop {
        let relative = lower.get(search_from..)?.find("encoding")?;
        let candidate = search_from + relative;
        let before_ok = candidate == 0 || lower.as_bytes()[candidate - 1].is_ascii_whitespace();
        let after = candidate + "encoding".len();
        let after_ok = lower
            .as_bytes()
            .get(after)
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'=');
        if before_ok && after_ok {
            break after;
        }
        search_from = after;
    };
    let rest = declaration.get(start..)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let value = rest.get(1..)?.split(quote).next()?.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

fn decode_xml_text(text: &BytesText<'_>) -> Result<String> {
    text.xml10_content()
        .map(|value| value.into_owned())
        .context("decoding XML text")
}

fn decode_xml_reference(reference: &BytesRef<'_>) -> Result<String> {
    if let Some(value) = reference
        .resolve_char_ref()
        .context("decoding XML character reference")?
    {
        return Ok(value.to_string());
    }
    let name = reference.decode().context("decoding XML entity name")?;
    resolve_xml_entity(&name)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("unsupported XML entity reference &{name};"))
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub(crate) struct CredentialStoreRecognition {
    pub store_type: &'static str,
    pub recognition_basis: &'static str,
    pub confidence: &'static str,
    pub structure_validated: bool,
}

/// Recognizes credential-store *locations* only when the basename and a known
/// parent layout agree. This deliberately does not claim that the file is
/// structurally valid or that any contained credential can be decrypted.
pub(crate) fn known_credential_store_type(
    path: &str,
    name: &str,
) -> Option<CredentialStoreRecognition> {
    let normalized = normalized_full_path(path, name);
    let filename = name.trim().to_ascii_lowercase();
    let recognized = |store_type, recognition_basis, confidence| CredentialStoreRecognition {
        store_type,
        recognition_basis,
        confidence,
        structure_validated: false,
    };
    if matches!(filename.as_str(), "sam" | "security")
        && (normalized.ends_with(&format!("/windows/system32/config/{filename}"))
            || normalized.ends_with(&format!("/winnt/system32/config/{filename}"))
            || normalized.ends_with(&format!("/windows/system32/config/regback/{filename}")))
    {
        Some(recognized(
            "Windows account credential database",
            "standard Windows Registry hive path and basename",
            "high",
        ))
    } else if filename == "ntds.dit" && normalized.ends_with("/windows/ntds/ntds.dit") {
        Some(recognized(
            "Active Directory database",
            "standard Windows NTDS path and basename",
            "high",
        ))
    } else if filename == "login data"
        && normalized.ends_with("/login data")
        && [
            "/google/chrome/",
            "/microsoft/edge/",
            "/chromium/",
            "/brave-browser/",
        ]
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        Some(recognized(
            "Chromium saved-login database",
            "known Chromium profile layout and exact database basename",
            "high",
        ))
    } else if matches!(filename.as_str(), "logins.json" | "key4.db" | "key3.db")
        && normalized.contains("/mozilla/firefox/profiles/")
    {
        Some(recognized(
            "Firefox saved-login store component",
            "known Firefox profile layout and exact component basename",
            "high",
        ))
    } else if filename.ends_with(".kdbx") || filename.ends_with(".psafe3") {
        Some(recognized(
            "Password manager database candidate",
            "recognized password-manager filename extension; file structure not validated",
            "medium",
        ))
    } else if normalized.contains("/microsoft/credentials/")
        || normalized.contains("/microsoft/vault/")
        || ((filename.ends_with(".vcrd") || filename.ends_with(".vpol"))
            && normalized.contains("/microsoft/vault/"))
    {
        Some(recognized(
            "Windows Credential Manager or Vault component",
            "known Windows credential/vault directory layout",
            "high",
        ))
    } else if normalized.contains("/microsoft/protect/") {
        Some(recognized(
            "Windows DPAPI master-key component",
            "known Windows DPAPI Protect directory layout",
            "high",
        ))
    } else if normalized.contains("/.ssh/")
        && matches!(
            filename.as_str(),
            "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519"
        )
    {
        Some(recognized(
            "SSH private-key candidate",
            "known SSH private-key basename under an .ssh directory; key structure not validated",
            "high",
        ))
    } else if filename == "credentials" && normalized.ends_with("/.aws/credentials") {
        Some(recognized(
            "AWS credential configuration",
            "exact AWS CLI credential path",
            "high",
        ))
    } else if matches!(
        filename.as_str(),
        "accesstokens.json" | "azureprofile.json" | "msal_token_cache.json"
    ) && (normalized.contains("/.azure/")
        || normalized.contains("/microsoft/identitycache/")
        || normalized.contains("/microsoft/identityservice/"))
    {
        Some(recognized(
            "Cloud authentication token-store candidate",
            "known cloud-authentication path and exact component basename",
            "high",
        ))
    } else {
        None
    }
}

fn normalized_full_path(path: &str, name: &str) -> String {
    let mut normalized = path.replace('\\', "/").to_ascii_lowercase();
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    // Indexed source paths are commonly volume-relative (for example,
    // `Windows/System32/config/SAM`).  Canonicalize both relative and absolute
    // forms so suffix-based layout checks do not depend on a leading slash.
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    let filename = name.trim().to_ascii_lowercase();
    if normalized
        .rsplit('/')
        .next()
        .is_none_or(|tail| tail != filename)
    {
        normalized.push('/');
        normalized.push_str(&filename);
    }
    normalized
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct StructuredSecretLead {
    pub key: String,
    pub value_length_bytes: usize,
    pub value_sha256: String,
    pub material_state: &'static str,
    pub source_location: String,
    pub source_format: &'static str,
    pub hash_basis: &'static str,
}

pub(crate) fn known_structured_secret_source(path: &str, name: &str) -> bool {
    let normalized = normalized_full_path(path, name);
    let filename = name.to_ascii_lowercase();
    filename == ".env"
        || filename.starts_with(".env.")
        || filename == ".git-credentials"
        || filename == ".netrc"
        || filename == ".npmrc"
        || filename == ".pypirc"
        || filename == "pip.conf"
        || filename == "unattend.xml"
        || filename == "autounattend.xml"
        || filename == "accesstokens.json"
        || filename == "application_default_credentials.json"
        || filename == "msal_token_cache.json"
        || (filename == "credentials" && normalized.contains("/.aws/"))
        || (filename == "config.json" && normalized.contains("/.docker/"))
        || (filename == "config" && normalized.contains("/.kube/"))
        || (filename == "secrets.json" && normalized.contains("/microsoft/usersecrets/"))
}

pub(crate) fn parse_structured_secret_leads(
    path: &str,
    name: &str,
    bytes: &[u8],
) -> Result<Vec<StructuredSecretLead>> {
    if bytes.len() > MAX_STRUCTURED_SECRET_SOURCE_BYTES {
        bail!(
            "structured secret source exceeds the {} byte parser limit",
            MAX_STRUCTURED_SECRET_SOURCE_BYTES
        );
    }
    let text = decode_text_file(bytes)?;
    let filename = name.to_ascii_lowercase();
    let mut leads = if filename == ".git-credentials" {
        parse_git_credential_urls(&text)
    } else if filename == ".netrc" {
        parse_netrc_secrets(&text)
    } else if filename.ends_with(".json") {
        parse_json_secret_leads(&text, &normalized_full_path(path, name))?
    } else if filename == "unattend.xml" || filename == "autounattend.xml" {
        parse_xml_secret_leads(&text)?
    } else {
        parse_assignment_secret_leads(&text)
    };
    let mut seen = HashSet::new();
    leads.retain(|lead| {
        seen.insert(format!(
            "{}\u{1f}{}\u{1f}{}",
            lead.key.to_ascii_lowercase(),
            lead.value_sha256,
            lead.source_location
        ))
    });
    for lead in &mut leads {
        lead.source_location = format!("{path}:{}", lead.source_location);
    }
    Ok(leads)
}

fn decode_text_file(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        if !bytes.len().is_multiple_of(2) {
            bail!("UTF-16LE text has an odd byte length");
        }
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).context("structured secret source contains malformed UTF-16LE")
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        if !bytes.len().is_multiple_of(2) {
            bail!("UTF-16BE text has an odd byte length");
        }
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).context("structured secret source contains malformed UTF-16BE")
    } else {
        std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .map(str::to_owned)
            .context("structured secret source is not valid UTF-8")
    }
}

fn normalized_secret_key(key: &str) -> String {
    let key = key
        .trim()
        .trim_matches(['"', '\'', '<', '>', '/'])
        .to_ascii_lowercase()
        .replace(['-', '.'], "_");
    key.rsplit(['/', ':'])
        .next()
        .unwrap_or(&key)
        .trim_matches('_')
        .to_string()
}

fn is_secret_key(key: &str) -> bool {
    let key = normalized_secret_key(key);
    // Structured formats commonly use camel/Pascal case (AccessToken,
    // AdministratorPassword, ClientSecret). Compare a compact form as well as
    // the separator-preserving form, while retaining exact suffix boundaries
    // so labels such as DisplayTokenName are not promoted.
    let compact = key.replace('_', "");
    key == "password"
        || key == "passwd"
        || key == "pwd"
        || key == "secret"
        || key == "token"
        || key == "api_key"
        || key == "apikey"
        || key == "access_token"
        || key == "refresh_token"
        || key == "id_token"
        || key == "auth_token"
        || key == "authtoken"
        || key == "aws_access_key_id"
        || key == "aws_secret_access_key"
        || key == "aws_session_token"
        || key.ends_with("_password")
        || key.ends_with("_passwd")
        || key.ends_with("_secret")
        || key.ends_with("_token")
        || key.ends_with("_api_key")
        || key.ends_with("_access_key")
        || key.ends_with("_private_key")
        || key.ends_with("_client_secret")
        || key.ends_with("_session_key")
        || key.ends_with("_connection_string")
        || compact == "password"
        || compact == "passwd"
        || compact == "pwd"
        || compact == "secret"
        || compact == "token"
        || compact == "apikey"
        || compact == "accesstoken"
        || compact == "refreshtoken"
        || compact == "idtoken"
        || compact == "authtoken"
        || compact == "awsaccesskeyid"
        || compact == "awssecretaccesskey"
        || compact == "awssessiontoken"
        || compact.ends_with("password")
        || compact.ends_with("passwd")
        || compact.ends_with("clientsecret")
        || compact.ends_with("privatekey")
        || compact.ends_with("sessionkey")
        || compact.ends_with("connectionstring")
}

fn structured_secret_lead(
    key: impl Into<String>,
    value: &str,
    source_location: impl Into<String>,
    source_format: &'static str,
    material_state: &'static str,
) -> Option<StructuredSecretLead> {
    let value = strip_matching_quotes(value.trim());
    if value.is_empty() || is_secret_placeholder(value) {
        return None;
    }
    Some(StructuredSecretLead {
        key: key.into(),
        value_length_bytes: value.len(),
        value_sha256: format!("{:x}", Sha256::digest(value.as_bytes())),
        material_state,
        source_location: source_location.into(),
        source_format,
        hash_basis: "decoded structured field encoded as UTF-8; the value itself is withheld",
    })
}

fn strip_matching_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'"', b'"') | (b'\'', b'\'')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn is_secret_placeholder(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "null" | "none" | "<redacted>" | "[redacted]" | "redacted" | "***redacted***"
    ) || (value.starts_with("${") && value.ends_with('}'))
        || (value.starts_with("{{") && value.ends_with("}}"))
        || (value.starts_with('%') && value.ends_with('%'))
        || (value.len() >= 4
            && value
                .chars()
                .all(|character| matches!(character, '*' | 'x' | 'X')))
}

fn parse_assignment_secret_leads(text: &str) -> Vec<StructuredSecretLead> {
    let mut leads = Vec::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }
        let pair = line.split_once('=').or_else(|| line.split_once(':'));
        let Some((key, value)) = pair else { continue };
        let key = key.trim().trim_start_matches("export ").trim();
        if !is_secret_key(key) {
            continue;
        }
        if let Some(lead) = structured_secret_lead(
            key,
            value,
            format!("line {} key {}", line_index + 1, key),
            "structured assignment",
            "textual_value_in_source",
        ) {
            leads.push(lead);
        }
    }
    leads
}

fn parse_json_secret_leads(text: &str, source_path: &str) -> Result<Vec<StructuredSecretLead>> {
    let value = serde_json::from_str::<serde_json::Value>(text)
        .context("parsing structured secret JSON")?;
    let mut leads = Vec::new();
    collect_json_secrets(&value, "#", source_path, 0, &mut leads)?;
    Ok(leads)
}

fn collect_json_secrets(
    value: &serde_json::Value,
    path: &str,
    source_path: &str,
    depth: usize,
    leads: &mut Vec<StructuredSecretLead>,
) -> Result<()> {
    if depth > MAX_XML_DEPTH {
        bail!("structured secret JSON exceeds the parser depth limit");
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                let child_path = format!("{path}/{escaped}");
                let docker_auth = key.eq_ignore_ascii_case("auth")
                    && source_path.ends_with("/.docker/config.json")
                    && path.starts_with("#/auths/");
                if is_secret_key(key) || docker_auth {
                    if let Some(value) = value.as_str().filter(|value| !value.is_empty()) {
                        if let Some(lead) = structured_secret_lead(
                            key,
                            value,
                            child_path.clone(),
                            "JSON",
                            if docker_auth {
                                "base64_encoded_value_in_source"
                            } else {
                                "textual_value_in_source"
                            },
                        ) {
                            leads.push(lead);
                        }
                    }
                }
                collect_json_secrets(value, &child_path, source_path, depth + 1, leads)?;
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_json_secrets(
                    value,
                    &format!("{path}/{index}"),
                    source_path,
                    depth + 1,
                    leads,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_xml_secret_leads(text: &str) -> Result<Vec<StructuredSecretLead>> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut text_stack = Vec::<String>::new();
    let mut leaves = Vec::<(Vec<String>, String)>::new();
    let mut root_seen = false;
    let mut root_closed = false;
    let mut event_count = 0_usize;
    loop {
        event_count = event_count.saturating_add(1);
        if event_count > MAX_XML_EVENTS {
            bail!("structured secret XML exceeds the parser event limit");
        }
        match reader
            .read_event_into(&mut buffer)
            .context("reading structured secret XML")?
        {
            Event::Start(start) => {
                if root_closed {
                    bail!("structured secret XML contains multiple root elements");
                }
                let raw = String::from_utf8_lossy(start.name().as_ref()).to_string();
                if stack.is_empty() {
                    if root_seen {
                        bail!("structured secret XML contains multiple root elements");
                    }
                    root_seen = true;
                }
                if stack.len() >= MAX_XML_DEPTH {
                    bail!("structured secret XML exceeds the parser depth limit");
                }
                stack.push(raw.rsplit(':').next().unwrap_or(&raw).to_string());
                text_stack.push(String::new());
            }
            Event::End(_) => {
                let (Some(key), Some(value)) = (stack.pop(), text_stack.pop()) else {
                    bail!("structured secret XML contains an unexpected closing element");
                };
                let value = value.trim();
                if !value.is_empty() {
                    let mut path = stack.clone();
                    path.push(key);
                    leaves.push((path, value.to_string()));
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                let decoded = decode_xml_text(&text)?;
                if let Some(value) = text_stack.last_mut() {
                    value.push_str(&decoded);
                } else if !decoded.chars().all(char::is_whitespace) {
                    bail!("structured secret XML contains text outside the root element");
                }
            }
            Event::GeneralRef(reference) => {
                let Some(value) = text_stack.last_mut() else {
                    bail!("structured secret XML contains a reference outside the root element");
                };
                value.push_str(&decode_xml_reference(&reference)?);
            }
            Event::CData(text) => {
                let Some(value) = text_stack.last_mut() else {
                    bail!("structured secret XML contains CDATA outside the root element");
                };
                value.push_str(
                    &text
                        .decode()
                        .context("decoding structured secret XML CDATA")?,
                );
            }
            Event::DocType(_) => bail!("structured secret XML document types are not supported"),
            Event::Eof => {
                if !stack.is_empty() || !text_stack.is_empty() {
                    bail!("structured secret XML ended with unclosed elements");
                }
                if !root_seen || !root_closed {
                    bail!("structured secret XML has no complete root element");
                }
                break;
            }
            _ => {}
        }
        buffer.clear();
    }

    let mut plaintext_flags = BTreeMap::<String, bool>::new();
    for (path, value) in &leaves {
        if path
            .last()
            .is_some_and(|element| element.eq_ignore_ascii_case("plaintext"))
        {
            plaintext_flags.insert(
                xml_parent_path(path),
                value.trim().eq_ignore_ascii_case("true"),
            );
        }
    }
    let mut leads = Vec::new();
    for (path, value) in leaves {
        let Some(last) = path.last() else { continue };
        let secret_element = is_secret_key(last);
        let wrapped_value = last.eq_ignore_ascii_case("value")
            && path[..path.len().saturating_sub(1)]
                .iter()
                .any(|element| is_secret_key(element));
        if !secret_element && !wrapped_value {
            continue;
        }
        let parent_path = xml_parent_path(&path);
        let state = match plaintext_flags.get(&parent_path) {
            Some(true) => "textual_value_in_source",
            Some(false) => "encoded_or_protected_value_in_source",
            None => "protection_state_unknown",
        };
        let key = if wrapped_value {
            path[..path.len() - 1]
                .iter()
                .rev()
                .find(|element| is_secret_key(element))
                .cloned()
                .unwrap_or_else(|| last.clone())
        } else {
            last.clone()
        };
        if let Some(lead) =
            structured_secret_lead(key, &value, format!("/{}", path.join("/")), "XML", state)
        {
            leads.push(lead);
        }
    }
    Ok(leads)
}

fn xml_parent_path(path: &[String]) -> String {
    path[..path.len().saturating_sub(1)]
        .join("/")
        .to_ascii_lowercase()
}

fn parse_git_credential_urls(text: &str) -> Vec<StructuredSecretLead> {
    let mut leads = Vec::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(scheme_end) = line.find("://") else {
            continue;
        };
        let authority = &line[scheme_end + 3..];
        let Some(at) = authority.rfind('@') else {
            continue;
        };
        let user_info = &authority[..at];
        let Some((username, password)) = user_info.split_once(':') else {
            continue;
        };
        if let Some(lead) = structured_secret_lead(
            format!("credential for {username}"),
            password,
            format!("line {} URL user-info password", line_index + 1),
            "Git credential URL",
            "url_userinfo_value_in_source",
        ) {
            leads.push(lead);
        }
    }
    leads
}

fn parse_netrc_secrets(text: &str) -> Vec<StructuredSecretLead> {
    let tokens = text
        .lines()
        .enumerate()
        .flat_map(|(line_index, line)| {
            line.split_once('#')
                .map(|(before, _)| before)
                .unwrap_or(line)
                .split_whitespace()
                .map(move |token| (token, line_index + 1))
        })
        .collect::<Vec<_>>();
    let mut leads = Vec::new();
    let mut machine = "unspecified";
    let mut index = 0;
    while index + 1 < tokens.len() {
        match tokens[index].0.to_ascii_lowercase().as_str() {
            "machine" => machine = tokens[index + 1].0,
            "default" => machine = "default",
            "password" => {
                if let Some(lead) = structured_secret_lead(
                    format!("password for {machine}"),
                    tokens[index + 1].0,
                    format!("line {} password token", tokens[index].1),
                    "netrc",
                    "textual_value_in_source",
                ) {
                    leads.push(lead);
                }
            }
            _ => {}
        }
        index += 1;
    }
    leads
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    #[test]
    fn exact_assignment_and_json_secrets_are_summarized_without_value_disclosure() {
        let env = parse_structured_secret_leads(
            "/Users/Alice/project/.env",
            ".env",
            b"STARTUP_LABEL=ignore\nAPI_TOKEN=abc123\nPASSWORD=hunter2\n",
        )
        .unwrap();
        assert_eq!(env.len(), 2);
        assert!(env.iter().any(|lead| lead.key == "API_TOKEN"));
        assert!(!env.iter().any(|lead| lead.key == "STARTUP_LABEL"));
        assert!(env.iter().any(|lead| lead.value_sha256 == digest("abc123")));
        let serialized = serde_json::to_string(&env).unwrap();
        assert!(!serialized.contains("abc123"));
        assert!(!serialized.contains("hunter2"));

        let json = parse_structured_secret_leads(
            "/Users/Alice/AppData/Roaming/Microsoft/UserSecrets/x/secrets.json",
            "secrets.json",
            br#"{"Database":{"Password":"db-pass"},"DisplayTokenName":"not-secret"}"#,
        )
        .unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0].value_sha256, digest("db-pass"));
        assert_eq!(
            json[0].source_location,
            "/Users/Alice/AppData/Roaming/Microsoft/UserSecrets/x/secrets.json:#/Database/Password"
        );
        assert!(!serde_json::to_string(&json).unwrap().contains("db-pass"));
    }

    #[test]
    fn domain_account_requires_an_explicit_winlogon_domain_user_pair() {
        let observations = vec![
            RegistryObservation {
                key_path: "ROOT/Microsoft/Windows NT/CurrentVersion/Winlogon".to_string(),
                value_name: "DefaultDomainName".to_string(),
                value_data: "CONTOSO".to_string(),
                value_data_truncated: false,
                value_file_relative_offset: Some(0x1000),
                value_size_bytes: Some(14),
                last_write_utc: Some("2024-01-02T03:04:05Z".to_string()),
            },
            RegistryObservation {
                key_path: "ROOT/Microsoft/Windows NT/CurrentVersion/Winlogon".to_string(),
                value_name: "DefaultUserName".to_string(),
                value_data: "alice".to_string(),
                value_data_truncated: false,
                value_file_relative_offset: Some(0x1100),
                value_size_bytes: Some(10),
                last_write_utc: Some("2024-01-02T03:04:05Z".to_string()),
            },
            RegistryObservation {
                key_path: "ROOT/Unrelated".to_string(),
                value_name: "TokenUser".to_string(),
                value_data: "must-not-be-an-account".to_string(),
                value_data_truncated: false,
                value_file_relative_offset: None,
                value_size_bytes: None,
                last_write_utc: None,
            },
        ];
        let accounts = derive_registry_domain_accounts("SOFTWARE", &observations);
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].qualified_account, "CONTOSO\\alice");
        assert_eq!(accounts[0].source_user_value, "DefaultUserName");

        let unpaired = derive_registry_domain_accounts("SOFTWARE", &observations[..1]);
        assert!(unpaired.is_empty());
        assert!(derive_registry_domain_accounts("SYSTEM", &observations).is_empty());
    }

    #[test]
    fn cloud_token_store_names_match_case_insensitively_without_keyword_guessing() {
        let recognition = known_credential_store_type(
            "/Users/Alice/.azure/accessTokens.json",
            "accessTokens.json",
        )
        .unwrap();
        assert_eq!(
            recognition.store_type,
            "Cloud authentication token-store candidate"
        );
        assert!(!recognition.structure_validated);
        assert!(known_credential_store_type(
            "/Users/Alice/Documents/token-notes.txt",
            "token-notes.txt"
        )
        .is_none());
        assert!(known_credential_store_type("Windows/System32/config/SAM", "SAM").is_some());
        assert!(
            known_credential_store_type("Windows/System32/config/SECURITY", "SECURITY").is_some()
        );
        assert!(known_credential_store_type("/Temp/SAM", "SAM").is_none());
        assert!(known_credential_store_type("/Temp/Login Data", "Login Data").is_none());
    }

    #[test]
    fn wlan_profile_preserves_entity_references() {
        let profile = parse_wifi_profile_xml(
            br#"<WLANProfile><name>Lab &amp; Field</name><SSIDConfig><SSID><name>Wi&#x2D;Fi</name></SSID></SSIDConfig><MSM><security><sharedKey><keyMaterial>a&amp;b</keyMaterial></sharedKey></security></MSM></WLANProfile>"#,
        )
        .unwrap();
        assert_eq!(profile.profile_name.as_deref(), Some("Lab & Field"));
        assert_eq!(profile.ssid.as_deref(), Some("Wi-Fi"));
        assert_eq!(profile.key_material.as_deref(), Some("a&b"));
    }

    #[test]
    fn wlan_profile_supports_utf16_and_rejects_doctype_and_wrong_root() {
        let source = "<?xml version=\"1.0\" encoding=\"utf-16\"?><WLANProfile><name>Field</name><SSIDConfig><SSID><name>Lab</name></SSID></SSIDConfig></WLANProfile>";
        let mut encoded = vec![0xff, 0xfe];
        for unit in source.encode_utf16() {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
        let profile = parse_wifi_profile_xml(&encoded).unwrap();
        assert_eq!(profile.ssid.as_deref(), Some("Lab"));
        assert!(parse_wifi_profile_xml(b"<!DOCTYPE WLANProfile><WLANProfile/>").is_err());
        assert!(parse_wifi_profile_xml(b"<not-a-profile/>").is_err());
        assert!(parse_wifi_profile_xml(&vec![b'x'; MAX_WIFI_PROFILE_BYTES + 1]).is_err());
    }

    #[test]
    fn xml_secret_is_hashed_and_not_split_at_entity_references() {
        let leads =
            parse_xml_secret_leads("<config><password>a&amp;b&#x31;</password></config>").unwrap();
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].key, "password");
        assert_eq!(leads[0].value_sha256, digest("a&b1"));
        assert_eq!(leads[0].source_location, "/config/password");
        assert_eq!(leads[0].material_state, "protection_state_unknown");
        assert!(!serde_json::to_string(&leads).unwrap().contains("a&b1"));
    }

    #[test]
    fn unattend_wrapped_password_honors_plaintext_flag_without_disclosing_value() {
        let leads = parse_xml_secret_leads(
            "<unattend><AdministratorPassword><Value>encoded-value</Value><PlainText>false</PlainText></AdministratorPassword></unattend>",
        )
        .unwrap();
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].key, "AdministratorPassword");
        assert_eq!(
            leads[0].material_state,
            "encoded_or_protected_value_in_source"
        );
        assert_eq!(leads[0].value_sha256, digest("encoded-value"));
        assert!(!serde_json::to_string(&leads)
            .unwrap()
            .contains("encoded-value"));
        assert!(parse_xml_secret_leads(
            "<!DOCTYPE unattend [<!ENTITY x 'secret'>]><unattend><password>&x;</password></unattend>"
        )
        .is_err());
    }

    #[test]
    fn docker_auth_is_exactly_scoped_and_malformed_json_is_a_diagnostic() {
        let docker = parse_structured_secret_leads(
            "/Users/Alice/.docker/config.json",
            "config.json",
            br#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}},"auth":"not-a-store-secret"}"#,
        )
        .unwrap();
        assert_eq!(docker.len(), 1);
        assert_eq!(docker[0].material_state, "base64_encoded_value_in_source");
        assert_eq!(
            docker[0].source_location,
            "/Users/Alice/.docker/config.json:#/auths/registry.example/auth"
        );
        assert!(!serde_json::to_string(&docker)
            .unwrap()
            .contains("dXNlcjpwYXNz"));
        assert!(parse_structured_secret_leads(
            "/Users/Alice/.docker/config.json",
            "config.json",
            br#"{"auths": "#,
        )
        .is_err());
    }

    #[test]
    fn assignment_parser_ignores_placeholders_and_generic_auth_modes() {
        let leads = parse_structured_secret_leads(
            "/Users/Alice/project/.env",
            ".env",
            b"PASSWORD=${PASSWORD}\nAUTH=negotiate\nAPI_TOKEN=real-value\nMASKED=********\n",
        )
        .unwrap();
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].key, "API_TOKEN");
    }

    #[test]
    fn invalid_network_strings_are_not_promoted_to_structured_network_facts() {
        let observations = vec![RegistryObservation {
            key_path: "ROOT/ControlSet001/Services/Tcpip/Parameters".to_string(),
            value_name: "NameServer".to_string(),
            value_data: "not an IP address".to_string(),
            value_data_truncated: false,
            value_file_relative_offset: Some(0x2000),
            value_size_bytes: Some(34),
            last_write_utc: None,
        }];
        assert!(derive_registry_leads("SYSTEM", &observations).is_empty());
    }
}
