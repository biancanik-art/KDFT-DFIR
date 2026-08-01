//! High-confidence identity and network derivation shared by embedded Registry
//! and WLAN-profile processing. These helpers never infer an account, address,
//! network, or secret from a loose filename keyword: every finding carries a
//! structured source path and the original source entry remains the authority.

use anyhow::{anyhow, bail, Context, Result};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, BytesText, Event};
use quick_xml::Reader;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub(crate) struct RegistryObservation {
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
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
        let key = observation.key_path.replace('\\', "/");
        let key_lower = key.to_ascii_lowercase();
        let name_lower = observation.value_name.to_ascii_lowercase();
        let value = observation.value_data.trim();
        if value.is_empty() {
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
            artifact_time_utc: observation.last_write_utc.clone(),
        });
    }
    leads
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DomainAccountLead {
    pub account_name: String,
    pub domain_name: String,
    pub qualified_account: String,
    pub source_key: String,
    pub source_user_value: String,
    pub source_domain_value: String,
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
        username: Option<(String, String, Option<String>)>,
        domain: Option<(String, String, Option<String>)>,
        alt_username: Option<(String, String, Option<String>)>,
        alt_domain: Option<(String, String, Option<String>)>,
    }

    let mut pairs: BTreeMap<String, Pair> = BTreeMap::new();
    for observation in observations {
        let key = observation.key_path.replace('\\', "/");
        let key_lower = key.to_ascii_lowercase();
        if !key_lower.ends_with("/microsoft/windows nt/currentversion/winlogon") {
            continue;
        }
        let value = observation.value_data.trim();
        if value.is_empty() {
            continue;
        }
        let field = (
            value.to_string(),
            observation.value_name.clone(),
            observation.last_write_utc.clone(),
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
                Some((username, username_field, username_time)),
                Some((domain, domain_field, domain_time)),
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
                artifact_time_utc: username_time.clone().or_else(|| domain_time.clone()),
            });
        }
    }
    results
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
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<String> = Vec::new();
    let mut text_stack: Vec<String> = Vec::new();
    let mut profile = WifiProfile::default();
    let mut buffer = Vec::new();

    loop {
        match reader
            .read_event_into(&mut buffer)
            .context("reading WLAN profile XML")?
        {
            Event::Start(start) => {
                let raw = String::from_utf8_lossy(start.name().as_ref()).to_string();
                stack.push(raw.rsplit(':').next().unwrap_or(&raw).to_ascii_lowercase());
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
                        "wlanprofile/name" => profile.profile_name = Some(value.to_string()),
                        "wlanprofile/ssidconfig/ssid/name" => {
                            profile.ssid = Some(value.to_string())
                        }
                        "wlanprofile/msm/security/authencryption/authentication" => {
                            profile.authentication = Some(value.to_string())
                        }
                        "wlanprofile/msm/security/authencryption/encryption" => {
                            profile.encryption = Some(value.to_string())
                        }
                        "wlanprofile/msm/security/sharedkey/keytype" => {
                            profile.key_type = Some(value.to_string())
                        }
                        "wlanprofile/msm/security/sharedkey/protected" => {
                            profile.key_protected = Some(value.to_string())
                        }
                        "wlanprofile/msm/security/sharedkey/keymaterial" => {
                            profile.key_material = Some(value.to_string())
                        }
                        _ => {}
                    }
                    if let Some(parent) = text_stack.last_mut() {
                        parent.push_str(value);
                    }
                }
                stack.pop();
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
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    Ok(profile)
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

pub(crate) fn known_credential_store_type(path: &str, name: &str) -> Option<&'static str> {
    let normalized = format!("{path}/{name}")
        .replace('\\', "/")
        .to_ascii_lowercase();
    let filename = name.to_ascii_lowercase();
    if matches!(filename.as_str(), "sam" | "security" | "ntds.dit") {
        Some("Windows account credential database")
    } else if matches!(
        filename.as_str(),
        "login data" | "logins.json" | "key4.db" | "key3.db"
    ) {
        Some("Browser saved-login store")
    } else if filename.ends_with(".kdbx") || filename.ends_with(".psafe3") {
        Some("Password manager database")
    } else if normalized.contains("/microsoft/credentials/")
        || normalized.contains("/microsoft/vault/")
        || filename.ends_with(".vcrd")
        || filename.ends_with(".vpol")
    {
        Some("Windows Credential Manager or Vault store")
    } else if normalized.contains("/microsoft/protect/") {
        Some("Windows DPAPI master-key material")
    } else if normalized.contains("/.ssh/")
        && matches!(
            filename.as_str(),
            "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519"
        )
    {
        Some("SSH private key")
    } else if normalized.ends_with("/.aws/credentials") {
        Some("AWS credential configuration")
    } else if matches!(
        filename.as_str(),
        "accesstokens.json" | "azureprofile.json" | "msal_token_cache.json"
    ) {
        Some("Cloud authentication token store")
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PlaintextSecretLead {
    pub key: String,
    pub value: String,
    pub source_location: String,
    pub source_format: &'static str,
}

pub(crate) fn known_plaintext_secret_source(path: &str, name: &str) -> bool {
    let normalized = format!("{path}/{name}")
        .replace('\\', "/")
        .to_ascii_lowercase();
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

pub(crate) fn parse_plaintext_secret_leads(
    path: &str,
    name: &str,
    bytes: &[u8],
) -> Vec<PlaintextSecretLead> {
    let text = decode_text_file(bytes);
    let filename = name.to_ascii_lowercase();
    let mut leads = if filename.ends_with(".json") {
        parse_json_secret_leads(&text)
    } else if filename == "unattend.xml" || filename == "autounattend.xml" {
        parse_xml_secret_leads(&text)
    } else {
        parse_assignment_secret_leads(&text)
    };
    if filename == ".git-credentials" {
        leads.extend(parse_git_credential_urls(&text));
    }
    if filename == ".netrc" {
        leads.extend(parse_netrc_secrets(&text));
    }
    let mut seen = HashSet::new();
    leads.retain(|lead| {
        !lead.value.is_empty()
            && seen.insert(format!(
                "{}\u{1f}{}\u{1f}{}",
                lead.key.to_ascii_lowercase(),
                lead.value,
                lead.source_location
            ))
    });
    for lead in &mut leads {
        lead.source_location = format!("{path}:{}", lead.source_location);
    }
    leads
}

fn decode_text_file(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes)
            .trim_start_matches('\u{feff}')
            .to_string()
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key
        .trim()
        .trim_matches(['"', '\'', '<', '>', '/'])
        .to_ascii_lowercase()
        .replace(['-', '.'], "_");
    key == "password"
        || key == "passwd"
        || key == "pwd"
        || key == "secret"
        || key == "token"
        || key == "auth"
        || key == "authorization"
        || key == "keymaterial"
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
}

fn bounded_secret_value(value: &str) -> String {
    const MAX_SECRET_CHARS: usize = 65_536;
    value.chars().take(MAX_SECRET_CHARS).collect()
}

fn parse_assignment_secret_leads(text: &str) -> Vec<PlaintextSecretLead> {
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
        let value = value
            .trim()
            .trim_matches(|character| character == '"' || character == '\'')
            .to_string();
        if value.is_empty() {
            continue;
        }
        leads.push(PlaintextSecretLead {
            key: key.to_string(),
            value: bounded_secret_value(&value),
            source_location: format!("line {}", line_index + 1),
            source_format: "structured assignment",
        });
    }
    leads
}

fn parse_json_secret_leads(text: &str) -> Vec<PlaintextSecretLead> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut leads = Vec::new();
    collect_json_secrets(&value, "$", &mut leads);
    leads
}

fn collect_json_secrets(
    value: &serde_json::Value,
    path: &str,
    leads: &mut Vec<PlaintextSecretLead>,
) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let child_path = format!("{path}.{key}");
                if is_secret_key(key) {
                    if let Some(value) = value.as_str().filter(|value| !value.is_empty()) {
                        leads.push(PlaintextSecretLead {
                            key: key.clone(),
                            value: bounded_secret_value(value),
                            source_location: child_path.clone(),
                            source_format: "JSON",
                        });
                    }
                }
                collect_json_secrets(value, &child_path, leads);
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_json_secrets(value, &format!("{path}[{index}]"), leads);
            }
        }
        _ => {}
    }
}

fn parse_xml_secret_leads(text: &str) -> Vec<PlaintextSecretLead> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut text_stack = Vec::<String>::new();
    let mut leads = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(start)) => {
                let raw = String::from_utf8_lossy(start.name().as_ref()).to_string();
                stack.push(raw.rsplit(':').next().unwrap_or(&raw).to_string());
                text_stack.push(String::new());
            }
            Ok(Event::End(_)) => {
                let (Some(key), Some(value)) = (stack.pop(), text_stack.pop()) else {
                    break;
                };
                if is_secret_key(&key) {
                    let source_location = if stack.is_empty() {
                        format!("/{key}")
                    } else {
                        format!("/{}/{key}", stack.join("/"))
                    };
                    let value = value.trim();
                    if !value.is_empty() {
                        leads.push(PlaintextSecretLead {
                            key,
                            value: bounded_secret_value(value),
                            source_location,
                            source_format: "XML",
                        });
                    }
                }
                if let Some(parent) = text_stack.last_mut() {
                    parent.push_str(&value);
                }
            }
            Ok(Event::Text(text)) => {
                let Ok(decoded) = decode_xml_text(&text) else {
                    break;
                };
                if let Some(value) = text_stack.last_mut() {
                    value.push_str(&decoded);
                } else if !decoded.chars().all(char::is_whitespace) {
                    break;
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                let Some(value) = text_stack.last_mut() else {
                    break;
                };
                let Ok(decoded) = decode_xml_reference(&reference) else {
                    break;
                };
                value.push_str(&decoded);
            }
            Ok(Event::CData(text)) => {
                let Some(value) = text_stack.last_mut() else {
                    break;
                };
                let Ok(decoded) = text.decode() else {
                    break;
                };
                value.push_str(&decoded);
            }
            Ok(Event::DocType(_)) | Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buffer.clear();
    }
    leads
}

fn parse_git_credential_urls(text: &str) -> Vec<PlaintextSecretLead> {
    let mut leads = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
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
        if !password.is_empty() {
            leads.push(PlaintextSecretLead {
                key: format!("credential for {username}"),
                value: bounded_secret_value(password),
                source_location: format!("line {} URL user-info", line_index + 1),
                source_format: "Git credential URL",
            });
        }
    }
    leads
}

fn parse_netrc_secrets(text: &str) -> Vec<PlaintextSecretLead> {
    let tokens = text.split_whitespace().collect::<Vec<_>>();
    let mut leads = Vec::new();
    let mut machine = "unspecified";
    let mut index = 0;
    while index + 1 < tokens.len() {
        match tokens[index].to_ascii_lowercase().as_str() {
            "machine" => machine = tokens[index + 1],
            "password" => leads.push(PlaintextSecretLead {
                key: format!("password for {machine}"),
                value: bounded_secret_value(tokens[index + 1]),
                source_location: format!("token {}", index + 1),
                source_format: "netrc",
            }),
            _ => {}
        }
        index += 2;
    }
    leads
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn exact_assignment_and_json_secrets_are_extracted_without_loose_keyword_rows() {
        let env = parse_plaintext_secret_leads(
            "/Users/Alice/project/.env",
            ".env",
            b"STARTUP_LABEL=ignore\nAPI_TOKEN=abc123\nPASSWORD=hunter2\n",
        );
        assert_eq!(env.len(), 2);
        assert!(env.iter().any(|lead| lead.key == "API_TOKEN"));
        assert!(!env.iter().any(|lead| lead.key == "STARTUP_LABEL"));

        let json = parse_plaintext_secret_leads(
            "/Users/Alice/AppData/Roaming/Microsoft/UserSecrets/x/secrets.json",
            "secrets.json",
            br#"{"Database":{"Password":"db-pass"},"DisplayTokenName":"not-secret"}"#,
        );
        assert_eq!(json.len(), 1);
        assert_eq!(json[0].value, "db-pass");
    }

    #[test]
    fn domain_account_requires_an_explicit_winlogon_domain_user_pair() {
        let observations = vec![
            RegistryObservation {
                key_path: "ROOT/Microsoft/Windows NT/CurrentVersion/Winlogon".to_string(),
                value_name: "DefaultDomainName".to_string(),
                value_data: "CONTOSO".to_string(),
                last_write_utc: Some("2024-01-02T03:04:05Z".to_string()),
            },
            RegistryObservation {
                key_path: "ROOT/Microsoft/Windows NT/CurrentVersion/Winlogon".to_string(),
                value_name: "DefaultUserName".to_string(),
                value_data: "alice".to_string(),
                last_write_utc: Some("2024-01-02T03:04:05Z".to_string()),
            },
            RegistryObservation {
                key_path: "ROOT/Unrelated".to_string(),
                value_name: "TokenUser".to_string(),
                value_data: "must-not-be-an-account".to_string(),
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
        assert_eq!(
            known_credential_store_type(
                "/Users/Alice/.azure/accessTokens.json",
                "accessTokens.json"
            ),
            Some("Cloud authentication token store")
        );
        assert!(known_credential_store_type(
            "/Users/Alice/Documents/token-notes.txt",
            "token-notes.txt"
        )
        .is_none());
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
    fn xml_secret_is_not_split_at_entity_references() {
        let leads = parse_xml_secret_leads("<config><password>a&amp;b&#x31;</password></config>");
        assert_eq!(leads.len(), 1);
        assert_eq!(leads[0].key, "password");
        assert_eq!(leads[0].value, "a&b1");
        assert_eq!(leads[0].source_location, "/config/password");
    }
}
