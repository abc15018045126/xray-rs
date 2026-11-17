use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use serde::Deserialize;
use uuid::Uuid;

use xray_rs_types::{Address, Destination, Error, Result};

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct XrayJsonConfig {
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConfig {
    pub tag: Option<String>,
    pub protocol: String,
    pub listen: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundConfig {
    pub tag: Option<String>,
    pub protocol: String,
    pub settings: Option<serde_json::Value>,
    pub stream_settings: Option<StreamSettings>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings {
    pub network: Option<String>,
    pub security: Option<String>,
    pub tls_settings: Option<TlsSettings>,
    pub ws_settings: Option<WsSettings>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsSettings {
    pub server_name: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WsSettings {
    pub path: Option<String>,
    pub host: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleConfig {
    pub outbound_tag: Option<String>,
    pub network: Option<String>,
    #[serde(default)]
    pub inbound_tag: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub process: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    pub port: Option<String>,
    #[serde(default)]
    pub ip: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VlessSettings {
    #[serde(default)]
    vnext: Vec<VlessServer>,
}

#[derive(Debug, Deserialize)]
struct VlessServer {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<VlessUser>,
}

#[derive(Debug, Deserialize)]
struct VlessUser {
    id: String,
    flow: Option<String>,
}

impl XrayJsonConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse {}: {}", path.display(), e)))
    }
}

pub fn parse_vless_settings(
    settings: &Option<serde_json::Value>,
) -> Result<(Destination, Uuid, Option<String>)> {
    let val = settings
        .as_ref()
        .ok_or_else(|| Error::Config("VLESS outbound missing settings".into()))?;
    let parsed: VlessSettings = serde_json::from_value(val.clone())
        .map_err(|e| Error::Config(format!("Invalid VLESS settings: {}", e)))?;
    let srv = parsed
        .vnext
        .into_iter()
        .next()
        .ok_or_else(|| Error::Config("VLESS settings missing vnext".into()))?;
    let user = srv
        .users
        .into_iter()
        .next()
        .ok_or_else(|| Error::Config("VLESS settings missing user".into()))?;

    let address = if let Ok(ip) = srv.address.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        }
    } else {
        Address::Domain(srv.address)
    };
    let uuid = Uuid::from_str(&user.id)
        .map_err(|e| Error::Config(format!("Invalid VLESS UUID '{}': {}", user.id, e)))?;

    Ok((Destination::tcp(address, srv.port), uuid, user.flow))
}

#[derive(Debug, Deserialize)]
struct TrojanSettings {
    #[serde(default)]
    servers: Vec<TrojanServer>,
}

#[derive(Debug, Deserialize)]
struct TrojanServer {
    address: String,
    port: u16,
    password: String,
}

pub fn parse_trojan_settings(
    settings: &Option<serde_json::Value>,
) -> Result<(Destination, String)> {
    let val = settings
        .as_ref()
        .ok_or_else(|| Error::Config("Trojan outbound missing settings".into()))?;
    let parsed: TrojanSettings = serde_json::from_value(val.clone())
        .map_err(|e| Error::Config(format!("Invalid Trojan settings: {}", e)))?;
    let srv = parsed
        .servers
        .into_iter()
        .next()
        .ok_or_else(|| Error::Config("Trojan settings missing servers".into()))?;
    let address = if let Ok(ip) = srv.address.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        }
    } else {
        Address::Domain(srv.address)
    };
    Ok((Destination::tcp(address, srv.port), srv.password))
}
