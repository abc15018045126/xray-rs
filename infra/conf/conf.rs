pub const CONF_DIR: &str = "conf";

use std::collections::HashMap;
use crate::app::router::{DomainMatcher, IpMatcher, Router, Rule};
use crate::common::errors::{Error, Result};
use crate::common::net::{Destination, Network};
use crate::features::inbound::InboundHandler;
use crate::features::outbound::OutboundHandler;
use crate::proxy as p;
use crate::transport::internet::TlsClient;
use crate::transport::internet::reality::RealityConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub dns: Option<serde_json::Value>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default)]
    pub loglevel: Option<String>,
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    pub tag: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub listen: Option<String>,
    pub protocol: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default, rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsConfig>,
    #[serde(default)]
    pub sniffing: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub tag: Option<String>,
    pub protocol: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default, rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsConfig>,
    #[serde(default)]
    pub mux: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettingsConfig {
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default, rename = "tlsSettings")]
    pub tls_settings: Option<TlsSettingsConfig>,
    #[serde(default, rename = "realitySettings")]
    pub reality_settings: Option<RealityConfig>,
    #[serde(default, rename = "wsSettings")]
    pub ws_settings: Option<WsSettingsConfig>,
    #[serde(default, rename = "httpupgradeSettings")]
    pub httpupgrade_settings: Option<WsSettingsConfig>,
    #[serde(default, rename = "grpcSettings")]
    pub grpc_settings: Option<serde_json::Value>,
    #[serde(default, rename = "xhttpSettings", alias = "splithttpSettings")]
    pub xhttp_settings: Option<crate::transport::internet::SplitHttpConfig>,
    #[serde(default)]
    pub finalmask: Option<FinalmaskConfigJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalmaskConfigJson {
    #[serde(default)]
    pub tcp: Option<Vec<FinalmaskLayerJson>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalmaskLayerJson {
    #[serde(rename = "type")]
    pub mask_type: String,
    #[serde(default)]
    pub settings: Option<FinalmaskSettingsJson>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinalmaskSettingsJson {
    #[serde(default)]
    pub packets: Option<String>,
    #[serde(default)]
    pub length: Option<serde_json::Value>,
    #[serde(default)]
    pub delay: Option<serde_json::Value>,
    #[serde(default)]
    pub interval: Option<serde_json::Value>,
    #[serde(default)]
    pub lengths: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub delays: Option<Vec<serde_json::Value>>,
    #[serde(default, rename = "maxSplit", alias = "max_split")]
    pub max_split: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSettingsConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, rename = "heartbeatPeriod")]
    pub heartbeat_period: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsCertificateConfig {
    #[serde(default, rename = "certificateFile")]
    pub certificate_file: Option<String>,
    #[serde(default, rename = "keyFile")]
    pub key_file: Option<String>,
    #[serde(default)]
    pub certificate: Option<Vec<String>>,
    #[serde(default)]
    pub key: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsSettingsConfig {
    #[serde(default, rename = "serverName")]
    pub server_name: Option<String>,
    #[serde(default, rename = "allowInsecure")]
    pub allow_insecure: Option<bool>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub certificates: Option<Vec<TlsCertificateConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default, rename = "domainStrategy")]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub rules: Option<Vec<RuleConfig>>,
    #[serde(default)]
    pub balancers: Option<Vec<BalancerRuleConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerStrategyConfig {
    #[serde(default, rename = "type")]
    pub strategy_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerRuleConfig {
    pub tag: String,
    #[serde(default)]
    pub selector: Vec<String>,
    #[serde(default)]
    pub strategy: Option<BalancerStrategyConfig>,
    #[serde(default, rename = "fallbackTag")]
    pub fallback_tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default, rename = "type")]
    pub rule_type: Option<String>,
    #[serde(default, rename = "ruleTag")]
    pub rule_tag: Option<String>,
    #[serde(default, rename = "outboundTag")]
    pub outbound_tag: String,
    #[serde(default, rename = "balancerTag")]
    pub balancer_tag: Option<String>,
    #[serde(default, rename = "inboundTag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(default, alias = "domains")]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    pub ip: Option<Vec<String>>,
    #[serde(default, rename = "sourceIP", alias = "source")]
    pub source_ip: Option<Vec<String>>,
    #[serde(default)]
    pub port: Option<serde_json::Value>,
    #[serde(default, rename = "sourcePort")]
    pub source_port: Option<serde_json::Value>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub protocol: Option<Vec<String>>,
    #[serde(default)]
    pub user: Option<Vec<String>>,
    #[serde(default)]
    pub process: Option<Vec<String>>,
    #[serde(default, rename = "localOS")]
    pub local_os: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub id: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub testpre: Option<u32>,
    #[serde(default, rename = "testpreIdle")]
    pub testpre_idle: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTargetConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiServerSettings {
    #[serde(default)]
    pub vnext: Vec<ServerTargetConfig>,
    #[serde(default)]
    pub servers: Vec<ServerTargetConfig>,
    #[serde(default)]
    pub clients: Vec<UserConfig>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub testpre: Option<u32>,
    #[serde(default, rename = "testpreIdle")]
    pub testpre_idle: Option<u32>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub fallbacks: Option<Vec<crate::proxy::vless::inbound::Fallback>>,
}

impl MultiServerSettings {
    fn normalize_flat_outbound(&mut self) {
        let Some(addr) = self.address.as_ref().filter(|a| !a.is_empty()) else { return; };
        let base = |users| ServerTargetConfig {
            address: Some(addr.clone()), port: self.port, users,
            password: self.password.clone(), method: self.method.clone(),
        };
        if self.vnext.is_empty() && let Some(ref id) = self.id && !id.is_empty() {
            self.vnext.push(base(vec![UserConfig {
                id: id.clone(), password: self.password.clone(), level: self.level,
                flow: self.flow.clone(), testpre: self.testpre, testpre_idle: self.testpre_idle,
            }]));
        }
        if self.servers.is_empty() { self.servers.push(base(Vec::new())); }
    }
}

fn parse_i64_range_val(val: &serde_json::Value, def_min: i64, def_max: i64) -> (i64, i64) {
    match val {
        serde_json::Value::Number(n) => {
            let v = n.as_i64().unwrap_or(def_min);
            (v, v)
        }
        serde_json::Value::String(s) => {
            if let Some((a, b)) = s.split_once('-') {
                (a.trim().parse().unwrap_or(def_min), b.trim().parse().unwrap_or(def_max))
            } else if let Ok(v) = s.trim().parse() {
                (v, v)
            } else {
                (def_min, def_max)
            }
        }
        serde_json::Value::Object(obj) => {
            let from = obj.get("from").and_then(|v| v.as_i64()).unwrap_or(def_min);
            let to = obj.get("to").and_then(|v| v.as_i64()).unwrap_or(from);
            (from, to)
        }
        _ => (def_min, def_max),
    }
}

fn build_fragment_from_settings(s: &FinalmaskSettingsJson) -> crate::transport::internet::finalmask::fragment::Config {
    let mut cfg = crate::transport::internet::finalmask::fragment::Config::default();
    match s.packets.as_deref().map(str::trim).unwrap_or("") {
        "" => { cfg.packets_from = 0; cfg.packets_to = 0; }
        p if p.eq_ignore_ascii_case("tlshello") => { cfg.packets_from = 0; cfg.packets_to = 1; }
        p => {
            if let Some((from_str, to_str)) = p.split_once('-') {
                cfg.packets_from = from_str.trim().parse().unwrap_or(1);
                cfg.packets_to = to_str.trim().parse().unwrap_or(cfg.packets_from);
            } else if let Ok(v) = p.parse() {
                cfg.packets_from = v;
                cfg.packets_to = v;
            }
        }
    }
    if let Some(ref list) = s.lengths && !list.is_empty() {
        for item in list {
            let (lo, hi) = parse_i64_range_val(item, 50, 100);
            cfg.lengths_min.push(lo);
            cfg.lengths_max.push(hi);
        }
        cfg.length_min = cfg.lengths_min[0];
        cfg.length_max = cfg.lengths_max[0];
    } else if let Some(ref l) = s.length {
        let (lo, hi) = parse_i64_range_val(l, 50, 100);
        cfg.length_min = lo;
        cfg.length_max = hi;
        cfg.lengths_min.push(lo);
        cfg.lengths_max.push(hi);
    }
    if let Some(ref list) = s.delays && !list.is_empty() {
        for item in list {
            let (lo, hi) = parse_i64_range_val(item, 0, 0);
            cfg.delays_min.push(lo);
            cfg.delays_max.push(hi);
        }
        cfg.delay_min = cfg.delays_min[0];
        cfg.delay_max = cfg.delays_max[0];
    } else if let Some(d) = s.delay.as_ref().or(s.interval.as_ref()) {
        let (lo, hi) = parse_i64_range_val(d, 0, 0);
        cfg.delay_min = lo;
        cfg.delay_max = hi;
        cfg.delays_min.push(lo);
        cfg.delays_max.push(hi);
    }
    if let Some(ref ms) = s.max_split {
        let (lo, hi) = parse_i64_range_val(ms, 0, 0);
        cfg.max_split_min = lo;
        cfg.max_split_max = hi;
    }
    cfg
}

fn parse_fragment_config(fm: &FinalmaskConfigJson) -> Option<crate::transport::internet::finalmask::fragment::Config> {
    let tcp_layers = fm.tcp.as_ref()?;
    for layer in tcp_layers {
        if layer.mask_type.eq_ignore_ascii_case("fragment") {
            let cfg = match layer.settings {
                Some(ref s) => build_fragment_from_settings(s),
                None => crate::transport::internet::finalmask::fragment::Config::default(),
            };
            return Some(cfg);
        }
    }
    None
}

fn parse_multi_settings(raw: Option<serde_json::Value>, proto: &str) -> Result<MultiServerSettings> {
    let mut s: MultiServerSettings = serde_json::from_value(raw.unwrap_or_default())
        .map_err(|e| Error::Config(format!("Invalid {} outbound settings: {}", proto, e)))?;
    s.normalize_flat_outbound();
    Ok(s)
}

fn sub_tag_for(tag: &str, len: usize, idx: usize) -> String {
    if len == 1 { tag.to_string() } else { format!("{}#{}", tag, idx) }
}

fn build_optional_tls(ss: Option<&StreamSettingsConfig>, addr: &str) -> Result<(Option<TlsClient>, Option<String>)> {
    let Some(ss) = ss else { return Ok((None, None)) };
    if ss.security.as_deref() != Some("tls") { return Ok((None, None)); }
    let cfg = ss.tls_settings.clone().unwrap_or_default();
    let sni = cfg.server_name.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| addr.to_string());
    let alpn = cfg.alpn.unwrap_or_default().into_iter().map(String::into_bytes).collect();
    let client = TlsClient::new_with_fingerprint(
        &sni,
        cfg.allow_insecure.unwrap_or(false),
        alpn,
        cfg.fingerprint.as_deref().unwrap_or(""),
    )?;
    Ok((Some(client), Some(sni)))
}

fn parse_json_str_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn parse_sniffing(
    v: Option<&serde_json::Value>,
    require_enabled: bool,
) -> Option<crate::common::session::SniffingRequest> {
    let v = v?;
    let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
    if require_enabled && !enabled { return None; }
    Some(crate::common::session::SniffingRequest {
        enabled,
        metadata_only: v.get("metadataOnly").and_then(|b| b.as_bool()).unwrap_or(false),
        route_only: v.get("routeOnly").and_then(|b| b.as_bool()).unwrap_or(false),
        override_destination_for_protocol: parse_json_str_array(v, "destOverride"),
        exclude_for_domain: parse_json_str_array(v, "domainsExcluded"),
    })
}

fn parse_client_uuids(clients: &[UserConfig]) -> Result<Vec<Uuid>> {
    clients.iter().map(|c| Uuid::from_str(&c.id).map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))).collect()
}

fn wrap_pingora_multi_outbound(
    tag: &str,
    handlers: Vec<Arc<dyn OutboundHandler>>,
    labels: Vec<String>,
) -> Result<Arc<dyn OutboundHandler>> {
    if handlers.len() == 1 { return Ok(handlers.into_iter().next().unwrap()); }
    let lb = Arc::new(crate::app::pingora_bridge::PingoraUpstreamBalancer::from_labels_ketama(labels)?);
    Ok(Arc::new(crate::app::pingora_bridge::PingoraPooledOutbound::new(
        tag,
        handlers,
        Some(lb),
        32,
        std::time::Duration::from_secs(60),
    )))
}

pub struct BuiltConfig {
    pub inbounds: Vec<(SocketAddr, Arc<dyn InboundHandler>)>,
    pub tun_devices: Vec<Arc<p::tun::WindowsTunDevice>>,
    pub outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    pub router: Router,
    pub default_outbound_tag: Option<String>,
}

impl Config {
    pub fn build(self) -> Result<BuiltConfig> {
        let mut inbounds = Vec::new();
        let mut tun_devices = Vec::new();
        let mut outbounds = HashMap::new();
        let mut default_outbound_tag = None;
        let dns_client = Arc::new(build_dns_client(self.dns.as_ref()));
        for (i, out_cfg) in self.outbounds.into_iter().enumerate() {
            let tag = out_cfg.tag.unwrap_or_else(|| format!("outbound-{}", i));
            if default_outbound_tag.is_none() { default_outbound_tag = Some(tag.clone()); }
            let handler: Arc<dyn OutboundHandler> = match out_cfg.protocol.to_lowercase().as_str() {
                "freedom" | "direct" => {
                    let mut h = p::freedom::Handler::new(&tag);
                    if let Some(ref st) = out_cfg.settings {
                        if let Some(ds) = st.get("targetStrategy").or_else(|| st.get("domainStrategy")).and_then(|v| v.as_str()) {
                            h = h.with_strategy(p::freedom::DomainStrategy::parse(ds));
                        }
                        if let Some(red) = st.get("redirect").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
                            && let Ok(dest) = Destination::from_str(red)
                        {
                            h = h.with_destination_override(dest);
                        }
                        if let Some(frag_val) = st.get("fragment")
                            && let Ok(fs) = serde_json::from_value::<FinalmaskSettingsJson>(frag_val.clone())
                        {
                            h = h.with_fragment(build_fragment_from_settings(&fs));
                        }
                    }
                    if let Some(f_cfg) = out_cfg.stream_settings.as_ref().and_then(|ss| ss.finalmask.as_ref()).and_then(parse_fragment_config) {
                        h = h.with_fragment(f_cfg);
                    }
                    Arc::new(h)
                }
                "blackhole" | "block" => {
                    let resp_type = out_cfg
                        .settings
                        .as_ref().and_then(|s| s.get("response")).and_then(|r| r.get("type")).and_then(|t| t.as_str())
                        .map(|t| match t.to_lowercase().as_str() {
                            "http" | "http403" => p::blackhole::ResponseType::Http403,
                            "http500" => p::blackhole::ResponseType::Http500,
                            _ => p::blackhole::ResponseType::None,
                        })
                        .unwrap_or(p::blackhole::ResponseType::None);
                    Arc::new(p::blackhole::Handler::with_response(&tag, resp_type))
                }
                "vless" => build_vless_outbound(&tag, out_cfg.settings, out_cfg.stream_settings)?,
                "trojan" => {
                    let s = parse_multi_settings(out_cfg.settings, "Trojan")?;
                    if s.servers.is_empty() { return Err(Error::Config("Trojan servers list is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.servers.len()), Vec::with_capacity(s.servers.len()));
                    for (idx, srv) in s.servers.iter().enumerate() {
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.servers.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let (tls, sni) = build_optional_tls(out_cfg.stream_settings.as_ref(), addr)?;
                        hs.push(Arc::new(p::trojan::OutboundClient::new(
                            &sub, dest, srv.password.clone().unwrap_or_default(), tls, sni,
                        )) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "shadowsocks" => {
                    let s = parse_multi_settings(out_cfg.settings, "Shadowsocks")?;
                    if s.servers.is_empty() { return Err(Error::Config("Shadowsocks servers list is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.servers.len()), Vec::with_capacity(s.servers.len()));
                    for (idx, srv) in s.servers.iter().enumerate() {
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(8388);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.servers.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let method = srv.method.clone().unwrap_or_else(|| "aes-256-gcm".into());
                        hs.push(Arc::new(p::shadowsocks::OutboundClient::new(
                            &sub, dest, method, srv.password.clone().unwrap_or_default(),
                        )) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "vmess" => {
                    let s = parse_multi_settings(out_cfg.settings, "VMess")?;
                    if s.vnext.is_empty() { return Err(Error::Config("VMess vnext is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.vnext.len()), Vec::with_capacity(s.vnext.len()));
                    for (idx, srv) in s.vnext.iter().enumerate() {
                        let user = srv.users.first().ok_or_else(|| Error::Config("VMess users is empty".into()))?;
                        let uid = Uuid::from_str(&user.id).map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.vnext.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let (tls, sni) = build_optional_tls(out_cfg.stream_settings.as_ref(), addr)?;
                        hs.push(Arc::new(p::vmess::OutboundClient::new(&sub, dest, uid, tls, sni)) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "socks" => {
                    let s = parse_multi_settings(out_cfg.settings, "SOCKS")?;
                    if s.servers.is_empty() { return Err(Error::Config("SOCKS servers list is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.servers.len()), Vec::with_capacity(s.servers.len()));
                    for (idx, srv) in s.servers.iter().enumerate() {
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(1080);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.servers.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        hs.push(Arc::new(p::socks::Client::new(&sub, dest)) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "http" => {
                    let s = parse_multi_settings(out_cfg.settings, "HTTP")?;
                    if s.servers.is_empty() { return Err(Error::Config("HTTP servers list is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.servers.len()), Vec::with_capacity(s.servers.len()));
                    for (idx, srv) in s.servers.iter().enumerate() {
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(8080);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.servers.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let c = match srv.users.first() {
                            Some(u) => p::http::client::HttpClient::with_auth(&sub, dest, &u.id, u.password.as_deref().unwrap_or("")),
                            None => p::http::client::HttpClient::new(&sub, dest),
                        };
                        hs.push(Arc::new(c) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "wireguard" => {
                    let wg_cfg: p::wireguard::WireGuardConfig =
                        serde_json::from_value(out_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid WireGuard outbound settings: {}", e)),
                        )?;
                    Arc::new(p::wireguard::Client::new(&tag, wg_cfg))
                }
                "hysteria" => {
                    let raw = out_cfg.settings.unwrap_or_default();
                    let addr_str = raw.get("address").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
                    let port_val = raw.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
                    let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
                    let hy_cfg: p::hysteria::HysteriaConfig = serde_json::from_value(raw).unwrap_or_default();
                    Arc::new(p::hysteria::HysteriaClient::new(&tag, dest, hy_cfg))
                }
                "dns" => Arc::new(p::DnsOutbound::new(tag.clone(), dns_client.clone())),
                other => { return Err(Error::Unsupported(format!("Outbound protocol '{}' is not supported", other))); }
            };
            outbounds.insert(tag, handler);
        }
        for (i, in_cfg) in self.inbounds.into_iter().enumerate() {
            let tag = in_cfg.tag.unwrap_or_else(|| format!("inbound-{}", i));
            let proto = in_cfg.protocol.to_lowercase();
            if proto == "tun" {
                let st = in_cfg.settings.as_ref();
                let tun_name = st.and_then(|s| s.get("name")?.as_str()).unwrap_or("xray_tun");
                let mtu = st.and_then(|s| s.get("mtu").or_else(|| s.get("MTU"))?.as_u64()).unwrap_or(1500) as usize;
                let mut gateway_v4: ipnet::Ipv4Net = "172.18.0.1/30".parse().unwrap();
                let mut gateway_v6: Option<ipnet::Ipv6Net> = None;
                if let Some(gws) = st.and_then(|s| s.get("gateway")?.as_array()) {
                    for gw in gws.iter().filter_map(|v| v.as_str()) {
                        if let Ok(net) = gw.parse::<ipnet::Ipv4Net>() {
                            gateway_v4 = net;
                        } else if let Ok(net) = gw.parse::<ipnet::Ipv6Net>() {
                            gateway_v6 = Some(net);
                        }
                    }
                }
                let (mut route_all, mut routes) = (false, Vec::new());
                if let Some(rt) = st.and_then(|s| s.get("autoSystemRoutingTable")) {
                    if let Some(arr) = rt.as_array() {
                        for s in arr.iter().filter_map(|x| x.as_str()) {
                            if s == "0.0.0.0/0" || s == "::/0" {
                                route_all = true;
                            } else if let Ok(net) = s.parse::<ipnet::IpNet>() {
                                routes.push(net);
                            }
                        }
                    } else if rt.as_bool() == Some(true) {
                        route_all = true;
                    }
                }
                tun_devices.push(Arc::new(p::tun::TunRunner::new(p::tun::TunConfig {
                    enable: true,
                    name: tun_name.to_string(),
                    device_id: tun_name.to_string(),
                    route_all,
                    routes,
                    gateway: gateway_v4,
                    gateway_v6,
                    mtu,
                    so_mark: None,
                    dns_hijack: false,
                    sniffing: parse_sniffing(in_cfg.sniffing.as_ref(), false),
                    auto_route: route_all,
                    strict_route: true,
                })));
                continue;
            }
            let listen_ip = in_cfg.listen.as_deref().unwrap_or("0.0.0.0");
            let port_val = in_cfg.port.unwrap_or(0);
            if port_val == 0 { continue; }
            let bind_addr: SocketAddr = format!("{}:{}", listen_ip, port_val)
                .parse()
                .map_err(|e| Error::Config(format!("Invalid listen address '{}:{}': {}", listen_ip, port_val, e)))?;
            let handler: Arc<dyn InboundHandler> = match proto.as_str() {
                "socks" | "socks5" => Arc::new(p::socks::Server::new(&tag)),
                "http" => Arc::new(p::http::Server::new(&tag)),
                "mixed" => Arc::new(p::mixed::Server::new(&tag)),
                "vless" => {
                    let s = parse_multi_settings(in_cfg.settings, "VLESS")?;
                    if let Some(ref dec) = s.decryption && !dec.is_empty() && !dec.eq_ignore_ascii_case("none")
                    {
                        return Err(Error::Config(format!(
                            "VLESS inbound '{}' unsupported decryption '{}': only 'none' is supported",
                            tag, dec
                        )));
                    }
                    let mut srv = p::vless::InboundServer::new(&tag, parse_client_uuids(&s.clients)?);
                    if let Some(fb) = s.fallbacks && !fb.is_empty() { srv = srv.with_fallbacks(fb); }
                    Arc::new(srv)
                }
                "trojan" => {
                    let s = parse_multi_settings(in_cfg.settings, "Trojan")?;
                    let pwds = s.clients.into_iter().filter_map(|c| c.password).collect();
                    Arc::new(p::trojan::InboundServer::new(&tag, pwds))
                }
                "shadowsocks" => {
                    let s = parse_multi_settings(in_cfg.settings, "Shadowsocks")?;
                    let first = s.servers.first();
                    let pwd = first.and_then(|x| x.password.clone()).unwrap_or_default();
                    let method = first.and_then(|x| x.method.clone()).unwrap_or_else(|| "aes-256-gcm".into());
                    Arc::new(p::shadowsocks::InboundServer::new(&tag, method, pwd))
                }
                "dokodemo-door" | "dokodemo" => {
                    let s = parse_multi_settings(in_cfg.settings, "Dokodemo")?;
                    let dest = Destination::from_str(&format!(
                        "{}:{}",
                        s.address.as_deref().unwrap_or("127.0.0.1"),
                        s.port.unwrap_or(80)
                    ))?;
                    let net = if s.network.as_deref() == Some("udp") { Network::Udp } else { Network::Tcp };
                    Arc::new(p::dokodemo::Server::new(&tag, dest, net))
                }
                "vmess" => {
                    let s = parse_multi_settings(in_cfg.settings, "VMess")?;
                    Arc::new(p::vmess::InboundServer::new(&tag, parse_client_uuids(&s.clients)?))
                }
                other => return Err(Error::Unsupported(format!("Inbound protocol '{}' is not supported", other))),
            };
            let sniffing_req = parse_sniffing(in_cfg.sniffing.as_ref(), true);
            let handler: Arc<dyn InboundHandler> = if let Some(ref stream_cfg) = in_cfg.stream_settings
            {
                let security = stream_cfg.security.as_deref().unwrap_or("none").to_ascii_lowercase();
                let network = stream_cfg.network.as_deref().unwrap_or("tcp").to_ascii_lowercase();
                let tls_server = if security == "tls" {
                    let tls_cfg = stream_cfg.tls_settings.as_ref().ok_or_else(|| {
                        Error::Config(format!("Inbound '{}' has security='tls' but missing tlsSettings", tag))
                    })?;
                    let alpn: Vec<Vec<u8>> = tls_cfg
                        .alpn
                        .as_ref().map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect()).unwrap_or_default();
                    let cert_cfg = tls_cfg.certificates.as_ref().and_then(|c| c.first())
                        .ok_or_else(|| {
                            Error::Config(format!(
                                "Inbound '{}' has security='tls' but missing tlsSettings.certificates",
                                tag
                            ))
                        })?;
                    let srv = if let (Some(cert_file), Some(key_file)) = (
                        cert_cfg.certificate_file.as_deref(),
                        cert_cfg.key_file.as_deref(),
                    ) {
                        crate::transport::internet::TlsServer::from_pem_files(cert_file, key_file, alpn)?
                    } else if let (Some(cert_lines), Some(key_lines)) = (
                        cert_cfg.certificate.as_ref(),
                        cert_cfg.key.as_ref(),
                    ) {
                        let cert_pem = cert_lines.join("\n");
                        let key_pem = key_lines.join("\n");
                        crate::transport::internet::TlsServer::from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), alpn)?
                    } else {
                        return Err(Error::Config(format!(
                            "Inbound '{}' tlsSettings.certificates requires certificateFile/keyFile or certificate/key",
                            tag
                        )));
                    };
                    Some(Arc::new(srv))
                } else {
                    None
                };
                let reality_server = if security == "reality" {
                    let rc = stream_cfg.reality_settings.as_ref().ok_or_else(|| {
                        Error::Config(format!("Inbound '{}' has security='reality' but missing realitySettings", tag))
                    })?;
                    Some(Arc::new(crate::transport::internet::reality::RealityServer::new(rc)?))
                } else {
                    None
                };
                let is_xhttp = network == "xhttp" || network == "splithttp";
                let splithttp_server = if is_xhttp {
                    let x_cfg = stream_cfg.xhttp_settings.clone().unwrap_or_default();
                    Some(Arc::new(crate::transport::internet::splithttp::SplitHttpServer::new(x_cfg)))
                } else {
                    None
                };
                let is_httpupgrade = !is_xhttp && network == "httpupgrade";
                let httpupgrade_pair = if is_httpupgrade {
                    let hu = stream_cfg.httpupgrade_settings.as_ref();
                    let path = hu.and_then(|h| h.path.clone());
                    let host = hu.and_then(|h| h.host.clone());
                    Some((path, host))
                } else {
                    None
                };
                let is_ws = !is_xhttp && !is_httpupgrade && (network == "ws" || network == "websocket");
                let (ws_path, ws_host) = if is_ws {
                    let ws_cfg = stream_cfg.ws_settings.as_ref();
                    let path = ws_cfg.and_then(|w| w.path.clone());
                    let host = ws_cfg.and_then(|w| {
                        w.host.clone().or_else(|| {
                            w.headers.as_ref().and_then(|h| {
                                h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone())
                            })
                        })
                    });
                    (path, host)
                } else {
                    (None, None)
                };
                if tls_server.is_some()
                    || reality_server.is_some()
                    || is_ws || httpupgrade_pair.is_some() || splithttp_server.is_some() || sniffing_req.is_some()
                {
                    let mut wrapped = crate::app::proxyman::inbound::StreamInboundHandler::new(
                        handler, tls_server, is_ws, ws_path, ws_host,
                    );
                    if let Some(r_srv) = reality_server { wrapped = wrapped.with_reality(r_srv); }
                    if let Some((hu_path, hu_host)) = httpupgrade_pair {
                        wrapped = wrapped.with_httpupgrade(hu_path, hu_host);
                    }
                    if let Some(xhttp_srv) = splithttp_server { wrapped = wrapped.with_splithttp(xhttp_srv); }
                    if let Some(sniff) = sniffing_req { wrapped = wrapped.with_sniffing(sniff); }
                    Arc::new(wrapped)
                } else {
                    handler
                }
            } else if let Some(sniff) = sniffing_req {
                Arc::new(
                    crate::app::proxyman::inbound::StreamInboundHandler::new(handler, None, false, None, None)
                    .with_sniffing(sniff),
                )
            } else {
                handler
            };
            inbounds.push((bind_addr, handler));
        }
        let outbound_tags: Vec<String> = outbounds.keys().cloned().collect();
        let router = build_router(self.routing, default_outbound_tag.clone(), &outbound_tags, dns_client.clone());
        dns_client.attach_routing(router.clone(), outbounds.clone());
        crate::transport::internet::tcp::dialer::init_system_dialer_dns(dns_client.clone());
        Ok(BuiltConfig {
            inbounds,
            tun_devices,
            outbounds,
            router,
            default_outbound_tag,
        })
    }
}

fn build_vless_outbound(
    tag: &str,
    settings_val: Option<serde_json::Value>,
    stream_settings: Option<StreamSettingsConfig>,
) -> Result<Arc<dyn OutboundHandler>> {
    let settings = parse_multi_settings(settings_val, "VLESS")?;
    if settings.vnext.is_empty() { return Err(Error::Config("VLESS vnext is empty".into())); }
    let (mut handlers, mut lbs) = (Vec::with_capacity(settings.vnext.len()), Vec::with_capacity(settings.vnext.len()));
    for (v_idx, server) in settings.vnext.iter().enumerate() {
        let user = server.users.first().ok_or_else(|| Error::Config("VLESS users is empty".into()))?;
        let user_uuid = Uuid::from_str(&user.id).map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
        let port_val = server.port.unwrap_or(443);
        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
        let sub_tag = sub_tag_for(tag, settings.vnext.len(), v_idx);
        lbs.push(format!("{}:{}", addr_str, port_val));
        let (mut tls_client, mut tls_sni, mut reality_client) = (None, None, None);
        let (mut ws_path, mut ws_host, mut ws_headers, mut ws_heartbeat) = (None, None, HashMap::new(), 0u32);
        let (mut xhttp_cfg, mut httpupgrade_cfg, mut fragment_cfg) = (None, None, None);
        if let Some(ref ss) = stream_settings {
            fragment_cfg = ss.finalmask.as_ref().and_then(parse_fragment_config);
            let net = ss.network.as_deref().unwrap_or("tcp").to_ascii_lowercase();
            let is_xhttp = matches!(net.as_str(), "xhttp" | "splithttp") || ss.xhttp_settings.is_some();
            if is_xhttp { xhttp_cfg = Some(ss.xhttp_settings.clone().unwrap_or_default()); }
            let is_hu = !is_xhttp && (net == "httpupgrade" || ss.httpupgrade_settings.is_some());
            if is_hu {
                let hu = ss.httpupgrade_settings.as_ref();
                let path = hu.and_then(|h| h.path.as_deref()).map(str::trim).filter(|p| !p.is_empty()).unwrap_or("/").to_string();
                let host = hu.and_then(|h| h.host.clone()).filter(|h| !h.trim().is_empty());
                let headers = hu.and_then(|h| h.headers.clone()).unwrap_or_default();
                httpupgrade_cfg = Some((path, host, headers));
            }
            let is_ws = !is_xhttp && !is_hu && (matches!(net.as_str(), "ws" | "websocket") || ss.ws_settings.is_some());
            if is_ws {
                let w = ss.ws_settings.as_ref();
                ws_heartbeat = w.and_then(|x| x.heartbeat_period).unwrap_or(0);
                let p = w.and_then(|x| x.path.as_deref()).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("/");
                ws_path = Some(p.to_string());
                if let Some(w) = w {
                    ws_host = w.host.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
                    if let Some(headers) = &w.headers {
                        ws_headers = headers.clone();
                        if ws_host.is_none() {
                            ws_host = headers
                                .iter()
                                .find(|(k, v)| k.eq_ignore_ascii_case("host") && !v.trim().is_empty())
                                .map(|(_, v)| v.trim().to_string());
                        }
                    }
                }
            }
            match ss.security.as_deref() {
                Some("tls") => {
                    let tls_cfg = ss.tls_settings.clone().unwrap_or_default();
                    let sni = tls_cfg
                        .server_name
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| ws_host.clone().filter(|s| !s.trim().is_empty()))
                        .unwrap_or_else(|| addr_str.to_string());
                    let alpn = tls_cfg.alpn.unwrap_or_default().into_iter().map(String::into_bytes).collect();
                    tls_client = Some(TlsClient::new_with_fingerprint(
                        &sni,
                        tls_cfg.allow_insecure.unwrap_or(false),
                        alpn,
                        tls_cfg.fingerprint.as_deref().unwrap_or(""),
                    )?);
                    tls_sni = Some(sni.clone());
                    ws_host.get_or_insert(sni);
                }
                Some("reality") if ss.reality_settings.is_some() => {
                    let rc = ss.reality_settings.as_ref().unwrap();
                    let sni = rc
                        .server_name
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| rc.server_names.first().map(String::as_str)).unwrap_or(addr_str);
                    let pub_key = rc.public_key.as_deref().ok_or_else(|| {
                        Error::Config(format!("Outbound '{}' has security='reality' but missing publicKey/password", tag))
                    })?;
                    let short_id = rc.short_id.as_deref().or_else(|| rc.short_ids.first().map(String::as_str)).unwrap_or("");
                    tls_client = Some(TlsClient::new_with_fingerprint(sni, true, vec![], rc.fingerprint.as_deref().unwrap_or(""))?);
                    tls_sni = Some(sni.to_string());
                    reality_client = Some(crate::transport::internet::reality::RealityClient::new(sni, pub_key, short_id)?);
                }
                _ => {}
            }
            if is_ws && ws_host.is_none() { ws_host = tls_sni.clone().or_else(|| Some(addr_str.to_string())); }
        }
        let is_ws_tls = ws_path.is_some() && tls_client.is_some();
        let mut client = p::vless::OutboundClient::new(&sub_tag, dest, user_uuid, tls_client, tls_sni, ws_path, ws_host)
            .with_ws_headers(ws_headers).with_ws_heartbeat(ws_heartbeat);
        if let Some(ref flow) = user.flow && !flow.is_empty()
        { client = client.with_flow(flow.clone()); }
        let testpre = user.testpre.unwrap_or_else(|| if is_ws_tls && !client.has_ws_early_data() { 3 } else { 0 });
        if testpre > 0 { client = client.with_testpre_idle(testpre, user.testpre_idle.unwrap_or(45)); }
        if let Some(rc) = reality_client { client = client.with_reality(rc); }
        if let Some(f_cfg) = fragment_cfg { client = client.with_fragment(f_cfg); }
        if let Some(x_cfg) = xhttp_cfg { client = client.with_splithttp(x_cfg); }
        if let Some((hu_path, hu_host, hu_headers)) = httpupgrade_cfg {
            client = client.with_httpupgrade(hu_path, hu_host, hu_headers);
        }
        handlers.push(Arc::new(client) as Arc<dyn OutboundHandler>);
    }
    wrap_pingora_multi_outbound(tag, handlers, lbs)
}

fn parse_port_value(port_val: serde_json::Value, ports: &mut Vec<u16>, ranges: &mut Vec<(u16, u16)>) {
    let ports_str = match port_val {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s,
        _ => String::new(),
    };
    for part in ports_str.split(',').map(str::trim) {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                if s <= e { ranges.push((s, e)); } else { ranges.push((e, s)); }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
}

fn build_router(
    routing: Option<RoutingConfig>,
    default_outbound_tag: Option<String>,
    outbound_tags: &[String],
    dns_client: Arc<crate::app::dns::DnsClient>,
) -> Router {
    let domain_strategy = routing
        .as_ref()
        .and_then(|r| r.domain_strategy.as_deref())
        .map(crate::app::router::router::DomainStrategy::parse)
        .unwrap_or_default();
    let balancers_cfg = routing.as_ref().and_then(|r| r.balancers.clone()).unwrap_or_default();
    let rules = build_routing_rules(routing);
    let mut router = Router::new(rules, default_outbound_tag);
    router.set_domain_strategy(domain_strategy);
    router.set_ip_resolver(Arc::new(move |domain: &str| dns_client.lookup_cached_or_hosts(domain)));
    for b_cfg in balancers_cfg {
        if b_cfg.tag.is_empty() || b_cfg.selector.is_empty() { continue; }
        let strategy: Arc<dyn crate::app::router::balancing::BalancingStrategy> =
            match b_cfg.strategy.as_ref().and_then(|s| s.strategy_type.as_deref()).unwrap_or("random").to_ascii_lowercase().as_str() {
                "roundrobin" => Arc::new(crate::app::router::balancing::RoundRobinStrategy::new(b_cfg.fallback_tag.clone())),
                _ => Arc::new(crate::app::router::balancing::RandomStrategy::new()),
            };
        let balancer = crate::app::router::balancing::Balancer::with_candidates(
            &b_cfg.tag,
            b_cfg.selector,
            outbound_tags.to_vec(),
            strategy,
            b_cfg.fallback_tag,
        );
        router.add_balancer(b_cfg.tag, Arc::new(balancer));
    }
    router
}

fn build_routing_rules(routing: Option<RoutingConfig>) -> Vec<Rule> {
    let mut rules = Vec::new();
    let Some(rule_configs) = routing.and_then(|r| r.rules) else { return rules };
    for r_cfg in rule_configs {
        if r_cfg.outbound_tag.is_empty() && r_cfg.balancer_tag.as_deref().unwrap_or("").is_empty() {
            continue;
        }
        let mut rule = Rule::new(&r_cfg.outbound_tag);
        rule.balancer_tag = r_cfg.balancer_tag.filter(|s| !s.is_empty());
        if let Some(in_tags) = r_cfg.inbound_tag { rule.inbound_tags = in_tags; }
        if let Some(domains) = r_cfg.domain {
            rule.domain_matchers.extend(domains.iter().map(|d| DomainMatcher::parse(d)));
        }
        if let Some(ips) = r_cfg.ip {
            let had_ips = !ips.is_empty();
            for ip_str in ips {
                if let Some(m) = IpMatcher::parse(&ip_str) {
                    rule.ip_matchers.push(m);
                } else {
                    tracing::warn!("Ignoring unrecognized routing IP matcher: '{}'", ip_str);
                }
            }
            if had_ips && rule.ip_matchers.is_empty() {
                tracing::warn!("Skipping routing rule for '{}' because none of its IP matchers could be parsed", rule.tag);
                continue;
            }
        }
        if let Some(src_ips) = r_cfg.source_ip {
            let had_src_ips = !src_ips.is_empty();
            for ip_str in src_ips {
                if let Some(m) = IpMatcher::parse(&ip_str) {
                    rule.source_ip_matchers.push(m);
                }
            }
            if had_src_ips && rule.source_ip_matchers.is_empty() {
                continue;
            }
        }
        if let Some(port_val) = r_cfg.port {
            parse_port_value(port_val, &mut rule.ports, &mut rule.port_ranges);
        }
        if let Some(src_port_val) = r_cfg.source_port {
            parse_port_value(src_port_val, &mut rule.source_ports, &mut rule.source_port_ranges);
        }
        if let Some(net_str) = r_cfg.network {
            rule.network = match net_str.to_lowercase().as_str() {
                "tcp" => Some(Network::Tcp),
                "udp" => Some(Network::Udp),
                _ => None,
            };
        }
        if let Some(protos) = r_cfg.protocol { rule.protocols = protos; }
        if let Some(users) = r_cfg.user { rule.user_emails = users; }
        if let Some(proc_list) = r_cfg.process { rule.process = proc_list; }
        if let Some(os_list) = r_cfg.local_os { rule.local_os = os_list; }
        rules.push(rule);
    }
    rules
}

fn build_dns_client(dns_val: Option<&serde_json::Value>) -> crate::app::dns::DnsClient {
    let mut client = crate::app::dns::DnsClient::new();
    let Some(val) = dns_val else { return client };
    if let Some(qs) = val.get("queryStrategy").and_then(|v| v.as_str()) {
        client.set_query_strategy(crate::app::dns::config::QueryStrategy::from_str(qs));
    }
    if let Some(dc) = val.get("disableCache").and_then(|v| v.as_bool()) { client.set_disable_cache(dc); }
    if let Some(df) = val.get("disableFallback").and_then(|v| v.as_bool()) { client.set_disable_fallback(df); }
    if let Some(dfim) = val.get("disableFallbackIfMatch").and_then(|v| v.as_bool()) {
        client.set_disable_fallback_if_match(dfim);
    }
    if let Some(hosts_obj) = val.get("hosts").and_then(|h| h.as_object()) {
        for (domain, ip_val) in hosts_obj {
            let ips: Vec<std::net::IpAddr> = match ip_val {
                serde_json::Value::String(s) => s.parse().into_iter().collect(),
                serde_json::Value::Array(arr) => arr.iter().filter_map(|x| x.as_str()?.parse().ok()).collect(),
                _ => Vec::new(),
            };
            if !ips.is_empty() { client.add_host(domain, ips); }
        }
    }
    let default_dns_tag = val.get("tag").and_then(|v| v.as_str()).map(str::to_string);
    let default_client_ip = val
        .get("clientIp").and_then(|v| v.as_str()).and_then(|s| s.parse::<std::net::IpAddr>().ok());
    if let Some(servers_arr) = val.get("servers").and_then(|s| s.as_array()) {
        for s in servers_arr {
            if let Some(addr) = s.as_str() {
                client.add_server(crate::app::dns::DnsServerConfig {
                    address: addr.to_string(),
                    tag: default_dns_tag.clone(),
                    client_ip: default_client_ip,
                    ..Default::default()
                });
            } else if let Some(obj) = s.as_object()
                && let Some(raw_addr) = obj.get("address").and_then(|v| v.as_str())
            {
                let address = match (
                    obj.get("port").and_then(|v| v.as_u64()),
                    raw_addr.parse::<std::net::IpAddr>().ok(),
                ) {
                    (Some(port), Some(ip)) => std::net::SocketAddr::new(ip, port as u16).to_string(),
                    _ => raw_addr.to_string(),
                };
                client.add_server(crate::app::dns::DnsServerConfig {
                    address,
                    domains: parse_json_str_array(s, "domains"),
                    expect_ips: parse_json_str_array(s, "expectIPs"),
                    skip_fallback: obj.get("skipFallback").and_then(|v| v.as_bool()).unwrap_or(false),
                    query_strategy: obj
                        .get("queryStrategy")
                        .and_then(|v| v.as_str()).map(crate::app::dns::config::QueryStrategy::from_str),
                    tag: obj
                        .get("tag").and_then(|v| v.as_str()).map(str::to_string).or_else(|| default_dns_tag.clone()),
                    client_ip: obj
                        .get("clientIp")
                        .and_then(|v| v.as_str())
                        .and_then(|x| x.parse::<std::net::IpAddr>().ok()).or(default_client_ip),
                });
            }
        }
    }
    client
}

