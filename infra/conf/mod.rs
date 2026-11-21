pub mod api;
pub mod blackhole;
pub mod buildable;
pub mod cfgcommon;
pub mod common;
pub mod conf;
pub mod dns;
pub mod dns_proxy;
pub mod dokodemo;
pub mod fakedns;
pub mod freedom;
pub mod grpc;
pub mod http;
pub mod hysteria;
pub mod init;
pub mod json;
pub mod lint;
pub mod loader;
pub mod log;
pub mod loopback;
pub mod metrics;
pub mod observatory;
pub mod policy;
pub mod reverse;
pub mod router;
pub mod router_strategy;
pub mod serial;
pub mod shadowsocks;
pub mod socks;
pub mod transport_authenticators;
pub mod transport_internet;
pub mod trojan;
pub mod tun;
pub mod version;
pub mod vless;
pub mod vmess;
pub mod wireguard;
pub mod xray;

#[cfg(test)]
pub mod api_test;
#[cfg(test)]
pub mod blackhole_test;
#[cfg(test)]
pub mod common_test;
#[cfg(test)]
pub mod dns_proxy_test;
#[cfg(test)]
pub mod dns_test;
#[cfg(test)]
pub mod dokodemo_test;
#[cfg(test)]
pub mod freedom_test;
#[cfg(test)]
pub mod general_test;
#[cfg(test)]
pub mod http_test;
#[cfg(test)]
pub mod loopback_test;
#[cfg(test)]
pub mod metrics_test;
#[cfg(test)]
pub mod policy_test;
#[cfg(test)]
pub mod reverse_test;
#[cfg(test)]
pub mod router_test;
#[cfg(test)]
pub mod shadowsocks_test;
#[cfg(test)]
pub mod socks_test;
#[cfg(test)]
pub mod transport_test;
#[cfg(test)]
pub mod trojan_test;
#[cfg(test)]
pub mod vless_test;
#[cfg(test)]
pub mod vmess_test;
#[cfg(test)]
pub mod wireguard_test;
#[cfg(test)]
pub mod xray_test;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalmaskSettingsJson {
    #[serde(default)]
    pub packets: Option<String>,
    #[serde(default)]
    pub length: Option<String>,
    #[serde(default)]
    pub delay: Option<String>,
    #[serde(default, rename = "maxSplit")]
    pub max_split: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default, rename = "type")]
    pub rule_type: Option<String>,
    #[serde(rename = "outboundTag")]
    pub outbound_tag: String,
    #[serde(default, rename = "inboundTag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(default)]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    pub ip: Option<Vec<String>>,
    #[serde(default)]
    pub port: Option<serde_json::Value>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub process: Option<Vec<String>>,
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
    pub network: Option<String>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub fallbacks: Option<Vec<crate::proxy::vless::inbound::Fallback>>,
}

fn parse_fragment_config(
    fm: &FinalmaskConfigJson,
) -> Option<crate::transport::internet::finalmask::fragment::Config> {
    let tcp_layers = fm.tcp.as_ref()?;
    for layer in tcp_layers {
        if layer.mask_type.eq_ignore_ascii_case("fragment") {
            let mut cfg = crate::transport::internet::finalmask::fragment::Config::default();
            if let Some(ref s) = layer.settings {
                if let Some(ref p) = s.packets {
                    if p.eq_ignore_ascii_case("tlshello") {
                        cfg.packets_from = 0;
                        cfg.packets_to = 1;
                    } else if let Some((from_str, to_str)) = p.split_once('-') {
                        cfg.packets_from = from_str.trim().parse().unwrap_or(0);
                        cfg.packets_to = to_str.trim().parse().unwrap_or(1);
                    }
                }
                if let Some(ref l) = s.length {
                    if let Some((min_str, max_str)) = l.split_once('-') {
                        cfg.length_min = min_str.trim().parse().unwrap_or(50);
                        cfg.length_max = max_str.trim().parse().unwrap_or(100);
                    } else if let Ok(val) = l.trim().parse() {
                        cfg.length_min = val;
                        cfg.length_max = val;
                    }
                }
                if let Some(ref d) = s.delay {
                    if let Some((min_str, max_str)) = d.split_once('-') {
                        cfg.delay_min = min_str.trim().parse().unwrap_or(10);
                        cfg.delay_max = max_str.trim().parse().unwrap_or(20);
                    } else if let Ok(val) = d.trim().parse() {
                        cfg.delay_min = val;
                        cfg.delay_max = val;
                    }
                }
                if let Some(ref ms) = s.max_split {
                    if let Some((min_str, max_str)) = ms.split_once('-') {
                        cfg.max_split_min = min_str.trim().parse().unwrap_or(0);
                        cfg.max_split_max = max_str.trim().parse().unwrap_or(0);
                    } else if let Ok(val) = ms.trim().parse() {
                        cfg.max_split_min = val;
                        cfg.max_split_max = val;
                    }
                }
            }
            return Some(cfg);
        }
    }
    None
}

fn wrap_pingora_multi_outbound(
    tag: &str,
    handlers: Vec<Arc<dyn OutboundHandler>>,
    labels: Vec<String>,
) -> Result<Arc<dyn OutboundHandler>> {
    if handlers.len() == 1 {
        return Ok(handlers.into_iter().next().unwrap());
    }
    let lb = Arc::new(
        crate::app::pingora_bridge::PingoraUpstreamBalancer::from_labels_ketama(labels)?,
    );
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

        // 1. Build Outbounds
        for (i, out_cfg) in self.outbounds.into_iter().enumerate() {
            let tag = out_cfg.tag.unwrap_or_else(|| format!("outbound-{}", i));
            if default_outbound_tag.is_none() {
                default_outbound_tag = Some(tag.clone());
            }

            let handler: Arc<dyn OutboundHandler> = match out_cfg.protocol.to_lowercase().as_str() {
                "freedom" | "direct" => Arc::new(p::freedom::Handler::new(&tag)),
                "blackhole" | "block" => {
                    let resp_type = out_cfg
                        .settings
                        .as_ref()
                        .and_then(|s| s.get("response"))
                        .and_then(|r| r.get("type"))
                        .and_then(|t| t.as_str())
                        .map(|t| match t.to_lowercase().as_str() {
                            "http" | "http403" => p::blackhole::ResponseType::Http403,
                            "http500" => p::blackhole::ResponseType::Http500,
                            _ => p::blackhole::ResponseType::None,
                        })
                        .unwrap_or(p::blackhole::ResponseType::None);
                    Arc::new(p::blackhole::Handler::with_response(&tag, resp_type))
                }
                "vless" => {
                    let settings: MultiServerSettings =
                        serde_json::from_value(out_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid VLESS outbound settings: {}", e)),
                        )?;
                    if settings.vnext.is_empty() {
                        return Err(Error::Config("VLESS vnext is empty".into()));
                    }

                    let stream_settings = out_cfg.stream_settings;
                    let mut vless_handlers: Vec<Arc<dyn OutboundHandler>> =
                        Vec::with_capacity(settings.vnext.len());
                    let mut lb_labels: Vec<String> = Vec::with_capacity(settings.vnext.len());

                    for (v_idx, server) in settings.vnext.iter().enumerate() {
                        let user = server
                            .users
                            .first()
                            .ok_or_else(|| Error::Config("VLESS users is empty".into()))?;
                        let user_uuid = Uuid::from_str(&user.id)
                            .map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;

                        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
                        let port_val = server.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
                        let sub_tag = if settings.vnext.len() == 1 {
                            tag.clone()
                        } else {
                            format!("{}#{}", tag, v_idx)
                        };
                        lb_labels.push(format!("{}:{}", addr_str, port_val));

                        let mut tls_client = None;
                        let mut tls_sni = None;
                        let mut ws_path = None;
                        let mut ws_host = None;
                        let mut ws_headers = HashMap::new();
                        let mut ws_heartbeat = 0u32;
                        let mut xhttp_cfg: Option<crate::transport::internet::SplitHttpConfig> =
                            None;
                        let mut httpupgrade_cfg: Option<(
                            String,
                            Option<String>,
                            HashMap<String, String>,
                        )> = None;
                        let mut fragment_cfg = None;

                        if let Some(ref stream_settings) = stream_settings {
                            if let Some(ref fm) = stream_settings.finalmask {
                                fragment_cfg = parse_fragment_config(fm);
                            }

                            let net_lower = stream_settings
                                .network
                                .as_deref()
                                .unwrap_or("tcp")
                                .to_ascii_lowercase();
                            let is_xhttp = net_lower == "xhttp"
                                || net_lower == "splithttp"
                                || stream_settings.xhttp_settings.is_some();
                            if is_xhttp {
                                xhttp_cfg = Some(
                                    stream_settings
                                        .xhttp_settings
                                        .clone()
                                        .unwrap_or_default(),
                                );
                            }

                            let is_httpupgrade = !is_xhttp
                                && (net_lower == "httpupgrade"
                                    || stream_settings.httpupgrade_settings.is_some());
                            if is_httpupgrade {
                                let hu = stream_settings.httpupgrade_settings.as_ref();
                                let path = hu
                                    .and_then(|h| h.path.as_deref())
                                    .map(|p| p.trim())
                                    .filter(|p| !p.is_empty())
                                    .unwrap_or("/")
                                    .to_string();
                                let host = hu
                                    .and_then(|h| h.host.clone())
                                    .filter(|h| !h.trim().is_empty());
                                let headers = hu
                                    .and_then(|h| h.headers.clone())
                                    .unwrap_or_default();
                                httpupgrade_cfg = Some((path, host, headers));
                            }

                            let is_ws = !is_xhttp
                                && !is_httpupgrade
                                && (net_lower == "ws"
                                    || net_lower == "websocket"
                                    || stream_settings.ws_settings.is_some());
                            if is_ws {
                                let ws_cfg = stream_settings.ws_settings.as_ref();
                                ws_heartbeat = ws_cfg.and_then(|w| w.heartbeat_period).unwrap_or(0);
                                let raw_path =
                                    ws_cfg.and_then(|w| w.path.as_deref()).unwrap_or("/");
                                let clean_path = if raw_path.trim().is_empty() {
                                    "/"
                                } else {
                                    raw_path.trim()
                                };
                                ws_path = Some(clean_path.to_string());

                                if let Some(w) = ws_cfg {
                                    if let Some(h) = &w.host
                                        && !h.trim().is_empty()
                                    {
                                        ws_host = Some(h.trim().to_string());
                                    }
                                    if let Some(headers) = &w.headers {
                                        ws_headers = headers.clone();
                                        if ws_host.is_none() {
                                            for (k, v) in headers {
                                                if k.eq_ignore_ascii_case("host")
                                                    && !v.trim().is_empty()
                                                {
                                                    ws_host = Some(v.trim().to_string());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if stream_settings.security.as_deref() == Some("tls") {
                                let tls_cfg =
                                    stream_settings.tls_settings.clone().unwrap_or_default();
                                let clean_server_name =
                                    tls_cfg.server_name.filter(|s| !s.trim().is_empty());
                                let clean_ws_host =
                                    ws_host.clone().filter(|s| !s.trim().is_empty());
                                let sni = clean_server_name
                                    .or(clean_ws_host)
                                    .unwrap_or_else(|| addr_str.to_string());
                                let allow_insecure = tls_cfg.allow_insecure.unwrap_or(false);
                                let alpn = tls_cfg
                                    .alpn
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|s| s.into_bytes())
                                    .collect();
                                let fp = tls_cfg.fingerprint.as_deref().unwrap_or("");
                                tls_client = Some(TlsClient::new_with_fingerprint(
                                    &sni,
                                    allow_insecure,
                                    alpn,
                                    fp,
                                )?);
                                tls_sni = Some(sni.clone());

                                if ws_host.is_none() {
                                    ws_host = Some(sni);
                                }
                            }

                            if is_ws && ws_host.is_none() {
                                ws_host = tls_sni.clone().or_else(|| Some(addr_str.to_string()));
                            }
                        }

                        let is_ws_tls = ws_path.is_some() && tls_client.is_some();
                        let mut client = p::vless::OutboundClient::new(
                            &sub_tag, dest, user_uuid, tls_client, tls_sni, ws_path, ws_host,
                        )
                        .with_ws_headers(ws_headers)
                        .with_ws_heartbeat(ws_heartbeat);
                        if let Some(ref flow) = user.flow
                            && !flow.is_empty()
                        {
                            client = client.with_flow(flow.clone());
                        }
                        let effective_testpre = match user.testpre {
                            Some(n) => n,
                            None => {
                                if is_ws_tls && !client.has_ws_early_data() {
                                    3
                                } else {
                                    0
                                }
                            }
                        };
                        if effective_testpre > 0 {
                            let idle_secs = user.testpre_idle.unwrap_or(45);
                            client = client.with_testpre_idle(effective_testpre, idle_secs);
                        }
                        if let Some(f_cfg) = fragment_cfg {
                            client = client.with_fragment(f_cfg);
                        }
                        if let Some(x_cfg) = xhttp_cfg {
                            client = client.with_splithttp(x_cfg);
                        }
                        if let Some((hu_path, hu_host, hu_headers)) = httpupgrade_cfg {
                            client = client.with_httpupgrade(hu_path, hu_host, hu_headers);
                        }
                        vless_handlers.push(Arc::new(client));
                    }

                    wrap_pingora_multi_outbound(&tag, vless_handlers, lb_labels)?
                }
                "trojan" => {
                    let settings: MultiServerSettings =
                        serde_json::from_value(out_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid Trojan outbound settings: {}", e)),
                        )?;
                    if settings.servers.is_empty() {
                        return Err(Error::Config("Trojan servers list is empty".into()));
                    }
                    let stream_settings = out_cfg.stream_settings;
                    let mut handlers: Vec<Arc<dyn OutboundHandler>> =
                        Vec::with_capacity(settings.servers.len());
                    let mut labels = Vec::with_capacity(settings.servers.len());

                    for (idx, server) in settings.servers.iter().enumerate() {
                        let password = server.password.clone().unwrap_or_default();
                        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
                        let port_val = server.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
                        let sub_tag = if settings.servers.len() == 1 {
                            tag.clone()
                        } else {
                            format!("{}#{}", tag, idx)
                        };
                        labels.push(format!("{}:{}", addr_str, port_val));

                        let mut tls_client = None;
                        let mut tls_sni = None;

                        if let Some(ref stream_settings) = stream_settings
                            && stream_settings.security.as_deref() == Some("tls")
                        {
                            let tls_cfg =
                                stream_settings.tls_settings.clone().unwrap_or_default();
                            let sni = tls_cfg
                                .server_name
                                .clone()
                                .unwrap_or_else(|| addr_str.to_string());
                            let allow_insecure = tls_cfg.allow_insecure.unwrap_or(false);
                            let alpn = tls_cfg
                                .alpn
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.into_bytes())
                                .collect();
                            let fp = tls_cfg.fingerprint.as_deref().unwrap_or("");
                            tls_client = Some(TlsClient::new_with_fingerprint(
                                &sni,
                                allow_insecure,
                                alpn,
                                fp,
                            )?);
                            tls_sni = Some(sni);
                        }

                        handlers.push(Arc::new(p::trojan::OutboundClient::new(
                            &sub_tag, dest, password, tls_client, tls_sni,
                        )));
                    }

                    wrap_pingora_multi_outbound(&tag, handlers, labels)?
                }
                "shadowsocks" => {
                    let settings: MultiServerSettings = serde_json::from_value(
                        out_cfg.settings.unwrap_or_default(),
                    )
                    .map_err(|e| {
                        Error::Config(format!("Invalid Shadowsocks outbound settings: {}", e))
                    })?;
                    if settings.servers.is_empty() {
                        return Err(Error::Config("Shadowsocks servers list is empty".into()));
                    }
                    let mut handlers: Vec<Arc<dyn OutboundHandler>> =
                        Vec::with_capacity(settings.servers.len());
                    let mut labels = Vec::with_capacity(settings.servers.len());

                    for (idx, server) in settings.servers.iter().enumerate() {
                        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
                        let port_val = server.port.unwrap_or(8388);
                        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
                        let password = server.password.clone().unwrap_or_default();
                        let method = server
                            .method
                            .clone()
                            .unwrap_or_else(|| "aes-256-gcm".into());
                        let sub_tag = if settings.servers.len() == 1 {
                            tag.clone()
                        } else {
                            format!("{}#{}", tag, idx)
                        };
                        labels.push(format!("{}:{}", addr_str, port_val));

                        handlers.push(Arc::new(p::shadowsocks::OutboundClient::new(
                            &sub_tag, dest, method, password,
                        )));
                    }

                    wrap_pingora_multi_outbound(&tag, handlers, labels)?
                }
                "vmess" => {
                    let settings: MultiServerSettings =
                        serde_json::from_value(out_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid VMess outbound settings: {}", e)),
                        )?;
                    if settings.vnext.is_empty() {
                        return Err(Error::Config("VMess vnext is empty".into()));
                    }
                    let stream_settings = out_cfg.stream_settings;
                    let mut handlers: Vec<Arc<dyn OutboundHandler>> =
                        Vec::with_capacity(settings.vnext.len());
                    let mut labels = Vec::with_capacity(settings.vnext.len());

                    for (idx, server) in settings.vnext.iter().enumerate() {
                        let user = server
                            .users
                            .first()
                            .ok_or_else(|| Error::Config("VMess users is empty".into()))?;
                        let user_uuid = Uuid::from_str(&user.id)
                            .map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
                        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
                        let port_val = server.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
                        let sub_tag = if settings.vnext.len() == 1 {
                            tag.clone()
                        } else {
                            format!("{}#{}", tag, idx)
                        };
                        labels.push(format!("{}:{}", addr_str, port_val));

                        let mut tls_client = None;
                        let mut tls_sni = None;

                        if let Some(ref stream_settings) = stream_settings
                            && stream_settings.security.as_deref() == Some("tls")
                        {
                            let tls_cfg =
                                stream_settings.tls_settings.clone().unwrap_or_default();
                            let sni = tls_cfg
                                .server_name
                                .clone()
                                .unwrap_or_else(|| addr_str.to_string());
                            let allow_insecure = tls_cfg.allow_insecure.unwrap_or(false);
                            let alpn = tls_cfg
                                .alpn
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.into_bytes())
                                .collect();
                            let fp = tls_cfg.fingerprint.as_deref().unwrap_or("");
                            tls_client = Some(TlsClient::new_with_fingerprint(
                                &sni,
                                allow_insecure,
                                alpn,
                                fp,
                            )?);
                            tls_sni = Some(sni);
                        }

                        handlers.push(Arc::new(p::vmess::OutboundClient::new(
                            &sub_tag, dest, user_uuid, tls_client, tls_sni,
                        )));
                    }

                    wrap_pingora_multi_outbound(&tag, handlers, labels)?
                }
                "socks" => {
                    let settings: MultiServerSettings =
                        serde_json::from_value(out_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid SOCKS outbound settings: {}", e)),
                        )?;
                    if settings.servers.is_empty() {
                        return Err(Error::Config("SOCKS servers list is empty".into()));
                    }
                    let mut handlers: Vec<Arc<dyn OutboundHandler>> =
                        Vec::with_capacity(settings.servers.len());
                    let mut labels = Vec::with_capacity(settings.servers.len());

                    for (idx, server) in settings.servers.iter().enumerate() {
                        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
                        let port_val = server.port.unwrap_or(1080);
                        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
                        let sub_tag = if settings.servers.len() == 1 {
                            tag.clone()
                        } else {
                            format!("{}#{}", tag, idx)
                        };
                        labels.push(format!("{}:{}", addr_str, port_val));

                        handlers.push(Arc::new(p::socks::Client::new(&sub_tag, dest)));
                    }

                    wrap_pingora_multi_outbound(&tag, handlers, labels)?
                }
                "dns" => Arc::new(p::DnsOutbound::new(tag.clone(), dns_client.clone())),
                other => {
                    return Err(Error::Unsupported(format!(
                        "Outbound protocol '{}' is not supported",
                        other
                    )));
                }
            };

            outbounds.insert(tag, handler);
        }

        // 2. Build Inbounds
        for (i, in_cfg) in self.inbounds.into_iter().enumerate() {
            let tag = in_cfg.tag.unwrap_or_else(|| format!("inbound-{}", i));
            let proto = in_cfg.protocol.to_lowercase();
            if proto == "tun" {
                let tun_name = in_cfg
                    .settings
                    .as_ref()
                    .and_then(|s| s.get("name").and_then(|v| v.as_str()))
                    .unwrap_or("xray_tun");
                let mtu = in_cfg
                    .settings
                    .as_ref()
                    .and_then(|s| {
                        s.get("mtu")
                            .or_else(|| s.get("MTU"))
                            .and_then(|v| v.as_u64())
                    })
                    .unwrap_or(1500) as usize;

                let mut gateway_v4: ipnet::Ipv4Net = "172.18.0.1/30".parse().unwrap();
                let mut gateway_v6: Option<ipnet::Ipv6Net> = None;

                if let Some(gateways) = in_cfg
                    .settings
                    .as_ref()
                    .and_then(|s| s.get("gateway").and_then(|v| v.as_array()))
                {
                    for gw in gateways {
                        if let Some(gw_str) = gw.as_str() {
                            if let Ok(net) = gw_str.parse::<ipnet::Ipv4Net>() {
                                gateway_v4 = net;
                            } else if let Ok(net) = gw_str.parse::<ipnet::Ipv6Net>() {
                                gateway_v6 = Some(net);
                            }
                        }
                    }
                }

                let mut route_all = false;
                let mut routes = Vec::new();
                if let Some(rt_val) = in_cfg
                    .settings
                    .as_ref()
                    .and_then(|s| s.get("autoSystemRoutingTable"))
                {
                    if let Some(arr) = rt_val.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                if s == "0.0.0.0/0" || s == "::/0" {
                                    route_all = true;
                                } else if let Ok(net) = s.parse::<ipnet::IpNet>() {
                                    routes.push(net);
                                }
                            }
                        }
                    } else if rt_val.as_bool() == Some(true) {
                        route_all = true;
                    }
                }

                let sniffing_req = in_cfg.sniffing.map(|s| {
                    let enabled = s.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let route_only = s
                        .get("routeOnly")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let mut dest_override = Vec::new();
                    if let Some(arr) = s.get("destOverride").and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(st) = item.as_str() {
                                dest_override.push(st.to_string());
                            }
                        }
                    }
                    crate::common::session::SniffingRequest {
                        enabled,
                        override_destination_for_protocol: dest_override,
                        route_only,
                        ..Default::default()
                    }
                });

                let tun_cfg = p::tun::TunConfig {
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
                    sniffing: sniffing_req,
                    auto_route: route_all,
                    strict_route: true,
                };

                let dev = Arc::new(p::tun::TunRunner::new(tun_cfg));
                tun_devices.push(dev);
                continue;
            }

            let listen_ip = in_cfg.listen.as_deref().unwrap_or("0.0.0.0");
            let port_val = in_cfg.port.unwrap_or(0);

            // Skip TCP binding for port 0
            if port_val == 0 {
                continue;
            }

            let bind_addr: SocketAddr =
                format!("{}:{}", listen_ip, port_val).parse().map_err(|e| {
                    Error::Config(format!(
                        "Invalid listen address '{}:{}': {}",
                        listen_ip, port_val, e
                    ))
                })?;

            let handler: Arc<dyn InboundHandler> = match proto.as_str() {
                "socks" | "socks5" => Arc::new(p::socks::Server::new(&tag)),
                "http" => Arc::new(p::http::Server::new(&tag)),
                "mixed" => Arc::new(p::mixed::Server::new(&tag)),
                "vless" => {
                    let settings: MultiServerSettings = serde_json::from_value(
                        in_cfg.settings.unwrap_or_default(),
                    )
                    .map_err(|e| Error::Config(format!("Invalid VLESS inbound settings: {}", e)))?;
                    let mut user_uuids = Vec::new();
                    for client in settings.clients {
                        let u = Uuid::from_str(&client.id)
                            .map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
                        user_uuids.push(u);
                    }
                    if let Some(ref dec) = settings.decryption
                        && !dec.is_empty()
                        && !dec.eq_ignore_ascii_case("none")
                    {
                        return Err(Error::Config(format!(
                            "VLESS inbound '{}' unsupported decryption '{}': only 'none' is supported",
                            tag, dec
                        )));
                    }
                    let mut server = p::vless::InboundServer::new(&tag, user_uuids);
                    if let Some(fallbacks) = settings.fallbacks
                        && !fallbacks.is_empty()
                    {
                        server = server.with_fallbacks(fallbacks);
                    }
                    Arc::new(server)
                }
                "trojan" => {
                    let settings: MultiServerSettings =
                        serde_json::from_value(in_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid Trojan inbound settings: {}", e)),
                        )?;
                    let mut passwords = Vec::new();
                    for client in settings.clients {
                        if let Some(pwd) = client.password {
                            passwords.push(pwd);
                        }
                    }
                    Arc::new(p::trojan::InboundServer::new(&tag, passwords))
                }
                "shadowsocks" => {
                    let settings: MultiServerSettings = serde_json::from_value(
                        in_cfg.settings.unwrap_or_default(),
                    )
                    .map_err(|e| {
                        Error::Config(format!("Invalid Shadowsocks inbound settings: {}", e))
                    })?;
                    let password = settings
                        .servers
                        .first()
                        .and_then(|s| s.password.clone())
                        .unwrap_or_default();
                    let method = settings
                        .servers
                        .first()
                        .and_then(|s| s.method.clone())
                        .unwrap_or_else(|| "aes-256-gcm".into());
                    Arc::new(p::shadowsocks::InboundServer::new(&tag, method, password))
                }
                "dokodemo-door" | "dokodemo" => {
                    let settings: MultiServerSettings =
                        serde_json::from_value(in_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid Dokodemo inbound settings: {}", e)),
                        )?;
                    let target_addr = settings.address.unwrap_or_else(|| "127.0.0.1".into());
                    let target_port = settings.port.unwrap_or(80);
                    let dest = Destination::from_str(&format!("{}:{}", target_addr, target_port))?;
                    let network = match settings.network.as_deref() {
                        Some("udp") => Network::Udp,
                        _ => Network::Tcp,
                    };
                    Arc::new(p::dokodemo::Server::new(&tag, dest, network))
                }
                "vmess" => {
                    let settings: MultiServerSettings = serde_json::from_value(
                        in_cfg.settings.unwrap_or_default(),
                    )
                    .map_err(|e| Error::Config(format!("Invalid VMess inbound settings: {}", e)))?;
                    let mut user_uuids = Vec::new();
                    for client in settings.clients {
                        let u = Uuid::from_str(&client.id)
                            .map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
                        user_uuids.push(u);
                    }
                    Arc::new(p::vmess::InboundServer::new(&tag, user_uuids))
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "Inbound protocol '{}' is not supported",
                        other
                    )));
                }
            };

            let sniffing_req = in_cfg.sniffing.as_ref().and_then(|v| {
                let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
                if !enabled {
                    return None;
                }
                let metadata_only = v
                    .get("metadataOnly")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                let route_only = v.get("routeOnly").and_then(|b| b.as_bool()).unwrap_or(false);
                let override_destination_for_protocol = v
                    .get("destOverride")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let exclude_for_domain = v
                    .get("domainsExcluded")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                Some(crate::common::session::SniffingRequest {
                    enabled,
                    metadata_only,
                    route_only,
                    exclude_for_domain,
                    override_destination_for_protocol,
                })
            });

            let handler: Arc<dyn InboundHandler> = if let Some(ref stream_cfg) =
                in_cfg.stream_settings
            {
                let security = stream_cfg
                    .security
                    .as_deref()
                    .unwrap_or("none")
                    .to_ascii_lowercase();
                let network = stream_cfg
                    .network
                    .as_deref()
                    .unwrap_or("tcp")
                    .to_ascii_lowercase();

                let tls_server = if security == "tls" {
                    let tls_cfg = stream_cfg.tls_settings.as_ref().ok_or_else(|| {
                        Error::Config(format!(
                            "Inbound '{}' has security='tls' but missing tlsSettings",
                            tag
                        ))
                    })?;
                    let alpn: Vec<Vec<u8>> = tls_cfg
                        .alpn
                        .as_ref()
                        .map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect())
                        .unwrap_or_default();
                    let cert_cfg = tls_cfg
                        .certificates
                        .as_ref()
                        .and_then(|c| c.first())
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
                        crate::transport::internet::TlsServer::from_pem_files(
                            cert_file, key_file, alpn,
                        )?
                    } else if let (Some(cert_lines), Some(key_lines)) = (
                        cert_cfg.certificate.as_ref(),
                        cert_cfg.key.as_ref(),
                    ) {
                        let cert_pem = cert_lines.join("\n");
                        let key_pem = key_lines.join("\n");
                        crate::transport::internet::TlsServer::from_pem(
                            cert_pem.as_bytes(),
                            key_pem.as_bytes(),
                            alpn,
                        )?
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
                        Error::Config(format!(
                            "Inbound '{}' has security='reality' but missing realitySettings",
                            tag
                        ))
                    })?;
                    Some(Arc::new(
                        crate::transport::internet::reality::RealityServer::new(rc)?,
                    ))
                } else {
                    None
                };

                let is_xhttp = network == "xhttp" || network == "splithttp";
                let splithttp_server = if is_xhttp {
                    let x_cfg = stream_cfg.xhttp_settings.clone().unwrap_or_default();
                    Some(Arc::new(
                        crate::transport::internet::splithttp::SplitHttpServer::new(x_cfg),
                    ))
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
                                h.iter()
                                    .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                                    .map(|(_, v)| v.clone())
                            })
                        })
                    });
                    (path, host)
                } else {
                    (None, None)
                };

                if tls_server.is_some()
                    || reality_server.is_some()
                    || is_ws
                    || httpupgrade_pair.is_some()
                    || splithttp_server.is_some()
                    || sniffing_req.is_some()
                {
                    let mut wrapped = crate::app::proxyman::inbound::StreamInboundHandler::new(
                        handler, tls_server, is_ws, ws_path, ws_host,
                    );
                    if let Some(r_srv) = reality_server {
                        wrapped = wrapped.with_reality(r_srv);
                    }
                    if let Some((hu_path, hu_host)) = httpupgrade_pair {
                        wrapped = wrapped.with_httpupgrade(hu_path, hu_host);
                    }
                    if let Some(xhttp_srv) = splithttp_server {
                        wrapped = wrapped.with_splithttp(xhttp_srv);
                    }
                    if let Some(sniff) = sniffing_req {
                        wrapped = wrapped.with_sniffing(sniff);
                    }
                    Arc::new(wrapped)
                } else {
                    handler
                }
            } else if let Some(sniff) = sniffing_req {
                Arc::new(
                    crate::app::proxyman::inbound::StreamInboundHandler::new(
                        handler, None, false, None, None,
                    )
                    .with_sniffing(sniff),
                )
            } else {
                handler
            };

            inbounds.push((bind_addr, handler));
        }

        // 3. Build Router
        let mut rules = Vec::new();
        if let Some(routing) = self.routing
            && let Some(rule_configs) = routing.rules
        {
            for r_cfg in rule_configs {
                let mut rule = Rule::new(&r_cfg.outbound_tag);
                if let Some(in_tags) = r_cfg.inbound_tag {
                    rule.inbound_tags = in_tags;
                }
                if let Some(domains) = r_cfg.domain {
                    for d in domains {
                        rule.domain_matchers.push(DomainMatcher::parse(&d));
                    }
                }
                if let Some(ips) = r_cfg.ip {
                    for ip_str in ips {
                        if let Some(ip_matcher) = IpMatcher::parse(&ip_str) {
                            rule.ip_matchers.push(ip_matcher);
                        }
                    }
                }
                if let Some(port_val) = r_cfg.port {
                    let ports_str = match port_val {
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => s,
                        _ => String::new(),
                    };
                    for part in ports_str.split(',') {
                        let trimmed = part.trim();
                        if trimmed.contains('-') {
                            let range_parts: Vec<&str> = trimmed.split('-').collect();
                            if range_parts.len() == 2
                                && let (Ok(start), Ok(end)) = (
                                    range_parts[0].trim().parse::<u16>(),
                                    range_parts[1].trim().parse::<u16>(),
                                )
                            {
                                for p in start..=end {
                                    rule.ports.push(p);
                                }
                            }
                        } else if let Ok(p) = trimmed.parse::<u16>() {
                            rule.ports.push(p);
                        }
                    }
                }
                if let Some(net_str) = r_cfg.network {
                    rule.network = match net_str.to_lowercase().as_str() {
                        "tcp" => Some(Network::Tcp),
                        "udp" => Some(Network::Udp),
                        _ => None,
                    };
                }
                if let Some(proc_list) = r_cfg.process {
                    rule.process = proc_list;
                }
                rules.push(rule);
            }
        }

        let router = Router::new(rules, default_outbound_tag.clone());
        dns_client.attach_routing(router.clone(), outbounds.clone());

        Ok(BuiltConfig {
            inbounds,
            tun_devices,
            outbounds,
            router,
            default_outbound_tag,
        })
    }
}

fn build_dns_client(dns_val: Option<&serde_json::Value>) -> crate::app::dns::DnsClient {
    let mut client = crate::app::dns::DnsClient::new();
    if let Some(val) = dns_val {
        if let Some(qs) = val.get("queryStrategy").and_then(|v| v.as_str()) {
            client.set_query_strategy(crate::app::dns::config::QueryStrategy::from_str(qs));
        }
        if let Some(dc) = val.get("disableCache").and_then(|v| v.as_bool()) {
            client.set_disable_cache(dc);
        }
        if let Some(df) = val.get("disableFallback").and_then(|v| v.as_bool()) {
            client.set_disable_fallback(df);
        }
        if let Some(dfim) = val.get("disableFallbackIfMatch").and_then(|v| v.as_bool()) {
            client.set_disable_fallback_if_match(dfim);
        }

        if let Some(hosts_obj) = val.get("hosts").and_then(|h| h.as_object()) {
            for (domain, ip_val) in hosts_obj {
                let mut ips = Vec::new();
                if let Some(s) = ip_val.as_str() {
                    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                        ips.push(ip);
                    }
                } else if let Some(arr) = ip_val.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_str()
                            && let Ok(ip) = s.parse::<std::net::IpAddr>()
                        {
                            ips.push(ip);
                        }
                    }
                }
                if !ips.is_empty() {
                    client.add_host(domain, ips);
                }
            }
        }

        let default_dns_tag = val
            .get("tag")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let default_client_ip = val
            .get("clientIp")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<std::net::IpAddr>().ok());

        if let Some(servers_arr) = val.get("servers").and_then(|s| s.as_array()) {
            let parse_str_list = |obj: &serde_json::Map<String, serde_json::Value>, key: &str| {
                obj.get(key)
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default()
            };

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
                    let addr = if let Some(port) = obj.get("port").and_then(|v| v.as_u64())
                        && let Ok(ip) = raw_addr.parse::<std::net::IpAddr>()
                    {
                        std::net::SocketAddr::new(ip, port as u16).to_string()
                    } else {
                        raw_addr.to_string()
                    };
                    let domains = parse_str_list(obj, "domains");
                    let expect_ips = parse_str_list(obj, "expectIPs");
                    let skip_fallback = obj
                        .get("skipFallback")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let query_strategy = obj
                        .get("queryStrategy")
                        .and_then(|v| v.as_str())
                        .map(crate::app::dns::config::QueryStrategy::from_str);
                    let tag = obj
                        .get("tag")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string())
                        .or_else(|| default_dns_tag.clone());
                    let client_ip = obj
                        .get("clientIp")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                        .or(default_client_ip);

                    client.add_server(crate::app::dns::DnsServerConfig {
                        address: addr,
                        domains,
                        expect_ips,
                        skip_fallback,
                        query_strategy,
                        tag,
                        client_ip,
                    });
                }
            }
        }
    }
    client
}
