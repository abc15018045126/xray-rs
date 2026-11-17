mod commander;
mod config;
mod stats;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{info, warn};

use xray_rs_inbound::tun::init_net_config;
use xray_rs_inbound::{MixedInbound, PingoraHttpInbound, SocksInbound, TunConfig, TunRunner};
use xray_rs_outbound::{
    BlackholeHandler, FreedomHandler, PingoraPooledOutbound, ShadowsocksOutboundHandler,
    TlsTransport, TrojanOutboundHandler, VlessOutboundHandler,
};
use xray_rs_route::{Dispatcher, DomainRule, IpRule, RouteRule, Router};
use xray_rs_types::{BoxStream, InboundHandler, Network, OutboundHandler};

use config::{
    XrayJsonConfig, parse_shadowsocks_settings, parse_trojan_settings, parse_vless_settings,
};
use stats::TrafficStats;

#[derive(Parser)]
#[command(name = "xray-cli", version, about = "Modular Pingora+Tokio Xray-rs")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Local Mixed (HTTP + SOCKS5) listen address when running without subcommand
    #[arg(short, long, default_value = "127.0.0.1:20808")]
    listen: SocketAddr,
}

#[derive(Subcommand)]
enum Commands {
    /// Run xray-cli with a v2rayN-compatible Xray JSON config
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
}

fn build_outbound(cfg: &config::OutboundConfig, idx: usize) -> Option<Arc<dyn OutboundHandler>> {
    let tag = cfg
        .tag
        .clone()
        .unwrap_or_else(|| format!("{}-{}", cfg.protocol, idx));
    match cfg.protocol.to_ascii_lowercase().as_str() {
        "freedom" => Some(Arc::new(FreedomHandler::new(tag))),
        "blackhole" => Some(Arc::new(BlackholeHandler::new(tag))),
        "vless" => {
            let (server, uuid, flow) = parse_vless_settings(&cfg.settings).ok()?;
            let mut handler = VlessOutboundHandler::new(tag.clone(), server, uuid);
            if let Some(f) = flow
                && !f.is_empty()
            {
                handler = handler.with_flow(f);
            }
            if let Some(ss) = &cfg.stream_settings {
                if ss.security.as_deref() == Some("tls") {
                    let tls_cfg = ss.tls_settings.as_ref();
                    let allow_insecure = tls_cfg.map(|t| t.allow_insecure).unwrap_or(false);
                    let alpn: Vec<Vec<u8>> = tls_cfg
                        .map(|t| t.alpn.iter().map(|s| s.as_bytes().to_vec()).collect())
                        .unwrap_or_default();
                    let fp = tls_cfg
                        .and_then(|t| t.fingerprint.as_deref())
                        .unwrap_or("");
                    if let Ok(tls) = TlsTransport::new(allow_insecure, alpn, fp) {
                        let sni = tls_cfg.and_then(|t| t.server_name.clone());
                        handler = handler.with_tls(tls, sni);
                    }
                }
                if ss.network.as_deref() == Some("ws") {
                    let ws_cfg = ss.ws_settings.as_ref();
                    let path = ws_cfg
                        .and_then(|w| w.path.clone())
                        .unwrap_or_else(|| "/".to_string());
                    let host = ws_cfg.and_then(|w| {
                        w.host
                            .clone()
                            .or_else(|| w.headers.get("Host").cloned())
                    });
                    handler = handler.with_websocket(path, host);
                }
            }
            let inner: Arc<dyn OutboundHandler> = Arc::new(handler);
            Some(Arc::new(PingoraPooledOutbound::new(
                tag,
                vec![inner],
                128,
                Duration::from_secs(60),
            )))
        }
        "trojan" => {
            let (server, password) = parse_trojan_settings(&cfg.settings).ok()?;
            let mut handler = TrojanOutboundHandler::new(tag.clone(), server, password);
            if let Some(ss) = &cfg.stream_settings {
                if ss.security.as_deref() == Some("tls") {
                    let tls_cfg = ss.tls_settings.as_ref();
                    let allow_insecure = tls_cfg.map(|t| t.allow_insecure).unwrap_or(false);
                    let alpn: Vec<Vec<u8>> = tls_cfg
                        .map(|t| t.alpn.iter().map(|s| s.as_bytes().to_vec()).collect())
                        .unwrap_or_default();
                    let fp = tls_cfg
                        .and_then(|t| t.fingerprint.as_deref())
                        .unwrap_or("");
                    if let Ok(tls) = TlsTransport::new(allow_insecure, alpn, fp) {
                        let sni = tls_cfg.and_then(|t| t.server_name.clone());
                        handler = handler.with_tls(tls, sni);
                    }
                }
                if ss.network.as_deref() == Some("ws") {
                    let ws_cfg = ss.ws_settings.as_ref();
                    let path = ws_cfg
                        .and_then(|w| w.path.clone())
                        .unwrap_or_else(|| "/".to_string());
                    let host = ws_cfg.and_then(|w| {
                        w.host
                            .clone()
                            .or_else(|| w.headers.get("Host").cloned())
                    });
                    handler = handler.with_websocket(path, host);
                }
            }
            let inner: Arc<dyn OutboundHandler> = Arc::new(handler);
            Some(Arc::new(PingoraPooledOutbound::new(
                tag,
                vec![inner],
                128,
                Duration::from_secs(60),
            )))
        }
        "shadowsocks" => {
            let (server, method, password) = parse_shadowsocks_settings(&cfg.settings).ok()?;
            let inner: Arc<dyn OutboundHandler> =
                Arc::new(ShadowsocksOutboundHandler::new(tag.clone(), server, method, password));
            Some(Arc::new(PingoraPooledOutbound::new(
                tag,
                vec![inner],
                128,
                Duration::from_secs(60),
            )))
        }
        other => {
            warn!("Skipping unsupported outbound protocol '{}'", other);
            None
        }
    }
}

async fn spawn_inbound(
    addr: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    dispatcher: Arc<Dispatcher>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Inbound [{}] listening on {}", handler.tag(), addr);
    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, remote_addr)) => {
                    let _ = stream.set_nodelay(true);
                    let handler = handler.clone();
                    let dispatcher = dispatcher.clone();
                    tokio::spawn(async move {
                        let box_stream: BoxStream = Box::pin(stream);
                        match handler.handle_connection(box_stream, remote_addr).await {
                            Ok(res) => {
                                if let Err(e) = dispatcher.dispatch(res.stream, res.session).await {
                                    warn!("Dispatch error: {}", e);
                                }
                            }
                            Err(e) => warn!("Inbound handshake error from {}: {}", remote_addr, e),
                        }
                    });
                }
                Err(e) => {
                    warn!("Accept error on [{}]: {}", handler.tag(), e);
                    break;
                }
            }
        }
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let stats = Arc::new(TrafficStats::default());
    let _commander = Arc::new(commander::Commander::new());
    _commander.register_service("StatsService");
    _commander.register_service("HandlerService");
    _commander.register_service("RoutingService");

    match cli.command {
        Some(Commands::Run { config }) => {
            let cfg = XrayJsonConfig::from_file(&config)?;
            let mut default_tag = "direct".to_string();
            let mut outbounds = Vec::new();
            for (idx, ob) in cfg.outbounds.iter().enumerate() {
                if let Some(h) = build_outbound(ob, idx) {
                    if idx == 0 {
                        default_tag = h.tag().to_string();
                    }
                    outbounds.push(h);
                }
            }

            let rules = cfg
                .routing
                .as_ref()
                .map(|r| {
                    r.rules
                        .iter()
                        .filter_map(|rc| {
                            if !rc.process.is_empty() {
                                return None;
                            }
                            let tag = rc.outbound_tag.as_ref()?;
                            let mut rule = RouteRule::new(tag);
                            rule.network = match rc.network.as_deref() {
                                Some("tcp") => Some(Network::Tcp),
                                Some("udp") => Some(Network::Udp),
                                _ => None,
                            };
                            rule.inbound_tags = rc.inbound_tag.clone();
                            rule.protocols = rc.protocol.clone();
                            if !rc.domain.is_empty() {
                                rule.domains = rc
                                    .domain
                                    .iter()
                                    .filter_map(|d| DomainRule::parse(d))
                                    .collect();
                                if rule.domains.is_empty() {
                                    return None;
                                }
                            }
                            if !rc.ip.is_empty() {
                                rule.ip_rules = rc
                                    .ip
                                    .iter()
                                    .filter_map(|s| IpRule::parse(s))
                                    .collect();
                                if rule.ip_rules.is_empty() {
                                    return None;
                                }
                            }
                            if let Some(port_str) = &rc.port {
                                rule.ports = port_str
                                    .split(',')
                                    .filter_map(|p| p.trim().parse::<u16>().ok())
                                    .collect();
                            }
                            Some(rule)
                        })
                        .collect()
                })
                .unwrap_or_default();

            let has_sniffing = cfg
                .inbounds
                .iter()
                .any(|ib| ib.sniffing.as_ref().is_some_and(|s| s.enabled));
            let stats_ref = stats.clone();
            let mut dispatcher = Dispatcher::new(default_tag)
                .with_router(Router::new(rules))
                .with_sniffing(has_sniffing)
                .with_stats_callback(Arc::new(move |up, down| {
                    stats_ref.add(up, down);
                }));
            for h in outbounds {
                dispatcher.register_outbound(h);
            }
            let dispatcher = Arc::new(dispatcher);

            let has_tun = cfg
                .inbounds
                .iter()
                .any(|ib| ib.protocol.eq_ignore_ascii_case("tun"));
            if has_tun {
                init_net_config(None).await;
            }

            let mut tasks = Vec::new();
            for (idx, ib) in cfg.inbounds.iter().enumerate() {
                let tag = ib
                    .tag
                    .clone()
                    .unwrap_or_else(|| format!("{}-{}", ib.protocol, idx));
                if ib.protocol.eq_ignore_ascii_case("tun") {
                    let mut tun_cfg = TunConfig {
                        tag,
                        ..Default::default()
                    };
                    if let Some(settings) = &ib.settings
                        && let Ok(ts) =
                            serde_json::from_value::<config::TunInboundSettings>(settings.clone())
                    {
                        if let Some(name) = ts.name
                            && !name.is_empty()
                        {
                            tun_cfg.name = name.clone();
                            tun_cfg.device_id = name;
                        }
                        if let Some(mtu) = ts.mtu
                            && mtu > 0
                        {
                            tun_cfg.mtu = mtu;
                        }
                        if let Some(ar) = ts.auto_route {
                            tun_cfg.auto_route = ar;
                            tun_cfg.route_all = ar;
                        }
                        if let Some(sr) = ts.strict_route {
                            tun_cfg.strict_route = sr;
                        }
                    }
                    let dsp = dispatcher.clone();
                    let cb: xray_rs_inbound::tun::DispatchCallback = Arc::new(move |stream, session| {
                        let dsp = dsp.clone();
                        Box::pin(async move {
                            if let Err(e) = dsp.dispatch(stream, session).await {
                                warn!("TUN dispatch error: {}", e);
                            }
                        })
                    });
                    let runner = TunRunner::new(tun_cfg);
                    tasks.push(runner.start(cb).await?);
                    continue;
                }

                let Some(port) = ib.port else { continue };
                let listen = ib.listen.as_deref().unwrap_or("127.0.0.1");
                let addr: SocketAddr = format!("{}:{}", listen, port).parse()?;
                let handler: Arc<dyn InboundHandler> =
                    match ib.protocol.to_ascii_lowercase().as_str() {
                        "http" => Arc::new(PingoraHttpInbound::new(tag)),
                        "socks" => Arc::new(SocksInbound::new(tag)),
                        "mixed" => Arc::new(MixedInbound::new(tag)),
                        other => {
                            warn!("Skipping unsupported inbound '{}'", other);
                            continue;
                        }
                    };
                tasks.push(spawn_inbound(addr, handler, dispatcher.clone()).await?);
            }

            for t in tasks {
                let _ = t.await;
            }
        }
        None => {
            let inbound: Arc<dyn InboundHandler> = Arc::new(MixedInbound::new("mixed-in"));
            let freedom = Arc::new(FreedomHandler::new("direct"));
            let pooled = Arc::new(PingoraPooledOutbound::new(
                "direct",
                vec![freedom],
                128,
                Duration::from_secs(60),
            ));
            let mut dispatcher = Dispatcher::new("direct");
            dispatcher.register_outbound(pooled);
            let dispatcher = Arc::new(dispatcher);
            let task = spawn_inbound(cli.listen, inbound, dispatcher).await?;
            let _ = task.await;
        }
    }

    Ok(())
}
