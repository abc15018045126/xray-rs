// Module: app\dispatcher\default.rs
// 1:1 Rust implementation corresponding to Go app\dispatcher\default.go

use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use pingora_timeout::timeout;
use tracing::{debug, info, warn};

use crate::app::dispatcher::sniffer::{SniffResult, Sniffer};
use crate::app::dns::fakedns::FakeDnsHolder;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::common::session::SniffingRequest;
use crate::features::feature::{Feature, TYPE_DISPATCHER};
use crate::features::outbound::{OutboundHandler, OutboundManager};
use crate::features::policy::PolicyManager;
use crate::features::routing::{Dispatcher, DispatcherFeature, RouterFeature};
use crate::features::stats::StatsManagerTrait;

/// DefaultDispatcher is the core routing dispatcher connecting Inbounds to Outbounds.
pub struct DefaultDispatcher {
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    default_outbound_tag: Option<String>,
    outbound_manager: Option<Arc<dyn OutboundManager>>,
    router: Option<Arc<dyn RouterFeature>>,
    policy: Option<Arc<dyn PolicyManager>>,
    stats: Option<Arc<dyn StatsManagerTrait>>,
    fakedns: Option<Arc<FakeDnsHolder>>,
    sniffer: Sniffer,
}

impl DefaultDispatcher {
    pub fn new(
        outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
        router: Arc<dyn RouterFeature>,
    ) -> Self {
        Self {
            outbounds,
            default_outbound_tag: None,
            outbound_manager: None,
            router: Some(router),
            policy: None,
            stats: None,
            fakedns: None,
            sniffer: Sniffer::new(None),
        }
    }

    pub fn with_default_outbound(mut self, tag: impl Into<String>) -> Self {
        self.default_outbound_tag = Some(tag.into());
        self
    }

    pub fn with_outbound_manager(mut self, om: Arc<dyn OutboundManager>) -> Self {
        self.outbound_manager = Some(om);
        self
    }

    pub fn with_router(mut self, router: Arc<dyn RouterFeature>) -> Self {
        self.router = Some(router);
        self
    }

    pub fn with_policy(mut self, policy: Arc<dyn PolicyManager>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_stats(mut self, stats: Arc<dyn StatsManagerTrait>) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_fakedns(mut self, fakedns: Arc<FakeDnsHolder>) -> Self {
        self.sniffer = Sniffer::new(Some(fakedns.clone()));
        self.fakedns = Some(fakedns);
        self
    }

    pub fn get_handler(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.outbounds.get(tag).cloned()
    }

    /// Determines whether the sniffed result should override the original destination
    /// following the exact Go logic.
    pub fn should_override(
        &self,
        result: &SniffResult,
        request: &SniffingRequest,
        destination: &Destination,
    ) -> bool {
        let domain = &result.domain;
        if domain.is_empty() {
            return false;
        }

        // Check exclusions: regex or exact domain match
        for exc in &request.exclude_for_domain {
            if let Some(pattern) = exc.strip_prefix("regexp:") {
                if let Ok(re) = Regex::new(pattern)
                    && re.is_match(domain)
                {
                    return false;
                }
            } else if domain.eq_ignore_ascii_case(exc) {
                return false;
            }
        }

        let protocol_str = &result.protocol;
        for p in &request.override_destination_for_protocol {
            if protocol_str.starts_with(p) || p.starts_with(protocol_str) {
                return true;
            }
            if p == "fakedns"
                && protocol_str != "bittorrent"
                && let Some(ip) = destination.address.as_ip()
                && self.sniffer.is_in_fake_ip_pool(&ip)
            {
                return true;
            }
        }

        false
    }

    pub async fn dispatch(
        &self,
        mut inbound_stream: BoxStream,
        mut session: SessionContext,
    ) -> Result<()> {
        let mut initial_payload: Vec<u8> = Vec::new();

        // 1. Sniffing phase if requested
        if let Some(sniff_req) = session.sniffing_request.clone()
            && sniff_req.enabled
        {
            // Read up to 2048 bytes with 200ms timeout
            let mut buf = [0u8; 2048];
            if let Ok(Ok(n)) =
                timeout(Duration::from_millis(200), inbound_stream.read(&mut buf)).await
                && n > 0
            {
                initial_payload.extend_from_slice(&buf[..n]);
                // Try sniffing content
                let network = match session.destination.address {
                    Address::Ipv4(_) | Address::Ipv6(_) | Address::Domain(_) => Network::Tcp,
                };
                if let Ok(sniff_res) = self.sniffer.sniff(&initial_payload, network) {
                    session.sniffed_protocol = Some(sniff_res.protocol.clone());
                    session.sniffed_domain = Some(sniff_res.domain.clone());

                    if self.should_override(&sniff_res, &sniff_req, &session.destination) {
                        info!(
                            "Sniffed domain: {} (protocol: {})",
                            sniff_res.domain, sniff_res.protocol
                        );
                        if sniff_req.route_only {
                            session.route_target = Some(Destination::new(
                                Address::Domain(sniff_res.domain.clone()),
                                session.destination.port,
                            ));
                        } else {
                            session.destination = Destination::new(
                                Address::Domain(sniff_res.domain.clone()),
                                session.destination.port,
                            );
                        }
                    }
                }
            }

            // If content sniffing didn't resolve domain, check FakeDNS metadata if target is IP
            if session.sniffed_domain.is_none()
                && let Some(ip) = session.destination.address.as_ip()
                && let Some(domain) = self.sniffer.sniff_ip(ip)
            {
                let fake_res = SniffResult {
                    protocol: "fakedns".into(),
                    domain: domain.clone(),
                };
                session.sniffed_protocol = Some("fakedns".into());
                session.sniffed_domain = Some(domain.clone());
                if self.should_override(&fake_res, &sniff_req, &session.destination) {
                    if sniff_req.route_only {
                        session.route_target = Some(Destination::new(
                            Address::Domain(domain),
                            session.destination.port,
                        ));
                    } else {
                        session.destination =
                            Destination::new(Address::Domain(domain), session.destination.port);
                    }
                }
            }
        }

        // 2. Detour / Outbound selection
        #[cfg(debug_assertions)]
        let debug_host = session
            .sniffed_domain
            .clone()
            .unwrap_or_else(|| session.destination.address.to_string());

        #[cfg(debug_assertions)]
        let debug_bypass = crate::debug_panel::should_bypass_direct(&debug_host);

        #[cfg(debug_assertions)]
        if debug_bypass && initial_payload.is_empty() {
            let mut peek_buf = [0u8; 2048];
            if let Ok(Ok(n)) =
                timeout(Duration::from_millis(80), inbound_stream.read(&mut peek_buf)).await
                && n > 0
            {
                initial_payload.extend_from_slice(&peek_buf[..n]);
            }
        }

        #[cfg(debug_assertions)]
        let debug_features = if !initial_payload.is_empty() {
            Some(crate::debug_panel::inspect_initial_payload(&initial_payload))
        } else {
            None
        };

        #[cfg(debug_assertions)]
        let debug_connect_start = std::time::Instant::now();

        let (outbound_tag, mut outbound_stream) = {
            #[cfg(debug_assertions)]
            let bypass_now = debug_bypass;
            #[cfg(not(debug_assertions))]
            let bypass_now = false;

            if bypass_now {
                let tag = "debug-direct-bypass".to_string();
                session.outbound_tag = Some(tag.clone());
                info!(
                    "[DEBUG DIRECT BYPASS] [{}] -> [{}] (kernel direct, no proxy)",
                    session
                        .source
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    session.destination
                );
                let stream = match crate::transport::internet::TcpDialer::dial(&session.destination).await {
                    Ok(s) => s,
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        crate::debug_panel::metrics().record_connect_failed(
                            &debug_host,
                            &tag,
                            true,
                            debug_connect_start.elapsed().as_secs_f64() * 1000.0,
                            &e.to_string(),
                        );
                        warn!(
                            "[DEBUG DIRECT BYPASS] Failed direct kernel connect for {}: {}",
                            session.destination, e
                        );
                        return Err(e);
                    }
                };
                (tag, stream)
            } else {
                let outbound_tag = if let Some(forced) = &session.forced_outbound_tag {
                    forced.clone()
                } else if let Some(router) = &self.router {
                    #[cfg(debug_assertions)]
                    let _rt0 = std::time::Instant::now();
                    let picked = router
                        .pick_outbound(&session)
                        .map(|s| s.to_string())
                        .or_else(|| self.default_outbound_tag.clone())
                        .ok_or_else(|| Error::NotFound("No matching outbound route found".into()));
                    #[cfg(debug_assertions)]
                    crate::debug_panel::record_stage("路由/Geo分流 (router)", _rt0.elapsed());
                    picked?
                } else if let Some(def_tag) = &self.default_outbound_tag {
                    def_tag.clone()
                } else if let Some(first_tag) = self.outbounds.keys().next() {
                    first_tag.clone()
                } else {
                    return Err(Error::NotFound("No outbound handlers configured".into()));
                };

                session.outbound_tag = Some(outbound_tag.clone());

                let outbound = if let Some(om) = &self.outbound_manager {
                    if let Some(h) = om.get_handler(&outbound_tag).await {
                        h
                    } else {
                        self.outbounds
                            .get(&outbound_tag)
                            .ok_or_else(|| {
                                Error::NotFound(format!("Outbound handler '{}' not found", outbound_tag))
                            })?
                            .clone()
                    }
                } else {
                    self.outbounds
                        .get(&outbound_tag)
                        .ok_or_else(|| {
                            Error::NotFound(format!("Outbound handler '{}' not found", outbound_tag))
                        })?
                        .clone()
                };

                info!(
                    "Dispatching [{}] -> [{}] via tag '{}'",
                    session
                        .source
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    session.destination,
                    outbound_tag
                );

                // 3. Connect to outbound
                #[cfg(debug_assertions)]
                let _ct0 = std::time::Instant::now();
                let stream = match outbound.connect(&session).await {
                    Ok(stream) => {
                        #[cfg(debug_assertions)]
                        crate::debug_panel::record_stage(
                            "出站建连握手 (TLS/WS/VLESS)",
                            _ct0.elapsed(),
                        );
                        stream
                    }
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        crate::debug_panel::record_stage(
                            "出站建连握手 (TLS/WS/VLESS)",
                            _ct0.elapsed(),
                        );
                        #[cfg(debug_assertions)]
                        crate::debug_panel::metrics().record_connect_failed(
                            &debug_host,
                            &outbound_tag,
                            false,
                            debug_connect_start.elapsed().as_secs_f64() * 1000.0,
                            &e.to_string(),
                        );
                        warn!(
                            "Failed to establish outbound connection for {}: {}",
                            session.destination, e
                        );
                        return Err(e);
                    }
                };
                (outbound_tag, stream)
            }
        };

        #[cfg(debug_assertions)]
        let debug_conn_id = crate::debug_panel::capture().next_conn_id();

        #[cfg(debug_assertions)]
        crate::debug_panel::metrics().record_connect_start(
            &debug_host,
            &outbound_tag,
            debug_bypass,
            false,
            debug_connect_start.elapsed().as_secs_f64() * 1000.0,
            debug_features,
        );
        let _ = &outbound_tag;

        // 4. Flush any initial payload buffered during sniffing
        let initial_len = initial_payload.len();
        if !initial_payload.is_empty() {
            #[cfg(debug_assertions)]
            {
                let src_str = session
                    .source
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "127.0.0.1:0".into());
                let dst_str = session.destination.to_string();
                crate::debug_panel::capture().record_chunk(
                    debug_conn_id,
                    &debug_host,
                    &src_str,
                    &dst_str,
                    crate::debug_panel::Direction::ClientToServer,
                    &outbound_tag,
                    debug_bypass,
                    &initial_payload,
                );
            }
            if let Err(e) = outbound_stream.write_all(&initial_payload).await {
                #[cfg(debug_assertions)]
                crate::debug_panel::metrics().record_connect_end(
                    &debug_host,
                    debug_bypass,
                    0,
                    0,
                    debug_connect_start.elapsed().as_secs_f64() * 1000.0,
                    crate::debug_panel::capture().flow_snapshot(debug_conn_id),
                );
                warn!("Failed to forward initial sniffed payload: {}", e);
                return Err(Error::Io(e));
            }
        }

        // 5. User traffic & stats accounting setup
        let (uplink_counter, downlink_counter, online_map, user_ip, conn_idle) = {
            let level = session.user.as_ref().map(|u| u.level).unwrap_or(0);
            let idle = if let Some(policy_mgr) = &self.policy {
                policy_mgr.for_level(level).timeouts.connection_idle
            } else {
                crate::features::policy::session_default()
                    .timeouts
                    .connection_idle
            };

            if let (Some(user), Some(policy_mgr), Some(stats_mgr)) =
                (&session.user, &self.policy, &self.stats)
            {
                let p = policy_mgr.for_level(user.level);
                let up = if p.stats.user_uplink && !user.email.is_empty() {
                    Some(
                        stats_mgr
                            .register_counter(&format!("user>>>{}>>>traffic>>>uplink", user.email)),
                    )
                } else {
                    None
                };
                let down =
                    if p.stats.user_downlink && !user.email.is_empty() {
                        Some(stats_mgr.register_counter(&format!(
                            "user>>>{}>>>traffic>>>downlink",
                            user.email
                        )))
                    } else {
                        None
                    };
                let (om, ip_str) = if p.stats.user_online && !user.email.is_empty() {
                    let om =
                        stats_mgr.register_online_map(&format!("user>>>{}>>>online", user.email));
                    let ip = session
                        .source
                        .map(|s| s.ip().to_string())
                        .unwrap_or_else(|| "127.0.0.1".into());
                    om.add_ip(&ip);
                    (Some(om), Some(ip))
                } else {
                    (None, None)
                };
                (up, down, om, ip_str, idle)
            } else {
                (None, None, None, None, idle)
            }
        };

        // 6. Bidirectional streaming (aligned with Xray-core CancelAfterInactivity using policy ConnectionIdle)
        #[cfg(debug_assertions)]
        let debug_tap = Some(DebugTapMeta {
            conn_id: debug_conn_id,
            host: debug_host.clone(),
            src: session
                .source
                .map(|s| s.to_string())
                .unwrap_or_else(|| "127.0.0.1:0".into()),
            dst: session.destination.to_string(),
            outbound: outbound_tag.clone(),
            bypassed: debug_bypass,
            connect_start: debug_connect_start,
        });

        #[cfg(debug_assertions)]
        let result = copy_bidirectional_with_timeout(
            &mut inbound_stream,
            &mut outbound_stream,
            conn_idle,
            debug_tap,
        )
        .await;

        #[cfg(not(debug_assertions))]
        let result =
            copy_bidirectional_with_timeout(&mut inbound_stream, &mut outbound_stream, conn_idle)
                .await;

        // 7. Update counters
        match result {
            Ok((from_client, from_server)) => {
                let total_uplink = from_client as i64 + initial_len as i64;
                if let Some(c) = &uplink_counter {
                    c.add(total_uplink);
                }
                if let Some(c) = &downlink_counter {
                    c.add(from_server as i64);
                }
                #[cfg(debug_assertions)]
                crate::debug_panel::metrics().record_connect_end(
                    &debug_host,
                    debug_bypass,
                    total_uplink.max(0) as u64,
                    from_server,
                    debug_connect_start.elapsed().as_secs_f64() * 1000.0,
                    crate::debug_panel::capture().flow_snapshot(debug_conn_id),
                );
                debug!(
                    "Connection closed for {}: client->server {} bytes, server->client {} bytes",
                    session.destination, total_uplink, from_server
                );
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                crate::debug_panel::metrics().record_connect_end(
                    &debug_host,
                    debug_bypass,
                    initial_len as u64,
                    0,
                    debug_connect_start.elapsed().as_secs_f64() * 1000.0,
                    crate::debug_panel::capture().flow_snapshot(debug_conn_id),
                );
                debug!("Stream relay ended for {}: {}", session.destination, e);
            }
        }

        // 8. Clean up online IP
        if let (Some(om), Some(ip)) = (&online_map, &user_ip) {
            om.remove_ip(ip);
        }

        Ok(())
    }
}

impl Feature for DefaultDispatcher {
    fn feature_type(&self) -> &'static str {
        TYPE_DISPATCHER
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dispatch(&self, session: SessionContext, stream: BoxStream) -> Result<()> {
        self.dispatch(stream, session).await
    }
}

#[async_trait]
impl DispatcherFeature for DefaultDispatcher {
    async fn dispatch(&self, inbound_stream: BoxStream, session: SessionContext) -> Result<()> {
        self.dispatch(inbound_stream, session).await
    }
}

#[cfg(debug_assertions)]
#[derive(Clone)]
struct DebugTapMeta {
    conn_id: u64,
    host: String,
    src: String,
    dst: String,
    outbound: String,
    bypassed: bool,
    connect_start: std::time::Instant,
}

async fn copy_one_dir<R, W>(
    mut reader: R,
    mut writer: W,
    activity_tx: tokio::sync::mpsc::Sender<()>,
    #[cfg(debug_assertions)] tap: Option<(DebugTapMeta, crate::debug_panel::Direction)>,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32768];
    let mut total = 0u64;
    #[cfg(debug_assertions)]
    let mut ttfb_recorded = false;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Ok(n) => {
                total += n as u64;
                let _ = activity_tx.try_send(());
                #[cfg(debug_assertions)]
                if let Some((ref meta, dir)) = tap {
                    if !ttfb_recorded && dir == crate::debug_panel::Direction::ServerToClient {
                        ttfb_recorded = true;
                        crate::debug_panel::metrics().record_ttfb(
                            &meta.host,
                            meta.bypassed,
                            meta.connect_start.elapsed().as_secs_f64() * 1000.0,
                        );
                    }
                    crate::debug_panel::capture().record_chunk(
                        meta.conn_id,
                        &meta.host,
                        &meta.src,
                        &meta.dst,
                        dir,
                        &meta.outbound,
                        meta.bypassed,
                        &buf[..n],
                    );
                }
                if let Err(e) = writer.write_all(&buf[..n]).await {
                    let _ = writer.shutdown().await;
                    return Err(e);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Treat missing TLS close_notify / abrupt EOF as stream end after flushing
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Err(e) => {
                let _ = writer.shutdown().await;
                return Err(e);
            }
        }
    }
}

/// Bidirectional streaming with activity-based idle timeout, matching Go Xray-core's
/// `signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)` behavior.
async fn copy_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
    #[cfg(debug_assertions)] tap: Option<DebugTapMeta>,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let timeout_duration = if idle_timeout.is_zero() {
        Duration::from_secs(300)
    } else {
        idle_timeout
    };

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel::<()>(1);
    let activity_tx_b = activity_tx.clone();

    let timer_task = async {
        let sleep = tokio::time::sleep(timeout_duration);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => {
                    break;
                }
                msg = activity_rx.recv() => {
                    match msg {
                        Some(()) => {
                            sleep.as_mut().reset(tokio::time::Instant::now() + timeout_duration);
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }
    };

    tokio::select! {
        (res_a, res_b) = async {
            #[cfg(debug_assertions)]
            let (tap_a, tap_b) = match tap {
                Some(m) => (
                    Some((m.clone(), crate::debug_panel::Direction::ClientToServer)),
                    Some((m, crate::debug_panel::Direction::ServerToClient)),
                ),
                None => (None, None),
            };
            #[cfg(debug_assertions)]
            let fut_a = copy_one_dir(&mut a_read, &mut b_write, activity_tx, tap_a);
            #[cfg(debug_assertions)]
            let fut_b = copy_one_dir(&mut b_read, &mut a_write, activity_tx_b, tap_b);
            #[cfg(not(debug_assertions))]
            let fut_a = copy_one_dir(&mut a_read, &mut b_write, activity_tx);
            #[cfg(not(debug_assertions))]
            let fut_b = copy_one_dir(&mut b_read, &mut a_write, activity_tx_b);
            tokio::join!(fut_a, fut_b)
        } => {
            match (res_a, res_b) {
                (Ok(from_client), Ok(from_server)) => Ok((from_client, from_server)),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        },
        _ = timer_task => {
            debug!("Session idle for {:?}, terminating connection", timeout_duration);
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "session idle timeout"))
        }
    }
}
