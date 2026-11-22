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

    pub fn r#type(&self) -> &'static str {
        TYPE_DISPATCHER
    }

    pub fn start(&self) -> Result<()> {
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        Ok(())
    }

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

    fn apply_sniff(
        &self,
        session: &mut SessionContext,
        res: &SniffResult,
        req: &SniffingRequest,
        log_hit: bool,
    ) {
        session.sniffed_protocol = Some(res.protocol.clone());
        session.sniffed_domain = Some(res.domain.clone());
        if self.should_override(res, req, &session.destination) {
            if log_hit {
                info!("Sniffed domain: {} (protocol: {})", res.domain, res.protocol);
            }
            let dst = Destination::new(Address::Domain(res.domain.clone()), session.destination.port);
            if req.route_only {
                session.route_target = Some(dst);
            } else {
                session.destination = dst;
            }
        }
    }

    pub async fn dispatch(
        &self,
        mut inbound_stream: BoxStream,
        mut session: SessionContext,
    ) -> Result<()> {
        let mut initial_payload: Vec<u8> = Vec::new();

        #[cfg(debug_assertions)]
        let debug_trace_origin = std::time::Instant::now();
        #[cfg(debug_assertions)]
        let debug_trace_id = {
            let init_host = session
                .sniffed_domain
                .clone()
                .unwrap_or_else(|| session.destination.address.to_string());
            let tid = crate::debug_panel::metrics().start_trace(
                &init_host,
                &session.destination.to_string(),
                &session.inbound_tag,
            );
            session.debug_trace_id = Some(tid);
            session.debug_trace_origin = Some(debug_trace_origin);
            tid
        };

        #[cfg(debug_assertions)]
        let _sniff_t0 = std::time::Instant::now();
        if let Some(sniff_req) = session.sniffing_request.clone()
            && sniff_req.enabled
        {
            let mut buf = [0u8; 2048];
            if let Ok(Ok(n)) =
                timeout(Duration::from_millis(200), inbound_stream.read(&mut buf)).await
                && n > 0
            {
                initial_payload.extend_from_slice(&buf[..n]);
                if let Ok(res) = self.sniffer.sniff(&initial_payload, Network::Tcp) {
                    self.apply_sniff(&mut session, &res, &sniff_req, true);
                }
            }

            if session.sniffed_domain.is_none()
                && let Some(ip) = session.destination.address.as_ip()
                && let Some(domain) = self.sniffer.sniff_ip(ip)
            {
                let res = SniffResult { protocol: "fakedns".into(), domain };
                self.apply_sniff(&mut session, &res, &sniff_req, false);
            }
        }

        #[cfg(debug_assertions)]
        let debug_host = session
            .sniffed_domain
            .clone()
            .unwrap_or_else(|| session.destination.address.to_string());

        #[cfg(debug_assertions)]
        {
            let detail = match (&session.sniffed_protocol, &session.sniffed_domain) {
                (Some(p), Some(d)) => format!("proto={} SNI={} ({}B)", p, d, initial_payload.len()),
                _ if !initial_payload.is_empty() => format!("已读首包 {}B (无 SNI)", initial_payload.len()),
                _ => "未触发嗅探".into(),
            };
            dbg_trace_step(debug_trace_id, "1. 本机嗅探 (Sniff)", debug_trace_origin, _sniff_t0, detail);
        }

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
        let debug_features = (!initial_payload.is_empty())
            .then(|| crate::debug_panel::inspect_initial_payload(&initial_payload));

        #[cfg(debug_assertions)]
        let debug_connect_start = std::time::Instant::now();

        let src_unknown = || {
            session
                .source
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".into())
        };

        let (outbound_tag, mut outbound_stream) = {
            #[cfg(debug_assertions)]
            let bypass_now = debug_bypass;
            #[cfg(not(debug_assertions))]
            let bypass_now = false;

            if bypass_now {
                let tag = "debug-direct-bypass".to_string();
                session.outbound_tag = Some(tag.clone());
                info!("[DEBUG DIRECT BYPASS] [{}] -> [{}] (kernel direct, no proxy)", src_unknown(), session.destination);
                #[cfg(debug_assertions)]
                let _bypass_t0 = std::time::Instant::now();
                #[cfg(debug_assertions)]
                crate::debug_panel::metrics().update_trace_meta(debug_trace_id, Some(&debug_host), Some(&tag), Some("bypass"), None);
                let stream = match crate::transport::internet::TcpDialer::dial(&session.destination).await {
                    Ok(s) => {
                        #[cfg(debug_assertions)]
                        dbg_trace_step(debug_trace_id, "3. 内核直连 TCP 建连", debug_trace_origin, _bypass_t0, format!("target={}", session.destination));
                        s
                    }
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        dbg_trace_fail(debug_trace_id, debug_trace_origin, debug_connect_start, &debug_host, &tag, true, &e.to_string());
                        warn!("[DEBUG DIRECT BYPASS] Failed direct kernel connect for {}: {}", session.destination, e);
                        return Err(e);
                    }
                };
                (tag, stream)
            } else {
                #[cfg(debug_assertions)]
                let _route_t0 = std::time::Instant::now();
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
                } else {
                    self.default_outbound_tag
                        .clone()
                        .or_else(|| self.outbounds.keys().next().cloned())
                        .ok_or_else(|| Error::NotFound("No outbound handlers configured".into()))?
                };

                session.outbound_tag = Some(outbound_tag.clone());

                #[cfg(debug_assertions)]
                {
                    let mode_str = match outbound_tag.as_str() {
                        "direct" | "freedom" => "direct",
                        "block" | "blackhole" => "block",
                        "dns" => "dns",
                        _ => "proxy",
                    };
                    crate::debug_panel::metrics().update_trace_meta(debug_trace_id, Some(&debug_host), Some(&outbound_tag), Some(mode_str), None);
                    dbg_trace_step(debug_trace_id, "2. 路由分流 (Route)", debug_trace_origin, _route_t0, format!("outbound={} ({})", outbound_tag, mode_str));
                }

                let outbound = match &self.outbound_manager {
                    Some(om) => om.get_handler(&outbound_tag).await,
                    None => None,
                }
                .or_else(|| self.outbounds.get(&outbound_tag).cloned())
                .ok_or_else(|| Error::NotFound(format!("Outbound handler '{}' not found", outbound_tag)))?;

                info!("Dispatching [{}] -> [{}] via tag '{}'", src_unknown(), session.destination, outbound_tag);

                #[cfg(debug_assertions)]
                let _ct0 = std::time::Instant::now();
                let stream = match outbound.connect(&session).await {
                    Ok(stream) => {
                        #[cfg(debug_assertions)]
                        {
                            crate::debug_panel::record_stage("出站建连握手 (TLS/WS/VLESS)", _ct0.elapsed());
                            if matches!(outbound_tag.as_str(), "direct" | "freedom" | "block" | "blackhole" | "dns") {
                                let label = match outbound_tag.as_str() {
                                    "block" | "blackhole" => "3. 规则拦截 (Blackhole)",
                                    "dns" => "3. 内置 DNS 处理",
                                    _ => "3. 直连 TCP 建连 (Direct)",
                                };
                                dbg_trace_step(debug_trace_id, label, debug_trace_origin, _ct0, format!("target={}", session.destination));
                            }
                        }
                        stream
                    }
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        {
                            crate::debug_panel::record_stage("出站建连握手 (TLS/WS/VLESS)", _ct0.elapsed());
                            dbg_trace_fail(debug_trace_id, debug_trace_origin, debug_connect_start, &debug_host, &outbound_tag, false, &e.to_string());
                        }
                        warn!("Failed to establish outbound connection for {}: {}", session.destination, e);
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
            dbg_ms(debug_connect_start.elapsed()),
            debug_features,
        );

        let initial_len = initial_payload.len();
        if !initial_payload.is_empty() {
            #[cfg(debug_assertions)]
            {
                let src_str = session.source.map(|s| s.to_string()).unwrap_or_else(|| "127.0.0.1:0".into());
                crate::debug_panel::capture().record_chunk(
                    debug_conn_id,
                    &debug_host,
                    &src_str,
                    &session.destination.to_string(),
                    crate::debug_panel::Direction::ClientToServer,
                    &outbound_tag,
                    debug_bypass,
                    &initial_payload,
                );
            }
            #[cfg(debug_assertions)]
            let _send0 = std::time::Instant::now();
            if let Err(e) = outbound_stream.write_all(&initial_payload).await {
                #[cfg(debug_assertions)]
                {
                    let err_str = e.to_string();
                    crate::debug_panel::metrics().record_connect_end(
                        &debug_host,
                        debug_bypass,
                        0,
                        0,
                        dbg_ms(debug_connect_start.elapsed()),
                        crate::debug_panel::capture().flow_snapshot(debug_conn_id),
                    );
                    crate::debug_panel::metrics().finish_trace(debug_trace_id, dbg_ms(debug_trace_origin.elapsed()), Some(&err_str));
                }
                warn!("Failed to forward initial sniffed payload: {}", e);
                return Err(Error::Io(e));
            }
            #[cfg(debug_assertions)]
            {
                let step = if debug_bypass || matches!(outbound_tag.as_str(), "direct" | "freedom") {
                    "4. 发送首包 (ClientHello/请求)"
                } else {
                    "6. 发送首包 (VLESS头+ClientHello)"
                };
                dbg_trace_step(debug_trace_id, step, debug_trace_origin, _send0, format!("{} B", initial_payload.len()));
            }
        }

        let level = session.user.as_ref().map(|u| u.level).unwrap_or(0);
        let conn_idle = self
            .policy
            .as_ref()
            .map(|m| m.for_level(level).timeouts.connection_idle)
            .unwrap_or_else(|| crate::features::policy::session_default().timeouts.connection_idle);

        let (uplink_counter, downlink_counter, online_map, user_ip) = match (&session.user, &self.policy, &self.stats) {
            (Some(user), Some(policy_mgr), Some(stats_mgr)) if !user.email.is_empty() => {
                let p = policy_mgr.for_level(user.level);
                let up = p.stats.user_uplink.then(|| stats_mgr.register_counter(&format!("user>>>{}>>>traffic>>>uplink", user.email)));
                let down = p.stats.user_downlink.then(|| stats_mgr.register_counter(&format!("user>>>{}>>>traffic>>>downlink", user.email)));
                let (om, ip_str) = if p.stats.user_online {
                    let om = stats_mgr.register_online_map(&format!("user>>>{}>>>online", user.email));
                    let ip = session.source.map(|s| s.ip().to_string()).unwrap_or_else(|| "127.0.0.1".into());
                    om.add_ip(&ip);
                    (Some(om), Some(ip))
                } else {
                    (None, None)
                };
                (up, down, om, ip_str)
            }
            _ => (None, None, None, None),
        };

        #[cfg(debug_assertions)]
        let debug_tap = Some(DebugTapMeta {
            conn_id: debug_conn_id,
            trace_id: debug_trace_id,
            trace_origin: debug_trace_origin,
            after_send_offset_ms: dbg_ms(debug_trace_origin.elapsed()),
            host: debug_host.clone(),
            src: session.source.map(|s| s.to_string()).unwrap_or_else(|| "127.0.0.1:0".into()),
            dst: session.destination.to_string(),
            outbound: outbound_tag.clone(),
            bypassed: debug_bypass,
            connect_start: debug_connect_start,
        });

        let (out_up_counter, out_down_counter) = if let Some(stats_mgr) = &self.stats {
            let up = stats_mgr.register_counter(&format!("outbound>>>{}>>>traffic>>>uplink", outbound_tag));
            let down = stats_mgr.register_counter(&format!("outbound>>>{}>>>traffic>>>downlink", outbound_tag));
            if initial_len > 0 {
                up.add(initial_len as i64);
            }
            (Some(up), Some(down))
        } else {
            (None, None)
        };

        #[cfg(debug_assertions)]
        let result = copy_bidirectional_with_timeout(&mut inbound_stream, &mut outbound_stream, conn_idle, out_up_counter, out_down_counter, debug_tap).await;
        #[cfg(not(debug_assertions))]
        let result = copy_bidirectional_with_timeout(&mut inbound_stream, &mut outbound_stream, conn_idle, out_up_counter, out_down_counter).await;

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
                    dbg_ms(debug_connect_start.elapsed()),
                    crate::debug_panel::capture().flow_snapshot(debug_conn_id),
                );
                debug!("Connection closed for {}: client->server {} bytes, server->client {} bytes", session.destination, total_uplink, from_server);
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                crate::debug_panel::metrics().record_connect_end(
                    &debug_host,
                    debug_bypass,
                    initial_len as u64,
                    0,
                    dbg_ms(debug_connect_start.elapsed()),
                    crate::debug_panel::capture().flow_snapshot(debug_conn_id),
                );
                debug!("Stream relay ended for {}: {}", session.destination, e);
            }
        }

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
fn dbg_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[cfg(debug_assertions)]
fn dbg_trace_step(
    tid: u64,
    name: &str,
    origin: std::time::Instant,
    t0: std::time::Instant,
    detail: String,
) {
    crate::debug_panel::metrics().add_trace_step(
        tid,
        name,
        dbg_ms(t0.saturating_duration_since(origin)),
        dbg_ms(t0.elapsed()),
        detail,
    );
}

#[cfg(debug_assertions)]
fn dbg_trace_fail(
    tid: u64,
    origin: std::time::Instant,
    start: std::time::Instant,
    host: &str,
    tag: &str,
    bypass: bool,
    err: &str,
) {
    crate::debug_panel::metrics().record_connect_failed(host, tag, bypass, dbg_ms(start.elapsed()), err);
    crate::debug_panel::metrics().finish_trace(tid, dbg_ms(origin.elapsed()), Some(err));
}

#[cfg(debug_assertions)]
#[derive(Clone)]
struct DebugTapMeta {
    conn_id: u64,
    trace_id: u64,
    trace_origin: std::time::Instant,
    after_send_offset_ms: f64,
    host: String,
    src: String,
    dst: String,
    outbound: String,
    bypassed: bool,
    connect_start: std::time::Instant,
}

async fn copy_one_dir<R, W>(
    reader: R,
    writer: W,
    activity_tx: tokio::sync::mpsc::Sender<()>,
    counter: Option<Arc<crate::features::stats::Counter>>,
    #[cfg(debug_assertions)] tap: Option<(DebugTapMeta, crate::debug_panel::Direction)>,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    #[cfg(debug_assertions)]
    let mut ttfb_recorded = false;
    crate::common::buf::copy::copy_one_way(reader, writer, activity_tx, counter, move |_chunk| {
        #[cfg(debug_assertions)]
        if let Some((ref meta, dir)) = tap {
            if !ttfb_recorded && dir == crate::debug_panel::Direction::ServerToClient {
                ttfb_recorded = true;
                let ttfb_ms = meta.connect_start.elapsed().as_secs_f64() * 1000.0;
                let total_from_origin = meta.trace_origin.elapsed().as_secs_f64() * 1000.0;
                let wait_ms = (total_from_origin - meta.after_send_offset_ms).max(0.0);
                crate::debug_panel::metrics().record_ttfb(&meta.host, meta.bypassed, ttfb_ms);
                let step_name = if meta.bypassed
                    || matches!(meta.outbound.as_str(), "direct" | "freedom")
                {
                    "5. 等待目标首响应 (TTFB)"
                } else {
                    "7. 首包穿透 -> 目标首响应 (TTFB)"
                };
                crate::debug_panel::metrics().add_trace_step(
                    meta.trace_id,
                    step_name,
                    meta.after_send_offset_ms,
                    wait_ms,
                    format!("收到首包 {}B (累计 {:.1}ms)", _chunk.len(), total_from_origin),
                );
                crate::debug_panel::metrics().finish_trace(meta.trace_id, total_from_origin, None);
            }
            crate::debug_panel::capture().record_chunk(
                meta.conn_id,
                &meta.host,
                &meta.src,
                &meta.dst,
                dir,
                &meta.outbound,
                meta.bypassed,
                _chunk,
            );
        }
    })
    .await
}

async fn copy_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
    up_counter: Option<Arc<crate::features::stats::Counter>>,
    down_counter: Option<Arc<crate::features::stats::Counter>>,
    #[cfg(debug_assertions)] tap: Option<DebugTapMeta>,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let timeout_duration = if idle_timeout.is_zero() { Duration::from_secs(300) } else { idle_timeout };
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel::<()>(1);
    let activity_tx_b = activity_tx.clone();

    let timer_task = async {
        let sleep = tokio::time::sleep(timeout_duration);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                msg = activity_rx.recv() => match msg {
                    Some(()) => sleep.as_mut().reset(tokio::time::Instant::now() + timeout_duration),
                    None => break,
                }
            }
        }
    };

    tokio::select! {
        (res_a, res_b) = async {
            #[cfg(debug_assertions)]
            let (tap_a, tap_b) = tap.map_or((None, None), |m| (
                Some((m.clone(), crate::debug_panel::Direction::ClientToServer)),
                Some((m, crate::debug_panel::Direction::ServerToClient)),
            ));
            #[cfg(debug_assertions)]
            let (fut_a, fut_b) = (
                copy_one_dir(&mut a_read, &mut b_write, activity_tx, up_counter, tap_a),
                copy_one_dir(&mut b_read, &mut a_write, activity_tx_b, down_counter, tap_b),
            );
            #[cfg(not(debug_assertions))]
            let (fut_a, fut_b) = (
                copy_one_dir(&mut a_read, &mut b_write, activity_tx, up_counter),
                copy_one_dir(&mut b_read, &mut a_write, activity_tx_b, down_counter),
            );
            tokio::join!(fut_a, fut_b)
        } => match (res_a, res_b) {
            (Ok(c), Ok(s)) => Ok((c, s)),
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        _ = timer_task => {
            debug!("Session idle for {:?}, terminating connection", timeout_duration);
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "session idle timeout"))
        }
    }
}
