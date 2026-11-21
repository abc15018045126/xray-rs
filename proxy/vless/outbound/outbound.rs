// Module: proxy\vless\outbound\outbound.rs
// 1:1 Rust implementation corresponding to Go proxy\vless\outbound\outbound.go

use async_trait::async_trait;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, Semaphore};
use uuid::Uuid;

use crate::app::pingora_bridge::{PingoraStreamPool, pool_key};
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::protocol::{RequestCommand, SessionContext};
use crate::features::outbound::OutboundHandler;
use crate::proxy::vless::encoding::{Addons, RequestHeader};
use crate::proxy::vless::flow::{FLOW_VISION, VisionStream};
use crate::transport::internet::reality::RealityClient;
use crate::transport::internet::websocket::{DelayDialConn, parse_ws_early_data};
use crate::transport::internet::{TcpDialer, TlsClient, WebSocketStream};

const DEFAULT_TESTPRE_IDLE_SECS: u32 = 45;

struct PingoraPrePool {
    pool: Arc<PingoraStreamPool>,
    key: u64,
    wake_refill: Arc<Notify>,
    refill_slots: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
    epoch: Instant,
    last_activity_ms: Arc<AtomicU64>,
}

impl PingoraPrePool {
    fn touch_activity(&self) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);
        self.wake_refill.notify_waiters();
    }
}

impl Drop for PingoraPrePool {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.refill_slots.close();
        self.wake_refill.notify_waiters();
    }
}

#[derive(Clone)]
struct DialParams {
    server_addr: Destination,
    tls_client: Option<Arc<TlsClient>>,
    tls_sni: Option<String>,
    reality_client: Option<Arc<RealityClient>>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    ws_headers: HashMap<String, String>,
    ws_heartbeat: u32,
    ws_ed: usize,
    fragment_cfg: Option<crate::transport::internet::finalmask::fragment::Config>,
}

impl DialParams {
    async fn dial_and_handshake(&self) -> Result<BoxStream> {
        self.dial_and_handshake_with_ed(
            None,
            #[cfg(debug_assertions)]
            None,
        )
        .await
    }

    async fn dial_and_handshake_with_ed(
        &self,
        early_data: Option<&[u8]>,
        #[cfg(debug_assertions)] trace_ctx: Option<(u64, std::time::Instant)>,
    ) -> Result<BoxStream> {
        pingora_timeout::timeout(
            Duration::from_secs(15),
            self.dial_and_handshake_inner(
                early_data,
                #[cfg(debug_assertions)]
                trace_ctx,
            ),
        )
        .await
        .map_err(|_| Error::Protocol("VLESS outbound dial/handshake timed out (15s)".into()))?
    }

    async fn dial_and_handshake_inner(
        &self,
        early_data: Option<&[u8]>,
        #[cfg(debug_assertions)] trace_ctx: Option<(u64, std::time::Instant)>,
    ) -> Result<BoxStream> {
        #[cfg(debug_assertions)]
        let _tcp_t0 = std::time::Instant::now();
        let tcp_stream = TcpDialer::dial(&self.server_addr).await?;
        #[cfg(debug_assertions)]
        if let Some((tid, origin)) = trace_ctx {
            crate::debug_panel::metrics().add_trace_step(
                tid,
                "3. 外层 TCP 建连 (RTT 1)",
                _tcp_t0.saturating_duration_since(origin).as_secs_f64() * 1000.0,
                _tcp_t0.elapsed().as_secs_f64() * 1000.0,
                format!("server={}", self.server_addr),
            );
        }

        let tcp_stream: BoxStream = if let Some(ref f_cfg) = self.fragment_cfg {
            Box::pin(
                crate::transport::internet::finalmask::fragment::FragmentConn::new_client(
                    f_cfg.clone(),
                    tcp_stream,
                ),
            )
        } else {
            tcp_stream
        };

        let sni = self
            .tls_sni
            .as_deref()
            .unwrap_or_else(|| match &self.server_addr.address {
                crate::common::net::Address::Domain(d) => d.as_str(),
                _ => "localhost",
            });

        // 1. Optional TLS or Reality Layer
        let stream = if let Some(reality) = &self.reality_client {
            if let Some(tls) = &self.tls_client {
                #[cfg(debug_assertions)]
                let _t0 = std::time::Instant::now();
                let s = tls.connect(&reality.server_name, tcp_stream).await?;
                #[cfg(debug_assertions)]
                {
                    let elapsed = _t0.elapsed();
                    crate::debug_panel::record_stage("VLESS TLS 握手 (Reality)", elapsed);
                    if let Some((tid, origin)) = trace_ctx {
                        crate::debug_panel::metrics().add_trace_step(
                            tid,
                            "4. 外层 TLS 握手 (RTT 2)",
                            _t0.saturating_duration_since(origin).as_secs_f64() * 1000.0,
                            elapsed.as_secs_f64() * 1000.0,
                            format!("Reality SNI={}", reality.server_name),
                        );
                    }
                }
                s
            } else {
                tcp_stream
            }
        } else if let Some(tls) = &self.tls_client {
            #[cfg(debug_assertions)]
            let _t0 = std::time::Instant::now();
            let s = tls.connect(sni, tcp_stream).await?;
            #[cfg(debug_assertions)]
            {
                let elapsed = _t0.elapsed();
                crate::debug_panel::record_stage("VLESS TLS 握手 (Rustls)", elapsed);
                if let Some((tid, origin)) = trace_ctx {
                    crate::debug_panel::metrics().add_trace_step(
                        tid,
                        "4. 外层 TLS 握手 (RTT 2)",
                        _t0.saturating_duration_since(origin).as_secs_f64() * 1000.0,
                        elapsed.as_secs_f64() * 1000.0,
                        format!("SNI={}", sni),
                    );
                }
            }
            s
        } else {
            tcp_stream
        };

        // 2. Optional WebSocket Layer
        let stream = if let Some(path) = &self.ws_path {
            let dest_host = match &self.server_addr.address {
                crate::common::net::Address::Domain(d) => d.clone(),
                crate::common::net::Address::Ipv4(ip) => ip.to_string(),
                crate::common::net::Address::Ipv6(ip) => format!("[{}]", ip),
            };
            let host_hdr = self.ws_host.as_deref().unwrap_or(sni);
            let scheme = if self.tls_client.is_some() || self.reality_client.is_some() {
                "wss"
            } else {
                "ws"
            };
            let ws_url = format!("{}://{}{}", scheme, dest_host, path);
            #[cfg(debug_assertions)]
            let _t0 = std::time::Instant::now();
            let s = WebSocketStream::client_handshake_with_headers(
                &ws_url,
                Some(host_hdr),
                if self.ws_headers.is_empty() {
                    None
                } else {
                    Some(&self.ws_headers)
                },
                stream,
                self.ws_heartbeat,
                early_data,
            )
            .await?;
            #[cfg(debug_assertions)]
            {
                let elapsed = _t0.elapsed();
                crate::debug_panel::record_stage("VLESS WS 升级 (WebSocket)", elapsed);
                if let Some((tid, origin)) = trace_ctx {
                    let ed_tag = match early_data {
                        Some(ed) if !ed.is_empty() => format!(" (ed={}B)", ed.len()),
                        _ => String::new(),
                    };
                    crate::debug_panel::metrics().add_trace_step(
                        tid,
                        "5. WS 升级握手 (RTT 3)",
                        _t0.saturating_duration_since(origin).as_secs_f64() * 1000.0,
                        elapsed.as_secs_f64() * 1000.0,
                        format!("{}://{}{}{} Host={}", scheme, dest_host, path, ed_tag, host_hdr),
                    );
                }
            }
            s
        } else {
            stream
        };

        Ok(stream)
    }
}

pub struct Client {
    tag: String,
    user_id: Uuid,
    flow: Option<String>,
    encryption: Option<String>,
    dial_params: DialParams,
    testpre: u32,
    testpre_idle_secs: u32,
    pre_conns: OnceLock<PingoraPrePool>,
}

impl Client {
    pub fn new(
        tag: impl Into<String>,
        server_addr: Destination,
        user_id: Uuid,
        tls_client: Option<TlsClient>,
        tls_sni: Option<String>,
        ws_path: Option<String>,
        ws_host: Option<String>,
    ) -> Self {
        let (clean_ws_path, ws_ed) = match ws_path {
            Some(p) => {
                let (c, ed) = parse_ws_early_data(&p);
                (Some(c), ed)
            }
            None => (None, 0),
        };
        Self {
            tag: tag.into(),
            user_id,
            flow: None,
            encryption: None,
            dial_params: DialParams {
                server_addr,
                tls_client: tls_client.map(Arc::new),
                tls_sni,
                reality_client: None,
                ws_path: clean_ws_path,
                ws_host,
                ws_headers: HashMap::new(),
                ws_heartbeat: 0,
                ws_ed,
                fragment_cfg: None,
            },
            testpre: 0,
            testpre_idle_secs: DEFAULT_TESTPRE_IDLE_SECS,
            pre_conns: OnceLock::new(),
        }
    }

    pub fn has_ws_early_data(&self) -> bool {
        self.dial_params.ws_ed > 0
    }

    pub fn with_ws_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.dial_params.ws_headers = headers;
        self
    }

    pub fn with_ws_heartbeat(mut self, secs: u32) -> Self {
        self.dial_params.ws_heartbeat = secs;
        self
    }

    pub fn with_fragment(
        mut self,
        cfg: crate::transport::internet::finalmask::fragment::Config,
    ) -> Self {
        self.dial_params.fragment_cfg = Some(cfg);
        self
    }

    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = Some(flow.into());
        self
    }

    pub fn with_encryption(mut self, enc: impl Into<String>) -> Self {
        self.encryption = Some(enc.into());
        self
    }

    pub fn with_reality(mut self, client: RealityClient) -> Self {
        self.dial_params.reality_client = Some(Arc::new(client));
        self
    }

    /// Pre-warm `count` transport connections (TCP+TLS+WS) in background tasks
    /// with default 90s idle TTL & auto-sleep (`testpreIdle: 90`).
    pub fn with_testpre(self, count: u32) -> Self {
        self.with_testpre_idle(count, DEFAULT_TESTPRE_IDLE_SECS)
    }

    /// Pre-warm `count` transport connections with configurable `idle_secs`:
    /// - `idle_secs > 0` (default 90): connections expire & close after `idle_secs`, and
    ///   background refilling sleeps when no proxy request occurs for `idle_secs` (auto-wakes on next request).
    /// - `idle_secs == 0`: classic Xray continuous pre-warm mode (120s TTL, no idle sleep).
    pub fn with_testpre_idle(mut self, count: u32, idle_secs: u32) -> Self {
        self.testpre = count;
        self.testpre_idle_secs = idle_secs;
        if count > 0 && tokio::runtime::Handle::try_current().is_ok() {
            let _ = self.init_pre_conns();
        }
        self
    }

    fn init_pre_conns(&self) -> &PingoraPrePool {
        self.pre_conns.get_or_init(|| {
            let cap = (self.testpre as usize).max(1);
            let ttl_secs = if self.testpre_idle_secs == 0 {
                120u64
            } else {
                self.testpre_idle_secs as u64
            };
            let idle_sleep_ms = if self.testpre_idle_secs == 0 {
                0u64
            } else {
                (self.testpre_idle_secs as u64) * 1000
            };
            let pool = Arc::new(PingoraStreamPool::new(cap, Duration::from_secs(ttl_secs)));
            let key = pool_key(&format!("{}:{}", self.tag, self.dial_params.server_addr));
            let wake_refill = Arc::new(Notify::new());
            let refill_slots = Arc::new(Semaphore::new(cap));
            let closed = Arc::new(AtomicBool::new(false));
            let epoch = Instant::now();
            // Option B: mark startup as active so initial `testpre` connection(s) warm immediately;
            // if unused for `idle_secs`, they expire and workers enter zero-traffic sleep.
            let last_activity_ms = Arc::new(AtomicU64::new(0));

            if idle_sleep_ms == 0 {
                tracing::info!(
                    "VLESS outbound '{}': starting Pingora testpre pool ({} workers, {}s TTL, continuous mode)",
                    self.tag,
                    self.testpre,
                    ttl_secs
                );
            } else {
                tracing::info!(
                    "VLESS outbound '{}': starting Pingora testpre pool ({} workers, {}s TTL & auto-sleep)",
                    self.tag,
                    self.testpre,
                    ttl_secs
                );
            }

            for _ in 0..self.testpre {
                let pool_clone = pool.clone();
                let wake_clone = wake_refill.clone();
                let slots_clone = refill_slots.clone();
                let closed_clone = closed.clone();
                let last_act_clone = last_activity_ms.clone();
                let params = self.dial_params.clone();
                let tag = self.tag.clone();

                tokio::spawn(async move {
                    loop {
                        if closed_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        if idle_sleep_ms > 0 {
                            let now_ms = epoch.elapsed().as_millis() as u64;
                            let last_ms = last_act_clone.load(Ordering::Relaxed);
                            if now_ms.saturating_sub(last_ms) >= idle_sleep_ms {
                                wake_clone.notified().await;
                                continue;
                            }
                        }
                        let Ok(permit) = slots_clone.clone().acquire_owned().await else {
                            break;
                        };
                        if closed_clone.load(Ordering::Relaxed) {
                            drop(permit);
                            break;
                        }
                        // Re-check after permit release (e.g. 90s idle expiry while user is away)
                        if idle_sleep_ms > 0 {
                            let now_ms = epoch.elapsed().as_millis() as u64;
                            let last_ms = last_act_clone.load(Ordering::Relaxed);
                            if now_ms.saturating_sub(last_ms) >= idle_sleep_ms {
                                drop(permit);
                                wake_clone.notified().await;
                                continue;
                            }
                        }
                        match params.dial_and_handshake().await {
                            Ok(conn) => {
                                if closed_clone.load(Ordering::Relaxed) {
                                    break;
                                }
                                pool_clone.put_with_permit(key, conn, permit);
                                pingora_timeout::sleep(Duration::from_millis(200)).await;
                            }
                            Err(e) => {
                                drop(permit);
                                tracing::warn!(
                                    "VLESS '{}' testpre pre-connect failed: {}",
                                    tag,
                                    e
                                );
                                pingora_timeout::sleep(Duration::from_millis(500)).await;
                            }
                        }
                    }
                });
            }

            PingoraPrePool {
                pool,
                key,
                wake_refill,
                refill_slots,
                closed,
                epoch,
                last_activity_ms,
            }
        })
    }

    async fn take_or_dial(&self, session: &SessionContext) -> Result<BoxStream> {
        #[cfg(debug_assertions)]
        let trace_ctx = session.debug_trace_id.zip(session.debug_trace_origin);

        // Official Xray-core WS Early Data (`?ed=N`): delegate to `transport/internet/websocket/dialer.rs::DelayDialConn`
        if self.dial_params.ws_ed > 0 && self.testpre == 0 {
            let params = self.dial_params.clone();
            let dial_fn: crate::transport::internet::websocket::DialWsFn = Arc::new(move |ed| {
                let p = params.clone();
                #[cfg(debug_assertions)]
                let tc = trace_ctx;
                Box::pin(async move {
                    p.dial_and_handshake_with_ed(
                        ed.as_deref(),
                        #[cfg(debug_assertions)]
                        tc,
                    )
                    .await
                })
            });
            return Ok(Box::pin(DelayDialConn::new(dial_fn, self.dial_params.ws_ed)));
        }

        if self.testpre > 0 {
            let pre_pool = self.init_pre_conns();
            pre_pool.touch_activity();
            // Fast path: take an already-warmed connection from Cloudflare `pingora-pool` (0ms).
            // If the pool is momentarily empty, dial immediately without stalling behind a wait timeout.
            if let Some(conn) = pre_pool.pool.get(pre_pool.key) {
                #[cfg(debug_assertions)]
                {
                    let host = session
                        .sniffed_domain
                        .clone()
                        .unwrap_or_else(|| session.destination.address.to_string());
                    crate::debug_panel::metrics().record_pool_reuse(&host, &self.tag);
                    if let Some((tid, origin)) = trace_ctx {
                        crate::debug_panel::metrics().update_trace_meta(
                            tid,
                            None,
                            None,
                            None,
                            Some(true),
                        );
                        crate::debug_panel::metrics().add_trace_step(
                            tid,
                            "3. 预热池复用 (Pingora Pool)",
                            origin.elapsed().as_secs_f64() * 1000.0,
                            0.0,
                            "复用预热连接，跳过 TCP+TLS+WS 握手",
                        );
                    }
                }
                let _ = session;
                return Ok(conn);
            }
        }

        self.dial_params
            .dial_and_handshake_with_ed(
                None,
                #[cfg(debug_assertions)]
                trace_ctx,
            )
            .await
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let stream = self.take_or_dial(session).await?;

        // 3. VLESS Protocol Layer: Build Request Header with Addons (coalesced with first payload)
        let command = match session.destination.network {
            Network::Tcp => RequestCommand::Tcp,
            Network::Udp => RequestCommand::Udp,
        };

        let mut req = RequestHeader::new(self.user_id, command, session.destination.clone());
        if let Some(ref flow) = self.flow {
            req.addons = Addons::new(flow.clone());
        }
        let header_bytes = req.encode_bytes();
        let is_udp = command == RequestCommand::Udp && self.flow.as_deref() != Some(FLOW_VISION);

        // 4. Wrap with non-blocking VlessStream (coalesces header, strips response header, frames UDP)
        let vless_stream: BoxStream =
            Box::pin(VlessStream::with_pending_header(stream, is_udp, header_bytes));

        // 5. Optional XTLS-Vision flow wrapping
        let final_stream: BoxStream = if self.flow.as_deref() == Some(FLOW_VISION) {
            Box::pin(VisionStream::new(
                vless_stream,
                crate::proxy::vless::flow::VisionContext::new(
                    self.user_id.into_bytes().to_vec(),
                    true,
                ),
                false,
            ))
        } else {
            vless_stream
        };

        Ok(final_stream)
    }
}

pub struct VlessStream {
    inner: BoxStream,
    header_parsed: bool,
    pending_buf: Vec<u8>,
    is_udp: bool,
    udp_pkt_remaining: usize,
    pending_header: Option<Vec<u8>>,
    pending_write: Vec<u8>,
    header_flush_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl VlessStream {
    pub fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            header_parsed: false,
            pending_buf: Vec::with_capacity(512),
            is_udp: false,
            udp_pkt_remaining: 0,
            pending_header: None,
            pending_write: Vec::new(),
            header_flush_timer: None,
        }
    }

    pub fn with_pending_header(inner: BoxStream, is_udp: bool, header: Vec<u8>) -> Self {
        Self {
            inner,
            header_parsed: false,
            pending_buf: Vec::with_capacity(512),
            is_udp,
            udp_pkt_remaining: 0,
            pending_header: Some(header),
            pending_write: Vec::new(),
            header_flush_timer: None,
        }
    }

    fn flush_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.pending_write.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write buffered VLESS bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let drain_n = n.min(self.pending_write.len());
                    self.pending_write.drain(..drain_n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn promote_pending_header(&mut self) {
        if let Some(hdr) = self.pending_header.take() {
            self.header_flush_timer = None;
            if self.pending_write.is_empty() {
                self.pending_write = hdr;
            } else {
                let mut combined = hdr;
                combined.extend_from_slice(&self.pending_write);
                self.pending_write = combined;
            }
        }
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If no write occurred within 500ms (server-speaks-first), flush VLESS request header
        if self.pending_header.is_some() {
            let timer = self
                .header_flush_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(500))));
            if timer.as_mut().poll(cx).is_ready() {
                self.promote_pending_header();
            }
        }
        if !self.pending_write.is_empty() {
            let _ = self.flush_pending_write(cx);
        }

        loop {
            if self.header_parsed {
                if self.is_udp {
                    if self.udp_pkt_remaining > 0 {
                        if !self.pending_buf.is_empty() {
                            let to_write = std::cmp::min(
                                buf.remaining(),
                                std::cmp::min(self.udp_pkt_remaining, self.pending_buf.len()),
                            );
                            buf.put_slice(&self.pending_buf[..to_write]);
                            self.pending_buf.drain(..to_write);
                            self.udp_pkt_remaining -= to_write;
                            return Poll::Ready(Ok(()));
                        }
                    } else if self.pending_buf.len() >= 2 {
                        let pkt_len =
                            u16::from_be_bytes([self.pending_buf[0], self.pending_buf[1]]) as usize;
                        self.pending_buf.drain(..2);
                        if pkt_len == 0 {
                            continue;
                        }
                        self.udp_pkt_remaining = pkt_len;
                        continue;
                    }
                } else {
                    if !self.pending_buf.is_empty() {
                        let to_write = std::cmp::min(buf.remaining(), self.pending_buf.len());
                        buf.put_slice(&self.pending_buf[..to_write]);
                        self.pending_buf.drain(..to_write);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }

            let mut temp_buf = [0u8; 2048];
            let mut temp_read_buf = ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self.inner).poll_read(cx, &mut temp_read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = temp_read_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.pending_buf.extend_from_slice(filled);

                    if !self.header_parsed && self.pending_buf.len() >= 2 {
                        let addons_len = self.pending_buf[1] as usize;
                        let header_len = 2 + addons_len;

                        if self.pending_buf.len() >= header_len {
                            self.header_parsed = true;
                            self.pending_buf.drain(..header_len);

                            if !self.is_udp && !self.pending_buf.is_empty() {
                                let to_write =
                                    std::cmp::min(buf.remaining(), self.pending_buf.len());
                                buf.put_slice(&self.pending_buf[..to_write]);
                                self.pending_buf.drain(..to_write);
                                return Poll::Ready(Ok(()));
                            }
                            continue;
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.pending_write.is_empty() {
            match self.flush_pending_write(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let payload = if self.is_udp && buf.len() > u16::MAX as usize {
            &buf[..u16::MAX as usize]
        } else {
            buf
        };

        if self.pending_header.is_none() && !self.is_udp {
            return Pin::new(&mut self.inner).poll_write(cx, payload);
        }

        let hdr_len = self.pending_header.as_ref().map_or(0, |h| h.len());
        let len_prefix = if self.is_udp { 2 } else { 0 };
        let mut frame = Vec::with_capacity(hdr_len + len_prefix + payload.len());
        if let Some(ref hdr) = self.pending_header {
            frame.extend_from_slice(hdr);
        }
        if self.is_udp {
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(payload);

        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(written)) => {
                self.pending_header = None;
                self.header_flush_timer = None;
                if written < frame.len() {
                    self.pending_write.extend_from_slice(&frame[written..]);
                }
                Poll::Ready(Ok(payload.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Commit the coalesced frame (header + payload) into pending_write so
                // `header_flush_timer` in `poll_read` cannot promote a separate smaller
                // header slice while an async dial (e.g. WS Early Data) is in flight.
                if self.pending_header.is_some() {
                    self.pending_header = None;
                    self.header_flush_timer = None;
                    self.pending_write = frame;
                    Poll::Ready(Ok(payload.len()))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.promote_pending_header();
        match self.flush_pending_write(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.promote_pending_header();
        match self.flush_pending_write(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

pub use Client as VlessOutboundClient;
pub use Client as Handler;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_vless_stream_tcp_coalesce_and_strip_header() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let header = vec![0x00, 0x01, 0x02];
        let mut stream = VlessStream::with_pending_header(Box::pin(client_io), false, header);

        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 32];
        let n = server_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"\x00\x01\x02hello");

        server_io.write_all(&[0x00, 0x00, b'o', b'k']).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ok");
    }

    #[tokio::test]
    async fn test_vless_stream_udp_length_framing() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let header = vec![0x00, 0xaa];
        let mut stream = VlessStream::with_pending_header(Box::pin(client_io), true, header);

        stream.write_all(b"ping1").await.unwrap();
        stream.write_all(b"ping22").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 64];
        let n = server_io.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"\x00\xaa\x00\x05ping1\x00\x06ping22"
        );

        server_io
            .write_all(&[0x00, 0x00, 0x00, 0x03, b'a', b'c', b'k', 0x00, 0x02, b'o', b'k'])
            .await
            .unwrap();

        let n1 = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], b"ack");
        let n2 = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"ok");
    }

    #[tokio::test]
    async fn test_vless_testpre_idle_auto_sleep_and_wake() {
        use std::sync::atomic::AtomicUsize;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_bg = accepted.clone();

        let accept_task = tokio::spawn(async move {
            loop {
                if let Ok((_sock, _)) = listener.accept().await {
                    accepted_bg.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let _s = _sock;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    });
                } else {
                    break;
                }
            }
        });

        let dest = Destination::from_ip_port(addr.ip(), addr.port());
        let client = Client::new("proxy", dest, Uuid::nil(), None, None, None, None)
            .with_testpre_idle(1, 1);

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "worker must stay asleep while idle instead of redialing"
        );

        client.init_pre_conns().touch_activity();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "worker must wake and refill on new activity"
        );

        drop(client);
        accept_task.abort();
    }
}
