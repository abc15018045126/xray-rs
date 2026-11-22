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
    httpupgrade_path: Option<String>,
    httpupgrade_host: Option<String>,
    httpupgrade_headers: HashMap<String, String>,
    splithttp_cfg: Option<crate::transport::internet::SplitHttpConfig>,
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
        .await.map_err(|_| Error::Protocol("VLESS outbound dial/handshake timed out (15s)".into()))?
    }
    async fn dial_and_handshake_inner(
        &self,
        early_data: Option<&[u8]>,
        #[cfg(debug_assertions)] trace_ctx: Option<(u64, std::time::Instant)>,
    ) -> Result<BoxStream> {
        if let Some(ref xhttp_cfg) = self.splithttp_cfg {
            let mut client = crate::transport::internet::splithttp::client::DefaultDialerClient::new(
                xhttp_cfg.clone(),
                self.server_addr.clone(),
                "1.1",
            );
            if let Some(ref tls) = self.tls_client {
                let sni = self.tls_sni.clone().unwrap_or_else(|| self.server_addr.address.to_string());
                client = client.with_tls(tls.clone(), sni);
            }
            let dialer = crate::transport::internet::splithttp::dialer::SplitHttpDialer::new(xhttp_cfg.clone());
            return dialer.dial_with_client(Arc::new(client), &self.server_addr).await;
        }
        #[cfg(debug_assertions)]
        let trace_step = |step: &str, t0: std::time::Instant, detail: String| {
            if let Some((tid, origin)) = trace_ctx {
                crate::debug_panel::metrics().add_trace_step(
                    tid,
                    step,
                    t0.saturating_duration_since(origin).as_secs_f64() * 1000.0,
                    t0.elapsed().as_secs_f64() * 1000.0,
                    detail,
                );
            }
        };
        #[cfg(debug_assertions)]
        let _tcp_t0 = std::time::Instant::now();
        let tcp_stream = TcpDialer::dial(&self.server_addr).await?;
        #[cfg(debug_assertions)]
        trace_step("3. 外层 TCP 建连 (RTT 1)", _tcp_t0, format!("server={}", self.server_addr));
        let tcp_stream: BoxStream = match &self.fragment_cfg {
            Some(f_cfg) => Box::pin(crate::transport::internet::finalmask::fragment::FragmentConn::new_client(f_cfg.clone(), tcp_stream)),
            None => tcp_stream,
        };
        let sni = self.tls_sni.as_deref().unwrap_or_else(|| match &self.server_addr.address {
            crate::common::net::Address::Domain(d) => d.as_str(),
            _ => "localhost",
        });
        let stream = if let Some(tls) = &self.tls_client {
            let (target_sni, is_reality) = match &self.reality_client {
                Some(r) => (r.server_name.as_str(), true),
                None => (sni, false),
            };
            #[cfg(debug_assertions)]
            let _t0 = std::time::Instant::now();
            let s = tls.connect(target_sni, tcp_stream).await?;
            #[cfg(debug_assertions)]
            {
                let (stage, detail) = if is_reality {
                    ("VLESS TLS 握手 (Reality)", format!("Reality SNI={}", target_sni))
                } else {
                    ("VLESS TLS 握手 (Rustls)", format!("SNI={}", target_sni))
                };
                crate::debug_panel::record_stage(stage, _t0.elapsed());
                trace_step("4. 外层 TLS 握手 (RTT 2)", _t0, detail);
            }
            let _ = is_reality;
            s
        } else {
            tcp_stream
        };
        let stream = if let Some(ref hu_path) = self.httpupgrade_path {
            let host_hdr = self.httpupgrade_host.as_deref().unwrap_or(sni);
            crate::transport::internet::httpupgrade::HttpUpgradeStream::client_handshake(
                host_hdr,
                hu_path,
                stream,
                &self.httpupgrade_headers,
            )
            .await?
        } else if let Some(path) = &self.ws_path {
            let dest_host = match &self.server_addr.address {
                crate::common::net::Address::Domain(d) => d.clone(),
                crate::common::net::Address::Ipv4(ip) => ip.to_string(),
                crate::common::net::Address::Ipv6(ip) => format!("[{}]", ip),
            };
            let host_hdr = self.ws_host.as_deref().unwrap_or(sni);
            let scheme = if self.tls_client.is_some() || self.reality_client.is_some() { "wss" } else { "ws" };
            let ws_url = format!("{}://{}{}", scheme, dest_host, path);
            #[cfg(debug_assertions)]
            let _t0 = std::time::Instant::now();
            let s = WebSocketStream::client_handshake_with_headers(
                &ws_url,
                Some(host_hdr),
                (!self.ws_headers.is_empty()).then_some(&self.ws_headers),
                stream,
                self.ws_heartbeat,
                early_data,
            )
            .await?;
            #[cfg(debug_assertions)]
            {
                crate::debug_panel::record_stage("VLESS WS 升级 (WebSocket)", _t0.elapsed());
                let ed_tag = match early_data {
                    Some(ed) if !ed.is_empty() => format!(" (ed={}B)", ed.len()),
                    _ => String::new(),
                };
                trace_step("5. WS 升级握手 (RTT 3)", _t0, format!("{}://{}{}{} Host={}", scheme, dest_host, path, ed_tag, host_hdr));
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
        let (ws_path, ws_ed) = ws_path.map_or((None, 0), |p| { let (c, ed) = parse_ws_early_data(&p); (Some(c), ed) });
        Self {
            tag: tag.into(), user_id, flow: None, encryption: None,
            dial_params: DialParams {
                server_addr, tls_client: tls_client.map(Arc::new), tls_sni, reality_client: None,
                ws_path, ws_host, ws_headers: HashMap::new(), ws_heartbeat: 0, ws_ed,
                httpupgrade_path: None, httpupgrade_host: None, httpupgrade_headers: HashMap::new(),
                splithttp_cfg: None, fragment_cfg: None,
            },
            testpre: 0, testpre_idle_secs: DEFAULT_TESTPRE_IDLE_SECS, pre_conns: OnceLock::new(),
        }
    }
    pub fn has_ws_early_data(&self) -> bool { self.dial_params.ws_ed > 0 }
    pub fn with_ws_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.dial_params.ws_headers = headers;
        self
    }
    pub fn with_ws_heartbeat(mut self, secs: u32) -> Self {
        self.dial_params.ws_heartbeat = secs;
        self
    }
    pub fn with_splithttp(mut self, cfg: crate::transport::internet::SplitHttpConfig) -> Self {
        self.dial_params.splithttp_cfg = Some(cfg);
        self
    }
    pub fn with_httpupgrade(mut self, path: String, host: Option<String>, headers: HashMap<String, String>) -> Self {
        self.dial_params.httpupgrade_path = Some(path);
        self.dial_params.httpupgrade_host = host;
        self.dial_params.httpupgrade_headers = headers;
        self
    }
    pub fn with_fragment(mut self, cfg: crate::transport::internet::finalmask::fragment::Config) -> Self {
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
    pub fn with_testpre(self, count: u32) -> Self { self.with_testpre_idle(count, DEFAULT_TESTPRE_IDLE_SECS) }
    pub fn with_testpre_idle(mut self, count: u32, idle_secs: u32) -> Self {
        self.testpre = count;
        self.testpre_idle_secs = idle_secs;
        if count > 0 && tokio::runtime::Handle::try_current().is_ok() { let _ = self.init_pre_conns(); }
        self
    }
    fn init_pre_conns(&self) -> &PingoraPrePool {
        self.pre_conns.get_or_init(|| {
            let cap = (self.testpre as usize).max(1);
            let ttl_secs = if self.testpre_idle_secs == 0 { 120u64 } else { self.testpre_idle_secs as u64 };
            let idle_sleep_ms = (self.testpre_idle_secs as u64) * 1000;
            let pool = Arc::new(PingoraStreamPool::new(cap, Duration::from_secs(ttl_secs)));
            let key = pool_key(&format!("{}:{}", self.tag, self.dial_params.server_addr));
            let wake_refill = Arc::new(Notify::new());
            let refill_slots = Arc::new(Semaphore::new(cap));
            let closed = Arc::new(AtomicBool::new(false));
            let epoch = Instant::now();
            let last_activity_ms = Arc::new(AtomicU64::new(0));
            let mode = if idle_sleep_ms == 0 { "continuous mode" } else { "auto-sleep" };
            tracing::info!(
                "VLESS outbound '{}': starting Pingora testpre pool ({} workers, {}s TTL, {})",
                self.tag, self.testpre, ttl_secs, mode
            );
            for _ in 0..self.testpre {
                let (pool, wake, slots, closed, last_act, params, tag) = (
                    pool.clone(),
                    wake_refill.clone(),
                    refill_slots.clone(),
                    closed.clone(),
                    last_activity_ms.clone(),
                    self.dial_params.clone(),
                    self.tag.clone(),
                );
                let is_idle = move || {
                    idle_sleep_ms > 0
                        && (epoch.elapsed().as_millis() as u64).saturating_sub(last_act.load(Ordering::Relaxed))
                            >= idle_sleep_ms
                };
                tokio::spawn(async move {
                    while !closed.load(Ordering::Relaxed) {
                        if is_idle() {
                            wake.notified().await;
                            continue;
                        }
                        let Ok(permit) = slots.clone().acquire_owned().await else { break };
                        if closed.load(Ordering::Relaxed) { break; }
                        if is_idle() {
                            drop(permit);
                            wake.notified().await;
                            continue;
                        }
                        match params.dial_and_handshake().await {
                            Ok(conn) if !closed.load(Ordering::Relaxed) => {
                                pool.put_with_permit(key, conn, permit);
                                pingora_timeout::sleep(Duration::from_millis(200)).await;
                            }
                            Ok(_) => break,
                            Err(e) => {
                                drop(permit);
                                tracing::warn!("VLESS '{}' testpre pre-connect failed: {}", tag, e);
                                pingora_timeout::sleep(Duration::from_millis(500)).await;
                            }
                        }
                    }
                });
            }
            PingoraPrePool { pool, key, wake_refill, refill_slots, closed, epoch, last_activity_ms }
        })
    }
    async fn take_or_dial(&self, session: &SessionContext) -> Result<BoxStream> {
        #[cfg(debug_assertions)]
        let trace_ctx = session.debug_trace_id.zip(session.debug_trace_origin);
        if self.dial_params.ws_ed > 0 && self.testpre == 0 {
            let params = self.dial_params.clone();
            let dial_fn: crate::transport::internet::websocket::DialWsFn = Arc::new(move |ed| {
                let p = params.clone();
                #[cfg(debug_assertions)]
                let tc = trace_ctx;
                Box::pin(async move {
                    p.dial_and_handshake_with_ed(ed.as_deref(), #[cfg(debug_assertions)] tc).await
                })
            });
            return Ok(Box::pin(DelayDialConn::new(dial_fn, self.dial_params.ws_ed)));
        }
        if self.testpre > 0 {
            let pre_pool = self.init_pre_conns();
            pre_pool.touch_activity();
            if let Some(conn) = pre_pool.pool.get(pre_pool.key) {
                #[cfg(debug_assertions)]
                {
                    let host = session.sniffed_domain.clone().unwrap_or_else(|| session.destination.address.to_string());
                    crate::debug_panel::metrics().record_pool_reuse(&host, &self.tag);
                    if let Some((tid, origin)) = trace_ctx {
                        crate::debug_panel::metrics().update_trace_meta(tid, None, None, None, Some(true));
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
        self.dial_params.dial_and_handshake_with_ed(None, #[cfg(debug_assertions)] trace_ctx).await
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let stream = self.take_or_dial(session).await?;
        let command = if session.destination.network == Network::Udp { RequestCommand::Udp } else { RequestCommand::Tcp };
        let mut req = RequestHeader::new(self.user_id, command, session.destination.clone());
        if let Some(ref flow) = self.flow { req.addons = Addons::new(flow.clone()); }
        let is_vision = matches!(self.flow.as_deref(), Some(FLOW_VISION) | Some(crate::proxy::vless::flow::FLOW_VISION_UDP443));
        let vless: BoxStream = Box::pin(VlessStream::with_pending_header(stream, command == RequestCommand::Udp && !is_vision, req.encode_bytes()));
        Ok(if is_vision {
            Box::pin(VisionStream::new(vless, crate::proxy::vless::flow::VisionContext::new(self.user_id.into_bytes().to_vec(), true), false))
        } else { vless })
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
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "failed to write buffered VLESS bytes"))),
                Poll::Ready(Ok(n)) => { let d = n.min(self.pending_write.len()); self.pending_write.drain(..d); }
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
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_header.is_some()
            && self
                .header_flush_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(500))))
                .as_mut().poll(cx).is_ready()
        { self.promote_pending_header(); }
        if !self.pending_write.is_empty() { let _ = self.flush_pending_write(cx); }
        loop {
            if self.header_parsed {
                if self.is_udp {
                    if self.udp_pkt_remaining > 0 {
                        if !self.pending_buf.is_empty() {
                            let n = buf.remaining().min(self.udp_pkt_remaining).min(self.pending_buf.len());
                            buf.put_slice(&self.pending_buf[..n]);
                            self.pending_buf.drain(..n);
                            self.udp_pkt_remaining -= n;
                            return Poll::Ready(Ok(()));
                        }
                    } else if self.pending_buf.len() >= 2 {
                        let pkt_len = u16::from_be_bytes([self.pending_buf[0], self.pending_buf[1]]) as usize;
                        self.pending_buf.drain(..2);
                        self.udp_pkt_remaining = pkt_len;
                        continue;
                    }
                } else if !self.pending_buf.is_empty() {
                    let n = buf.remaining().min(self.pending_buf.len());
                    buf.put_slice(&self.pending_buf[..n]);
                    self.pending_buf.drain(..n);
                    return Poll::Ready(Ok(()));
                } else {
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }
            let mut temp_buf = [0u8; 2048];
            let mut temp_read_buf = ReadBuf::new(&mut temp_buf);
            match Pin::new(&mut self.inner).poll_read(cx, &mut temp_read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = temp_read_buf.filled();
                    if filled.is_empty() { return Poll::Ready(Ok(())); }
                    self.pending_buf.extend_from_slice(filled);
                    if !self.header_parsed && self.pending_buf.len() >= 2 {
                        let header_len = 2 + self.pending_buf[1] as usize;
                        if self.pending_buf.len() >= header_len {
                            self.header_parsed = true;
                            self.pending_buf.drain(..header_len);
                        }
                    }
                }
                other => return other,
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if !self.pending_write.is_empty() {
            match self.flush_pending_write(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let payload = if self.is_udp && buf.len() > u16::MAX as usize { &buf[..u16::MAX as usize] } else { buf };
        if self.pending_header.is_none() && !self.is_udp { return Pin::new(&mut self.inner).poll_write(cx, payload); }
        let mut frame = Vec::with_capacity(
            self.pending_header.as_ref().map_or(0, Vec::len) + if self.is_udp { 2 } else { 0 } + payload.len(),
        );
        if let Some(ref hdr) = self.pending_header { frame.extend_from_slice(hdr); }
        if self.is_udp { frame.extend_from_slice(&(payload.len() as u16).to_be_bytes()); }
        frame.extend_from_slice(payload);
        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(written)) => {
                (self.pending_header, self.header_flush_timer) = (None, None);
                self.pending_write.extend_from_slice(&frame[written..]);
                Poll::Ready(Ok(payload.len()))
            }
            Poll::Pending if self.pending_header.is_some() => {
                (self.pending_header, self.header_flush_timer) = (None, None);
                self.pending_write = frame;
                Poll::Ready(Ok(payload.len()))
            }
            other => other,
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
        assert_eq!(&buf[..n], b"\x00\xaa\x00\x05ping1\x00\x06ping22");
        server_io.write_all(&[0x00, 0x00, 0x00, 0x03, b'a', b'c', b'k', 0x00, 0x02, b'o', b'k']).await.unwrap();
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
        let client = Client::new("proxy", dest, Uuid::nil(), None, None, None, None).with_testpre_idle(1, 1);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "worker must stay asleep while idle instead of redialing");
        client.init_pre_conns().touch_activity();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "worker must wake and refill on new activity");
        drop(client);
        accept_task.abort();
    }
}
