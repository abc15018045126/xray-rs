// Module: proxy\vless\outbound\outbound.rs
// 1:1 Rust implementation corresponding to Go proxy\vless\outbound\outbound.go

use async_trait::async_trait;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::common::errors::Result;
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::protocol::{RequestCommand, SessionContext};
use crate::features::outbound::OutboundHandler;
use crate::proxy::vless::encoding::{Addons, RequestHeader};
use crate::proxy::vless::flow::{FLOW_VISION, VisionStream};
use crate::transport::internet::reality::RealityClient;
use crate::transport::internet::{TcpDialer, TlsClient, WebSocketStream};

struct PreConn {
    conn: BoxStream,
    expire: Instant,
}

#[derive(Clone)]
struct DialParams {
    server_addr: Destination,
    tls_client: Option<Arc<TlsClient>>,
    tls_sni: Option<String>,
    reality_client: Option<Arc<RealityClient>>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    ws_heartbeat: u32,
    fragment_cfg: Option<crate::transport::internet::finalmask::fragment::Config>,
}

impl DialParams {
    async fn dial_and_handshake(&self) -> Result<BoxStream> {
        let tcp_stream = TcpDialer::dial(&self.server_addr).await?;

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
                tls.connect(&reality.server_name, tcp_stream).await?
            } else {
                tcp_stream
            }
        } else if let Some(tls) = &self.tls_client {
            tls.connect(sni, tcp_stream).await?
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
            WebSocketStream::client_handshake_with_options(
                &ws_url,
                Some(host_hdr),
                stream,
                self.ws_heartbeat,
                None,
            )
            .await?
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
    pre_conns: OnceLock<Mutex<mpsc::Receiver<PreConn>>>,
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
                ws_path,
                ws_host,
                ws_heartbeat: 0,
                fragment_cfg: None,
            },
            testpre: 0,
            pre_conns: OnceLock::new(),
        }
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

    /// Official Xray-core `testpre`: pre-warm `count` transport connections (TCP+TLS+WS)
    /// in background tasks with a 2-minute expiration, matching `proxy/vless/outbound/outbound.go`.
    pub fn with_testpre(mut self, count: u32) -> Self {
        self.testpre = count;
        if count > 0 && tokio::runtime::Handle::try_current().is_ok() {
            let _ = self.init_pre_conns();
        }
        self
    }

    fn init_pre_conns(&self) -> &Mutex<mpsc::Receiver<PreConn>> {
        self.pre_conns.get_or_init(|| {
            let cap = (self.testpre as usize).max(1);
            let (tx, rx) = mpsc::channel::<PreConn>(cap);
            tracing::info!(
                "VLESS outbound '{}': starting testpre transport pre-warm pool ({} workers)",
                self.tag,
                self.testpre
            );
            for _ in 0..self.testpre {
                let tx_clone = tx.clone();
                let params = self.dial_params.clone();
                let tag = self.tag.clone();
                tokio::spawn(async move {
                    loop {
                        if tx_clone.is_closed() {
                            break;
                        }
                        match params.dial_and_handshake().await {
                            Ok(conn) => {
                                let item = PreConn {
                                    conn,
                                    expire: Instant::now() + Duration::from_secs(120),
                                };
                                if tx_clone.send(item).await.is_err() {
                                    break;
                                }
                                // Match official Xray-core 200ms pacing between pre-connect refills
                                tokio::time::sleep(Duration::from_millis(200)).await;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "VLESS '{}' testpre pre-connect failed: {}",
                                    tag,
                                    e
                                );
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                        }
                    }
                });
            }
            Mutex::new(rx)
        })
    }

    async fn take_or_dial(&self, session: &SessionContext) -> Result<BoxStream> {
        if self.testpre > 0 {
            let rx_mutex = self.init_pre_conns();
            let mut rx = rx_mutex.lock().await;
            while let Ok(pre) = rx.try_recv() {
                if Instant::now() < pre.expire {
                    #[cfg(debug_assertions)]
                    {
                        let host = session
                            .sniffed_domain
                            .clone()
                            .unwrap_or_else(|| session.destination.address.to_string());
                        crate::debug_panel::metrics().record_pool_reuse(&host, &self.tag);
                    }
                    let _ = session;
                    return Ok(pre.conn);
                }
                // Expired pre-warmed connection: drop it and check the next one
            }
            drop(rx);
        }

        self.dial_params.dial_and_handshake().await
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
                    self.pending_write.drain(..n);
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
            Poll::Pending => Poll::Pending,
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
}
