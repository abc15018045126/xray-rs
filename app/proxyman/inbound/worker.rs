use crate::app::stats::Counter;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::session::SniffingRequest;
use crate::features::inbound::{InboundHandler, InboundResult};
use crate::transport::internet::httpupgrade::HttpUpgradeStream;
use crate::transport::internet::reality::RealityServer;
use crate::transport::internet::splithttp::SplitHttpServer;
use crate::transport::internet::{TlsServer, WebSocketStream};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Stream-layer transport wrapper for inbound handlers, aligned with official Xray-core
/// `app/proxyman/inbound/worker.go` (`tcpWorker`): terminates inbound TLS/REALITY and
/// WebSocket/XHTTP/HttpUpgrade, attaches inbound `SniffingRequest` to `SessionContext`,
/// and tracks per-inbound counters before handing the decrypted stream to the protocol
/// `InboundHandler` (VLESS/VMess/Trojan/etc.).
pub struct StreamInboundHandler {
    inner: Arc<dyn InboundHandler>,
    tls_server: Option<Arc<TlsServer>>,
    reality_server: Option<Arc<RealityServer>>,
    is_ws: bool,
    ws_path: Option<String>,
    ws_host: Option<String>,
    httpupgrade: Option<(Option<String>, Option<String>)>,
    splithttp_server: Option<Arc<SplitHttpServer>>,
    sniffing_request: Option<SniffingRequest>,
    pub uplink_counter: Arc<Counter>,
    pub downlink_counter: Arc<Counter>,
}

impl StreamInboundHandler {
    pub fn new(
        inner: Arc<dyn InboundHandler>,
        tls_server: Option<Arc<TlsServer>>,
        is_ws: bool,
        ws_path: Option<String>,
        ws_host: Option<String>,
    ) -> Self {
        Self {
            inner,
            tls_server,
            reality_server: None,
            is_ws,
            ws_path,
            ws_host,
            httpupgrade: None,
            splithttp_server: None,
            sniffing_request: None,
            uplink_counter: Arc::new(Counter::new()),
            downlink_counter: Arc::new(Counter::new()),
        }
    }

    pub fn with_reality(mut self, server: Arc<RealityServer>) -> Self {
        self.reality_server = Some(server);
        self
    }

    pub fn with_httpupgrade(mut self, path: Option<String>, host: Option<String>) -> Self {
        self.httpupgrade = Some((path, host));
        self
    }

    pub fn with_splithttp(mut self, server: Arc<SplitHttpServer>) -> Self {
        self.splithttp_server = Some(server);
        self
    }

    pub fn with_sniffing(mut self, sniffing: SniffingRequest) -> Self {
        self.sniffing_request = Some(sniffing);
        self
    }
}

#[async_trait]
impl InboundHandler for StreamInboundHandler {
    fn tag(&self) -> &str {
        self.inner.tag()
    }

    async fn handle_connection(
        &self,
        mut stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        if let Some(ref reality) = self.reality_server {
            match reality.accept(stream).await? {
                Some(s) => stream = s,
                None => return Err(Error::Closed),
            }
        } else if let Some(ref tls) = self.tls_server {
            stream = tls.accept(stream).await?;
        }
        if let Some(ref xhttp) = self.splithttp_server {
            match xhttp.accept_stream(stream, remote_addr).await? {
                Some(conn) => stream = conn,
                None => return Err(Error::Closed),
            }
        } else if let Some((ref path, ref host)) = self.httpupgrade {
            stream = HttpUpgradeStream::server_handshake(stream, host.as_deref(), path.as_deref())
                .await?;
        } else if self.is_ws {
            stream = WebSocketStream::server_handshake_with_config(
                stream,
                self.ws_path.as_deref(),
                self.ws_host.as_deref(),
            )
            .await?;
        }
        let mut res = self.inner.handle_connection(stream, remote_addr).await?;
        if res.session.sniffing_request.is_none()
            && let Some(ref sniff) = self.sniffing_request
        {
            res.session.sniffing_request = Some(sniff.clone());
        }
        Ok(res)
    }

    async fn start(&self) -> Result<()> {
        self.inner.start().await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

pub struct InboundWorker {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub running: AtomicBool,
    pub uplink_counter: Arc<Counter>,
    pub downlink_counter: Arc<Counter>,
}

impl InboundWorker {
    pub fn new(tag: impl Into<String>, listen: impl Into<String>, port: u16) -> Self {
        Self {
            tag: tag.into(),
            listen: listen.into(),
            port,
            running: AtomicBool::new(false),
            uplink_counter: Arc::new(Counter::new()),
            downlink_counter: Arc::new(Counter::new()),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn start(&self) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);
        Ok(())
    }
}
