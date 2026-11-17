use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use xray_rs_proto::{TrojanRequestHeader, VlessRequestHeader, VlessStream};
use xray_rs_types::{Address, BoxStream, Destination, Error, OutboundHandler, Result, SessionContext};

use crate::transport::{
    PingoraStreamPool, TcpTransport, TlsTransport, WebSocketTransport, pool_key,
};

/// Direct TCP outbound handler ("freedom").
pub struct FreedomHandler {
    tag: String,
}

impl FreedomHandler {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl OutboundHandler for FreedomHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        TcpTransport::dial(&session.destination).await
    }
}

/// Drop-all outbound handler ("blackhole").
pub struct BlackholeHandler {
    tag: String,
}

impl BlackholeHandler {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl OutboundHandler for BlackholeHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _session: &SessionContext) -> Result<BoxStream> {
        Err(Error::Closed)
    }
}

/// VLESS outbound handler supporting TCP -> optional TLS -> optional WebSocket -> VLESS.
pub struct VlessOutboundHandler {
    tag: String,
    server: Destination,
    user_id: Uuid,
    flow: Option<String>,
    tls: Option<Arc<TlsTransport>>,
    tls_sni: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
}

impl VlessOutboundHandler {
    pub fn new(
        tag: impl Into<String>,
        server: Destination,
        user_id: Uuid,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            user_id,
            flow: None,
            tls: None,
            tls_sni: None,
            ws_path: None,
            ws_host: None,
        }
    }

    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = Some(flow.into());
        self
    }

    pub fn with_tls(mut self, tls: TlsTransport, sni: Option<String>) -> Self {
        self.tls = Some(Arc::new(tls));
        self.tls_sni = sni;
        self
    }

    pub fn with_websocket(mut self, path: impl Into<String>, host: Option<String>) -> Self {
        self.ws_path = Some(path.into());
        self.ws_host = host;
        self
    }
}

#[async_trait]
impl OutboundHandler for VlessOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut stream = TcpTransport::dial(&self.server).await?;

        let default_sni = match &self.server.address {
            Address::Domain(d) => d.as_str(),
            _ => "localhost",
        };
        let sni = self.tls_sni.as_deref().unwrap_or(default_sni);

        if let Some(tls) = &self.tls {
            stream = tls.connect(sni, stream).await?;
        }

        if let Some(path) = &self.ws_path {
            let scheme = if self.tls.is_some() { "wss" } else { "ws" };
            let dest_host = self.server.address.to_string();
            let ws_url = format!("{}://{}{}", scheme, dest_host, path);
            let host_hdr = self.ws_host.as_deref().unwrap_or(sni);
            stream = WebSocketTransport::client_handshake(&ws_url, Some(host_hdr), stream).await?;
        }

        let mut req = VlessRequestHeader::new(self.user_id, session.destination.clone());
        if let Some(flow) = &self.flow {
            req = req.with_flow(flow.clone());
        }
        req.write_to(&mut stream).await?;

        Ok(Box::pin(VlessStream::new(stream)))
    }
}

/// Trojan outbound handler supporting TCP -> TLS -> optional WebSocket -> Trojan.
pub struct TrojanOutboundHandler {
    tag: String,
    server: Destination,
    password: String,
    tls: Option<Arc<TlsTransport>>,
    tls_sni: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
}

impl TrojanOutboundHandler {
    pub fn new(
        tag: impl Into<String>,
        server: Destination,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            password: password.into(),
            tls: None,
            tls_sni: None,
            ws_path: None,
            ws_host: None,
        }
    }

    pub fn with_tls(mut self, tls: TlsTransport, sni: Option<String>) -> Self {
        self.tls = Some(Arc::new(tls));
        self.tls_sni = sni;
        self
    }

    pub fn with_websocket(mut self, path: impl Into<String>, host: Option<String>) -> Self {
        self.ws_path = Some(path.into());
        self.ws_host = host;
        self
    }
}

#[async_trait]
impl OutboundHandler for TrojanOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut stream = TcpTransport::dial(&self.server).await?;

        let default_sni = match &self.server.address {
            Address::Domain(d) => d.as_str(),
            _ => "localhost",
        };
        let sni = self.tls_sni.as_deref().unwrap_or(default_sni);

        if let Some(tls) = &self.tls {
            stream = tls.connect(sni, stream).await?;
        }

        if let Some(path) = &self.ws_path {
            let scheme = if self.tls.is_some() { "wss" } else { "ws" };
            let ws_url = format!("{}://{}{}", scheme, self.server.address, path);
            let host_hdr = self.ws_host.as_deref().unwrap_or(sni);
            stream = WebSocketTransport::client_handshake(&ws_url, Some(host_hdr), stream).await?;
        }

        let req = TrojanRequestHeader::new(&self.password, session.destination.clone());
        req.write_to(&mut stream).await?;

        Ok(stream)
    }
}

/// Outbound handler wrapper backed by Cloudflare `pingora-pool`.
pub struct PingoraPooledOutbound {
    tag: String,
    pool: Arc<PingoraStreamPool>,
    upstreams: Vec<Arc<dyn OutboundHandler>>,
}

impl PingoraPooledOutbound {
    pub fn new(
        tag: impl Into<String>,
        upstreams: Vec<Arc<dyn OutboundHandler>>,
        capacity: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            tag: tag.into(),
            pool: Arc::new(PingoraStreamPool::new(capacity, idle_timeout)),
            upstreams,
        }
    }

    pub fn pool(&self) -> &Arc<PingoraStreamPool> {
        &self.pool
    }
}

#[async_trait]
impl OutboundHandler for PingoraPooledOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let key = pool_key(&format!("{}:{}", self.tag, session.destination));
        if let Some(reused) = self.pool.get(key) {
            return Ok(reused);
        }

        let mut last_err = None;
        for upstream in &self.upstreams {
            match upstream.connect(session).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(Error::Closed))
    }
}
