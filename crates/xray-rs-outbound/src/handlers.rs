use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use xray_rs_proto::{
    FLOW_VISION, TrojanRequestHeader, VisionContext, VisionStream, VlessRequestHeader, VlessStream,
    write_target_address,
};
use xray_rs_types::{Address, BoxStream, Destination, Error, OutboundHandler, Result, SessionContext};

use crate::transport::{
    FragmentConfig, FragmentConn, HttpUpgradeTransport, PingoraStreamPool, TcpTransport,
    TlsTransport, WebSocketTransport, pool_key,
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

/// Xray `dns` outbound: hijacked DNS queries are answered by plain-IP upstream resolvers over
/// DNS-over-TCP (RFC 7766). Upstream sockets are pinned to the physical interface by
/// [`TcpTransport`], so they never loop back into the TUN, and both IPv4 and IPv6 upstreams are
/// raced, so it also works on IPv6-only (or IPv4-only) networks.
pub struct DnsOutboundHandler {
    tag: String,
    upstreams: Vec<Destination>,
}

impl DnsOutboundHandler {
    const DEFAULT_UPSTREAMS: [IpAddr; 4] = [
        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        IpAddr::V6(Ipv6Addr::new(0x2402, 0x4e00, 0, 0, 0, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
    ];

    pub fn new(tag: impl Into<String>) -> Self {
        Self::with_upstreams(tag, Self::DEFAULT_UPSTREAMS.to_vec())
    }

    pub fn with_upstreams(tag: impl Into<String>, upstreams: Vec<IpAddr>) -> Self {
        let upstreams = if upstreams.is_empty() {
            Self::DEFAULT_UPSTREAMS.to_vec()
        } else {
            upstreams
        };
        Self {
            tag: tag.into(),
            upstreams: upstreams
                .into_iter()
                .map(|ip| {
                    let addr = match ip {
                        IpAddr::V4(v4) => Address::Ipv4(v4),
                        IpAddr::V6(v6) => Address::Ipv6(v6),
                    };
                    Destination::tcp(addr, 53)
                })
                .collect(),
        }
    }
}

#[async_trait]
impl OutboundHandler for DnsOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn is_dns(&self) -> bool {
        true
    }

    async fn connect(&self, _session: &SessionContext) -> Result<BoxStream> {
        let attempts = self.upstreams.iter().map(|dest| {
            Box::pin(TcpTransport::dial_with_timeout(dest, Duration::from_secs(3)))
        });
        match futures::future::select_ok(attempts).await {
            Ok((stream, _rest)) => Ok(stream),
            Err(e) => Err(e),
        }
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
    httpupgrade_path: Option<String>,
    httpupgrade_host: Option<String>,
    fragment: Option<FragmentConfig>,
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
            httpupgrade_path: None,
            httpupgrade_host: None,
            fragment: None,
        }
    }

    pub fn with_httpupgrade(mut self, path: impl Into<String>, host: Option<String>) -> Self {
        self.httpupgrade_path = Some(path.into());
        self.httpupgrade_host = host;
        self
    }

    pub fn with_fragment(mut self, cfg: FragmentConfig) -> Self {
        self.fragment = Some(cfg);
        self
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
        if let Some(frag) = &self.fragment {
            stream = Box::pin(FragmentConn::new_client(frag.clone(), stream));
        }

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
        } else if let Some(path) = &self.httpupgrade_path {
            let host_hdr = self.httpupgrade_host.as_deref().unwrap_or(sni);
            stream = HttpUpgradeTransport::client_handshake(path, host_hdr, stream).await?;
        }

        let mut req = VlessRequestHeader::new(self.user_id, session.destination.clone());
        if let Some(flow) = &self.flow {
            req = req.with_flow(flow.clone());
        }
        req.write_to(&mut stream).await?;

        let vless_stream: BoxStream = Box::pin(VlessStream::new(stream));
        if self.flow.as_deref() == Some(FLOW_VISION) {
            Ok(Box::pin(VisionStream::new(
                vless_stream,
                VisionContext::new(self.user_id.into_bytes().to_vec(), true),
                false,
            )))
        } else {
            Ok(vless_stream)
        }
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
    fragment: Option<FragmentConfig>,
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
            fragment: None,
        }
    }

    pub fn with_fragment(mut self, cfg: FragmentConfig) -> Self {
        self.fragment = Some(cfg);
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
impl OutboundHandler for TrojanOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut stream = TcpTransport::dial(&self.server).await?;
        if let Some(frag) = &self.fragment {
            stream = Box::pin(FragmentConn::new_client(frag.clone(), stream));
        }

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

/// Shadowsocks outbound handler.
pub struct ShadowsocksOutboundHandler {
    tag: String,
    server: Destination,
    method: String,
    password: String,
}

impl ShadowsocksOutboundHandler {
    pub fn new(
        tag: impl Into<String>,
        server: Destination,
        method: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            method: method.into(),
            password: password.into(),
        }
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[async_trait]
impl OutboundHandler for ShadowsocksOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut stream = TcpTransport::dial(&self.server).await?;
        write_target_address(&mut stream, &session.destination).await?;
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
