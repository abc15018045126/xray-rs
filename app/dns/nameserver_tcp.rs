// Module: app\dns\nameserver_tcp.rs
// 1:1 Rust implementation corresponding to Go app\dns\nameserver_tcp.go

use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;

use super::nameserver::{NameServer, build_dns_query_with_ecs, parse_dns_response};
use super::nameserver_doh::DohRoutingCtx;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::routing::RouterFeature;

pub struct TcpNameServer {
    pub server_addr: SocketAddr,
    pub timeout: Duration,
    tag: Option<String>,
    routing: Option<Arc<OnceLock<DohRoutingCtx>>>,
    client_ip: Option<IpAddr>,
}

impl TcpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout: Duration::from_secs(5),
            tag: None,
            routing: None,
            client_ip: None,
        }
    }

    pub fn new_local_with_ecs(server_addr: SocketAddr, client_ip: Option<IpAddr>) -> Self {
        let mut s = Self::new(server_addr);
        s.client_ip = client_ip;
        s
    }

    pub fn new_routed(
        server_addr: SocketAddr,
        tag: Option<String>,
        routing: Arc<OnceLock<DohRoutingCtx>>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            server_addr,
            timeout: Duration::from_secs(5),
            tag,
            routing: Some(routing),
            client_ip,
        }
    }

    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            server_addr,
            timeout,
            tag: None,
            routing: None,
            client_ip: None,
        }
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

#[async_trait]
impl NameServer for TcpNameServer {
    fn name(&self) -> &str {
        "tcp"
    }

    fn routes_via_proxy(&self) -> bool {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else {
            return false;
        };
        let dest = Destination::from_ip_port(self.server_addr.ip(), self.server_addr.port());
        let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
        let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
        !matches!(picked, "direct" | "freedom" | "dns" | "block" | "blackhole")
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let clean = domain.trim_end_matches('.');
        let mut stream: BoxStream = if let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) {
            let dest = Destination::from_ip_port(self.server_addr.ip(), self.server_addr.port());
            let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
            let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
            if matches!(picked, "block" | "blackhole") {
                return Err(Error::Protocol(format!(
                    "TCP DNS server '{}' blocked by routing rule",
                    self.server_addr
                )));
            } else if !matches!(picked, "direct" | "freedom" | "dns")
                && let Some(outbound) = ctx.outbounds.get(picked)
            {
                pingora_timeout::timeout(self.timeout, outbound.connect(&session))
                    .await
                    .map_err(|_| Error::Timeout)??
            } else {
                pingora_timeout::timeout(
                    self.timeout,
                    crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(self.server_addr),
                )
                .await
                .map_err(|_| Error::Timeout)??
            }
        } else {
            pingora_timeout::timeout(
                self.timeout,
                crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(self.server_addr),
            )
            .await
            .map_err(|_| Error::Timeout)??
        };

        let query = build_dns_query_with_ecs(clean, 1, self.client_ip);
        let len_prefix = (query.len() as u16).to_be_bytes();

        stream.write_all(&len_prefix).await.map_err(Error::Io)?;
        stream.write_all(&query).await.map_err(Error::Io)?;

        let mut resp_len_buf = [0u8; 2];
        pingora_timeout::timeout(self.timeout, stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp = vec![0u8; resp_len];
        pingora_timeout::timeout(self.timeout, stream.read_exact(&mut resp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        parse_dns_response(&resp, clean)
    }
}
