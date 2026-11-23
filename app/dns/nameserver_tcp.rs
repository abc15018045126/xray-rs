use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;
use super::nameserver::{NameServer, build_dns_query_with_ecs, parse_dns_response_with_ttl};
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
    pub fn server_addr(&self) -> SocketAddr { self.server_addr }
}

impl TcpNameServer {
    async fn query_qtype(&self, clean: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
        let mut routed_stream = None;
        if let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) {
            let dest = Destination::from_ip_port(self.server_addr.ip(), self.server_addr.port());
            let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
            let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
            if matches!(picked, "block" | "blackhole") {
                return Err(Error::Protocol(format!("TCP DNS server '{}' blocked by routing rule", self.server_addr)));
            }
            if !matches!(picked, "direct" | "freedom" | "dns") && let Some(outbound) = ctx.outbounds.get(picked)
            {
                routed_stream = Some(
                    pingora_timeout::timeout(self.timeout, outbound.connect(&session))
                        .await.map_err(|_| Error::Timeout)??,
                );
            }
        }
        let mut stream: BoxStream = match routed_stream {
            Some(s) => s,
            None => pingora_timeout::timeout(
                self.timeout,
                crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(self.server_addr),
            )
            .await.map_err(|_| Error::Timeout)??,
        };
        let query = build_dns_query_with_ecs(clean, qtype, self.client_ip);
        pingora_timeout::timeout(self.timeout, async {
            stream.write_all(&(query.len() as u16).to_be_bytes()).await?;
            stream.write_all(&query).await
        })
        .await.map_err(|_| Error::Timeout)??;
        let mut resp_len_buf = [0u8; 2];
        pingora_timeout::timeout(self.timeout, stream.read_exact(&mut resp_len_buf))
            .await.map_err(|_| Error::Timeout)??;
        let mut resp = vec![0u8; u16::from_be_bytes(resp_len_buf) as usize];
        pingora_timeout::timeout(self.timeout, stream.read_exact(&mut resp)).await.map_err(|_| Error::Timeout)??;
        parse_dns_response_with_ttl(&resp, clean)
    }
}

#[async_trait]
impl NameServer for TcpNameServer {
    fn name(&self) -> &str { "tcp" }
    fn routes_via_proxy(&self) -> bool {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else { return false; };
        let dest = Destination::from_ip_port(self.server_addr.ip(), self.server_addr.port());
        let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
        !matches!(ctx.router.pick_outbound(&session).unwrap_or("direct"), "direct" | "freedom" | "dns" | "block" | "blackhole")
    }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.query_ip_with_opt(domain, true, false).await.map(|(ips, _)| ips)
    }
    async fn query_ip_with_opt(&self, domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        let clean = domain.trim_end_matches('.');
        let (mut ips, mut ttl, mut last_err) = (Vec::new(), u32::MAX, None);
        if ipv4 {
            match self.query_qtype(clean, 1).await {
                Ok((v, t)) => { ips.extend(v); ttl = ttl.min(t); }
                Err(e) => last_err = Some(e),
            }
        }
        if ipv6 {
            match self.query_qtype(clean, 28).await {
                Ok((v, t)) => { ips.extend(v); ttl = ttl.min(t); }
                Err(e) => last_err = Some(e),
            }
        }
        if !ips.is_empty() {
            Ok((ips, if ttl == u32::MAX { 60 } else { ttl }))
        } else {
            Err(last_err.unwrap_or_else(|| Error::NotFound(format!("No IP found for {}", clean))))
        }
    }
}
