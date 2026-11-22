use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::UdpSocket;
use super::nameserver::{NameServer, build_dns_query_with_ecs, parse_dns_response};
use super::nameserver_doh::DohRoutingCtx;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use crate::common::protocol::SessionContext;
use crate::features::routing::RouterFeature;

pub struct UdpNameServer {
    pub server_addr: SocketAddr,
    pub timeout: Duration,
    tag: Option<String>,
    routing: Option<Arc<OnceLock<DohRoutingCtx>>>,
    client_ip: Option<IpAddr>,
}

impl UdpNameServer {
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

#[async_trait]
impl NameServer for UdpNameServer {
    fn name(&self) -> &str { "udp" }
    fn routes_via_proxy(&self) -> bool {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else { return false; };
        let addr = match self.server_addr.ip() {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        };
        let dest = Destination::udp(addr, self.server_addr.port());
        let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
        let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
        !matches!(picked, "direct" | "freedom" | "dns" | "block" | "blackhole")
    }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let clean = domain.trim_end_matches('.');
        let query_a = build_dns_query_with_ecs(clean, 1, self.client_ip);
        if let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) {
            let dest = Destination::udp(Address::ip(self.server_addr.ip()), self.server_addr.port());
            let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
            let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
            if matches!(picked, "block" | "blackhole") {
                return Err(Error::Protocol(format!("UDP DNS server '{}' blocked by routing rule", self.server_addr)));
            }
            if !matches!(picked, "direct" | "freedom" | "dns") && let Some(outbound) = ctx.outbounds.get(picked)
            {
                let mut stream = pingora_timeout::timeout(self.timeout, outbound.connect(&session))
                    .await.map_err(|_| Error::Timeout)??;
                stream.write_all(&query_a).await?;
                let mut buf = [0u8; 2048];
                let n = pingora_timeout::timeout(self.timeout, stream.read(&mut buf))
                    .await.map_err(|_| Error::Timeout)??;
                return parse_dns_response(&buf[..n], clean);
            }
        }
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let socket = {
            let iface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.read().await;
            crate::proxy::tun::socket_helpers::new_udp_socket(None, iface.as_ref(), Some(self.server_addr)).await?
        };
        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        let socket = UdpSocket::bind(if self.server_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
        socket.connect(self.server_addr).await?;
        socket.send(&query_a).await?;
        let mut buf = [0u8; 2048];
        let n = pingora_timeout::timeout(self.timeout, socket.recv(&mut buf)).await.map_err(|_| Error::Timeout)??;
        parse_dns_response(&buf[..n], clean)
    }
}
