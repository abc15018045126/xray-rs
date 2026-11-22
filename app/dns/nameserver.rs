use crate::app::dns::fakedns::FakeDnsHolder;
use crate::common::errors::{Error, Result};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::{TcpStream, UdpSocket};

#[async_trait]
pub trait NameServer: Send + Sync {
    fn name(&self) -> &str;
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>>;
    fn is_disable_cache(&self) -> bool {
        false
    }
    fn routes_via_proxy(&self) -> bool {
        false
    }
}

pub struct UdpNameServer {
    name: String,
    server_addr: SocketAddr,
    timeout: Duration,
}

impl UdpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            name: format!("udp://{}", server_addr),
            server_addr,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            name: format!("udp://{}", server_addr),
            server_addr,
            timeout,
        }
    }
}

#[async_trait]
impl NameServer for UdpNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        #[cfg(target_os = "windows")]
        let socket = {
            let iface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.read().await;
            let sock = crate::proxy::tun::socket_helpers::new_udp_socket(
                None,
                iface.as_ref(),
                Some(self.server_addr),
            )
            .await
            .map_err(Error::Io)?;
            sock.connect(self.server_addr).await?;
            sock
        };
        #[cfg(not(target_os = "windows"))]
        let socket = {
            let s = UdpSocket::bind("0.0.0.0:0").await?;
            s.connect(self.server_addr).await?;
            s
        };

        let query = build_dns_query(domain);
        socket.send(&query).await?;

        let mut resp = [0u8; 1024];
        let n = pingora_timeout::timeout(self.timeout, socket.recv(&mut resp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        parse_dns_response(&resp[..n], domain)
    }
}

pub struct TcpNameServer {
    name: String,
    server_addr: SocketAddr,
    timeout: Duration,
}

impl TcpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            name: format!("tcp://{}", server_addr),
            server_addr,
            timeout: Duration::from_secs(5),
        }
    }
}

#[async_trait]
impl NameServer for TcpNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut stream = pingora_timeout::timeout(
            self.timeout,
            crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(self.server_addr),
        )
        .await
        .map_err(|_| Error::Timeout)??;

        let query = build_dns_query(domain);
        let len_prefix = (query.len() as u16).to_be_bytes();

        stream.write_all(&len_prefix).await?;
        stream.write_all(&query).await?;

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

        parse_dns_response(&resp, domain)
    }
}

pub struct FakeDnsNameServer {
    name: String,
    holder: Arc<FakeDnsHolder>,
}

impl FakeDnsNameServer {
    pub fn new(holder: Arc<FakeDnsHolder>) -> Self {
        Self {
            name: "fakedns".into(),
            holder,
        }
    }
}

#[async_trait]
impl NameServer for FakeDnsNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let ip = self.holder.get_fake_ip_for_domain(domain);
        Ok(vec![IpAddr::V4(ip)])
    }
}

pub struct LocalNameServer {
    name: String,
}

impl LocalNameServer {
    pub fn new() -> Self {
        Self {
            name: "local".into(),
        }
    }
}

impl Default for LocalNameServer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NameServer for LocalNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let addr_str = format!("{}:80", domain);
        let addrs = tokio::net::lookup_host(addr_str).await.map_err(Error::Io)?;
        let ips: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
        if ips.is_empty() {
            Err(Error::NotFound(format!(
                "Local DNS could not resolve {}",
                domain
            )))
        } else {
            Ok(ips)
        }
    }
}

pub fn build_dns_query(domain: &str) -> Vec<u8> {
    build_dns_query_typed(domain, 1)
}

pub fn build_dns_query_typed(domain: &str, qtype: u16) -> Vec<u8> {
    build_dns_query_with_ecs(domain, qtype, None)
}

pub fn build_dns_query_with_ecs(domain: &str, qtype: u16, client_ip: Option<IpAddr>) -> Vec<u8> {
    let mut query = vec![
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, u8::from(client_ip.is_some()),
    ];
    for part in domain.trim_end_matches('.').split('.').filter(|p| !p.is_empty()) {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]);

    if let Some(ip) = client_ip {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                query.extend_from_slice(&[
                    0, 0, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0x0B, 0, 8, 0, 7, 0, 1, 24, 0, o[0], o[1], o[2],
                ]);
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                query.extend_from_slice(&[
                    0, 0, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0x0F, 0, 8, 0, 0x0B, 0, 2, 56, 0,
                    o[0], o[1], o[2], o[3], o[4], o[5], o[6],
                ]);
            }
        }
    }
    query
}

pub fn parse_dns_response(resp: &[u8], domain: &str) -> Result<Vec<IpAddr>> {
    parse_dns_response_with_ttl(resp, domain).map(|(ips, _)| ips)
}

pub fn parse_dns_response_with_ttl(resp: &[u8], domain: &str) -> Result<(Vec<IpAddr>, u32)> {
    let n = resp.len();
    if n < 12 {
        return Err(Error::Protocol("DNS response too short (< 12 bytes)".into()));
    }
    let rcode = resp[3] & 0x0F;
    if rcode != 0 {
        return Err(Error::NotFound(format!("DNS server returned error code {} for domain {}", rcode, domain)));
    }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let skip_name = |pos: &mut usize| {
        while *pos < n {
            let len = resp[*pos] as usize;
            if len == 0 {
                *pos += 1;
                return;
            }
            if len & 0xc0 == 0xc0 {
                *pos += 2;
                return;
            }
            *pos += 1 + len;
        }
    };

    let mut pos = 12;
    for _ in 0..qdcount {
        skip_name(&mut pos);
        pos += 4;
    }
    if pos > n {
        return Err(Error::Protocol("Malformed DNS response questions".into()));
    }

    let (mut ips, mut min_ttl) = (Vec::new(), u32::MAX);
    for _ in 0..ancount {
        if pos >= n {
            break;
        }
        skip_name(&mut pos);
        if pos + 10 > n {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > n {
            break;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                let b: [u8; 4] = resp[pos..pos + 4].try_into().unwrap();
                ips.push(IpAddr::V4(std::net::Ipv4Addr::from(b)));
                min_ttl = min_ttl.min(ttl);
            }
            (28, 16) => {
                let b: [u8; 16] = resp[pos..pos + 16].try_into().unwrap();
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(b)));
                min_ttl = min_ttl.min(ttl);
            }
            _ => {}
        }
        pos += rdlength;
    }

    if ips.is_empty() {
        Err(Error::NotFound(format!("No IP resolved for {}", domain)))
    } else {
        Ok((ips, if min_ttl == u32::MAX || min_ttl == 0 { 300 } else { min_ttl }))
    }
}
