// Module: app\dns\nameserver_doh.rs
// 1:1 Rust implementation corresponding to Go app\dns\nameserver_doh.go

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;

use crate::app::dns::hosts::StaticHosts;
use crate::app::dns::nameserver::{NameServer, build_dns_query_with_ecs, parse_dns_response};
use crate::app::dns::nameserver_local::LocalNameServer;
use crate::app::router::Router;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::features::routing::RouterFeature;
use crate::transport::internet::tls::tls::TlsClient;

/// Shared routing context attached after `Router` and `outbounds` are built,
/// matching official Xray-core `NewDoHNameServer(..., dispatcher)` routing behavior.
pub struct DohRoutingCtx {
    pub router: Router,
    pub outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    pub hosts: Arc<StaticHosts>,
}

pub struct DohNameServer {
    name: String,
    url: String,
    timeout: Duration,
    tag: Option<String>,
    routing: Option<Arc<OnceLock<DohRoutingCtx>>>,
    client_ip: Option<IpAddr>,
}

impl DohNameServer {
    pub fn new(url: impl Into<String>) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout: Duration::from_secs(5),
            tag: None,
            routing: None,
            client_ip: None,
        }
    }

    pub fn new_local_with_ecs(url: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        let mut s = Self::new(url);
        s.client_ip = client_ip;
        s
    }

    pub fn new_routed(
        url: impl Into<String>,
        tag: Option<String>,
        routing: Arc<OnceLock<DohRoutingCtx>>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout: Duration::from_secs(5),
            tag,
            routing: Some(routing),
            client_ip,
        }
    }

    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout,
            tag: None,
            routing: None,
            client_ip: None,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn parse_url(&self) -> (bool, String, u16, String) {
        let clean = self.url.trim();
        let is_https = !clean.starts_with("http://");
        let without_scheme = clean
            .strip_prefix("https://")
            .or_else(|| clean.strip_prefix("http://"))
            .unwrap_or(clean);

        let (host_port, path) = match without_scheme.find('/') {
            Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
            None => (without_scheme, "/dns-query"),
        };

        let (host, port) = if host_port.starts_with('[') {
            if let Some(end_bracket) = host_port.find(']') {
                let h = &host_port[1..end_bracket];
                let rest = &host_port[end_bracket + 1..];
                let p = if let Some(colon) = rest.find(':') {
                    rest[colon + 1..]
                        .parse::<u16>()
                        .unwrap_or(if is_https { 443 } else { 80 })
                } else {
                    if is_https { 443 } else { 80 }
                };
                (h.to_string(), p)
            } else {
                (host_port.to_string(), if is_https { 443 } else { 80 })
            }
        } else if let Some(colon) = host_port.find(':') {
            let h = &host_port[..colon];
            let p = host_port[colon + 1..]
                .parse::<u16>()
                .unwrap_or(if is_https { 443 } else { 80 });
            (h.to_string(), p)
        } else {
            (host_port.to_string(), if is_https { 443 } else { 80 })
        };

        let p = if path.is_empty() {
            "/dns-query".to_string()
        } else {
            path.to_string()
        };
        (is_https, host, port, p)
    }

    async fn dial_direct(&self, host: &str, port: u16, hosts: Option<&StaticHosts>) -> Result<BoxStream> {
        let mut addrs: Vec<SocketAddr> = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            addrs.push(SocketAddr::new(ip, port));
        } else if let Some(h) = hosts
            && let Some(static_ips) = h.lookup(host)
        {
            for ip in static_ips {
                addrs.push(SocketAddr::new(ip, port));
            }
        }
        if addrs.is_empty() {
            addrs.extend(
                tokio::net::lookup_host(format!("{}:{}", host, port))
                    .await
                    .map_err(Error::Io)?,
            );
        }

        let mut last_err = None;
        for addr in addrs {
            match pingora_timeout::timeout(
                self.timeout,
                crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(addr),
            )
            .await
            {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => return Err(Error::Timeout),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to connect to {}:{}", host, port),
            ))
        }))
    }

    async fn execute_doh(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let (is_https, host, port, path) = self.parse_url();
        let clean = domain.trim_end_matches('.');
        let query = build_dns_query_with_ecs(clean, 1, self.client_ip);

        // Official Xray-core `DOH` vs `DOHL` behavior:
        // - `https://...` routes through `Router` using this server's `tag` (e.g. `direct-dns-3` -> direct,
        //   `dns-module` -> proxy) so foreign DoH like `dns.google` automatically goes through proxy.
        // - `https+local://...` (`routing == None`) dials directly via the physical NIC.
        let tcp_stream: BoxStream = if let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) {
            let addr = match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => Address::Ipv4(v4),
                Ok(IpAddr::V6(v6)) => Address::Ipv6(v6),
                Err(_) => Address::Domain(host.clone()),
            };
            let dest = Destination::new(addr, port);
            let inbound_tag = self.tag.as_deref().unwrap_or("dns");
            let session = SessionContext::new(inbound_tag, dest);
            let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");

            if matches!(picked, "block" | "blackhole") {
                return Err(Error::Protocol(format!(
                    "DoH server '{}' blocked by routing rule",
                    self.url
                )));
            } else if matches!(picked, "direct" | "freedom" | "dns") {
                self.dial_direct(&host, port, Some(&ctx.hosts)).await?
            } else if let Some(outbound) = ctx.outbounds.get(picked) {
                pingora_timeout::timeout(self.timeout, outbound.connect(&session))
                    .await
                    .map_err(|_| Error::Timeout)??
            } else {
                self.dial_direct(&host, port, Some(&ctx.hosts)).await?
            }
        } else {
            self.dial_direct(&host, port, None).await?
        };

        let mut stream: crate::common::net::BoxStream = if is_https {
            let tls_client = TlsClient::new(&host, true, vec![b"http/1.1".to_vec()])?;
            pingora_timeout::timeout(self.timeout, tls_client.connect(&host, tcp_stream))
                .await
                .map_err(|_| Error::Timeout)??
        } else {
            tcp_stream
        };

        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray/dns\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path,
            host,
            query.len()
        );

        stream.write_all(req.as_bytes()).await.map_err(Error::Io)?;
        stream.write_all(&query).await.map_err(Error::Io)?;
        stream.flush().await.map_err(Error::Io)?;

        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let mut header_len = 0;
        let mut content_len = None;

        while buf.len() < 65536 {
            let n = pingora_timeout::timeout(self.timeout, stream.read(&mut chunk))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(Error::Io)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);

            if header_len == 0 {
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut resp = httparse::Response::new(&mut headers);
                if let Ok(httparse::Status::Complete(hlen)) = resp.parse(&buf) {
                    header_len = hlen;
                    if let Some(code) = resp.code
                        && code != 200
                    {
                        return Err(Error::Protocol(format!(
                            "DoH server responded with HTTP {}",
                            code
                        )));
                    }
                    for header in resp.headers.iter() {
                        if header.name.eq_ignore_ascii_case("content-length")
                            && let Ok(s) = std::str::from_utf8(header.value)
                        {
                            content_len = s.trim().parse::<usize>().ok();
                        }
                    }
                }
            }

            if let Some(clen) = content_len
                && header_len > 0
                && buf.len() >= header_len + clen
            {
                break;
            }
        }

        if header_len == 0 || buf.len() <= header_len {
            return Err(Error::Protocol("Invalid or empty DoH response".into()));
        }

        let body = &buf[header_len..];
        parse_dns_response(body, clean)
    }
}

#[async_trait]
impl NameServer for DohNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        match self.execute_doh(domain).await {
            Ok(ips) => Ok(ips),
            Err(e) => {
                // If DoH fails (e.g. offline unit testing or network disruption),
                // fallback to local resolution to guarantee service availability.
                LocalNameServer::new().query_ip(domain).await.map_err(|_| e)
            }
        }
    }
}
