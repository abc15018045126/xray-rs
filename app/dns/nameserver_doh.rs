use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::app::dns::hosts::StaticHosts;
use crate::app::dns::nameserver::{NameServer, build_dns_query_with_ecs, parse_dns_response};
#[cfg(not(target_os = "android"))]
use crate::app::dns::nameserver_local::LocalNameServer;
use crate::app::router::Router;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::features::routing::RouterFeature;
use crate::transport::internet::tls::tls::TlsClient;

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
    h2_client: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
}

impl DohNameServer {
    pub fn new(url: impl Into<String>) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout: Duration::from_secs(8),
            tag: None,
            routing: None,
            client_ip: None,
            h2_client: Arc::new(Mutex::new(None)),
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
            timeout: Duration::from_secs(8),
            tag,
            routing: Some(routing),
            client_ip,
            h2_client: Arc::new(Mutex::new(None)),
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
            h2_client: Arc::new(Mutex::new(None)),
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

    async fn dial_transport(&self, host: &str, port: u16) -> Result<BoxStream> {
        if let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) {
            let addr = match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => Address::Ipv4(v4),
                Ok(IpAddr::V6(v6)) => Address::Ipv6(v6),
                Err(_) => Address::Domain(host.to_string()),
            };
            let dest = Destination::new(addr, port);
            let inbound_tag = self.tag.as_deref().unwrap_or("dns");
            let session = SessionContext::new(inbound_tag, dest);
            let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");

            if matches!(picked, "block" | "blackhole") {
                Err(Error::Protocol(format!(
                    "DoH server '{}' blocked by routing rule",
                    self.url
                )))
            } else if matches!(picked, "direct" | "freedom" | "dns") {
                self.dial_direct(host, port, Some(&ctx.hosts)).await
            } else if let Some(outbound) = ctx.outbounds.get(picked) {
                pingora_timeout::timeout(self.timeout, outbound.connect(&session))
                    .await
                    .map_err(|_| {
                        Error::Protocol(format!("DoH outbound '{}' connect timeout", picked))
                    })?
            } else {
                self.dial_direct(host, port, Some(&ctx.hosts)).await
            }
        } else {
            self.dial_direct(host, port, None).await
        }
    }

    async fn get_or_connect_h2(
        &self,
        host: &str,
        port: u16,
    ) -> Result<h2::client::SendRequest<Bytes>> {
        let mut guard = self.h2_client.lock().await;
        if let Some(existing) = guard.as_ref() {
            let candidate = existing.clone();
            if candidate.ready().await.is_ok() {
                return Ok(existing.clone());
            }
            *guard = None;
        }

        let tcp_stream = self.dial_transport(host, port).await?;
        let tls_client = TlsClient::new(host, true, vec![b"h2".to_vec()])?;
        let tls_stream = pingora_timeout::timeout(
            self.timeout,
            tls_client.connect(host, tcp_stream),
        )
        .await
        .map_err(|_| Error::Protocol(format!("DoH TLS handshake timeout with '{}'", host)))??;

        let (send_req, h2_conn) = pingora_timeout::timeout(
            self.timeout,
            h2::client::Builder::new()
                .initial_window_size(65536)
                .initial_connection_window_size(262144)
                .handshake(tls_stream),
        )
        .await
        .map_err(|_| Error::Protocol(format!("DoH H2 handshake timeout with '{}'", host)))?
        .map_err(|e| Error::Protocol(format!("DoH H2 handshake failed with '{}': {}", host, e)))?;

        let slot = self.h2_client.clone();
        tokio::spawn(async move {
            let _ = h2_conn.await;
            let mut g = slot.lock().await;
            *g = None;
        });

        *guard = Some(send_req.clone());
        Ok(send_req)
    }

    async fn send_h2_query(
        &self,
        send_req: h2::client::SendRequest<Bytes>,
        host: &str,
        port: u16,
        path: &str,
        query: &[u8],
    ) -> Result<Vec<u8>> {
        let authority = if port == 443 { host.to_string() } else { format!("{}:{}", host, port) };
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{}{}", authority, path))
            .header(http::header::ACCEPT, "application/dns-message")
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::USER_AGENT, "xray/dns")
            .body(())
            .map_err(|e| Error::Protocol(format!("DoH H2 request build error: {}", e)))?;

        let mut ready = pingora_timeout::timeout(self.timeout, send_req.ready())
            .await
            .map_err(|_| Error::Protocol("DoH H2 ready timeout".into()))?
            .map_err(|e| Error::Protocol(format!("DoH H2 ready error: {}", e)))?;
        let (resp_fut, mut send_stream) = ready
            .send_request(req, false)
            .map_err(|e| Error::Protocol(format!("DoH H2 send_request error: {}", e)))?;
        send_stream
            .send_data(Bytes::copy_from_slice(query), true)
            .map_err(|e| Error::Protocol(format!("DoH H2 send_data error: {}", e)))?;

        let resp = pingora_timeout::timeout(self.timeout, resp_fut)
            .await
            .map_err(|_| Error::Protocol("DoH H2 response timeout".into()))?
            .map_err(|e| Error::Protocol(format!("DoH H2 response error: {}", e)))?;
        let status = resp.status();
        let mut body_stream = resp.into_body();
        let mut out = Vec::with_capacity(512);
        while let Some(chunk_res) = pingora_timeout::timeout(self.timeout, body_stream.data())
            .await
            .map_err(|_| Error::Protocol("DoH H2 body read timeout".into()))?
        {
            let chunk = chunk_res.map_err(|e| Error::Protocol(format!("DoH H2 body chunk error: {}", e)))?;
            let _ = body_stream.flow_control().release_capacity(chunk.len());
            out.extend_from_slice(&chunk);
            if out.len() > 65536 {
                break;
            }
        }

        if status != http::StatusCode::OK {
            return Err(Error::Protocol(format!("DoH server responded with HTTP {}", status.as_u16())));
        }
        if out.is_empty() {
            return Err(Error::Protocol("Invalid or empty DoH H2 response".into()));
        }
        Ok(out)
    }

    async fn execute_doh(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let (is_https, host, port, path) = self.parse_url();
        let clean = domain.trim_end_matches('.');
        if clean.eq_ignore_ascii_case(&host) {
            return Err(Error::Protocol(format!("DoH server '{}' tries to resolve itself", self.url)));
        }

        let query = build_dns_query_with_ecs(clean, 1, self.client_ip);
        if is_https {
            for attempt in 0..2 {
                let send_req = self.get_or_connect_h2(&host, port).await?;
                match self.send_h2_query(send_req, &host, port, &path, &query).await {
                    Ok(body) => return parse_dns_response(&body, clean),
                    Err(e) if attempt == 0 => {
                        *self.h2_client.lock().await = None;
                        tracing::debug!("DoH H2 query failed for '{}' on attempt 0 ({}), retrying on fresh H2 conn", clean, e);
                    }
                    Err(e) => return Err(e),
                }
            }
            return Err(Error::Protocol("DoH H2 retry exhausted".into()));
        }

        let mut stream = self.dial_transport(&host, port).await?;
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray/dns\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host, query.len()
        );
        stream.write_all(req.as_bytes()).await.map_err(Error::Io)?;
        stream.write_all(&query).await.map_err(Error::Io)?;
        stream.flush().await.map_err(Error::Io)?;

        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let (mut header_len, mut content_len, mut is_chunked, mut decoded_chunked) = (0, None, false, None);

        while buf.len() < 65536 {
            let n = pingora_timeout::timeout(self.timeout, stream.read(&mut chunk))
                .await
                .map_err(|_| Error::Protocol(format!("DoH HTTP read timeout (buf_len={}, header_len={}, chunked={})", buf.len(), header_len, is_chunked)))?
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
                        return Err(Error::Protocol(format!("DoH server responded with HTTP {}", code)));
                    }
                    for h in resp.headers.iter() {
                        let Ok(s) = std::str::from_utf8(h.value) else { continue };
                        if h.name.eq_ignore_ascii_case("content-length") {
                            content_len = s.trim().parse::<usize>().ok();
                        } else if h.name.eq_ignore_ascii_case("transfer-encoding")
                            && s.to_ascii_lowercase().contains("chunked")
                        {
                            is_chunked = true;
                        }
                    }
                }
            }

            if header_len > 0 {
                if content_len.is_some_and(|clen| buf.len() >= header_len + clen) {
                    break;
                }
                if content_len.is_none()
                    && is_chunked
                    && let Some(decoded) = decode_chunked_complete(&buf[header_len..])
                {
                    decoded_chunked = Some(decoded);
                    break;
                }
            }
        }

        if header_len == 0 || buf.len() <= header_len {
            return Err(Error::Protocol("Invalid or empty DoH response".into()));
        }
        if let Some(body) = decoded_chunked {
            return parse_dns_response(&body, clean);
        }
        let end = content_len.map_or(buf.len(), |clen| (header_len + clen).min(buf.len()));
        parse_dns_response(&buf[header_len..end], clean)
    }
}

fn decode_chunked_complete(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let rest = input.get(pos..)?;
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).ok()?;
        pos += line_end + 2;
        if chunk_size == 0 {
            let trailer = input.get(pos..)?;
            if trailer.starts_with(b"\r\n")
                || trailer.windows(4).any(|w| w == b"\r\n\r\n")
            {
                return Some(out);
            }
            return None;
        }
        if input.len() < pos + chunk_size + 2 {
            return None;
        }
        out.extend_from_slice(&input[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }
}

#[async_trait]
impl NameServer for DohNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    fn routes_via_proxy(&self) -> bool {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else {
            return false;
        };
        let (_, host, port, _) = self.parse_url();
        let addr = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => Address::Ipv4(v4),
            Ok(IpAddr::V6(v6)) => Address::Ipv6(v6),
            Err(_) => Address::Domain(host),
        };
        let dest = Destination::new(addr, port);
        let inbound_tag = self.tag.as_deref().unwrap_or("dns");
        let session = SessionContext::new(inbound_tag, dest);
        let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
        !matches!(picked, "direct" | "freedom" | "dns" | "block" | "blackhole")
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        match self.execute_doh(domain).await {
            Ok(ips) => Ok(ips),
            Err(e) => {
                tracing::warn!(
                    "DoH query failed for '{}' via '{}': {}",
                    domain,
                    self.url,
                    e
                );
                #[cfg(target_os = "android")]
                {
                    Err(e)
                }
                #[cfg(not(target_os = "android"))]
                {
                    LocalNameServer::new().query_ip(domain).await.map_err(|_| e)
                }
            }
        }
    }
}
