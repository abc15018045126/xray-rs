use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use xray_rs_types::{
    Address, BoxStream, Destination, Error, OutboundHandler, Result, SessionContext,
};

use crate::router::{DomainRule, Router};

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// One server entry from Xray `config.json` -> `"dns.servers"`.
#[derive(Clone)]
pub struct DnsUpstreamConfig {
    pub address: String,
    pub domains: Vec<DomainRule>,
    pub tag: String,
    pub skip_fallback: bool,
}

/// Unified Xray `dns` module configured from `config.json` (`hosts` + `servers`) and routed
/// through the exact same `Router` and `OutboundHandler`s as normal proxy traffic.
pub struct DnsModule {
    pub module_tag: String,
    pub hosts: HashMap<String, Vec<IpAddr>>,
    pub servers: Vec<DnsUpstreamConfig>,
    tls: TlsConnector,
}

impl DnsModule {
    pub fn new(
        module_tag: impl Into<String>,
        hosts: HashMap<String, Vec<IpAddr>>,
        servers: Vec<DnsUpstreamConfig>,
    ) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            module_tag: module_tag.into(),
            hosts,
            servers,
            tls: TlsConnector::from(Arc::new(tls_cfg)),
        }
    }

    /// Resolves a raw DNS wire query using `hosts` first, then `servers` via `router`.
    pub async fn resolve_wire(
        &self,
        query: &[u8],
        router: &Router,
        outbounds: &HashMap<String, Arc<dyn OutboundHandler>>,
        default_outbound: &str,
    ) -> Result<Vec<u8>> {
        let req = Message::from_vec(query)
            .map_err(|e| Error::Protocol(format!("Invalid DNS query packet: {}", e)))?;
        let question = req
            .queries
            .first()
            .ok_or_else(|| Error::Protocol("DNS query has no question".into()))?;
        let qtype = question.query_type;
        let qname = question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if let Some(ips) = self.hosts.get(&qname)
            && let Some(reply) = build_hosts_reply(&req, question, qtype, ips)
        {
            return Ok(reply);
        }

        let matching: Vec<&DnsUpstreamConfig> = self
            .servers
            .iter()
            .filter(|s| !s.domains.is_empty() && s.domains.iter().any(|d| d.matches(&qname)))
            .collect();

        let mut allow_fallback = matching.is_empty();
        for srv in matching {
            match self
                .query_server(srv, query, router, outbounds, default_outbound)
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    debug!("DNS server '{}' ({}) failed for {}: {}", srv.tag, srv.address, qname, e);
                    if !srv.skip_fallback {
                        allow_fallback = true;
                    }
                }
            }
        }

        if allow_fallback {
            for srv in self.servers.iter().filter(|s| s.domains.is_empty()) {
                match self
                    .query_server(srv, query, router, outbounds, default_outbound)
                    .await
                {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        debug!(
                            "Fallback DNS server '{}' ({}) failed for {}: {}",
                            srv.tag, srv.address, qname, e
                        );
                    }
                }
            }
        }

        Err(Error::Protocol(format!("All DNS servers failed for '{}'", qname)))
    }

    async fn query_server(
        &self,
        srv: &DnsUpstreamConfig,
        query: &[u8],
        router: &Router,
        outbounds: &HashMap<String, Arc<dyn OutboundHandler>>,
        default_outbound: &str,
    ) -> Result<Vec<u8>> {
        if let Some(rest) = srv.address.strip_prefix("https://") {
            let (host_port, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/dns-query"),
            };
            let (host, port) = match host_port.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().unwrap_or(443)),
                None => (host_port, 443),
            };
            let targets = self.resolve_doh_targets(host);
            let mut last_err = None;
            for target_addr in targets {
                let dest = Destination::tcp(target_addr, port);
                let session = SessionContext::new(&srv.tag, dest);
                let out_tag = router
                    .pick_outbound(&session)
                    .unwrap_or(default_outbound);
                let Some(outbound) = outbounds.get(out_tag) else {
                    continue;
                };
                match timeout(DNS_QUERY_TIMEOUT, async {
                    let stream = outbound.connect(&session).await?;
                    doh_post(&self.tls, host, path, stream, query).await
                })
                .await
                {
                    Ok(Ok(resp)) => return Ok(resp),
                    Ok(Err(e)) => last_err = Some(e),
                    Err(_) => last_err = Some(Error::Timeout),
                }
            }
            return Err(last_err.unwrap_or(Error::Closed));
        }

        let ip: IpAddr = srv
            .address
            .parse()
            .map_err(|_| Error::Config(format!("Unsupported DNS server '{}'", srv.address)))?;
        let addr = match ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        };
        let session = SessionContext::new(&srv.tag, Destination::tcp(addr, 53));
        let out_tag = router.pick_outbound(&session).unwrap_or(default_outbound);
        let outbound = outbounds
            .get(out_tag)
            .ok_or_else(|| Error::NotFound(format!("Outbound '{}' not found", out_tag)))?;
        timeout(DNS_QUERY_TIMEOUT, async {
            let mut stream = outbound.connect(&session).await?;
            dns_tcp_exchange(&mut stream, query).await.map_err(Error::Io)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    fn resolve_doh_targets(&self, host: &str) -> Vec<Address> {
        if let Some(ips) = self.hosts.get(&host.to_ascii_lowercase())
            && !ips.is_empty()
        {
            return ips
                .iter()
                .map(|ip| match ip {
                    IpAddr::V4(v4) => Address::Ipv4(*v4),
                    IpAddr::V6(v6) => Address::Ipv6(*v6),
                })
                .collect();
        }
        vec![Address::Domain(host.to_string())]
    }
}

pub async fn dns_tcp_exchange(upstream: &mut BoxStream, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let len = u16::try_from(query.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "DNS query too large"))?;
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(query);
    upstream.write_all(&frame).await?;
    upstream.flush().await?;

    let mut len_buf = [0u8; 2];
    upstream.read_exact(&mut len_buf).await?;
    let mut resp = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    upstream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn doh_post(
    tls: &TlsConnector,
    host: &str,
    path: &str,
    stream: BoxStream,
    query: &[u8],
) -> Result<Vec<u8>> {
    let sni = ServerName::try_from(host.to_string())
        .map_err(|e| Error::Protocol(format!("Invalid DoH SNI '{}': {}", host, e)))?;
    let mut tls_stream = tls
        .connect(sni, stream)
        .await
        .map_err(|e| Error::Protocol(format!("DoH TLS handshake failed: {}", e)))?;

    let req_head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        query.len()
    );
    tls_stream.write_all(req_head.as_bytes()).await?;
    tls_stream.write_all(query).await?;
    tls_stream.flush().await?;

    let mut raw = Vec::with_capacity(2048);
    let _ = tls_stream.read_to_end(&mut raw).await;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let split = match resp.parse(&raw) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return Err(Error::Protocol("Malformed DoH HTTP response".into())),
    };
    if resp.code != Some(200) {
        return Err(Error::Protocol(format!("DoH HTTP error: {:?}", resp.code)));
    }
    let is_chunked = resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("chunked")
    });
    let body = &raw[split..];
    if is_chunked {
        decode_chunked(body)
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(crlf) = data.windows(2).position(|w| w == b"\r\n") {
        let size_str = std::str::from_utf8(&data[..crlf])
            .map_err(|_| Error::Protocol("Invalid chunked size".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Error::Protocol("Invalid chunked hex".into()))?;
        data = &data[crlf + 2..];
        if size == 0 || data.len() < size {
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = data.get(size + 2..).unwrap_or(&[]);
    }
    Ok(out)
}

fn build_hosts_reply(
    req: &Message,
    question: &hickory_proto::op::Query,
    qtype: RecordType,
    ips: &[IpAddr],
) -> Option<Vec<u8>> {
    let rdatas: Vec<RData> = ips
        .iter()
        .filter_map(|ip| match (qtype, ip) {
            (RecordType::A, IpAddr::V4(v4)) => Some(RData::A((*v4).into())),
            (RecordType::AAAA, IpAddr::V6(v6)) => Some(RData::AAAA((*v6).into())),
            _ => None,
        })
        .collect();
    if rdatas.is_empty() {
        return None;
    }

    let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.add_query(question.clone());
    for rdata in rdatas {
        resp.add_answer(Record::from_rdata(question.name.clone(), 60, rdata));
    }
    resp.to_vec().ok()
}

/// Async DNS resolver backed by `hickory-resolver` (UDP/TCP/DoT/DoH + caching).
pub struct HickoryDnsResolver {
    resolver: TokioResolver,
}

impl HickoryDnsResolver {
    /// Uses OS system DNS configuration.
    pub fn from_system() -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| Error::Config(format!("Failed to init system DNS resolver: {}", e)))?
            .build()
            .map_err(|e| Error::Config(format!("Failed to build system DNS resolver: {}", e)))?;
        Ok(Self { resolver })
    }

    /// Uses Cloudflare DNS-over-HTTPS (`1.1.1.1`).
    pub fn cloudflare_doh() -> Result<Self> {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::https(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| Error::Config(format!("Failed to build DoH DNS resolver: {}", e)))?;
        Ok(Self { resolver })
    }

    /// Resolves a domain name to a list of IP addresses.
    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>> {
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::Protocol(format!("DNS lookup failed for '{}': {}", host, e)))?;
        Ok(lookup.iter().collect())
    }
}
