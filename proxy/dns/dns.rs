use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use pingora_timeout::timeout;

use crate::app::dns::DnsClient;
use crate::common::errors::Result;
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::features::dns::IPOption;
use crate::features::outbound::OutboundHandler;

const DNS_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct DefaultDnsHandler {
    pub tag: String,
}

impl DefaultDnsHandler {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[derive(Clone)]
pub struct DnsOutbound {
    pub tag: String,
    dns_client: Arc<DnsClient>,
}

impl DnsOutbound {
    pub fn new(tag: String, dns_client: Arc<DnsClient>) -> Self {
        Self { tag, dns_client }
    }

    async fn handle_dns_message(&self, raw_query: &[u8]) -> Option<Vec<u8>> {
        let req = Message::from_vec(raw_query).ok()?;
        let q = req.queries.first()?.clone();
        let domain = q.name().to_utf8();
        let clean = domain.trim_end_matches('.');
        if clean.is_empty() {
            return None;
        }

        let mut resp = Message::response(req.metadata.id, OpCode::Query);
        resp.metadata.authoritative = true;
        resp.metadata.recursion_desired = true;
        resp.metadata.recursion_available = true;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.queries.push(q.clone());

        match q.query_type() {
            RecordType::A => {
                let opt = IPOption { ipv4_enable: true, ipv6_enable: false, fake_enable: true };
                match self.dns_client.lookup_ip_with_option(clean, opt).await {
                    Ok((ips, ttl)) => {
                        let ttl = ttl.max(1);
                        for ip in ips {
                            if let IpAddr::V4(v4) = ip {
                                resp.answers.push(Record::from_rdata(q.name().clone(), ttl, RData::A(A(v4))));
                            }
                        }
                        tracing::info!("DNS-OUT A '{}' -> {} answers", clean, resp.answers.len());
                    }
                    Err(e) => {
                        tracing::warn!("DNS-OUT A '{}' failed: {}", clean, e);
                        resp.metadata.response_code = ResponseCode::ServFail;
                    }
                }
            }
            RecordType::AAAA => {
                for ip in self.dns_client.lookup_hosts_or_cache_ipv6(clean) {
                    if let IpAddr::V6(v6) = ip {
                        resp.answers.push(Record::from_rdata(q.name().clone(), 300, RData::AAAA(AAAA(v6))));
                    }
                }
            }
            _ => {}
        }

        resp.to_vec().ok()
    }

    pub async fn process<S>(&self, mut stream: S, dest: Destination) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let is_tcp = dest.network == Network::Tcp;
        let mut buf = vec![0u8; 4096];

        loop {
            let query_bytes: Vec<u8> = if is_tcp {
                let mut len_buf = [0u8; 2];
                match timeout(DNS_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
                    Ok(Ok(_)) => {
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        if msg_len == 0 || msg_len > 65535 {
                            break;
                        }
                        let mut msg = vec![0u8; msg_len];
                        match timeout(DNS_IDLE_TIMEOUT, stream.read_exact(&mut msg)).await {
                            Ok(Ok(_)) => msg,
                            _ => break,
                        }
                    }
                    _ => break,
                }
            } else {
                match timeout(DNS_IDLE_TIMEOUT, stream.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => buf[..n].to_vec(),
                    Ok(Err(_)) => break,
                }
            };

            #[cfg(debug_assertions)]
            let _dt0 = std::time::Instant::now();
            let resp_opt = self.handle_dns_message(&query_bytes).await;
            #[cfg(debug_assertions)]
            crate::debug_panel::record_stage("DNS 解析 (proxy/dns)", _dt0.elapsed());
            if let Some(resp_bytes) = resp_opt {
                if is_tcp {
                    let len_prefix = (resp_bytes.len() as u16).to_be_bytes();
                    if stream.write_all(&len_prefix).await.is_err() {
                        break;
                    }
                }
                if stream.write_all(&resp_bytes).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl OutboundHandler for DnsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let handler = self.clone();
        let dest = session.destination.clone();
        tokio::spawn(async move {
            if let Err(e) = handler.process(server_io, dest).await {
                tracing::debug!("DNS outbound process ended: {}", e);
            }
        });
        Ok(Box::pin(client_io))
    }
}
