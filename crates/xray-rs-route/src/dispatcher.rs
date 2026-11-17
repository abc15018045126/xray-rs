use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use xray_rs_types::{
    Address, BoxStream, Destination, Error, Network, OutboundHandler, Result, SessionContext,
};

use crate::dns::{DnsModule, dns_tcp_exchange};
use crate::relay::copy_bidirectional_with_timeout;
use crate::router::Router;
use crate::sniffer::{sniff_http_host, sniff_tls_sni};

const DNS_HEADER_LEN: usize = 12;
const DNS_FLOW_IDLE: Duration = Duration::from_secs(30);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimal dataflow dispatcher connecting Inbound -> Sniffer -> Router -> Outbound.
pub struct Dispatcher {
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    router: Router,
    default_outbound: String,
    idle_timeout: Duration,
    sniffing_enabled: bool,
    stats_cb: Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
    dns_module: Option<Arc<DnsModule>>,
}

impl Dispatcher {
    pub fn new(default_outbound: impl Into<String>) -> Self {
        Self {
            outbounds: HashMap::new(),
            router: Router::default(),
            default_outbound: default_outbound.into(),
            idle_timeout: Duration::from_secs(300),
            sniffing_enabled: false,
            stats_cb: None,
            dns_module: None,
        }
    }

    pub fn with_dns_module(mut self, dns: Arc<DnsModule>) -> Self {
        self.dns_module = Some(dns);
        self
    }

    async fn relay_dns_datagrams(
        &self,
        mut inbound: BoxStream,
        outbound: Arc<dyn OutboundHandler>,
        session: &SessionContext,
        first_datagram: Vec<u8>,
    ) -> Result<()> {
        let mut upstream: Option<BoxStream> = None;
        let mut pending = (!first_datagram.is_empty()).then_some(first_datagram);
        let mut buf = vec![0u8; usize::from(u16::MAX)];

        loop {
            let query = match pending.take() {
                Some(q) => q,
                None => match timeout(DNS_FLOW_IDLE, inbound.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => buf[..n].to_vec(),
                    Ok(Err(e)) => {
                        debug!("DNS flow {} read error: {}", session.destination, e);
                        break;
                    }
                },
            };
            if query.len() < DNS_HEADER_LEN {
                continue;
            }

            if let Some(dns) = self.dns_module.as_deref() {
                match dns
                    .resolve_wire(&query, &self.router, &self.outbounds, &self.default_outbound)
                    .await
                {
                    Ok(resp) => {
                        inbound.write_all(&resp).await?;
                    }
                    Err(e) => {
                        debug!("Unified DNS module failed for {}: {}", session.destination, e);
                    }
                }
                continue;
            }

            let mut answered = false;
            for _ in 0..2 {
                if upstream.is_none() {
                    match outbound.connect(session).await {
                        Ok(s) => upstream = Some(s),
                        Err(e) => {
                            warn!("DNS upstream connect failed: {}", e);
                            break;
                        }
                    }
                }
                let Some(up) = upstream.as_mut() else {
                    break;
                };
                match timeout(DNS_QUERY_TIMEOUT, dns_tcp_exchange(up, &query)).await {
                    Ok(Ok(resp)) => {
                        inbound.write_all(&resp).await?;
                        answered = true;
                        break;
                    }
                    Ok(Err(e)) => {
                        debug!("DNS upstream exchange failed, reconnecting: {}", e);
                        upstream = None;
                    }
                    Err(_) => {
                        debug!("DNS upstream exchange timed out, reconnecting");
                        upstream = None;
                    }
                }
            }
            if !answered {
                debug!("DNS query to {} left unanswered", session.destination);
            }
        }
        Ok(())
    }

    pub fn with_router(mut self, router: Router) -> Self {
        self.router = router;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    pub fn with_sniffing(mut self, enabled: bool) -> Self {
        self.sniffing_enabled = enabled;
        self
    }

    pub fn with_stats_callback(mut self, cb: Arc<dyn Fn(u64, u64) + Send + Sync>) -> Self {
        self.stats_cb = Some(cb);
        self
    }

    pub fn register_outbound(&mut self, handler: Arc<dyn OutboundHandler>) {
        self.outbounds.insert(handler.tag().to_string(), handler);
    }

    pub async fn dispatch(
        &self,
        mut inbound_stream: BoxStream,
        mut session: SessionContext,
    ) -> Result<()> {
        let mut initial_payload = Vec::new();
        if self.sniffing_enabled && session.sniffed_domain.is_none() {
            let mut buf = [0u8; 2048];
            if let Ok(Ok(n)) =
                timeout(Duration::from_millis(200), inbound_stream.read(&mut buf)).await
                && n > 0
            {
                initial_payload.extend_from_slice(&buf[..n]);
                if let Some(sni) = sniff_tls_sni(&initial_payload) {
                    session.sniffed_protocol = Some("tls".into());
                    session.sniffed_domain = Some(sni.clone());
                    session.destination =
                        Destination::tcp(Address::Domain(sni), session.destination.port);
                } else if let Some(host) = sniff_http_host(&initial_payload) {
                    session.sniffed_protocol = Some("http".into());
                    session.sniffed_domain = Some(host.clone());
                    session.destination =
                        Destination::tcp(Address::Domain(host), session.destination.port);
                }
            }
        }

        let tag = session
            .outbound_tag
            .clone()
            .or_else(|| self.router.pick_outbound(&session).map(str::to_string))
            .unwrap_or_else(|| self.default_outbound.clone());
        session.outbound_tag = Some(tag.clone());

        let outbound = self
            .outbounds
            .get(&tag)
            .ok_or_else(|| Error::NotFound(format!("Outbound '{}' not found", tag)))?
            .clone();

        info!("Dispatching {} via '{}'", session.destination, tag);

        if outbound.is_dns() && session.destination.network == Network::Udp {
            return self
                .relay_dns_datagrams(inbound_stream, outbound, &session, initial_payload)
                .await;
        }

        let mut outbound_stream = outbound.connect(&session).await?;

        if !initial_payload.is_empty() {
            outbound_stream.write_all(&initial_payload).await?;
        }

        match copy_bidirectional_with_timeout(
            &mut inbound_stream,
            &mut outbound_stream,
            self.idle_timeout,
        )
        .await
        {
            Ok((up, down)) => {
                if let Some(cb) = &self.stats_cb {
                    cb(up, down);
                }
                debug!(
                    "Session {} closed: up={} down={}",
                    session.destination, up, down
                );
            }
            Err(e) => {
                warn!("Session {} relay ended: {}", session.destination, e);
            }
        }

        Ok(())
    }
}
