use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use xray_rs_types::{Address, BoxStream, Destination, Error, OutboundHandler, Result, SessionContext};

use crate::relay::copy_bidirectional_with_timeout;
use crate::router::Router;
use crate::sniffer::{sniff_http_host, sniff_tls_sni};

/// Minimal dataflow dispatcher connecting Inbound -> Sniffer -> Router -> Outbound.
pub struct Dispatcher {
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    router: Router,
    default_outbound: String,
    idle_timeout: Duration,
    sniffing_enabled: bool,
}

impl Dispatcher {
    pub fn new(default_outbound: impl Into<String>) -> Self {
        Self {
            outbounds: HashMap::new(),
            router: Router::default(),
            default_outbound: default_outbound.into(),
            idle_timeout: Duration::from_secs(300),
            sniffing_enabled: false,
        }
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
