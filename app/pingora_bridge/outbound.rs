use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use super::pool::{PingoraStreamPool, PingoraUpstreamBalancer, pool_key};

pub struct PingoraPooledOutbound {
    tag: String,
    pool: Arc<PingoraStreamPool>,
    upstreams: Vec<Arc<dyn OutboundHandler>>,
    balancer: Option<Arc<PingoraUpstreamBalancer>>,
}

impl PingoraPooledOutbound {
    pub fn new(
        tag: impl Into<String>,
        upstreams: Vec<Arc<dyn OutboundHandler>>,
        balancer: Option<Arc<PingoraUpstreamBalancer>>,
        pool_capacity: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            tag: tag.into(),
            pool: Arc::new(PingoraStreamPool::new(pool_capacity, idle_timeout)),
            upstreams,
            balancer,
        }
    }
    pub fn pool(&self) -> &Arc<PingoraStreamPool> { &self.pool }
    fn pick_upstream_index(&self, key: &[u8]) -> usize {
        if self.upstreams.len() <= 1 { return 0; }
        if let Some(lb) = &self.balancer && let Some(idx) = lb.select_index_for_key(key) && idx < self.upstreams.len()
        { return idx; }
        0
    }
}

#[async_trait]
impl OutboundHandler for PingoraPooledOutbound {
    fn tag(&self) -> &str { &self.tag }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let key = pool_key(&format!("{}:{}", self.tag, session.destination));
        if let Some(reused) = self.pool.get(key) {
            #[cfg(debug_assertions)]
            crate::debug_panel::metrics().record_pool_reuse(&session.destination.address.to_string(), &self.tag);
            return Ok(reused);
        }
        if self.upstreams.is_empty() {
            return Err(Error::NotFound(format!("PingoraPooledOutbound '{}' has no upstreams", self.tag)));
        }
        let target_key = session.sniffed_domain.clone().unwrap_or_else(|| session.destination.address.to_string());
        let start = self.pick_upstream_index(target_key.as_bytes());
        let mut last_err = None;
        for offset in 0..self.upstreams.len() {
            match self.upstreams[(start + offset) % self.upstreams.len()].connect(session).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(Error::Closed))
    }
}
