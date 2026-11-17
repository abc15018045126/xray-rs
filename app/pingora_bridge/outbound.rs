use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;

use super::pool::{PingoraStreamPool, PingoraUpstreamBalancer, pool_key};

/// Outbound wrapper backed by Cloudflare `pingora-pool` and optional `pingora-load-balancing`.
/// Reuses pre-warmed streams when available and delegates fresh dials to the inner `OutboundHandler`s.
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

    /// Returns a handle to the underlying Pingora stream pool (for pre-warming or returning clean streams).
    pub fn pool(&self) -> &Arc<PingoraStreamPool> {
        &self.pool
    }

    fn pick_upstream_index(&self) -> usize {
        if self.upstreams.len() <= 1 {
            return 0;
        }
        if let Some(lb) = &self.balancer
            && let Some(backend) = lb.select()
        {
            let addr_str = backend.addr.to_string();
            for (idx, h) in self.upstreams.iter().enumerate() {
                if h.tag().contains(&addr_str) {
                    return idx;
                }
            }
        }
        0
    }
}

#[async_trait]
impl OutboundHandler for PingoraPooledOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let key = pool_key(&format!("{}:{}", self.tag, session.destination));
        if let Some(reused) = self.pool.get(key) {
            return Ok(reused);
        }

        if self.upstreams.is_empty() {
            return Err(Error::NotFound(format!(
                "PingoraPooledOutbound '{}' has no upstreams",
                self.tag
            )));
        }

        let start = self.pick_upstream_index();
        let mut last_err = None;
        for offset in 0..self.upstreams.len() {
            let idx = (start + offset) % self.upstreams.len();
            match self.upstreams[idx].connect(session).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| Error::Closed))
    }
}
