use std::net::SocketAddr;

use async_trait::async_trait;

use xray_rs_types::{
    Address, BoxStream, Destination, InboundHandler, InboundResult, Result, SessionContext,
};

/// Loopback inbound handler that re-injects traffic back into the router with a configured tag.
pub struct LoopbackInbound {
    tag: String,
}

impl LoopbackInbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl InboundHandler for LoopbackInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let dest = Destination::tcp(Address::Domain("localhost".into()), 0);
        let mut session = SessionContext::new(&self.tag, dest);
        session.source = Some(remote_addr);
        Ok(InboundResult { stream, session })
    }
}
