use std::net::SocketAddr;

use async_trait::async_trait;

use xray_rs_types::{
    BoxStream, Destination, InboundHandler, InboundResult, Result, SessionContext,
};

/// Dokodemo-door inbound handler forwarding all connections to a fixed destination.
pub struct DokodemoInbound {
    tag: String,
    target: Destination,
}

impl DokodemoInbound {
    pub fn new(tag: impl Into<String>, target: Destination) -> Self {
        Self {
            tag: tag.into(),
            target,
        }
    }
}

#[async_trait]
impl InboundHandler for DokodemoInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let mut session = SessionContext::new(&self.tag, self.target.clone());
        session.source = Some(remote_addr);
        Ok(InboundResult { stream, session })
    }
}
