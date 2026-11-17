use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::Result;
use crate::net::BoxStream;
use crate::session::SessionContext;

/// Result produced by an inbound handler after protocol handshake.
pub struct InboundResult {
    pub stream: BoxStream,
    pub session: SessionContext,
}

/// Inbound proxy handler (HTTP, SOCKS5, Mixed, TUN).
#[async_trait]
pub trait InboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn handle_connection(
        &self,
        stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult>;
}

/// Outbound proxy handler (Freedom, Blackhole, VLESS, Trojan, Pooled).
#[async_trait]
pub trait OutboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream>;
    /// `true` for Xray's `dns` outbound: UDP DNS datagrams are relayed as DNS-over-TCP (RFC 7766).
    fn is_dns(&self) -> bool {
        false
    }
}
