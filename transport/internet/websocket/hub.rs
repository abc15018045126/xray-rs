use super::ws::WebSocketStream;
use crate::common::errors::Result;
use crate::common::net::BoxStream;
use crate::transport::internet::tcp::TcpHub;
use std::net::SocketAddr;

pub struct WebSocketHub {
    tcp_hub: TcpHub,
    path: Option<String>,
    host: Option<String>,
}

impl WebSocketHub {
    pub async fn listen(addr: SocketAddr) -> Result<Self> { Self::listen_with_config(addr, None, None).await }
    pub async fn listen_with_config(addr: SocketAddr, path: Option<String>, host: Option<String>) -> Result<Self> {
        let tcp_hub = TcpHub::listen(addr).await?;
        Ok(Self {
            tcp_hub,
            path,
            host,
        })
    }
    pub fn local_addr(&self) -> SocketAddr { self.tcp_hub.local_addr() }
    pub async fn accept(&self) -> Result<(BoxStream, SocketAddr)> {
        let (raw_stream, remote_addr) = self.tcp_hub.accept().await?;
        let ws_stream = WebSocketStream::server_handshake_with_config(
            raw_stream,
            self.path.as_deref(),
            self.host.as_deref(),
        )
        .await?;
        Ok((ws_stream, remote_addr))
    }
}
