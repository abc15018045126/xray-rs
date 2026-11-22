use super::config::HttpUpgradeConfig;
use super::connection::HttpUpgradeConnection;
use super::httpupgrade::HttpUpgradeStream;
use crate::common::errors::Result;
use crate::transport::internet::tcp::TcpHub;
use std::net::SocketAddr;

pub struct HttpUpgradeHub {
    tcp_hub: TcpHub,
    config: HttpUpgradeConfig,
}

impl HttpUpgradeHub {
    pub async fn listen(addr: SocketAddr, config: HttpUpgradeConfig) -> Result<Self> {
        let tcp_hub = TcpHub::listen(addr).await?;
        Ok(Self { tcp_hub, config })
    }
    pub fn local_addr(&self) -> SocketAddr { self.tcp_hub.local_addr() }
    pub async fn accept(&self) -> Result<HttpUpgradeConnection> {
        let (raw, addr) = self.tcp_hub.accept().await?;
        let host = (!self.config.host.is_empty()).then_some(self.config.host.as_str());
        let path = self.config.get_normalized_path();
        let s = HttpUpgradeStream::server_handshake(raw, host, Some(path.as_str())).await?;
        Ok(HttpUpgradeConnection::new(s, addr.to_string()))
    }
}
