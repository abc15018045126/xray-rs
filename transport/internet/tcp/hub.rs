use std::net::SocketAddr;

use crate::common::errors::Result;
use crate::common::net::BoxStream;
use crate::transport::internet::sockopt::SocketOptions;
use crate::transport::internet::system_listener::SystemListener;

pub struct TcpHub {
    listener: SystemListener,
    local_addr: SocketAddr,
}

impl TcpHub {
    pub async fn listen(addr: SocketAddr) -> Result<Self> {
        Self::listen_with_sockopt(addr, None).await
    }

    pub async fn listen_with_sockopt(
        addr: SocketAddr,
        sockopt: Option<&SocketOptions>,
    ) -> Result<Self> {
        let default_opts = SocketOptions::new();
        let listener =
            SystemListener::listen_tcp(addr, Some(sockopt.unwrap_or(&default_opts))).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn accept(&self) -> Result<(BoxStream, SocketAddr)> {
        let (stream, remote_addr) = self.listener.accept().await?;
        let _ = stream.set_nodelay(true);
        Ok((Box::pin(stream), remote_addr))
    }
}
