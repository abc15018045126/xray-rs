use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::config::WireGuardConfig;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;

pub struct Client {
    tag: String,
    config: WireGuardConfig,
}

impl Client {
    pub fn new(tag: impl Into<String>, config: WireGuardConfig) -> Self {
        Self {
            tag: tag.into(),
            config,
        }
    }

    pub fn config(&self) -> &WireGuardConfig {
        &self.config
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _session: &SessionContext) -> Result<BoxStream> {
        let peer = self.config.peers.first().ok_or_else(|| Error::Config("No WireGuard peers defined".into()))?;
        let endpoint: SocketAddr = peer
            .endpoint
            .parse()
            .map_err(|e| Error::AddressParse(format!("Invalid WireGuard peer endpoint {}: {}", peer.endpoint, e)))?;

        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(endpoint).await?;
        let (client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);

        tokio::spawn(async move {
            let (mut s_buf, mut u_buf) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
            loop {
                tokio::select! {
                    res = server_stream.read(&mut s_buf) => match res {
                        Ok(n) if n > 0 && socket.send(&s_buf[..n]).await.is_ok() => {}
                        _ => break,
                    },
                    res = socket.recv(&mut u_buf) => match res {
                        Ok(n) if server_stream.write_all(&u_buf[..n]).await.is_ok() => {}
                        _ => break,
                    },
                }
            }
        });

        Ok(Box::pin(client_stream))
    }
}
