use super::config::{BlackholeConfig, ResponseType};
use crate::common::errors::Result;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub struct BlackholeHandler {
    config: BlackholeConfig,
}

impl BlackholeHandler {
    pub fn new(config: BlackholeConfig) -> Self {
        Self { config }
    }

    pub async fn handle<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<()> {
        match self.config.response {
            ResponseType::None => Ok(()),
            ResponseType::Http403 => {
                writer
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    .await?;
                writer.flush().await?;
                Ok(())
            }
            ResponseType::Http500 => {
                writer
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n")
                    .await?;
                writer.flush().await?;
                Ok(())
            }
        }
    }
}

use crate::common::net::BoxStream;
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use async_trait::async_trait;

pub struct Handler {
    tag: String,
    response: ResponseType,
}

impl Handler {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            response: ResponseType::None,
        }
    }

    pub fn with_response(tag: impl Into<String>, response: ResponseType) -> Self {
        Self {
            tag: tag.into(),
            response,
        }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _session: &SessionContext) -> Result<BoxStream> {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let msg: Option<&'static [u8]> = match self.response {
            ResponseType::Http403 => Some(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"),
            ResponseType::Http500 => Some(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n"),
            ResponseType::None => None,
        };
        if let Some(bytes) = msg {
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = client_stream.write_all(bytes).await;
                let _ = client_stream.flush().await;
            });
        }
        Ok(Box::pin(server_stream))
    }
}
