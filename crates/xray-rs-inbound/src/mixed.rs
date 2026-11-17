use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use xray_rs_types::{BoxStream, Error, InboundHandler, InboundResult, Result};

use crate::http::{PingoraHttpInbound, PrefixedStream};
use crate::socks::SocksInbound;

/// Mixed HTTP + SOCKS5 inbound handler sharing a single listening port.
pub struct MixedInbound {
    tag: String,
    socks: SocksInbound,
    http: PingoraHttpInbound,
}

impl MixedInbound {
    pub fn new(tag: impl Into<String>) -> Self {
        let tag_str = tag.into();
        Self {
            socks: SocksInbound::new(&tag_str),
            http: PingoraHttpInbound::new(&tag_str),
            tag: tag_str,
        }
    }
}

#[async_trait]
impl InboundHandler for MixedInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        mut stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let first_byte = stream.read_u8().await?;
        let prepended: BoxStream = Box::pin(PrefixedStream::new(vec![first_byte], stream));

        if first_byte == 0x04 || first_byte == 0x05 {
            self.socks.handle_connection(prepended, remote_addr).await
        } else if first_byte.is_ascii_alphabetic() || first_byte == b'/' {
            self.http.handle_connection(prepended, remote_addr).await
        } else {
            Err(Error::Protocol(format!(
                "Unsupported first byte on mixed inbound: {}",
                first_byte
            )))
        }
    }
}
