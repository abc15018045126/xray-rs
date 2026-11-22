use async_trait::async_trait;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::proxy::shadowsocks_2022::config::Shadowsocks2022Config;
use crate::proxy::shadowsocks_2022::protocol::{HEADER_TYPE_SERVER, SessionHeader};
use crate::transport::internet::TcpDialer;

pub struct Client {
    pub tag: String,
    pub server_addr: Destination,
    pub config: Shadowsocks2022Config,
}

impl Client {
    pub fn new(tag: impl Into<String>, server_addr: Destination, config: Shadowsocks2022Config) -> Self {
        Self {
            tag: tag.into(),
            server_addr,
            config,
        }
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut stream = TcpDialer::dial(&self.server_addr).await?;
        let req = SessionHeader::new_client(session.destination.clone());
        let expected_id = req.session_id;
        req.encode(&mut stream).await?;
        let resp = SessionHeader::decode(&mut stream).await?;
        if resp.header_type != HEADER_TYPE_SERVER {
            return Err(Error::Protocol(format!("Invalid server header type: expected {}, got {}", HEADER_TYPE_SERVER, resp.header_type)));
        }
        if resp.session_id != expected_id {
            return Err(Error::Protocol(format!("Session ID mismatch: expected {}, got {}", expected_id, resp.session_id)));
        }
        Ok(stream)
    }
}
