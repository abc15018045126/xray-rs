use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use xray_rs_types::{
    Address, BoxStream, Destination, Error, InboundHandler, InboundResult, Network, Result,
    SessionContext,
};

/// SOCKS5 inbound handler (no-auth).
pub struct SocksInbound {
    tag: String,
}

impl SocksInbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl InboundHandler for SocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        mut stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let ver = stream.read_u8().await?;
        if ver != 0x05 {
            return Err(Error::Protocol(format!("Unsupported SOCKS version: {}", ver)));
        }

        let nmethods = stream.read_u8().await? as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        stream.write_all(&[0x05, 0x00]).await?;
        stream.flush().await?;

        let ver = stream.read_u8().await?;
        if ver != 0x05 {
            return Err(Error::Protocol(format!(
                "Invalid SOCKS5 request version: {}",
                ver
            )));
        }

        let cmd = stream.read_u8().await?;
        let _rsv = stream.read_u8().await?;
        let atyp = stream.read_u8().await?;

        let address = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                Address::Ipv4(Ipv4Addr::from(ip))
            }
            0x03 => {
                let len = stream.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let s = String::from_utf8(domain)
                    .map_err(|e| Error::Protocol(format!("Invalid domain: {}", e)))?;
                Address::Domain(s)
            }
            0x04 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                Address::Ipv6(Ipv6Addr::from(ip))
            }
            _ => return Err(Error::Protocol(format!("Unsupported SOCKS5 ATYP: {}", atyp))),
        };

        let port = stream.read_u16().await?;
        let network = match cmd {
            0x01 => Network::Tcp,
            0x03 => Network::Udp,
            _ => return Err(Error::Protocol(format!("Unsupported SOCKS5 CMD: {}", cmd))),
        };

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        stream.flush().await?;

        let destination = Destination {
            network,
            address,
            port,
        };
        let mut session = SessionContext::new(&self.tag, destination);
        session.source = Some(remote_addr);

        Ok(InboundResult { stream, session })
    }
}
