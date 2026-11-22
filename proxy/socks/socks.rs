pub const PROTOCOL_NAME: &str = "socks";
pub const VERSION_5: u8 = 0x05;
pub const VERSION_4: u8 = 0x04;

use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::features::inbound::{InboundHandler, InboundResult};
use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Server {
    tag: String,
}

impl Server {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl InboundHandler for Server {
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

        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Err(Error::Protocol(format!("Invalid SOCKS5 version in request: {}", hdr[0])));
        }

        let address = match hdr[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                Address::Ipv4(Ipv4Addr::from(ip))
            }
            0x03 => {
                let len = stream.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                Address::Domain(String::from_utf8(buf).map_err(|e| Error::Protocol(format!("Invalid domain string: {}", e)))?)
            }
            0x04 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                Address::Ipv6(Ipv6Addr::from(ip))
            }
            atyp => return Err(Error::Protocol(format!("Unsupported SOCKS5 ATYP: {}", atyp))),
        };

        let port = stream.read_u16().await?;
        let network = match hdr[1] {
            0x01 => Network::Tcp,
            0x03 => Network::Udp,
            cmd => return Err(Error::Protocol(format!("Unsupported SOCKS5 command: {}", cmd))),
        };

        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        stream.flush().await?;

        let mut session = SessionContext::new(&self.tag, Destination { network, address, port });
        session.source = Some(remote_addr);
        Ok(InboundResult { stream, session })
    }
}
