use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use xray_rs_proto::trojan_password_hash;
use xray_rs_types::{
    Address, BoxStream, Destination, Error, InboundHandler, InboundResult, Network, Result,
    SessionContext,
};

/// Trojan server inbound handler.
pub struct TrojanInbound {
    tag: String,
    allowed_hashes: HashSet<String>,
}

impl TrojanInbound {
    pub fn new(tag: impl Into<String>, passwords: &[String]) -> Self {
        Self {
            tag: tag.into(),
            allowed_hashes: passwords
                .iter()
                .map(|p| trojan_password_hash(p))
                .collect(),
        }
    }
}

#[async_trait]
impl InboundHandler for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        mut stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let mut hash_bytes = [0u8; 56];
        stream.read_exact(&mut hash_bytes).await?;
        let hash_str = std::str::from_utf8(&hash_bytes)
            .map_err(|_| Error::Protocol("Invalid Trojan password hash".into()))?;
        if !self.allowed_hashes.is_empty() && !self.allowed_hashes.contains(hash_str) {
            return Err(Error::Protocol("Unauthorized Trojan password".into()));
        }

        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(Error::Protocol("Missing CRLF after Trojan hash".into()));
        }

        let cmd = stream.read_u8().await?;
        let network = match cmd {
            0x01 => Network::Tcp,
            0x03 => Network::Udp,
            _ => return Err(Error::Protocol(format!("Unsupported Trojan cmd: {}", cmd))),
        };

        let atyp = stream.read_u8().await?;
        let address = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                Address::Ipv4(Ipv4Addr::from(ip))
            }
            0x03 => {
                let len = stream.read_u8().await? as usize;
                let mut d = vec![0u8; len];
                stream.read_exact(&mut d).await?;
                let s = String::from_utf8(d)
                    .map_err(|e| Error::Protocol(format!("Invalid Trojan domain: {}", e)))?;
                Address::Domain(s)
            }
            0x04 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                Address::Ipv6(Ipv6Addr::from(ip))
            }
            _ => return Err(Error::Protocol(format!("Unsupported Trojan ATYP: {}", atyp))),
        };

        let port = stream.read_u16().await?;
        stream.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(Error::Protocol("Missing CRLF after Trojan request".into()));
        }

        let dest = Destination {
            network,
            address,
            port,
        };
        let mut session = SessionContext::new(&self.tag, dest);
        session.source = Some(remote_addr);
        Ok(InboundResult { stream, session })
    }
}
