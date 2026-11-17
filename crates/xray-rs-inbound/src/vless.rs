use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use xray_rs_types::{
    Address, BoxStream, Destination, Error, InboundHandler, InboundResult, Network, Result,
    SessionContext,
};

/// VLESS server inbound handler.
pub struct VlessInbound {
    tag: String,
    allowed_users: HashSet<Uuid>,
}

impl VlessInbound {
    pub fn new(tag: impl Into<String>, users: Vec<Uuid>) -> Self {
        Self {
            tag: tag.into(),
            allowed_users: users.into_iter().collect(),
        }
    }
}

#[async_trait]
impl InboundHandler for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle_connection(
        &self,
        mut stream: BoxStream,
        remote_addr: SocketAddr,
    ) -> Result<InboundResult> {
        let ver = stream.read_u8().await?;
        if ver != 0 {
            return Err(Error::Protocol(format!("Unsupported VLESS version: {}", ver)));
        }

        let mut id_bytes = [0u8; 16];
        stream.read_exact(&mut id_bytes).await?;
        let user_id = Uuid::from_bytes(id_bytes);
        if !self.allowed_users.is_empty() && !self.allowed_users.contains(&user_id) {
            return Err(Error::Protocol("Unauthorized VLESS user".into()));
        }

        let addons_len = stream.read_u8().await? as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await?;
        }

        let cmd = stream.read_u8().await?;
        let network = match cmd {
            0x01 => Network::Tcp,
            0x02 => Network::Udp,
            _ => return Err(Error::Protocol(format!("Unsupported VLESS command: {}", cmd))),
        };

        let port = stream.read_u16().await?;
        let atyp = stream.read_u8().await?;
        let address = match atyp {
            1 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                Address::Ipv4(Ipv4Addr::from(ip))
            }
            2 => {
                let len = stream.read_u8().await? as usize;
                let mut d = vec![0u8; len];
                stream.read_exact(&mut d).await?;
                let s = String::from_utf8(d)
                    .map_err(|e| Error::Protocol(format!("Invalid VLESS domain: {}", e)))?;
                Address::Domain(s)
            }
            3 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                Address::Ipv6(Ipv6Addr::from(ip))
            }
            _ => return Err(Error::Protocol(format!("Unsupported VLESS ATYP: {}", atyp))),
        };

        // Send VLESS response header: [version=0, addons_len=0]
        stream.write_all(&[0u8, 0u8]).await?;
        stream.flush().await?;

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
