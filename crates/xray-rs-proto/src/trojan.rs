use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use xray_rs_types::{Address, Destination, Network, Result};

/// Computes the 56-byte lowercase hex SHA-224 digest of a Trojan password.
pub fn trojan_password_hash(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Trojan outbound request header:
/// `[56-byte hex SHA224(password)] \r\n [cmd:1] [atyp+addr+port] \r\n`
#[derive(Debug, Clone)]
pub struct TrojanRequestHeader {
    pub password_hash: String,
    pub destination: Destination,
}

impl TrojanRequestHeader {
    pub fn new(password: &str, destination: Destination) -> Self {
        Self {
            password_hash: trojan_password_hash(password),
            destination,
        }
    }

    pub fn encode_to(&self, out: &mut BytesMut) {
        out.put_slice(self.password_hash.as_bytes());
        out.put_slice(b"\r\n");

        let cmd = match self.destination.network {
            Network::Tcp => 0x01u8,
            Network::Udp => 0x03u8,
        };
        out.put_u8(cmd);

        match &self.destination.address {
            Address::Ipv4(ip) => {
                out.put_u8(0x01);
                out.put_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                let d = domain.as_bytes();
                out.put_u8(0x03);
                out.put_u8(d.len() as u8);
                out.put_slice(d);
            }
            Address::Ipv6(ip) => {
                out.put_u8(0x04);
                out.put_slice(&ip.octets());
            }
        }

        out.put_u16(self.destination.port);
        out.put_slice(b"\r\n");
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut buf = BytesMut::with_capacity(128);
        self.encode_to(&mut buf);
        writer.write_all(&buf).await?;
        Ok(())
    }
}
