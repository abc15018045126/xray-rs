use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use crate::common::protocol::RequestCommand;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CRLF: &[u8; 2] = b"\r\n";

pub type RequestHeader = TrojanRequestHeader;

pub fn hash_password(password: &str) -> [u8; 56] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let hex_str = hex::encode(hash);
    let mut out = [0u8; 56];
    out.copy_from_slice(hex_str.as_bytes());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanRequestHeader {
    pub password_hash: [u8; 56],
    pub command: RequestCommand,
    pub destination: Destination,
}

impl TrojanRequestHeader {
    pub fn new(password: &str, command: RequestCommand, destination: Destination) -> Self {
        let password_hash = hash_password(password);
        Self {
            password_hash,
            command,
            destination,
        }
    }

    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.password_hash);
        buf.extend_from_slice(CRLF);

        let cmd_byte = match self.command {
            RequestCommand::Tcp => 1,
            RequestCommand::Udp => 3,
            RequestCommand::Mux | RequestCommand::Rvs => 1,
        };
        buf.push(cmd_byte);

        match &self.destination.address {
            Address::Ipv4(v4) => {
                buf.push(1);
                buf.extend_from_slice(&v4.octets());
            }
            Address::Domain(dom) => {
                buf.push(3);
                buf.push(dom.len() as u8);
                buf.extend_from_slice(dom.as_bytes());
            }
            Address::Ipv6(v6) => {
                buf.push(4);
                buf.extend_from_slice(&v6.octets());
            }
        }

        buf.extend_from_slice(&self.destination.port.to_be_bytes());
        buf.extend_from_slice(CRLF);

        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut hdr = [0u8; 60];
        reader.read_exact(&mut hdr).await?;
        let password_hash: [u8; 56] = hdr[..56].try_into().unwrap();
        if &hdr[56..58] != CRLF {
            return Err(Error::Protocol("Invalid Trojan CRLF after password hash".into()));
        }
        let command = match hdr[58] {
            1 => RequestCommand::Tcp,
            3 => RequestCommand::Udp,
            other => return Err(Error::Protocol(format!("Invalid Trojan command: {}", other))),
        };
        let address = match hdr[59] {
            1 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                Address::Ipv4(std::net::Ipv4Addr::from(ip))
            }
            3 => {
                let len = reader.read_u8().await? as usize;
                let mut dom = vec![0u8; len];
                reader.read_exact(&mut dom).await?;
                Address::Domain(String::from_utf8(dom).map_err(|e| Error::Protocol(format!("Invalid UTF-8 domain in Trojan header: {}", e)))?)
            }
            4 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                Address::Ipv6(std::net::Ipv6Addr::from(ip))
            }
            other => return Err(Error::Protocol(format!("Invalid Trojan address type: {}", other))),
        };
        let mut tail = [0u8; 4];
        reader.read_exact(&mut tail).await?;
        if &tail[2..4] != CRLF {
            return Err(Error::Protocol("Invalid Trojan CRLF after destination".into()));
        }
        let port = u16::from_be_bytes([tail[0], tail[1]]);
        let destination = if command == RequestCommand::Udp {
            Destination::udp(address, port)
        } else {
            Destination::tcp(address, port)
        };
        Ok(Self { password_hash, command, destination })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanUdpPacket {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

impl TrojanUdpPacket {
    pub fn new(destination: Destination, payload: Vec<u8>) -> Self {
        Self {
            destination,
            payload,
        }
    }

    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut buf = Vec::new();
        match &self.destination.address {
            Address::Ipv4(v4) => {
                buf.push(1);
                buf.extend_from_slice(&v4.octets());
            }
            Address::Domain(dom) => {
                buf.push(3);
                buf.push(dom.len() as u8);
                buf.extend_from_slice(dom.as_bytes());
            }
            Address::Ipv6(v6) => {
                buf.push(4);
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf.extend_from_slice(&self.destination.port.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(CRLF);
        buf.extend_from_slice(&self.payload);

        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let address = match reader.read_u8().await? {
            1 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                Address::Ipv4(std::net::Ipv4Addr::from(ip))
            }
            3 => {
                let len = reader.read_u8().await? as usize;
                let mut dom = vec![0u8; len];
                reader.read_exact(&mut dom).await?;
                Address::Domain(String::from_utf8(dom).map_err(|e| Error::Protocol(format!("Invalid UTF-8 domain in Trojan UDP packet: {}", e)))?)
            }
            4 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                Address::Ipv6(std::net::Ipv6Addr::from(ip))
            }
            other => return Err(Error::Protocol(format!("Invalid Trojan UDP address type: {}", other))),
        };

        let mut tail = [0u8; 6];
        reader.read_exact(&mut tail).await?;
        if &tail[4..6] != CRLF {
            return Err(Error::Protocol("Invalid Trojan UDP CRLF".into()));
        }
        let port = u16::from_be_bytes([tail[0], tail[1]]);
        let mut payload = vec![0u8; u16::from_be_bytes([tail[2], tail[3]]) as usize];
        reader.read_exact(&mut payload).await?;
        Ok(Self { destination: Destination::udp(address, port), payload })
    }
}
