use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use crate::common::protocol::RequestCommand;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const VLESS_VERSION: u8 = 0;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addons {
    pub flow: String,
    pub seed: Vec<u8>,
}

impl Addons {
    pub fn new(flow: impl Into<String>) -> Self {
        Self {
            flow: flow.into(),
            seed: Vec::new(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if !self.flow.is_empty() {
            let flow_bytes = self.flow.as_bytes();
            buf.push((1 << 3) | 2);
            buf.push(flow_bytes.len() as u8);
            buf.extend_from_slice(flow_bytes);
        }
        if !self.seed.is_empty() {
            buf.push((2 << 3) | 2);
            buf.push(self.seed.len() as u8);
            buf.extend_from_slice(&self.seed);
        }
        buf
    }
    pub fn decode(bytes: &[u8]) -> Self {
        let mut flow = String::new();
        let mut seed = Vec::new();
        let mut idx = 0;
        while idx < bytes.len() {
            let tag_wire = bytes[idx];
            idx += 1;
            let field_num = tag_wire >> 3;
            if idx >= bytes.len() { break; }
            let len = bytes[idx] as usize;
            idx += 1;
            if idx + len > bytes.len() { break; }
            let data = &bytes[idx..idx + len];
            idx += len;
            match field_num {
                1 => flow = String::from_utf8_lossy(data).to_string(),
                2 => seed = data.to_vec(),
                _ => {}
            }
        }
        Self { flow, seed }
    }
}

#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub user_id: Uuid,
    pub command: RequestCommand,
    pub destination: Destination,
    pub addons: Addons,
}

impl RequestHeader {
    pub fn new(user_id: Uuid, command: RequestCommand, destination: Destination) -> Self {
        Self {
            user_id,
            command,
            destination,
            addons: Addons::default(),
        }
    }
    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(VLESS_VERSION);
        buf.extend_from_slice(self.user_id.as_bytes());
        let addons = self.addons.encode();
        buf.push(addons.len() as u8);
        buf.extend_from_slice(&addons);
        buf.push(self.command.to_u8());
        if !matches!(self.command, RequestCommand::Mux | RequestCommand::Rvs) {
            buf.extend_from_slice(&self.destination.port.to_be_bytes());
            match &self.destination.address {
                Address::Ipv4(v4) => { buf.push(1); buf.extend_from_slice(&v4.octets()); }
                Address::Domain(d) => { buf.extend_from_slice(&[2, d.len() as u8]); buf.extend_from_slice(d.as_bytes()); }
                Address::Ipv6(v6) => { buf.push(3); buf.extend_from_slice(&v6.octets()); }
            }
        }
        buf
    }
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let buf = self.encode_bytes();
        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut head = [0u8; 18];
        reader.read_exact(&mut head).await?;
        if head[0] != VLESS_VERSION { return Err(Error::Protocol(format!("Unsupported VLESS version: {}", head[0]))); }
        let user_id = Uuid::from_bytes(head[1..17].try_into().unwrap());
        let addons = if head[17] > 0 {
            let mut addons_buf = vec![0u8; head[17] as usize];
            reader.read_exact(&mut addons_buf).await?;
            Addons::decode(&addons_buf)
        } else {
            Addons::default()
        };
        let cmd_byte = reader.read_u8().await?;
        let command = RequestCommand::from_u8(cmd_byte)
            .ok_or_else(|| Error::Protocol(format!("Invalid VLESS command: {}", cmd_byte)))?;
        let destination = if matches!(command, RequestCommand::Mux | RequestCommand::Rvs) {
            Destination::tcp(Address::Domain("v1.mux.cool".into()), 666)
        } else {
            let mut meta = [0u8; 3];
            reader.read_exact(&mut meta).await?;
            let port = u16::from_be_bytes([meta[0], meta[1]]);
            let address = match meta[2] {
                1 => {
                    let mut ip = [0u8; 4];
                    reader.read_exact(&mut ip).await?;
                    Address::Ipv4(std::net::Ipv4Addr::from(ip))
                }
                2 => {
                    let len = reader.read_u8().await? as usize;
                    let mut dom = vec![0u8; len];
                    reader.read_exact(&mut dom).await?;
                    Address::Domain(String::from_utf8(dom).map_err(|e| Error::Protocol(format!("Invalid UTF-8 domain in VLESS header: {}", e)))?)
                }
                3 => {
                    let mut ip = [0u8; 16];
                    reader.read_exact(&mut ip).await?;
                    Address::Ipv6(std::net::Ipv6Addr::from(ip))
                }
                other => return Err(Error::Protocol(format!("Invalid VLESS address type: {}", other))),
            };
            if command == RequestCommand::Udp {
                Destination::udp(address, port)
            } else {
                Destination::tcp(address, port)
            }
        };
        Ok(Self { user_id, command, destination, addons })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResponseHeader {
    pub addons: Addons,
}

impl ResponseHeader {
    pub fn new() -> Self { Self { addons: Addons::default(), } }
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut buf = Vec::new();
        buf.push(VLESS_VERSION);
        let addons_bytes = self.addons.encode();
        buf.push(addons_bytes.len() as u8);
        buf.extend_from_slice(&addons_bytes);
        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let version = reader.read_u8().await?;
        if version != VLESS_VERSION {
            return Err(Error::Protocol(format!("Unsupported VLESS response version: {}", version)));
        }
        let addons_len = reader.read_u8().await? as usize;
        let addons = if addons_len > 0 {
            let mut buf = vec![0u8; addons_len];
            reader.read_exact(&mut buf).await?;
            Addons::decode(&buf)
        } else {
            Addons::default()
        };
        Ok(Self { addons })
    }
}
