use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const XUDP_MAGIC: u16 = 0x5855;
pub const XUDP_MAX_PACKET_SIZE: usize = 65535;

pub fn write_address_port(buf: &mut Vec<u8>, addr: &Address, port: u16) {
    buf.extend_from_slice(&port.to_be_bytes());
    match addr {
        Address::Ipv4(v4) => {
            buf.push(1);
            buf.extend_from_slice(&v4.octets());
        }
        Address::Domain(dom) => {
            buf.push(2);
            buf.push(dom.len() as u8);
            buf.extend_from_slice(dom.as_bytes());
        }
        Address::Ipv6(v6) => {
            buf.push(3);
            buf.extend_from_slice(&v6.octets());
        }
    }
}

pub fn read_address_port(data: &[u8]) -> Result<(Address, u16, usize)> {
    if data.len() < 3 {
        return Err(Error::Protocol("short address buffer".into()));
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    match data[2] {
        1 => {
            let ip: [u8; 4] = data.get(3..7).and_then(|s| s.try_into().ok())
                .ok_or_else(|| Error::Protocol("short IPv4 buffer".into()))?;
            Ok((Address::Ipv4(Ipv4Addr::from(ip)), port, 7))
        }
        2 => {
            let len = *data.get(3).ok_or_else(|| Error::Protocol("short domain length byte".into()))? as usize;
            let raw = data.get(4..4 + len).ok_or_else(|| Error::Protocol("short domain buffer".into()))?;
            let s = std::str::from_utf8(raw).map_err(|e| Error::Protocol(format!("invalid domain: {}", e)))?;
            Ok((Address::Domain(s.to_string()), port, 4 + len))
        }
        3 => {
            let ip: [u8; 16] = data.get(3..19).and_then(|s| s.try_into().ok())
                .ok_or_else(|| Error::Protocol("short IPv6 buffer".into()))?;
            Ok((Address::Ipv6(Ipv6Addr::from(ip)), port, 19))
        }
        other => Err(Error::Protocol(format!("unknown address family: {}", other))),
    }
}

pub struct PacketWriter<W> {
    writer: W,
    dest: Destination,
    global_id: [u8; 8],
    is_first: bool,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    pub fn new(writer: W, dest: Destination, global_id: [u8; 8]) -> Self {
        Self {
            writer,
            dest,
            global_id,
            is_first: true,
        }
    }

    pub fn destination(&self) -> &Destination {
        &self.dest
    }

    pub async fn write_packet(&mut self, payload: &[u8], is_proxy_req: bool) -> Result<()> {
        let mut meta = vec![0, 0, 0, 0, if self.is_first { 1 } else { 2 }, 1, 2];
        write_address_port(&mut meta, &self.dest.address, self.dest.port);
        if self.is_first {
            if is_proxy_req { meta.extend_from_slice(&self.global_id); }
            self.is_first = false;
        }
        let meta_len = (meta.len() - 2) as u16;
        meta[0..2].copy_from_slice(&meta_len.to_be_bytes());
        meta.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        meta.extend_from_slice(payload);
        self.writer.write_all(&meta).await.map_err(Error::Io)?;
        self.writer.flush().await.map_err(Error::Io)?;
        Ok(())
    }
}

pub struct PacketReader<R> {
    reader: R,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub async fn read_packet(&mut self) -> Result<(Destination, Vec<u8>)> {
        let mut len_buf = [0u8; 2];
        self.reader.read_exact(&mut len_buf).await.map_err(Error::Io)?;
        let meta_len = u16::from_be_bytes(len_buf) as usize;
        if meta_len < 4 { return Err(Error::Protocol("XUDP meta too short".into())); }
        let mut meta = vec![0u8; meta_len];
        self.reader.read_exact(&mut meta).await.map_err(Error::Io)?;
        let dest = if meta.len() > 4 && meta[4] == 2 {
            let (addr, port, _) = read_address_port(&meta[5..])?;
            Destination::udp(addr, port)
        } else {
            Destination::udp(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 0)
        };
        self.reader.read_exact(&mut len_buf).await.map_err(Error::Io)?;
        let mut payload = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        self.reader.read_exact(&mut payload).await.map_err(Error::Io)?;
        Ok((dest, payload))
    }
}

use std::net::SocketAddr;

pub fn generate_global_id(src: &SocketAddr, base_key: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(base_key);
    hasher.update(src.to_string().as_bytes());
    let res = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&res[0..8]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XudpPacket {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

impl XudpPacket {
    pub fn new(destination: Destination, payload: Vec<u8>) -> Self {
        Self {
            destination,
            payload,
        }
    }

    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut buf = self.destination.port.to_be_bytes().to_vec();
        match &self.destination.address {
            Address::Ipv4(v4) => { buf.push(1); buf.extend_from_slice(&v4.octets()); }
            Address::Domain(d) => { buf.extend_from_slice(&[2, d.len() as u8]); buf.extend_from_slice(d.as_bytes()); }
            Address::Ipv6(v6) => { buf.push(3); buf.extend_from_slice(&v6.octets()); }
        }
        buf.extend_from_slice(&self.payload);
        writer.write_all(&buf).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let port = reader.read_u16().await?;
        let address = match reader.read_u8().await? {
            1 => { let mut ip = [0u8; 4]; reader.read_exact(&mut ip).await?; Address::Ipv4(Ipv4Addr::from(ip)) }
            2 => {
                let mut dom = vec![0u8; reader.read_u8().await? as usize];
                reader.read_exact(&mut dom).await?;
                Address::Domain(String::from_utf8(dom).map_err(|e| Error::Protocol(format!("Invalid UTF-8 domain in XUDP: {}", e)))?)
            }
            3 => { let mut ip = [0u8; 16]; reader.read_exact(&mut ip).await?; Address::Ipv6(Ipv6Addr::from(ip)) }
            other => return Err(Error::Protocol(format!("Invalid XUDP address type: {}", other))),
        };
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).await?;
        Ok(Self { destination: Destination::udp(address, port), payload })
    }
}
