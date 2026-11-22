use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};

pub const UOT_MAGIC_ADDRESS: &str = "sp-uot.v2fly.org";
pub const UOT_LEGACY_MAGIC_ADDRESS: &str = "sp-uot-v1.v2fly.org";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    Legacy = 1,
    Standard = 2,
}

pub struct UotPacket {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

impl UotPacket {
    pub fn new(destination: Destination, payload: Vec<u8>) -> Self {
        Self {
            destination,
            payload,
        }
    }
    pub fn encode(&self, version: UotVersion) -> Vec<u8> {
        let mut buf = Vec::new();
        if version == UotVersion::Standard { buf.push(0x00); }
        match &self.destination.address {
            Address::Ipv4(ip) => { buf.push(0x01); buf.extend_from_slice(&ip.octets()); }
            Address::Domain(d) => { buf.extend_from_slice(&[0x03, d.len() as u8]); buf.extend_from_slice(d.as_bytes()); }
            Address::Ipv6(ip) => { buf.push(0x04); buf.extend_from_slice(&ip.octets()); }
        }
        buf.extend_from_slice(&self.destination.port.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
    pub fn decode(data: &[u8], version: UotVersion) -> Result<(Self, usize)> {
        if data.len() < 7 { return Err(Error::Protocol("UoT packet too short".into())); }
        let mut pos = usize::from(version == UotVersion::Standard);
        let atyp = data[pos];
        pos += 1;
        let address = match atyp {
            0x01 => {
                let b: [u8; 4] = data.get(pos..pos + 4).and_then(|s| s.try_into().ok())
                    .ok_or_else(|| Error::Protocol("Incomplete IPv4 in UoT".into()))?;
                pos += 4;
                Address::Ipv4(std::net::Ipv4Addr::from(b))
            }
            0x03 => {
                let len = *data.get(pos).ok_or_else(|| Error::Protocol("Incomplete Domain len in UoT".into()))? as usize;
                pos += 1;
                let raw = data.get(pos..pos + len).ok_or_else(|| Error::Protocol("Incomplete Domain in UoT".into()))?;
                let dom = std::str::from_utf8(raw).map_err(|_| Error::Protocol("Invalid UTF-8 domain in UoT".into()))?;
                pos += len;
                Address::Domain(dom.to_string())
            }
            0x04 => {
                let b: [u8; 16] = data.get(pos..pos + 16).and_then(|s| s.try_into().ok())
                    .ok_or_else(|| Error::Protocol("Incomplete IPv6 in UoT".into()))?;
                pos += 16;
                Address::Ipv6(std::net::Ipv6Addr::from(b))
            }
            _ => return Err(Error::Protocol(format!("Invalid ATYP 0x{:02x} in UoT", atyp))),
        };
        if pos + 4 > data.len() { return Err(Error::Protocol("Incomplete port/length in UoT".into())); }
        let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let payload_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        let payload = data.get(pos..pos + payload_len)
            .ok_or_else(|| Error::Protocol("Incomplete payload in UoT".into()))?.to_vec();
        pos += payload_len;
        Ok((UotPacket { destination: Destination::udp(address, port), payload }, pos))
    }
}

pub fn is_uot_destination(dest: &Destination) -> Option<UotVersion> {
    match &dest.address {
        Address::Domain(d) if d == UOT_MAGIC_ADDRESS => Some(UotVersion::Standard),
        Address::Domain(d) if d == UOT_LEGACY_MAGIC_ADDRESS => Some(UotVersion::Legacy),
        _ => None,
    }
}
