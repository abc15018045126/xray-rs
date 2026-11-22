pub mod config;
pub mod conn;

use crate::common::errors::{Error, Result};
use rand::Rng;

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub domain: String,
}

impl DnsHeader {
    pub fn new(domain: impl Into<String>) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            id: rng.r#gen(),
            domain: domain.into(),
        }
    }

    pub fn pack_domain_name(domain: &str, buf: &mut [u8]) -> Result<usize> {
        let mut off = 0;
        for part in domain.split('.').map(str::as_bytes).filter(|p| !p.is_empty()) {
            if part.len() > 63 { return Err(Error::Protocol("DNS label too long".into())); }
            if off + 1 + part.len() >= buf.len() { return Err(Error::BufferOverflow); }
            buf[off] = part.len() as u8;
            buf[off + 1..off + 1 + part.len()].copy_from_slice(part);
            off += 1 + part.len();
        }
        if off >= buf.len() { return Err(Error::BufferOverflow); }
        buf[off] = 0;
        Ok(off + 1)
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 12 { return Err(Error::BufferOverflow); }
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..12].copy_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let total = 12 + Self::pack_domain_name(&self.domain, &mut buf[12..])?;
        if total + 4 > buf.len() { return Err(Error::BufferOverflow); }
        buf[total..total + 4].copy_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        Ok(total + 4)
    }
}
