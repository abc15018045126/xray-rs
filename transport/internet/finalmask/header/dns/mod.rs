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
        let mut offset = 0;
        for part in domain.split('.') {
            let part_bytes = part.as_bytes();
            if part_bytes.is_empty() {
                continue;
            }
            if part_bytes.len() > 63 {
                return Err(Error::Protocol("DNS label too long".into()));
            }
            if offset + 1 + part_bytes.len() >= buf.len() {
                return Err(Error::BufferOverflow);
            }
            buf[offset] = part_bytes.len() as u8;
            offset += 1;
            buf[offset..offset + part_bytes.len()].copy_from_slice(part_bytes);
            offset += part_bytes.len();
        }
        if offset >= buf.len() {
            return Err(Error::BufferOverflow);
        }
        buf[offset] = 0x00;
        offset += 1;
        Ok(offset)
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 12 {
            return Err(Error::BufferOverflow);
        }
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        buf[4..6].copy_from_slice(&0x0001u16.to_be_bytes());
        buf[6..8].copy_from_slice(&0x0000u16.to_be_bytes());
        buf[8..10].copy_from_slice(&0x0000u16.to_be_bytes());
        buf[10..12].copy_from_slice(&0x0000u16.to_be_bytes());

        let domain_len = Self::pack_domain_name(&self.domain, &mut buf[12..])?;
        let total = 12 + domain_len;
        if total + 4 > buf.len() {
            return Err(Error::BufferOverflow);
        }
        buf[total..total + 2].copy_from_slice(&0x0001u16.to_be_bytes());
        buf[total + 2..total + 4].copy_from_slice(&0x0001u16.to_be_bytes());
        Ok(total + 4)
    }
}
