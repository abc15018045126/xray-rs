pub mod uuid;

#[cfg(test)]
pub mod uuid_test;

pub use uuid::{new_uuid, parse_bytes, parse_string, parse_uuid, UUID};
use ::uuid::Uuid;
use crate::common::errors::{Error, Result};

pub fn process_uuid(uuid_bytes: [u8; 16]) -> [u8; 16] {
    uuid_bytes
}

pub fn parse_str(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| Error::Protocol(format!("Invalid UUID: {}", e)))
}
