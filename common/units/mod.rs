pub mod bytesize;

#[cfg(test)]
pub mod bytesize_test;

pub use bytesize::{format_bytes, ByteSize, EB, GB, KB, MB, PB, TB};
pub use crate::common::errors::{Error, Result};

pub fn parse_bytesize(s: &str) -> Result<u64> {
    let mut bs = ByteSize::default();
    bs.parse(s)?;
    Ok(bs.0)
}

pub fn format_bytesize(bytes: u64) -> String {
    ByteSize(bytes).to_string_formatted()
}
