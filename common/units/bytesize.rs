use crate::common::errors::{Error, Result};
use std::fmt;
use std::ops::Deref;

pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * KB;
pub const GB: u64 = 1024 * MB;
pub const TB: u64 = 1024 * GB;
pub const PB: u64 = 1024 * TB;
pub const EB: u64 = 1024 * PB;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const KB: ByteSize = ByteSize(KB);
    pub const MB: ByteSize = ByteSize(MB);
    pub const GB: ByteSize = ByteSize(GB);
    pub const TB: ByteSize = ByteSize(TB);
    pub const PB: ByteSize = ByteSize(PB);
    pub const EB: ByteSize = ByteSize(EB);

    pub fn new(val: u64) -> Self {
        ByteSize(val)
    }

    pub fn parse(&mut self, s: &str) -> Result<()> {
        let s = s.trim().to_uppercase();
        let i = s.find(char::is_alphabetic).ok_or_else(|| Error::Protocol("invalid or unsupported unit".into()))?;
        let (bytes_str, unit) = s.split_at(i);
        let bytes: f64 = bytes_str.trim().parse().map_err(|_| Error::Protocol("invalid size".into()))?;
        if bytes <= 0.0 { return Err(Error::Protocol("invalid size".into())); }
        let mult = match unit {
            "B" => 1.0,
            "K" | "KB" | "KIB" => KB as f64,
            "M" | "MB" | "MIB" => MB as f64,
            "G" | "GB" | "GIB" => GB as f64,
            "T" | "TB" | "TIB" => TB as f64,
            "P" | "PB" | "PIB" => PB as f64,
            "E" | "EB" | "EIB" => EB as f64,
            _ => return Err(Error::Protocol("invalid or unsupported unit".into())),
        };
        self.0 = (bytes * mult) as u64;
        Ok(())
    }

    pub fn to_string_formatted(&self) -> String {
        if self.0 == 0 { return "0".into(); }
        let (div, unit) = [(EB, "EB"), (PB, "PB"), (TB, "TB"), (GB, "GB"), (MB, "MB"), (KB, "KB")]
            .into_iter().find(|&(t, _)| self.0 >= t).unwrap_or((1, "B"));
        let formatted = format!("{:.2}", self.0 as f64 / div as f64);
        format!("{}{}", formatted.trim_end_matches(".0"), unit)
    }
}

impl Deref for ByteSize {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<u64> for ByteSize {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ByteSize> for u64 {
    fn eq(&self, other: &ByteSize) -> bool {
        *self == other.0
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_formatted())
    }
}

pub fn format_bytes(bytes: u64) -> String {
    ByteSize(bytes).to_string_formatted()
}
