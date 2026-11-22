use crate::common::errors::{Error, Result};

pub type Instance = LogManager;

pub fn parse_mask_address(c: &str) -> Result<(u8, u8)> {
    match c.to_lowercase().as_str() {
        "half" => Ok((16, 32)),
        "quarter" => Ok((8, 16)),
        "full" => Ok((0, 0)),
        "" => Ok((32, 128)),
        custom => {
            let parse_part = |s: Option<&str>, def: u8, label: &str| -> Result<u8> {
                match s.map(|x| x.trim().trim_start_matches('/')).filter(|x| !x.is_empty()) {
                    Some(t) => t.parse().map_err(|e| Error::Config(format!("Invalid {} mask in mask_address: {}", label, e))),
                    None => Ok(def),
                }
            };
            let mut it = custom.split('+');
            let (m4, m6) = (parse_part(it.next(), 32, "IPv4")?, parse_part(it.next(), 128, "IPv6")?);
            if !m4.is_multiple_of(8) || m4 > 32 {
                return Err(Error::Config("Log Mask: ipv4 mask must be divisible by 8 and between 0-32".into()));
            }
            if m6 > 128 { return Err(Error::Config("Log Mask: ipv6 mask must be between 0-128".into())); }
            Ok((m4, m6))
        }
    }
}

pub struct MaskedMsgWrapper {
    pub mask4: u8,
    pub mask6: u8,
}

impl MaskedMsgWrapper {
    pub fn new(mask4: u8, mask6: u8) -> Self { Self { mask4, mask6 } }
    pub fn mask_ipv4_string(&self, s: &str) -> String {
        if self.mask4 == 32 { return s.to_string(); }
        if self.mask4 == 0 { return "[Masked IPv4]".into(); }
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 { return s.to_string(); }
        let keep = (self.mask4 / 8) as usize;
        parts.iter().enumerate().map(|(i, p)| if i < keep { *p } else { "*" }).collect::<Vec<_>>().join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_mask_address_presets() {
        assert_eq!(parse_mask_address("half").unwrap(), (16, 32));
        assert_eq!(parse_mask_address("quarter").unwrap(), (8, 16));
        assert_eq!(parse_mask_address("full").unwrap(), (0, 0));
        assert_eq!(parse_mask_address("").unwrap(), (32, 128));
    }
    #[test]
    fn test_parse_mask_address_custom() {
        assert_eq!(parse_mask_address("/16+/64").unwrap(), (16, 64));
        assert_eq!(parse_mask_address("/24").unwrap(), (24, 128));
        assert!(parse_mask_address("/15").is_err());
    }
    #[test]
    fn test_masked_msg_wrapper() {
        let wrapper = MaskedMsgWrapper::new(16, 32);
        assert_eq!(wrapper.mask_ipv4_string("192.168.1.100"), "192.168.*.*");
        let full_mask = MaskedMsgWrapper::new(0, 0);
        assert_eq!(full_mask.mask_ipv4_string("1.2.3.4"), "[Masked IPv4]");
        let no_mask = MaskedMsgWrapper::new(32, 128);
        assert_eq!(no_mask.mask_ipv4_string("1.2.3.4"), "1.2.3.4");
    }
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, Ordering};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
}

impl LogLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warning" | "warn" => LogLevel::Warning,
            "error" => LogLevel::Error,
            "none" => LogLevel::None,
            _ => LogLevel::Warning,
        }
    }
}

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct MultiWriter {
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl MultiWriter {
    pub fn new(path: Option<&str>) -> Self {
        let file = path.and_then(|p| {
            if let Some(parent) = std::path::Path::new(p).parent() && !parent.as_os_str().is_empty()
            { let _ = std::fs::create_dir_all(parent); }
            OpenOptions::new().create(true).append(true).open(p).ok().map(|f| Arc::new(Mutex::new(f)))
        });
        Self { file }
    }
}

impl Write for MultiWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stdout().write_all(buf);
        if let Some(ref f) = self.file && let Ok(mut file) = f.lock()
        { let _ = file.write_all(buf); }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        if let Some(ref f) = self.file && let Ok(mut file) = f.lock()
        { let _ = file.flush(); }
        Ok(())
    }
}

pub fn init_logger(level_str: &str) { init_logger_ext(level_str, None); }

pub fn init_logger_ext(level_str: &str, file_path: Option<&str>) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level_str));
    if let Some(path) = file_path {
        let writer = MultiWriter::new(Some(path));
        let _ = fmt()
            .with_env_filter(filter).with_target(false).with_ansi(false).with_writer(move || writer.clone()).try_init();
    } else {
        let _ = fmt().with_env_filter(filter).with_target(false).try_init();
    }
}

pub struct LogManager {
    level: AtomicU8,
    mask4: u8,
    mask6: u8,
}

impl LogManager {
    pub fn new(level: LogLevel, mask4: u8, mask6: u8) -> Self {
        Self {
            level: AtomicU8::new(level as u8),
            mask4,
            mask6,
        }
    }
    pub fn start(&self) {
    }
    pub fn get_level(&self) -> LogLevel {
        match self.level.load(Ordering::Relaxed) {
            0 => LogLevel::None,
            1 => LogLevel::Error,
            2 => LogLevel::Warning,
            3 => LogLevel::Info,
            4 => LogLevel::Debug,
            _ => LogLevel::Warning,
        }
    }
    pub fn set_level(&self, level: LogLevel) { self.level.store(level as u8, Ordering::Relaxed); }
    pub fn mask_ip(&self, ip: &IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) if self.mask4 > 0 => {
                let mask = !0u32 << (32 - self.mask4.min(32));
                IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(v4.octets()) & mask))
            }
            IpAddr::V6(v6) if self.mask6 > 0 => {
                let mask = !0u128 << (128 - self.mask6.min(128));
                IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(v6.octets()) & mask))
            }
            _ => *ip,
        }
    }
    pub fn format_access_log(&self, from_ip: Option<&IpAddr>, dest: &str, status: &str, outbound: &str) -> String {
        let from_str = match from_ip {
            Some(ip) => self.mask_ip(ip).to_string(),
            None => "unknown".to_string(),
        };
        format!("{} [{}] {} -> [{}]", from_str, status, dest, outbound)
    }
}
