use crate::common::errors::{Error, Result};
use std::net::IpAddr;

pub fn find_process_darwin(_network: &str, _src_ip: IpAddr, _src_port: u16) -> Result<(u32, String)> {
    Err(Error::Unsupported("process lookup on macOS requires darwin sysctl".into()))
}
