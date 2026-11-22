use crate::common::errors::Result;
use std::net::SocketAddr;

pub fn apply_freebsd_socket_options(_addr: &SocketAddr, _fd: i32) -> Result<()> {
    Ok(())
}
