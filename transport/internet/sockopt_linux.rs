// Module: transport\internet\sockopt_linux.rs
// 1:1 Rust implementation corresponding to Go transport\internet\sockopt_linux.go

use crate::common::errors::Result;
use crate::transport::internet::sockopt::SocketOptions;
use std::net::SocketAddr;

/// Applies Linux inbound socket options (`SO_REUSEADDR`, `SO_MARK`, `TCP_NODELAY`)
/// aligned with official Xray-core `transport/internet/sockopt_linux.go`.
#[cfg(target_os = "linux")]
pub fn apply_inbound_socket_options(
    _addr: &SocketAddr,
    socket: &socket2::Socket,
    opts: &SocketOptions,
) -> Result<()> {
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nodelay(true);
    if opts.mark != 0 {
        let _ = socket.set_mark(opts.mark as u32);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_inbound_socket_options(
    _addr: &SocketAddr,
    _socket: &socket2::Socket,
    _opts: &SocketOptions,
) -> Result<()> {
    Ok(())
}

/// Applies Linux outbound socket options (`SO_MARK`, `TCP_NODELAY`)
/// aligned with official Xray-core `transport/internet/sockopt_linux.go`.
#[cfg(target_os = "linux")]
pub fn apply_outbound_socket_options(
    _addr: &SocketAddr,
    socket: &socket2::Socket,
    opts: &SocketOptions,
) -> Result<()> {
    let _ = socket.set_nodelay(true);
    if opts.mark != 0 {
        let _ = socket.set_mark(opts.mark as u32);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_outbound_socket_options(
    _addr: &SocketAddr,
    _socket: &socket2::Socket,
    _opts: &SocketOptions,
) -> Result<()> {
    Ok(())
}
