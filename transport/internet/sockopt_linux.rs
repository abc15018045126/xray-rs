use crate::common::errors::Result;
use crate::transport::internet::sockopt::SocketOptions;
use std::net::SocketAddr;

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
