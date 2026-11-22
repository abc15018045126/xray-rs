use std::net::TcpStream;
use std::time::Duration;
use socket2::{SockRef, TcpKeepalive};
use crate::common::errors::Result;
use super::sockopt::SocketOptions;

pub fn apply_socket_options(stream: &TcpStream, opts: &SocketOptions) -> Result<()> {
    let _ = stream.set_nodelay(true);
    if opts.tcp_keep_alive_idle > 0 || opts.tcp_keep_alive_interval > 0 {
        let mut ka = TcpKeepalive::new();
        if opts.tcp_keep_alive_idle > 0 { ka = ka.with_time(Duration::from_secs(opts.tcp_keep_alive_idle as u64)); }
        if opts.tcp_keep_alive_interval > 0 { ka = ka.with_interval(Duration::from_secs(opts.tcp_keep_alive_interval as u64)); }
        SockRef::from(stream).set_tcp_keepalive(&ka)?;
    }
    Ok(())
}
