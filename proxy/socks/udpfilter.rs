use std::net::SocketAddr;

pub fn should_filter_socks_udp(_addr: &SocketAddr) -> bool { false }
