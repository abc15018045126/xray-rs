use crate::common::errors::{Error, Result};
use std::net::SocketAddr;

pub fn fake_udp_openbsd(_addr: SocketAddr, _mark: u32) -> Result<tokio::net::UdpSocket> {
    Err(Error::Unsupported("fake UDP on OpenBSD requires pf divert-to".into()))
}
