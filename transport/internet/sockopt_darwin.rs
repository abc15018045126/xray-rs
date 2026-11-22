use std::net::TcpStream;
use crate::common::errors::Result;
use super::sockopt::SocketOptions;

pub fn apply_socket_options(_stream: &TcpStream, _opts: &SocketOptions) -> Result<()> {
    Ok(())
}
