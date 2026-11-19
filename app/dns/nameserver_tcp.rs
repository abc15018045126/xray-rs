// Module: app\dns\nameserver_tcp.rs
// 1:1 Rust implementation corresponding to Go app\dns\nameserver_tcp.go

use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;

use super::nameserver::{NameServer, build_dns_query_typed, parse_dns_response};
use crate::common::errors::{Error, Result};

pub struct TcpNameServer {
    pub server_addr: SocketAddr,
    pub timeout: Duration,
}

impl TcpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            server_addr,
            timeout,
        }
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

#[async_trait]
impl NameServer for TcpNameServer {
    fn name(&self) -> &str {
        "tcp"
    }

    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let clean = domain.trim_end_matches('.');
        let mut stream = pingora_timeout::timeout(
            self.timeout,
            crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(self.server_addr),
        )
        .await
        .map_err(|_| Error::Timeout)??;

        let query = build_dns_query_typed(clean, 1);
        let len_prefix = (query.len() as u16).to_be_bytes();

        stream.write_all(&len_prefix).await.map_err(Error::Io)?;
        stream.write_all(&query).await.map_err(Error::Io)?;

        let mut resp_len_buf = [0u8; 2];
        pingora_timeout::timeout(self.timeout, stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp = vec![0u8; resp_len];
        pingora_timeout::timeout(self.timeout, stream.read_exact(&mut resp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        parse_dns_response(&resp, clean)
    }
}
