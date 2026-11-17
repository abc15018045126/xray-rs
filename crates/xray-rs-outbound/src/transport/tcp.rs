use std::net::SocketAddr;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::time::timeout;

use xray_rs_types::{Address, BoxStream, Destination, Error, Result};

/// TCP dialer with `TCP_NODELAY` and OS keepalive options.
pub struct TcpTransport;

impl TcpTransport {
    pub async fn dial(dest: &Destination) -> Result<BoxStream> {
        Self::dial_with_timeout(dest, Duration::from_secs(10)).await
    }

    pub async fn dial_with_timeout(dest: &Destination, connect_timeout: Duration) -> Result<BoxStream> {
        let stream = match &dest.address {
            Address::Ipv4(ip) => {
                let addr = SocketAddr::new((*ip).into(), dest.port);
                timeout(connect_timeout, TcpStream::connect(addr))
                    .await
                    .map_err(|_| Error::Timeout)??
            }
            Address::Ipv6(ip) => {
                let addr = SocketAddr::new((*ip).into(), dest.port);
                timeout(connect_timeout, TcpStream::connect(addr))
                    .await
                    .map_err(|_| Error::Timeout)??
            }
            Address::Domain(domain) => {
                let addr_str = format!("{}:{}", domain, dest.port);
                timeout(connect_timeout, TcpStream::connect(&addr_str))
                    .await
                    .map_err(|_| Error::Timeout)??
            }
        };

        let _ = stream.set_nodelay(true);
        let ka = TcpKeepalive::new()
            .with_time(Duration::from_secs(15))
            .with_interval(Duration::from_secs(5));
        let _ = SockRef::from(&stream).set_tcp_keepalive(&ka);

        Ok(Box::pin(stream))
    }
}
