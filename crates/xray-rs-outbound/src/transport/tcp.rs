use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use xray_rs_types::net::OUTBOUND_IFACE_INDEX;
use xray_rs_types::{Address, BoxStream, Destination, Error, Result};

#[cfg(windows)]
#[allow(unsafe_code)]
fn bind_windows_iface(socket: &Socket, domain: Domain, iface_idx: u32) {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt,
    };
    let raw = SOCKET(socket.as_raw_socket() as usize);
    let idx_bytes = match domain {
        Domain::IPV4 => iface_idx.to_be_bytes(),
        _ => iface_idx.to_ne_bytes(),
    };
    let (level, opt) = match domain {
        Domain::IPV4 => (IPPROTO_IP.0, IP_UNICAST_IF),
        _ => (IPPROTO_IPV6.0, IPV6_UNICAST_IF),
    };
    unsafe {
        let _ = setsockopt(raw, level, opt, Some(&idx_bytes));
    }
}

async fn connect_addr(addr: SocketAddr, connect_timeout: Duration) -> Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, None)?;
    #[cfg(windows)]
    if !addr.ip().is_loopback()
        && let Some(idx) = *OUTBOUND_IFACE_INDEX.read().unwrap()
    {
        bind_windows_iface(&socket, domain, idx);
    }
    let _ = socket.set_keepalive(true);
    let _ = socket.set_nodelay(true);
    socket.set_nonblocking(true)?;

    let tokio_sock = TcpSocket::from_std_stream(socket.into());
    let stream = timeout(connect_timeout, tokio_sock.connect(addr))
        .await
        .map_err(|_| Error::Timeout)??;
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    let _ = SockRef::from(&stream).set_tcp_keepalive(&ka);
    Ok(stream)
}

/// TCP dialer with `TCP_NODELAY`, OS keepalive, and TUN anti-loop interface binding.
pub struct TcpTransport;

impl TcpTransport {
    pub async fn dial(dest: &Destination) -> Result<BoxStream> {
        Self::dial_with_timeout(dest, Duration::from_secs(10)).await
    }

    pub async fn dial_with_timeout(dest: &Destination, connect_timeout: Duration) -> Result<BoxStream> {
        let stream = match &dest.address {
            Address::Ipv4(ip) => connect_addr(SocketAddr::new((*ip).into(), dest.port), connect_timeout).await?,
            Address::Ipv6(ip) => connect_addr(SocketAddr::new((*ip).into(), dest.port), connect_timeout).await?,
            Address::Domain(domain) => {
                let addr_str = format!("{}:{}", domain, dest.port);
                let addrs = timeout(connect_timeout, tokio::net::lookup_host(&addr_str))
                    .await
                    .map_err(|_| Error::Timeout)??;
                let mut last_err = None;
                let mut connected = None;
                for addr in addrs {
                    match connect_addr(addr, connect_timeout).await {
                        Ok(s) => {
                            connected = Some(s);
                            break;
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                match connected {
                    Some(s) => s,
                    None => {
                        return Err(last_err.unwrap_or_else(|| {
                            Error::Io(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                format!("Failed to resolve or connect to {}", addr_str),
                            ))
                        }));
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}
