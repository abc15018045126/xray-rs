use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use socket2::{Domain, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use xray_rs_types::net::OUTBOUND_IFACE_INDEX;
use xray_rs_types::{Address, BoxStream, Destination, Error, Result};

type HostDnsCache = RwLock<HashMap<String, (Instant, Vec<IpAddr>)>>;
static DNS_CACHE: LazyLock<HostDnsCache> = LazyLock::new(|| RwLock::new(HashMap::new()));
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

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

async fn query_direct_tcp_dns(
    dns_ip: IpAddr,
    domain: &str,
    qtype: RecordType,
    connect_timeout: Duration,
) -> Result<Vec<IpAddr>> {
    let name = Name::from_str(domain)
        .map_err(|e| Error::Protocol(format!("Invalid domain '{}': {}", domain, e)))?;
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, qtype));
    let wire = msg
        .to_vec()
        .map_err(|e| Error::Protocol(format!("DNS encode error: {}", e)))?;
    let len = u16::try_from(wire.len()).map_err(|_| Error::Protocol("DNS query too large".into()))?;

    let mut stream = connect_addr(SocketAddr::new(dns_ip, 53), connect_timeout.min(Duration::from_secs(3))).await?;
    let mut frame = Vec::with_capacity(wire.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&wire);
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| Error::Timeout)??;
    let mut resp_buf = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    timeout(Duration::from_secs(3), stream.read_exact(&mut resp_buf))
        .await
        .map_err(|_| Error::Timeout)??;

    let resp = Message::from_vec(&resp_buf)
        .map_err(|e| Error::Protocol(format!("DNS decode error: {}", e)))?;
    Ok(resp
        .answers
        .iter()
        .filter_map(|rec| match rec.data {
            RData::A(v4) => Some(IpAddr::V4(v4.0)),
            RData::AAAA(v6) => Some(IpAddr::V6(v6.0)),
            _ => None,
        })
        .collect())
}

async fn resolve_domain(domain: &str, port: u16, connect_timeout: Duration) -> Result<Vec<SocketAddr>> {
    let key = domain.to_ascii_lowercase();
    if let Some((ts, ips)) = DNS_CACHE.read().unwrap().get(&key)
        && ts.elapsed() < DNS_CACHE_TTL
        && !ips.is_empty()
    {
        return Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
    }

    let in_tun = OUTBOUND_IFACE_INDEX.read().unwrap().is_some();
    let ips = if in_tun {
        // In TUN mode, bypass Windows system DNS (fec0:0:0:ffff::1 -> TUN loop) by querying
        // direct resolvers over sockets bound to OUTBOUND_IFACE_INDEX, matching Xray-core.
        const DIRECT_DNS: [IpAddr; 4] = [
            IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V6(Ipv6Addr::new(0x2402, 0x4e00, 0, 0, 0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
        ];
        let mut resolved = Vec::new();
        for dns_ip in DIRECT_DNS {
            let (r_a, r_aaaa) = tokio::join!(
                query_direct_tcp_dns(dns_ip, domain, RecordType::A, connect_timeout),
                query_direct_tcp_dns(dns_ip, domain, RecordType::AAAA, connect_timeout),
            );
            if let Ok(v) = r_a {
                resolved.extend(v);
            }
            if let Ok(v) = r_aaaa {
                resolved.extend(v);
            }
            if !resolved.is_empty() {
                break;
            }
        }
        resolved
    } else {
        let addr_str = format!("{}:{}", domain, port);
        timeout(connect_timeout, tokio::net::lookup_host(&addr_str))
            .await
            .map_err(|_| Error::Timeout)??
            .map(|sa| sa.ip())
            .collect()
    };

    if !ips.is_empty() {
        DNS_CACHE
            .write()
            .unwrap()
            .insert(key, (Instant::now(), ips.clone()));
    }

    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
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
                let addrs = resolve_domain(domain, dest.port, connect_timeout).await?;
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
                                format!("Failed to resolve or connect to {}:{}", domain, dest.port),
                            ))
                        }));
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}
