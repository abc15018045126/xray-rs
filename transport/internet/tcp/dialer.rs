// Module: transport\internet\tcp\dialer.rs
// 1:1 Rust implementation corresponding to Go transport\internet\tcp\dialer.go

use std::net::SocketAddr;
#[allow(unused_imports)]
use tokio::net::TcpStream as TokioTcpStream;

use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};

pub struct TcpDialer;

impl TcpDialer {
    pub async fn dial(dest: &Destination) -> Result<BoxStream> {
        #[cfg(target_os = "windows")]
        {
            let iface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.read().await;
            match &dest.address {
                crate::common::net::Address::Ipv4(ip) => {
                    let addr = SocketAddr::new(std::net::IpAddr::V4(*ip), dest.port);
                    #[cfg(debug_assertions)]
                    let _t0 = std::time::Instant::now();
                    let stream =
                        crate::proxy::tun::socket_helpers::new_tcp_stream(addr, iface.as_ref())
                            .await
                            .map_err(Error::Io)?;
                    #[cfg(debug_assertions)]
                    crate::debug_panel::record_stage("TCP 建连 (IPv4 connect)", _t0.elapsed());
                    let _ = stream.set_nodelay(true);
                    Ok(Box::pin(stream))
                }
                crate::common::net::Address::Ipv6(ip) => {
                    let addr = SocketAddr::new(std::net::IpAddr::V6(*ip), dest.port);
                    #[cfg(debug_assertions)]
                    let _t0 = std::time::Instant::now();
                    let stream =
                        crate::proxy::tun::socket_helpers::new_tcp_stream(addr, iface.as_ref())
                            .await
                            .map_err(Error::Io)?;
                    #[cfg(debug_assertions)]
                    crate::debug_panel::record_stage("TCP 建连 (IPv6 connect)", _t0.elapsed());
                    let _ = stream.set_nodelay(true);
                    Ok(Box::pin(stream))
                }
                crate::common::net::Address::Domain(domain) => {
                    let addr_str = format!("{}:{}", domain, dest.port);
                    #[cfg(debug_assertions)]
                    let _dt0 = std::time::Instant::now();
                    let addrs = tokio::net::lookup_host(&addr_str)
                        .await
                        .map_err(Error::Io)?;
                    #[cfg(debug_assertions)]
                    crate::debug_panel::record_stage("TCP 域名解析 (lookup_host)", _dt0.elapsed());
                    let mut last_err = None;
                    for addr in addrs {
                        #[cfg(debug_assertions)]
                        let _ct0 = std::time::Instant::now();
                        match crate::proxy::tun::socket_helpers::new_tcp_stream(
                            addr,
                            iface.as_ref(),
                        )
                        .await
                        {
                            Ok(stream) => {
                                #[cfg(debug_assertions)]
                                crate::debug_panel::record_stage(
                                    if addr.is_ipv6() {
                                        "TCP 建连 (域名->IPv6)"
                                    } else {
                                        "TCP 建连 (域名->IPv4)"
                                    },
                                    _ct0.elapsed(),
                                );
                                let _ = stream.set_nodelay(true);
                                return Ok(Box::pin(stream));
                            }
                            Err(e) => {
                                #[cfg(debug_assertions)]
                                crate::debug_panel::record_stage(
                                    if addr.is_ipv6() {
                                        "TCP 建连失败 (IPv6 超时/拒绝)"
                                    } else {
                                        "TCP 建连失败 (IPv4 超时/拒绝)"
                                    },
                                    _ct0.elapsed(),
                                );
                                last_err = Some(e);
                            }
                        }
                    }
                    Err(Error::Io(last_err.unwrap_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Failed to resolve or connect to {}", addr_str),
                        )
                    })))
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let stream = match &dest.address {
                crate::common::net::Address::Ipv4(ip) => {
                    let addr = SocketAddr::new(std::net::IpAddr::V4(*ip), dest.port);
                    TokioTcpStream::connect(addr).await?
                }
                crate::common::net::Address::Ipv6(ip) => {
                    let addr = SocketAddr::new(std::net::IpAddr::V6(*ip), dest.port);
                    TokioTcpStream::connect(addr).await?
                }
                crate::common::net::Address::Domain(domain) => {
                    let addr_str = format!("{}:{}", domain, dest.port);
                    TokioTcpStream::connect(&addr_str).await.map_err(|e| {
                        Error::Io(std::io::Error::new(
                            e.kind(),
                            format!("Failed to connect to {}: {}", addr_str, e),
                        ))
                    })?
                }
            };

            let _ = stream.set_nodelay(true);
            Ok(Box::pin(stream))
        }
    }
}
