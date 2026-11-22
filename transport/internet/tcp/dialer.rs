// Module: transport\internet\tcp\dialer.rs
// 1:1 Rust implementation corresponding to Go transport\internet\tcp\dialer.go

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use crate::app::dns::DnsClient;
use crate::app::pingora_bridge::PingoraCoreConnector;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};

static SYSTEM_DNS_CLIENT: RwLock<Option<Arc<DnsClient>>> = RwLock::new(None);

/// Registers the active `DnsClient` for system dialing, matching `Xray-core/transport/internet/dialer.go`
/// `InitSystemDialer(dc, om)`.
pub fn init_system_dialer_dns(dc: Arc<DnsClient>) {
    if let Ok(mut guard) = SYSTEM_DNS_CLIENT.write() {
        *guard = Some(dc);
    }
}

pub struct TcpDialer;

impl TcpDialer {
    pub async fn dial(dest: &Destination) -> Result<BoxStream> {
        match &dest.address {
            crate::common::net::Address::Ipv4(ip) => {
                let addr = SocketAddr::new(std::net::IpAddr::V4(*ip), dest.port);
                #[cfg(debug_assertions)]
                let _t0 = std::time::Instant::now();
                let stream = PingoraCoreConnector::dial_tcp(addr).await?;
                #[cfg(debug_assertions)]
                crate::debug_panel::record_stage("TCP 建连 (Pingora IPv4)", _t0.elapsed());
                Ok(stream)
            }
            crate::common::net::Address::Ipv6(ip) => {
                let addr = SocketAddr::new(std::net::IpAddr::V6(*ip), dest.port);
                #[cfg(debug_assertions)]
                let _t0 = std::time::Instant::now();
                let stream = PingoraCoreConnector::dial_tcp(addr).await?;
                #[cfg(debug_assertions)]
                crate::debug_panel::record_stage("TCP 建连 (Pingora IPv6)", _t0.elapsed());
                Ok(stream)
            }
            crate::common::net::Address::Domain(domain) => {
                let addr_str = format!("{}:{}", domain, dest.port);
                #[cfg(debug_assertions)]
                let _dt0 = std::time::Instant::now();

                // 1:1 with `Xray-core/transport/internet/dialer.go` (`LookupForIP`):
                // try built-in `DnsClient` (`dns.hosts` + direct/local DNS) first, then fall back
                // to system `lookup_host` if unresolved.
                let mut addrs: Vec<SocketAddr> = Vec::new();
                let dns_opt = SYSTEM_DNS_CLIENT.read().ok().and_then(|g| g.clone());
                if let Some(dc) = dns_opt
                    && let Ok(ips) = dc.lookup_for_dialer(domain).await
                {
                    for ip in ips {
                        addrs.push(SocketAddr::new(ip, dest.port));
                    }
                }
                if addrs.is_empty() {
                    addrs.extend(
                        tokio::net::lookup_host(&addr_str)
                            .await
                            .map_err(Error::Io)?,
                    );
                }
                // Prefer IPv4 before IPv6 so IPv4-only networks don't stall waiting on IPv6 timeouts.
                addrs.sort_by_key(|a| a.is_ipv6());

                #[cfg(debug_assertions)]
                crate::debug_panel::record_stage("TCP 域名解析 (DnsClient/lookup_host)", _dt0.elapsed());
                let mut last_err = None;
                for addr in addrs {
                    #[cfg(debug_assertions)]
                    let _ct0 = std::time::Instant::now();
                    match PingoraCoreConnector::dial_tcp(addr).await {
                        Ok(stream) => {
                            #[cfg(debug_assertions)]
                            crate::debug_panel::record_stage(
                                if addr.is_ipv6() {
                                    "TCP 建连 (Pingora 域名->IPv6)"
                                } else {
                                    "TCP 建连 (Pingora 域名->IPv4)"
                                },
                                _ct0.elapsed(),
                            );
                            return Ok(stream);
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
                Err(last_err.unwrap_or_else(|| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Failed to resolve or connect to {}", addr_str),
                    ))
                }))
            }
        }
    }
}
