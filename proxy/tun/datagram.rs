// Module: proxy\tun\datagram.rs
// SOCKS5 UDP datagram handling for tun2proxy internal bridge

use crate::app::dispatcher::DefaultDispatcher;
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::common::session::SniffingRequest;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

struct SessionEntry {
    tx: mpsc::Sender<Vec<u8>>,
    last_seen: Instant,
}

pub fn parse_socks5_udp(buf: &[u8]) -> Option<(Destination, &[u8])> {
    if buf.len() < 7 {
        return None;
    }
    // buf[0..2] is RSV (0x00, 0x00), buf[2] is FRAG (0x00)
    let atyp = buf[3];
    match atyp {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((
                Destination {
                    network: Network::Udp,
                    address: Address::Ipv4(ip),
                    port,
                },
                &buf[10..],
            ))
        }
        0x03 => {
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return None;
            }
            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            Some((
                Destination {
                    network: Network::Udp,
                    address: Address::Domain(domain),
                    port,
                },
                &buf[7 + len..],
            ))
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((
                Destination {
                    network: Network::Udp,
                    address: Address::Ipv6(ip),
                    port,
                },
                &buf[22..],
            ))
        }
        _ => None,
    }
}

pub fn encode_socks5_udp(dest: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + payload.len());
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, RSV, FRAG
    match &dest.address {
        Address::Ipv4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.octets());
        }
        Address::Domain(domain) => {
            buf.push(0x03);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&dest.port.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub async fn handle_inbound_datagram(
    socket: Arc<UdpSocket>,
    dispatcher: Arc<DefaultDispatcher>,
    sniffing: Option<SniffingRequest>,
    cancel: CancellationToken,
) {
    let sessions: Arc<Mutex<HashMap<(SocketAddr, Destination), SessionEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Background session cleanup
    let sessions_cleaner = sessions.clone();
    let cancel_cleaner = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_cleaner.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    let mut guard = sessions_cleaner.lock().await;
                    let now = Instant::now();
                    guard.retain(|_, entry| now.duration_since(entry.last_seen) < Duration::from_secs(60));
                }
            }
        }
    });

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client_addr) = tokio::select! {
            _ = cancel.cancelled() => break,
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("tun UDP recv error: {}", e);
                        break;
                    }
                }
            }
        };

        let Some((dest, payload)) = parse_socks5_udp(&buf[..n]) else {
            continue;
        };

        trace!(
            "tun UDP packet from {}: dest={}, len={}",
            client_addr,
            dest,
            payload.len()
        );

        let key = (client_addr, dest.clone());
        let mut guard = sessions.lock().await;
        let mut need_new_session = false;

        if let Some(entry) = guard.get_mut(&key) {
            match entry.tx.try_send(payload.to_vec()) {
                Ok(_) => {
                    entry.last_seen = Instant::now();
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    entry.last_seen = Instant::now();
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    need_new_session = true;
                }
            }
        } else {
            need_new_session = true;
        }

        if need_new_session {
            let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(64);
            let _ = packet_tx.send(payload.to_vec()).await;

            guard.insert(
                key.clone(),
                SessionEntry {
                    tx: packet_tx,
                    last_seen: Instant::now(),
                },
            );
            drop(guard);

            let (app_stream, tun_side) = tokio::io::duplex(64 * 1024);
            let socket_clone = socket.clone();
            let dest_clone = dest.clone();

            tokio::spawn(async move {
                let (mut tun_r, mut tun_w) = tokio::io::split(tun_side);

                let send_task = async {
                    let mut read_buf = vec![0u8; 65535];
                    loop {
                        match tun_r.read(&mut read_buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let resp = encode_socks5_udp(&dest_clone, &read_buf[..n]);
                                if let Err(e) = socket_clone.send_to(&resp, client_addr).await {
                                    debug!("tun UDP send back failed: {}", e);
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                };

                let recv_task = async {
                    while let Some(data) = packet_rx.recv().await {
                        if tun_w.write_all(&data).await.is_err() {
                            break;
                        }
                        if tun_w.flush().await.is_err() {
                            break;
                        }
                    }
                };

                tokio::select! {
                    _ = send_task => {},
                    _ = recv_task => {},
                }
            });

            let mut session = SessionContext::new("tun-in", dest);
            session.source = Some(client_addr);
            session.sniffing_request = sniffing.clone();

            let d = dispatcher.clone();
            tokio::spawn(async move {
                if let Err(e) = d.dispatch(Box::pin(app_stream), session).await {
                    debug!("tun UDP session ended: {}", e);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_udp_ipv4_encode_decode() {
        let dest = Destination {
            network: Network::Udp,
            address: Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            port: 53,
        };
        let payload = b"hello udp dns query";
        let encoded = encode_socks5_udp(&dest, payload);
        let (parsed_dest, parsed_payload) =
            parse_socks5_udp(&encoded).expect("parse should succeed");
        assert_eq!(parsed_dest, dest);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_socks5_udp_domain_encode_decode() {
        let dest = Destination {
            network: Network::Udp,
            address: Address::Domain("dns.google.com".to_string()),
            port: 443,
        };
        let payload = b"quic client initial packet";
        let encoded = encode_socks5_udp(&dest, payload);
        let (parsed_dest, parsed_payload) =
            parse_socks5_udp(&encoded).expect("parse should succeed");
        assert_eq!(parsed_dest, dest);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_socks5_udp_ipv6_encode_decode() {
        let dest = Destination {
            network: Network::Udp,
            address: Address::Ipv6(std::net::Ipv6Addr::new(
                0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
            )),
            port: 53,
        };
        let payload = vec![0xAB; 512];
        let encoded = encode_socks5_udp(&dest, &payload);
        let (parsed_dest, parsed_payload) =
            parse_socks5_udp(&encoded).expect("parse should succeed");
        assert_eq!(parsed_dest, dest);
        assert_eq!(parsed_payload, payload.as_slice());
    }

    #[test]
    fn test_socks5_udp_invalid_header() {
        assert!(parse_socks5_udp(&[]).is_none());
        assert!(parse_socks5_udp(&[0, 0, 0, 1, 127]).is_none());
        assert!(parse_socks5_udp(&[0, 0, 0, 99, 1, 2, 3, 4, 0, 53]).is_none());
    }
}
