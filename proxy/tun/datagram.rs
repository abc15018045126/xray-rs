use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, trace};
use watfaq_netstack::{Packet, UdpPacket, UdpSocket};

use crate::app::dispatcher::DefaultDispatcher;
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::common::session::SniffingRequest;

struct SessionEntry {
    tx: mpsc::Sender<Vec<u8>>,
    last_seen: Instant,
}

pub async fn handle_inbound_datagram(
    socket: UdpSocket,
    dispatcher: Arc<DefaultDispatcher>,
    sniffing: Option<SniffingRequest>,
) {
    let (mut lr, ls) = socket.split();
    let sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), SessionEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Background cleanup task for expired UDP sessions
    let sessions_cleaner = sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut guard = sessions_cleaner.lock().await;
            let now = Instant::now();
            guard.retain(|_, entry| now.duration_since(entry.last_seen) < Duration::from_secs(60));
        }
    });

    while let Some(pkt) = lr.recv().await {
        let local_addr = pkt.local_addr;
        let remote_addr = pkt.remote_addr;

        if remote_addr.ip().is_multicast() || remote_addr.ip().is_unspecified() {
            continue;
        }

        if let std::net::IpAddr::V4(ipv4) = remote_addr.ip()
            && (ipv4.is_broadcast()
                || ipv4.octets()[3] == 255
                || ipv4 == std::net::Ipv4Addr::new(172, 19, 0, 3))
        {
            continue;
        }

        // Drop Windows LAN discovery / NetBIOS / LLMNR broadcasts
        if matches!(
            remote_addr.port(),
            135 | 137 | 138 | 139 | 5353 | 5355 | 1900
        ) {
            continue;
        }

        trace!(
            "tun UDP packet: {} -> {}, len={}",
            local_addr,
            remote_addr,
            pkt.data().len()
        );

        let key = (local_addr, remote_addr);
        let mut guard = sessions.lock().await;

        let mut need_new_session = false;
        if let Some(entry) = guard.get_mut(&key) {
            match entry.tx.try_send(pkt.data().to_vec()) {
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
            let _ = packet_tx.send(pkt.data().to_vec()).await;

            guard.insert(
                key,
                SessionEntry {
                    tx: packet_tx,
                    last_seen: Instant::now(),
                },
            );
            drop(guard);

            let (app_stream, tun_side) = tokio::io::duplex(64 * 1024);
            let mut ls_clone = ls.clone();

            tokio::spawn(async move {
                let (mut tun_r, mut tun_w) = tokio::io::split(tun_side);

                let send_task = async {
                    let mut buf = vec![0u8; 2048];
                    loop {
                        match tun_r.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let resp = UdpPacket {
                                    data: Packet::new(buf[..n].to_vec()),
                                    local_addr: remote_addr,
                                    remote_addr: local_addr,
                                };
                                if let Err(e) = ls_clone.send(resp).await {
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

            let destination = Destination {
                network: Network::Udp,
                address: Address::ip(remote_addr.ip()),
                port: remote_addr.port(),
            };
            let mut session = SessionContext::new("tun-in", destination);
            session.source = Some(local_addr);
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
