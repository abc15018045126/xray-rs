// Module: proxy\tun\runner.rs
// High-performance TUN runner powered by tun2proxy and native Xray dispatcher

use clap::Parser;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use super::config::TunConfig;
use super::datagram::handle_inbound_datagram;
use super::routes;
use crate::app::dispatcher::DefaultDispatcher;
use crate::common::errors::{Error, Result};

pub struct TunRunner {
    pub cfg: TunConfig,
    cancellation_token: CancellationToken,
}

impl TunRunner {
    pub fn new(cfg: TunConfig) -> Self {
        Self {
            cfg,
            cancellation_token: CancellationToken::new(),
        }
    }

    pub fn shutdown(&self) {
        info!("shutting down tun runner");
        let tun_name = if self.cfg.name.is_empty() {
            "xray-tun".to_string()
        } else {
            self.cfg.name.clone()
        };
        let _ = routes::maybe_routes_clean_up(&self.cfg, &tun_name);
        self.cancellation_token.cancel();
    }

    pub async fn start(&self, dispatcher: Arc<DefaultDispatcher>) -> Result<JoinHandle<()>> {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return Ok(tokio::spawn(async {}));
        }

        let cfg = self.cfg.clone();
        let cancellation_token = self.cancellation_token.clone();

        // 1. Bind internal loopback SOCKS5 server for tun2proxy integration
        let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(Error::Io)?;
        let socks_addr = socks_listener.local_addr().map_err(Error::Io)?;
        let socks_port = socks_addr.port();
        info!("tun internal SOCKS5 bridge listening on {}", socks_addr);

        // Bind internal UDP socket for SOCKS5 UDP ASSOCIATE
        let udp_socket = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(Error::Io)?,
        );
        let udp_associate_addr = udp_socket.local_addr().map_err(Error::Io)?;
        let udp_port = udp_associate_addr.port();
        info!(
            "tun internal UDP associate bridge listening on {}",
            udp_associate_addr
        );

        // Spawn SOCKS5 TCP listener loop
        let dsp_tcp = dispatcher.clone();
        let sniffing_tcp = cfg.sniffing.clone();
        let cancel_tcp = cancellation_token.clone();
        let udp_port_for_socks = udp_port;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_tcp.cancelled() => break,
                    conn = socks_listener.accept() => {
                        let (mut stream, peer) = match conn {
                            Ok(c) => c,
                            Err(e) => {
                                error!("tun SOCKS5 accept error: {}", e);
                                continue;
                            }
                        };
                        let d = dsp_tcp.clone();
                        let s = sniffing_tcp.clone();
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};

                            // SOCKS5 greeting negotiation
                            let ver = match stream.read_u8().await {
                                Ok(v) => v,
                                Err(_) => return,
                            };
                            if ver != 0x05 {
                                return;
                            }
                            let nmethods = match stream.read_u8().await {
                                Ok(n) => n as usize,
                                Err(_) => return,
                            };
                            let mut methods = vec![0u8; nmethods];
                            if stream.read_exact(&mut methods).await.is_err() {
                                return;
                            }
                            if stream.write_all(&[0x05, 0x00]).await.is_err() || stream.flush().await.is_err() {
                                return;
                            }

                            // SOCKS5 request
                            let ver = match stream.read_u8().await {
                                Ok(v) => v,
                                Err(_) => return,
                            };
                            if ver != 0x05 {
                                return;
                            }
                            let cmd = match stream.read_u8().await {
                                Ok(c) => c,
                                Err(_) => return,
                            };
                            let _rsv = match stream.read_u8().await {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            let atyp = match stream.read_u8().await {
                                Ok(a) => a,
                                Err(_) => return,
                            };

                            let address = match atyp {
                                0x01 => {
                                    let mut ip = [0u8; 4];
                                    if stream.read_exact(&mut ip).await.is_err() {
                                        return;
                                    }
                                    crate::common::net::Address::Ipv4(std::net::Ipv4Addr::from(ip))
                                }
                                0x03 => {
                                    let len = match stream.read_u8().await {
                                        Ok(l) => l as usize,
                                        Err(_) => return,
                                    };
                                    let mut dom = vec![0u8; len];
                                    if stream.read_exact(&mut dom).await.is_err() {
                                        return;
                                    }
                                    crate::common::net::Address::Domain(String::from_utf8_lossy(&dom).to_string())
                                }
                                0x04 => {
                                    let mut ip = [0u8; 16];
                                    if stream.read_exact(&mut ip).await.is_err() {
                                        return;
                                    }
                                    crate::common::net::Address::Ipv6(std::net::Ipv6Addr::from(ip))
                                }
                                _ => return,
                            };
                            let port = match stream.read_u16().await {
                                Ok(p) => p,
                                Err(_) => return,
                            };

                            if cmd == 0x01 {
                                // TCP CONNECT
                                if stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await.is_err() || stream.flush().await.is_err() {
                                    return;
                                }
                                let destination = crate::common::net::Destination {
                                    network: crate::common::net::Network::Tcp,
                                    address,
                                    port,
                                };
                                let mut session = crate::common::protocol::SessionContext::new("tun-in", destination);
                                session.source = Some(peer);
                                session.sniffing_request = s;
                                let _ = d.dispatch(Box::pin(stream), session).await;
                            } else if cmd == 0x03 {
                                // UDP ASSOCIATE
                                let port_bytes = udp_port_for_socks.to_be_bytes();
                                let resp = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, port_bytes[0], port_bytes[1]];
                                if stream.write_all(&resp).await.is_err() || stream.flush().await.is_err() {
                                    return;
                                }
                                // Hold TCP connection until client closes or cancel
                                let mut discard = [0u8; 64];
                                while let Ok(n) = stream.read(&mut discard).await {
                                    if n == 0 {
                                        break;
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });

        // Spawn SOCKS5 UDP datagram handler loop
        let dsp_udp = dispatcher.clone();
        let sniffing_udp = cfg.sniffing.clone();
        let cancel_udp = cancellation_token.clone();
        let udp_socket_clone = udp_socket.clone();
        tokio::spawn(async move {
            handle_inbound_datagram(udp_socket_clone, dsp_udp, sniffing_udp, cancel_udp).await;
        });

        // 2. Configure and create TUN device using cross-platform `tun` crate
        let tun_name = if cfg.name.is_empty() {
            "xray-tun".to_string()
        } else {
            cfg.name.clone()
        };
        let mtu = if cfg.mtu > 0 { cfg.mtu as u16 } else { 1500u16 };

        let mut tun_cfg = tun::Configuration::default();
        tun_cfg.tun_name(&tun_name).mtu(mtu);

        #[cfg(target_os = "windows")]
        {
            tun_cfg
                .address(cfg.gateway.addr())
                .netmask(cfg.gateway.netmask())
                .up();
            let guid =
                uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, tun_name.as_bytes()).as_u128();
            tun_cfg.platform_config(move |p| {
                p.device_guid(guid);
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            tun_cfg
                .address(cfg.gateway.addr())
                .netmask(cfg.gateway.netmask())
                .up();
        }

        info!("initializing TUN device with tun2proxy: {}", tun_name);
        let device = tun::create_as_async(&tun_cfg).map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "failed to create tun device {}: {}",
                tun_name, e
            )))
        })?;

        // Configure system routing table
        if let Err(e) = routes::maybe_add_routes(&cfg, &tun_name) {
            error!("failed to configure routes for {}: {}", tun_name, e);
        }

        // 3. Launch `tun2proxy::run` with cancellation token
        let args = tun2proxy::Args::parse_from([
            "tun2proxy",
            "--proxy",
            &format!("socks5://127.0.0.1:{}", socks_port),
            "--dns",
            "direct",
        ]);

        let cfg_clean = cfg.clone();
        let tun_name_clean = tun_name.clone();
        let cancel_run = cancellation_token.clone();

        let handle = tokio::spawn(async move {
            let res = tun2proxy::run(device, mtu, args, cancel_run).await;
            info!("tun2proxy exited: {:?}", res);
            let _ = routes::maybe_routes_clean_up(&cfg_clean, &tun_name_clean);
        });

        Ok(handle)
    }
}
