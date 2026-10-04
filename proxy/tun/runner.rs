use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use super::config::TunConfig;
use super::datagram::handle_inbound_datagram;
use super::routes;
use super::stream::handle_inbound_stream;
use crate::app::dispatcher::DefaultDispatcher;
use crate::common::errors::{Error, Result};

const TUN_VISIBILITY_MAX_ATTEMPTS: u32 = 40;
const TUN_VISIBILITY_POLL_INTERVAL_MS: u64 = 50;

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
        let _ = routes::maybe_routes_clean_up(&self.cfg, &self.cfg.name);
        self.cancellation_token.cancel();
    }

    pub async fn start(&self, dispatcher: Arc<DefaultDispatcher>) -> Result<JoinHandle<()>> {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return Ok(tokio::spawn(async {}));
        }

        let cfg = self.cfg.clone();
        let cancellation_token = self.cancellation_token.clone();

        #[cfg(target_os = "windows")]
        {
            return self
                .start_windows(dispatcher, cfg, cancellation_token)
                .await;
        }

        #[cfg(not(target_os = "windows"))]
        {
            return self
                .start_non_windows(dispatcher, cfg, cancellation_token)
                .await;
        }
    }

    #[cfg(target_os = "windows")]
    async fn start_windows(
        &self,
        dispatcher: Arc<DefaultDispatcher>,
        cfg: TunConfig,
        cancellation_token: CancellationToken,
    ) -> Result<JoinHandle<()>> {
        let tun_name = if cfg.name.is_empty() {
            "xray-tun".to_string()
        } else {
            cfg.name.clone()
        };

        info!("initializing pure Rust native Wintun adapter: {}", tun_name);

        let guid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, tun_name.as_bytes()).as_u128();

        let adapter = Arc::new(
            wintun::Adapter::create(&tun_name, "Xray", Some(guid))
                .or_else(|_| wintun::Adapter::open(&tun_name))
                .map_err(|e| {
                    Error::Other(format!(
                        "failed to create wintun adapter {}: {}",
                        tun_name, e
                    ))
                })?,
        );

        let session = Arc::new(
            adapter
                .start_session(0x400000)
                .map_err(|e| Error::Other(format!("failed to start wintun session: {}", e)))?,
        );

        let mut tun_iface_opt = None;
        for _ in 0..TUN_VISIBILITY_MAX_ATTEMPTS {
            if let Some(iface) = super::net::get_interface_by_name(&tun_name) {
                tun_iface_opt = Some(iface);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(
                TUN_VISIBILITY_POLL_INTERVAL_MS,
            ))
            .await;
        }

        let tun_iface = tun_iface_opt.ok_or_else(|| {
            Error::Other(format!("tun device {} not visible after waiting", tun_name))
        })?;

        // Assign IP addresses to the Wintun adapter
        let _ = routes::add_address(&tun_iface, ipnet::IpNet::V4(cfg.gateway));
        if let Some(gw6) = cfg.gateway_v6 {
            let _ = routes::add_address(&tun_iface, ipnet::IpNet::V6(gw6));
        }

        // Configure system routing table and DNS
        routes::maybe_add_routes(&cfg, &tun_name).map_err(Error::Io)?;

        // Initialize user-space network stack
        let (stack, mut tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let handle = tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(2048);
            let session_recv = session.clone();
            let cancel_recv = cancellation_token.clone();

            // Background reader thread: zero-copy ring buffer drain (100% safe Rust, no unsafe!)
            std::thread::Builder::new()
                .name("wintun-receiver".to_string())
                .spawn(move || {
                    while !cancel_recv.is_cancelled() {
                        let mut had_packet = false;
                        while let Ok(Some(pkt)) = session_recv.receive_packet() {
                            had_packet = true;
                            let b = bytes::Bytes::copy_from_slice(&pkt);
                            if tx.blocking_send(b).is_err() {
                                return;
                            }
                        }

                        if !had_packet {
                            session_recv.wait_for_data(50);
                        }
                    }
                })
                .expect("failed to spawn wintun receiver thread");

            // Dispatch packets from Wintun -> Stack
            let mut fut_tun_dispatcher = async || {
                while let Some(pkt) = rx.recv().await {
                    if let Err(e) = stack_sink.send(watfaq_netstack::Packet::new(pkt)).await {
                        error!("failed to send pkt to stack: {}", e);
                        break;
                    }
                }
            };

            // Dispatch packets from Stack -> Wintun
            let session_send = session.clone();
            let mut fut_dispatcher_tun = async || {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            let data = pkt.into_bytes();
                            match session_send.allocate_send_packet(data.len() as u32) {
                                Ok(mut send_pkt) => {
                                    send_pkt.copy_from_slice(&data);
                                    session_send.send_packet(send_pkt);
                                }
                                Err(_) => {
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            error!("tun stack error: {}", e);
                            break;
                        }
                    }
                }
            };

            let dsp = dispatcher.clone();
            let sniffing = cfg.sniffing.clone();
            let mut fut_tcp_dispatch = async || {
                while let Some(stream) = tcp_listener.next().await {
                    debug!(
                        "new tun TCP connection: {} -> {}",
                        stream.local_addr(),
                        stream.remote_addr()
                    );
                    let d = dsp.clone();
                    let s = sniffing.clone();
                    tokio::spawn(async move {
                        handle_inbound_stream(stream, d, s).await;
                    });
                }
            };

            let dsp_udp = dispatcher.clone();
            let sniffing_udp = cfg.sniffing.clone();
            let fut_udp_dispatch = async || {
                handle_inbound_datagram(udp_socket, dsp_udp, sniffing_udp).await;
            };

            tokio::select! {
                _ = fut_dispatcher_tun() => {},
                _ = fut_tun_dispatcher() => {},
                _ = fut_tcp_dispatch() => {},
                _ = fut_udp_dispatch() => {},
                _ = cancellation_token.cancelled() => {
                    info!("tun stop signal received");
                }
            }

            drop(adapter);
            info!("tun runner exited");
        });

        Ok(handle)
    }

    #[cfg(not(target_os = "windows"))]
    async fn start_non_windows(
        &self,
        dispatcher: Arc<DefaultDispatcher>,
        cfg: TunConfig,
        cancellation_token: CancellationToken,
    ) -> Result<JoinHandle<()>> {
        let (dev, stack, mut tcp_listener, udp_socket) = Self::new_internal(&cfg).await?;

        let framed =
            tun_rs::async_framed::DeviceFramed::new(dev, tun_rs::async_framed::BytesCodec::new());
        let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let handle = tokio::spawn(async move {
            let mut fut_dispatcher_tun = async || {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                                if e.kind() == std::io::ErrorKind::TimedOut
                                    || e.kind() == std::io::ErrorKind::WouldBlock
                                {
                                    continue;
                                }
                                error!("failed to send pkt to tun: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stack error: {}", e);
                            break;
                        }
                    }
                }
            };

            let mut fut_tun_dispatcher = async || {
                while let Some(pkt) = tun_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = stack_sink.send(watfaq_netstack::Packet::new(pkt)).await
                            {
                                error!("failed to send pkt to stack: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stream error: {}", e);
                            break;
                        }
                    }
                }
            };

            let dsp = dispatcher.clone();
            let sniffing = cfg.sniffing.clone();
            let mut fut_tcp_dispatch = async || {
                while let Some(stream) = tcp_listener.next().await {
                    debug!(
                        "new tun TCP connection: {} -> {}",
                        stream.local_addr(),
                        stream.remote_addr()
                    );
                    let d = dsp.clone();
                    let s = sniffing.clone();
                    tokio::spawn(async move {
                        handle_inbound_stream(stream, d, s).await;
                    });
                }
            };

            let dsp_udp = dispatcher.clone();
            let sniffing_udp = cfg.sniffing.clone();
            let fut_udp_dispatch = async || {
                handle_inbound_datagram(udp_socket, dsp_udp, sniffing_udp).await;
            };

            tokio::select! {
                _ = fut_dispatcher_tun() => {},
                _ = fut_tun_dispatcher() => {},
                _ = fut_tcp_dispatch() => {},
                _ = fut_udp_dispatch() => {},
                _ = cancellation_token.cancelled() => {
                    info!("tun stop signal received");
                }
            }

            info!("tun runner exited");
        });

        Ok(handle)
    }

    #[cfg(not(target_os = "windows"))]
    async fn new_internal(
        cfg: &TunConfig,
    ) -> Result<(
        tun_rs::AsyncDevice,
        watfaq_netstack::NetStack,
        watfaq_netstack::TcpListener,
        watfaq_netstack::UdpSocket,
    )> {
        let tun_name = if cfg.name.is_empty() {
            "xray_tun".to_string()
        } else {
            cfg.name.clone()
        };

        let tun_exist = network_interface::NetworkInterface::show()
            .map(|ifs| ifs.into_iter().any(|x| x.name == tun_name))
            .unwrap_or_default();

        if tun_exist {
            info!("tun device {} already exists, using it.", &tun_name);
        } else {
            info!("tun device {} does not exist, creating.", &tun_name);
        }

        let mut tun_builder = tun_rs::DeviceBuilder::new();
        let mtu = if cfg.mtu > 0 { cfg.mtu as u16 } else { 1500u16 };
        tun_builder = tun_builder.name(&tun_name).mtu(mtu);

        if !tun_exist {
            debug!("setting tun ipv4 addr: {:?}", cfg.gateway);
            tun_builder = tun_builder.ipv4(cfg.gateway.addr(), cfg.gateway.netmask(), None);
            if let Some(gateway_v6) = cfg.gateway_v6 {
                debug!("setting tun ipv6 addr: {:?}", cfg.gateway_v6);
                tun_builder = tun_builder.ipv6(gateway_v6.addr(), gateway_v6.netmask());
            }
        }

        let dev = tun_builder.build_async().map_err(|e| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        if !tun_exist {
            let mut tun_visible = false;
            for _ in 0..TUN_VISIBILITY_MAX_ATTEMPTS {
                if let Ok(ifs) = network_interface::NetworkInterface::show() {
                    if ifs.into_iter().any(|x| x.name == tun_name) {
                        tun_visible = true;
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(
                    TUN_VISIBILITY_POLL_INTERVAL_MS,
                ))
                .await;
            }

            if !tun_visible {
                return Err(Error::Other(format!(
                    "tun device {} not visible after waiting",
                    tun_name
                )));
            }

            info!("setting up routes for tun {}", &tun_name);
            routes::maybe_add_routes(cfg, &tun_name).map_err(Error::Io)?;
        }

        let (stack, tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();
        Ok((dev, stack, tcp_listener, udp_socket))
    }
}
