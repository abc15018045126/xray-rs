use super::ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig, TcpOptions};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use super::config::TunConfig;
use super::routes;
use crate::app::dispatcher::DefaultDispatcher;
#[cfg(not(target_os = "android"))]
use crate::common::errors::Error;
use crate::common::errors::Result;
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;

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
        let tun_name = if cfg.name.is_empty() {
            "xray-tun".to_string()
        } else {
            cfg.name.clone()
        };
        let mtu = if cfg.mtu > 0 { cfg.mtu as u16 } else { 1500u16 };
        info!("initializing TUN device with native ipstack: {}", tun_name);
        #[cfg(target_os = "windows")]
        let device = {
            let guid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, tun_name.as_bytes()).as_u128();
            let dev = super::tun_windows::WintunAsyncDevice::create(&tun_name, guid, 0x800000)
                .map_err(|e| {
                    Error::Io(std::io::Error::other(format!(
                        "failed to create native wintun device {}: {}",
                        tun_name, e
                    )))
                })?;
            for _ in 0..30 {
                if let Some(iface) = super::net::get_interface_by_name(&tun_name) {
                    let _ = super::routes::add_address(&iface, cfg.gateway.into());
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            dev
        };
        #[cfg(target_os = "android")]
        let device = { super::tun_android::AndroidTunDevice::from_env()? };
        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        let device = {
            let mut tun_cfg = tun::Configuration::default();
            tun_cfg.tun_name(&tun_name).mtu(mtu);
            tun_cfg.address(cfg.gateway.addr()).netmask(cfg.gateway.netmask()).up();
            tun::create_as_async(&tun_cfg).map_err(|e| {
                Error::Io(std::io::Error::other(format!("failed to create tun device {}: {}", tun_name, e)))
            })?
        };
        #[cfg(not(target_os = "android"))]
        if let Err(e) = routes::maybe_add_routes(&cfg, &tun_name) {
            error!("failed to configure routes for {}: {}", tun_name, e);
        }
        let mut ipstack_cfg = IpStackConfig::default();
        let _ = ipstack_cfg.mtu(mtu);
        let mss = mtu.saturating_sub(40).max(536);
        let tcp_cfg = TcpConfig {
            options: Some(vec![TcpOptions::MaximumSegmentSize(mss)]),
            ..Default::default()
        };
        ipstack_cfg.with_tcp_config(tcp_cfg);
        let mut ip_stack = IpStack::new(ipstack_cfg, device);
        let cfg_clean = cfg.clone();
        let tun_name_clean = tun_name.clone();
        let cancel_run = cancellation_token.clone();
        let dsp = dispatcher.clone();
        let sniffing = cfg.sniffing.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_run.cancelled() => {
                        info!("tun runner cancelled");
                        break;
                    }
                    res = ip_stack.accept() => match res {
                        Ok(stream) => {
                            let (network, local, peer, boxed, kind): (Network, _, _, crate::common::net::BoxStream, _) = match stream {
                                IpStackStream::Tcp(s) => (Network::Tcp, s.local_addr(), s.peer_addr(), Box::pin(s), "TCP"),
                                IpStackStream::Udp(s) => (Network::Udp, s.local_addr(), s.peer_addr(), Box::pin(s), "UDP"),
                                _ => continue,
                            };
                            if should_drop_tun_addr(local.ip(), peer.ip()) { continue; }
                            let dest = Destination { network, address: Address::ip(peer.ip()), port: peer.port() };
                            let mut session = SessionContext::new("tun-in", dest);
                            session.inbound_tag = "tun".to_string();
                            session.source = Some(local);
                            session.sniffing_request = sniffing.clone();
                            let d = dsp.clone();
                            tokio::spawn(async move {
                                if let Err(e) = d.dispatch(boxed, session).await {
                                    debug!("tun {} dispatch error: {}", kind, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("ipstack accept error: {}", e);
                            break;
                        }
                    }
                }
            }
            info!("tun runner exiting, cleaning up routes...");
            let _ = routes::maybe_routes_clean_up(&cfg_clean, &tun_name_clean);
        });
        Ok(handle)
    }
}

fn should_drop_tun_addr(src: std::net::IpAddr, dst: std::net::IpAddr) -> bool {
    if src.is_loopback() || dst.is_loopback() || dst.is_unspecified() || src.is_multicast() || dst.is_multicast()
    { return true; }
    matches!(dst, std::net::IpAddr::V4(v4) if v4.is_broadcast())
}
