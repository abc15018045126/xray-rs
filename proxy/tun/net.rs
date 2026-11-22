use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock};
use tracing::trace;

pub static DEFAULT_OUTBOUND_INTERFACE: LazyLock<
    Arc<tokio::sync::RwLock<Option<OutboundInterface>>>,
> = LazyLock::new(Default::default);

pub static TUN_SOMARK: LazyLock<tokio::sync::RwLock<Option<u32>>> = LazyLock::new(Default::default);

pub async fn init_net_config(tun_somark: Option<u32>) {
    *DEFAULT_OUTBOUND_INTERFACE.write().await = get_outbound_interface();
    *TUN_SOMARK.write().await = tun_somark;
    let (iface, somark) = (DEFAULT_OUTBOUND_INTERFACE.read().await, TUN_SOMARK.read().await);
    trace!("default outbound interface: {:?}, tun somark: {:?}", *iface, *somark);
}

#[derive(Debug, Clone)]
pub struct OutboundInterface {
    pub name: String,
    pub addr_v4: Option<Ipv4Addr>,
    pub netmask_v4: Option<Ipv4Addr>,
    pub broadcast_v4: Option<Ipv4Addr>,
    pub addr_v6: Option<Ipv6Addr>,
    pub netmask_v6: Option<Ipv6Addr>,
    pub broadcast_v6: Option<Ipv6Addr>,
    pub index: u32,
    pub mac_addr: Option<String>,
}

impl From<NetworkInterface> for OutboundInterface {
    fn from(iface: NetworkInterface) -> Self {
        let (mut v4, mut v6) = (None, None);
        for addr in &iface.addr {
            if v4.is_some() && v6.is_some() { break; }
            match addr {
                network_interface::Addr::V4(a) if !a.ip.is_loopback() && !a.ip.is_link_local() && !a.ip.is_unspecified() => v4 = Some(*a),
                network_interface::Addr::V6(a) if a.ip.is_unique_local() || (!a.ip.is_loopback() && !a.ip.is_unspecified()) => v6 = Some(*a),
                _ => {}
            }
        }
        OutboundInterface {
            name: iface.name, index: iface.index, mac_addr: iface.mac_addr,
            addr_v4: v4.map(|x| x.ip), netmask_v4: v4.and_then(|x| x.netmask), broadcast_v4: v4.and_then(|x| x.broadcast),
            addr_v6: v6.map(|x| x.ip), netmask_v6: v6.and_then(|x| x.netmask), broadcast_v6: v6.and_then(|x| x.broadcast),
        }
    }
}

pub fn get_interface_by_name(name: &str) -> Option<OutboundInterface> {
    let now = std::time::Instant::now();
    let outbound = network_interface::NetworkInterface::show()
        .ok()?.into_iter().find(|iface| iface.name == name)?.into();
    trace!("found interface by name: {:?}, took: {}ms", outbound, now.elapsed().as_millis());
    Some(outbound)
}

pub fn get_outbound_interface() -> Option<OutboundInterface> {
    let now = std::time::Instant::now();
    let mut outbounds: Vec<OutboundInterface> = network_interface::NetworkInterface::show().ok()?
        .into_iter().map(Into::into)
        .filter(|i: &OutboundInterface| !i.name.contains("tun") && (i.addr_v4.is_some() || i.addr_v6.is_some()))
        .collect();
    let prio: &[&str] = if cfg!(target_os = "windows") { &["Ethernet", "Wi-Fi", "Tailscale"] }
        else if cfg!(target_os = "linux") { &["eth", "wlp", "en", "Tailscale"] }
        else if cfg!(target_os = "macos") { &["en", "pdp_ip", "Tailscale"] }
        else { &["eth", "en", "wlp"] };
    outbounds.sort_by_key(|i| prio.iter().position(|x| i.name.contains(x)).unwrap_or(usize::MAX));
    trace!("sorted outbound interfaces: {:?}, took: {}ms", outbounds, now.elapsed().as_millis());
    outbounds.into_iter().next()
}
