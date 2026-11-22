use ipnet::IpNet;
use std::{io, net::SocketAddr};
use tracing::{debug, error, info, warn};

use super::super::config::TunConfig;
use super::super::net::OutboundInterface;

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    warn!("adding route to destination {} via {}", dest, via.name);
    let next_hop: SocketAddr = if dest.addr().is_ipv4() {
        (via.addr_v4.ok_or_else(|| io::Error::other("tun interface has no ipv4 address"))?, 0).into()
    } else {
        (via.addr_v6.ok_or_else(|| io::Error::other("tun interface has no ipv6 address"))?, 0).into()
    };
    match xray_rs_window::add_ip_forward_entry(via.index, dest, next_hop, 0) {
        Ok(true) => info!("successfully added route to destination {} via {}", dest, via.name),
        Ok(false) => warn!("route to destination {} via {} already exists", dest, via.name),
        Err(e) => {
            error!("failed to add route to destination {} via {}: {}", dest, via.name, e);
            return Err(e);
        }
    }
    Ok(())
}

pub fn delete_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    warn!("deleting route to destination {} via {}", dest, via.name);
    let next_hop: SocketAddr = if dest.addr().is_ipv4() {
        let Some(v4) = via.addr_v4 else { return Ok(()); };
        (v4, 0).into()
    } else {
        let Some(v6) = via.addr_v6 else { return Ok(()); };
        (v6, 0).into()
    };
    if let Err(e) = xray_rs_window::delete_ip_forward_entry(via.index, dest, next_hop) {
        debug!("delete route to destination {} via {}: {}", dest, via.name, e);
    }
    Ok(())
}

#[allow(dead_code)]
pub fn add_address(iface: &OutboundInterface, addr_net: IpNet) -> io::Result<()> {
    xray_rs_window::add_unicast_ip_address(iface.index, addr_net)
}

pub fn maybe_routes_clean_up(cfg: &TunConfig, tun_name: &str) -> io::Result<()> {
    if let Some(via) = super::super::net::get_interface_by_name(tun_name) {
        if cfg.route_all {
            for r in ["0.0.0.0/1", "128.0.0.0/1"] { let _ = delete_route(&via, &r.parse().unwrap()); }
            if via.addr_v6.is_some() {
                for r in ["::/1", "8000::/1"] { let _ = delete_route(&via, &r.parse().unwrap()); }
            }
        }
        for r in &cfg.routes { let _ = delete_route(&via, r); }
    }
    Ok(())
}
