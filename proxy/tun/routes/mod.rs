#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{add_address, add_route, delete_route, maybe_routes_clean_up};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{add_route, maybe_add_default_route, maybe_routes_clean_up};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    add_route, check_ip_command_installed, maybe_routes_clean_up, setup_policy_routing,
};

#[cfg(not(any(windows, target_os = "macos", target_os = "linux",)))]
mod other;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux",)))]
pub use other::{add_route, maybe_routes_clean_up};

use super::config::TunConfig;
use super::net::get_interface_by_name;
use tracing::warn;

pub fn maybe_add_routes(cfg: &TunConfig, tun_name: &str) -> std::io::Result<()> {
    if !cfg.route_all && cfg.routes.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    linux::check_ip_command_installed()?;

    let tun_iface = get_interface_by_name(tun_name).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, format!("tun interface {} not found", tun_name))
    })?;

    if cfg.route_all {
        warn!("route_all is enabled, traffic will be routed through the tun interface");
        #[cfg(not(target_os = "linux"))]
        {
            let mut routes: Vec<ipnet::IpNet> = vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()];
            if tun_iface.addr_v6.is_some() {
                routes.extend(["::/1".parse::<ipnet::IpNet>().unwrap(), "8000::/1".parse().unwrap()]);
            }
            for r in &routes {
                add_route(&tun_iface, r)?;
            }
            #[cfg(target_os = "macos")]
            macos::maybe_add_default_route()?;
        }
        #[cfg(target_os = "linux")]
        linux::setup_policy_routing(cfg, &tun_iface)?;
    } else {
        for r in &cfg.routes {
            add_route(&tun_iface, r)?;
        }
    }
    Ok(())
}
