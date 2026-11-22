use super::super::config::TunConfig;
use super::super::net::OutboundInterface;
use ipnet::IpNet;
use tracing::warn;

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let flag = if matches!(dest, IpNet::V4(_)) { "-net" } else { "-inet6" };
    warn!("executing: route add {} {} -interface {}", flag, dest, via.name);
    let output = std::process::Command::new("route")
        .args(["add", flag, &dest.to_string(), "-interface", &via.name])
        .output()?;
    if output.status.success() { Ok(()) } else { Err(std::io::Error::other("add route failed")) }
}

pub fn maybe_add_default_route() -> std::io::Result<()> {
    Ok(())
}

pub fn maybe_routes_clean_up(_cfg: &TunConfig, _tun_name: &str) -> std::io::Result<()> {
    Ok(())
}
