use anyhow::anyhow;
use ipnet::IpNet;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tracing::{debug, error, info, warn};
use windows::{
    core::{GUID, PWSTR},
    Win32::{
        Foundation::ERROR_OBJECT_ALREADY_EXISTS,
        NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
            DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
            DNS_SETTING_NAMESERVER, GetIfEntry2, InitializeIpForwardEntry, IP_ADDRESS_PREFIX,
            MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, IpPrefixOriginManual, IpSuffixOriginManual, SOCKADDR_INET,
        },
    },
};

use super::super::config::TunConfig;
use super::super::net::OutboundInterface;

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    warn!("adding route to destination {} via {}", dest, via.name);
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }

    row.InterfaceIndex = via.index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: match dest {
            IpNet::V4(ipv4) => {
                let mut s = SOCKADDR_INET::default();
                s.Ipv4.sin_family = AF_INET;
                s.Ipv4.sin_addr = ipv4.addr().into();
                s
            }
            IpNet::V6(ipv6) => {
                let mut s = SOCKADDR_INET::default();
                s.Ipv6.sin6_family = AF_INET6;
                s.Ipv6.sin6_addr = ipv6.addr().into();
                s
            }
        },
        PrefixLength: dest.prefix_len(),
    };
    let metric = 0;
    let next_hop: SocketAddr = if dest.addr().is_ipv4() {
        (
            via.addr_v4
                .ok_or_else(|| io::Error::other("tun interface has no ipv4 address"))?,
            0,
        )
            .into()
    } else {
        (
            via.addr_v6
                .ok_or_else(|| io::Error::other("tun interface has no ipv6 address"))?,
            0,
        )
            .into()
    };
    row.NextHop = next_hop.into();
    row.Metric = metric;

    let res = unsafe { CreateIpForwardEntry2(&row) }.to_hresult();
    if let Err(e) = res.ok() {
        if e.code().0 == ERROR_OBJECT_ALREADY_EXISTS.0 as i32
            || e.code().0 as u32 == 0x80071392
        {
            warn!(
                "route to destination {} via {} already exists",
                dest, via.name
            );
            return Ok(());
        }
        error!(
            "failed to add route to destination {} via {}: {}",
            dest, via.name, e
        );
        return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
    }

    info!("successfully added route to destination {} via {}", dest, via.name);
    Ok(())
}

pub fn delete_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    warn!("deleting route to destination {} via {}", dest, via.name);
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }

    row.InterfaceIndex = via.index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: match dest {
            IpNet::V4(ipv4) => {
                let mut s = SOCKADDR_INET::default();
                s.Ipv4.sin_family = AF_INET;
                s.Ipv4.sin_addr = ipv4.addr().into();
                s
            }
            IpNet::V6(ipv6) => {
                let mut s = SOCKADDR_INET::default();
                s.Ipv6.sin6_family = AF_INET6;
                s.Ipv6.sin6_addr = ipv6.addr().into();
                s
            }
        },
        PrefixLength: dest.prefix_len(),
    };
    let next_hop: SocketAddr = if dest.addr().is_ipv4() {
        if let Some(v4) = via.addr_v4 {
            (v4, 0).into()
        } else {
            return Ok(());
        }
    } else {
        if let Some(v6) = via.addr_v6 {
            (v6, 0).into()
        } else {
            return Ok(());
        }
    };
    row.NextHop = next_hop.into();

    let res = unsafe { DeleteIpForwardEntry2(&row) }.to_hresult();
    if let Err(e) = res.ok() {
        debug!("delete route to destination {} via {}: {}", dest, via.name, e);
    }
    Ok(())
}

fn get_guid(iface: &OutboundInterface) -> Option<GUID> {
    let mut if_row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    if_row.InterfaceIndex = iface.index;

    let result = unsafe { GetIfEntry2(&mut if_row) }.to_hresult().ok();
    match result {
        Ok(_) => Some(if_row.InterfaceGuid),
        Err(e) => {
            error!(
                "failed to get interface row with index: {} due to {}",
                iface.index, e
            );
            None
        }
    }
}

pub fn set_dns_v4(
    iface: &OutboundInterface,
    name_servers: &[Ipv4Addr],
) -> anyhow::Result<()> {
    let mut dns_wstr = name_servers
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
        .encode_utf16()
        .collect::<Vec<u16>>();
    dns_wstr.push(0);

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64,
        NameServer: PWSTR::from_raw(dns_wstr.as_mut_ptr()),
        ..Default::default()
    };

    let guid = get_guid(iface).ok_or_else(|| anyhow!("interface {} not found", iface.name))?;

    unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
        .to_hresult()
        .ok()
        .map_err(|e| anyhow::anyhow!(e))
}

pub fn set_dns_v6(
    iface: &OutboundInterface,
    name_servers: &[Ipv6Addr],
) -> anyhow::Result<()> {
    let mut dns_wstr = name_servers
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
        .encode_utf16()
        .collect::<Vec<u16>>();
    dns_wstr.push(0);

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6) as u64,
        NameServer: PWSTR::from_raw(dns_wstr.as_mut_ptr()),
        ..Default::default()
    };

    let guid = get_guid(iface).ok_or_else(|| anyhow!("interface {} not found", iface.name))?;

    unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
        .to_hresult()
        .ok()
        .map_err(|e| anyhow::anyhow!(e))
}

#[allow(dead_code)]
pub fn add_address(
    iface: &OutboundInterface,
    addr_net: IpNet,
) -> anyhow::Result<()> {
    let mut addr_inet = SOCKADDR_INET::default();
    match addr_net {
        IpNet::V4(ipv4_net) => {
            addr_inet.Ipv4.sin_family = windows::Win32::Networking::WinSock::ADDRESS_FAMILY(AF_INET.0);
            addr_inet.Ipv4.sin_addr.S_un.S_addr = u32::from_le_bytes(ipv4_net.addr().octets());
        }
        IpNet::V6(ipv6_net) => {
            addr_inet.Ipv6.sin6_family = windows::Win32::Networking::WinSock::ADDRESS_FAMILY(AF_INET6.0);
            addr_inet.Ipv6.sin6_addr.u.Byte = ipv6_net.addr().octets();
        }
    }

    let row = MIB_UNICASTIPADDRESS_ROW {
        InterfaceIndex: iface.index,
        Address: addr_inet,
        OnLinkPrefixLength: addr_net.prefix_len(),
        PrefixOrigin: IpPrefixOriginManual,
        SuffixOrigin: IpSuffixOriginManual,
        ValidLifetime: 0xffffffff,
        PreferredLifetime: 0xffffffff,
        SkipAsSource: false,
        ..Default::default()
    };

    let res = unsafe { CreateUnicastIpAddressEntry(&row) }.to_hresult();
    if res.is_ok() || res == ERROR_OBJECT_ALREADY_EXISTS.to_hresult() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("failed to add address to tun interface: {}", res.message()))
    }
}

pub fn maybe_routes_clean_up(cfg: &TunConfig, tun_name: &str) -> io::Result<()> {
    if let Some(via) = super::super::net::get_interface_by_name(tun_name) {
        if cfg.route_all {
            let r1 = "0.0.0.0/1".parse().unwrap();
            let r2 = "128.0.0.0/1".parse().unwrap();
            let _ = delete_route(&via, &r1);
            let _ = delete_route(&via, &r2);
            if via.addr_v6.is_some() {
                let v6_1 = "::/1".parse().unwrap();
                let v6_2 = "8000::/1".parse().unwrap();
                let _ = delete_route(&via, &v6_1);
                let _ = delete_route(&via, &v6_2);
            }
        }
        for r in &cfg.routes {
            let _ = delete_route(&via, r);
        }
    }
    Ok(())
}
