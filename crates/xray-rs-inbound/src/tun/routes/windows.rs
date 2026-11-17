use ipnet::IpNet;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tracing::{debug, error, info, warn};
use windows::Win32::{
    Foundation::ERROR_OBJECT_ALREADY_EXISTS,
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
        GetIpInterfaceEntry, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
        InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
        MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IpPrefixOriginManual, IpSuffixOriginManual, RouterDiscoveryDisabled,
        SOCKADDR_INET,
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
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    row.NextHop = next_hop.into();
    row.Metric = metric;

    let res = unsafe { CreateIpForwardEntry2(&row) }.to_hresult();
    if let Err(e) = res.ok() {
        if e.code().0 == ERROR_OBJECT_ALREADY_EXISTS.0 as i32 || e.code().0 as u32 == 0x80071392 {
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
        return Err(io::Error::other(e.to_string()));
    }

    info!(
        "successfully added route to destination {} via {}",
        dest, via.name
    );
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
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    row.NextHop = next_hop.into();

    let res = unsafe { DeleteIpForwardEntry2(&row) }.to_hresult();
    if let Err(e) = res.ok() {
        debug!(
            "delete route to destination {} via {}: {}",
            dest, via.name, e
        );
    }
    Ok(())
}

#[allow(dead_code)]
pub fn add_address(iface: &OutboundInterface, addr_net: IpNet) -> io::Result<()> {
    let mut addr_inet = SOCKADDR_INET::default();
    match addr_net {
        IpNet::V4(ipv4_net) => {
            addr_inet.Ipv4.sin_family =
                windows::Win32::Networking::WinSock::ADDRESS_FAMILY(AF_INET.0);
            addr_inet.Ipv4.sin_addr.S_un.S_addr = u32::from_le_bytes(ipv4_net.addr().octets());
        }
        IpNet::V6(ipv6_net) => {
            addr_inet.Ipv6.sin6_family =
                windows::Win32::Networking::WinSock::ADDRESS_FAMILY(AF_INET6.0);
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
        Err(io::Error::other(format!(
            "failed to add address to tun interface: {}",
            res.message()
        )))
    }
}

pub fn configure_tun_interface(iface_index: u32, mtu: u32) {
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe {
            InitializeIpInterfaceEntry(&mut row);
        }
        row.Family = family;
        row.InterfaceIndex = iface_index;
        let get_res = unsafe { GetIpInterfaceEntry(&mut row) };
        if get_res.is_err() {
            continue;
        }
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.DadTransmits = 0;
        row.ManagedAddressConfigurationSupported = false;
        row.OtherStatefulConfigurationSupported = false;
        if mtu > 0 {
            row.NlMtu = mtu;
        }
        row.UseAutomaticMetric = false;
        row.Metric = 0;
        let set_res = unsafe { SetIpInterfaceEntry(&mut row) };
        if set_res.is_err() {
            debug!(
                "SetIpInterfaceEntry failed for iface {} family {:?}: {:?}",
                iface_index, family, set_res
            );
        }
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
