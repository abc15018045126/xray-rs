use super::Destination;
use crate::common::errors::Result;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

pub struct ProcessFinder;

impl ProcessFinder {
    pub fn find_process(dest: &Destination) -> Result<Option<ProcessInfo>> {
        #[cfg(target_os = "windows")]
        {
            if let Some(addr) = dest.to_socket_addr() {
                let is_tcp = dest.network == crate::common::net::Network::Tcp;
                return Ok(windows_impl::find_process(is_tcp, addr));
            }
            Ok(None)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = dest;
            Ok(None)
        }
    }
    pub fn find_process_by_socket(src: SocketAddr, is_tcp: bool) -> Result<Option<ProcessInfo>> {
        #[cfg(debug_assertions)]
        let _t0 = std::time::Instant::now();
        #[cfg(target_os = "windows")]
        let res = Ok(windows_impl::find_process(is_tcp, src));
        #[cfg(not(target_os = "windows"))]
        let res = { let _ = (src, is_tcp); Ok(None) };
        #[cfg(debug_assertions)]
        crate::debug_panel::record_stage("进程查表 (find_process)", _t0.elapsed());
        res
    }
}

#[cfg(target_os = "windows")]
pub mod windows_impl {
    use super::ProcessInfo;
    use std::net::{IpAddr, SocketAddr};
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    pub fn find_process(is_tcp: bool, src: SocketAddr) -> Option<ProcessInfo> {
        let port = src.port();
        let ip = src.ip();
        let family = match ip {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        let pid = if is_tcp {
            search_tcp(family, ip, port)?
        } else {
            search_udp(family, ip, port)?
        };
        Some(get_process_info_from_pid(pid))
    }
    fn search_tcp(family: u32, ip: IpAddr, port: u16) -> Option<u32> {
        let buf = xray_rs_window::get_extended_tcp_table(family)?;
        let num_entries = u32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
        let (item_size, port_offset, ip_offset, ip_len, pid_offset, state_offset) =
            if family == AF_INET {
                (24, 8, 4, 4, 20, 0)
            } else {
                (56, 20, 0, 16, 52, 48)
            };
        for i in 0..num_entries {
            let start = 4 + i * item_size;
            let end = start + item_size;
            if end > buf.len() { break; }
            let row = &buf[start..end];
            let tcp_state = u32::from_ne_bytes(row[state_offset..state_offset + 4].try_into().ok()?);
            if tcp_state != 5 { continue; }
            let row_port = u16::from_be_bytes([row[port_offset], row[port_offset + 1]]);
            if row_port != port { continue; }
            let row_ip = &row[ip_offset..ip_offset + ip_len];
            let is_unspecified = row_ip.iter().all(|&b| b == 0);
            if !is_unspecified {
                match ip {
                    IpAddr::V4(v4) => { if row_ip != v4.octets() { continue; } }
                    IpAddr::V6(v6) => { if row_ip != v6.octets() { continue; } }
                }
            }
            let pid = u32::from_ne_bytes(row[pid_offset..pid_offset + 4].try_into().ok()?);
            return Some(pid);
        }
        None
    }
    fn search_udp(family: u32, ip: IpAddr, port: u16) -> Option<u32> {
        let buf = xray_rs_window::get_extended_udp_table(family)?;
        let num_entries = u32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
        let (item_size, port_off, ip_len, pid_off) = if family == AF_INET { (12, 4, 4, 8) } else { (28, 20, 16, 24) };
        for row in buf[4..].chunks_exact(item_size).take(num_entries) {
            if u16::from_be_bytes([row[port_off], row[port_off + 1]]) != port { continue; }
            let row_ip = &row[..ip_len];
            if row_ip.iter().any(|&b| b != 0) {
                let ip_match = match ip {
                    IpAddr::V4(v4) => row_ip == v4.octets(),
                    IpAddr::V6(v6) => row_ip == v6.octets(),
                };
                if !ip_match { continue; }
            }
            return Some(u32::from_ne_bytes(row[pid_off..pid_off + 4].try_into().ok()?));
        }
        None
    }
    pub fn get_process_info_from_pid(pid: u32) -> ProcessInfo {
        let from_path = |raw: String| {
            let path = raw.replace('\\', "/");
            let name = path.split('/').next_back().unwrap_or(&path).trim_end_matches(".exe").to_string();
            ProcessInfo { pid, name, path }
        };
        match pid {
            0 => return ProcessInfo { pid: 0, name: ":System Idle Process".into(), path: ":System Idle Process".into() },
            4 => return ProcessInfo { pid: 4, name: ":System".into(), path: ":System".into() },
            p if p == std::process::id() => {
                let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "xray.exe".into());
                return from_path(exe);
            }
            _ => {}
        }
        if let Some(raw) = xray_rs_window::query_process_image_path(pid) {
            return from_path(raw);
        }
        ProcessInfo { pid, name: format!("pid-{}", pid), path: String::new() }
    }
}
