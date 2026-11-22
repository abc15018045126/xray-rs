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
    use std::ffi::c_void;
    use std::net::{IpAddr, SocketAddr};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_CONNECTIONS,
        UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
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
        let mut size: u32 = 0;
        unsafe { let _ = GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0); }
        if size == 0 { return None; }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut c_void),
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if ret != 0 { return None; }
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
        let mut size = 0u32;
        unsafe { let _ = GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0); }
        if size == 0 { return None; }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut c_void), &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
        };
        if ret != 0 { return None; }
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
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buf = [0u16; 1024];
                let mut len = buf.len() as u32;
                let res = QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut len);
                let _ = CloseHandle(handle);
                if res.is_ok() && len > 0 { return from_path(String::from_utf16_lossy(&buf[..len as usize])); }
            }
        }
        ProcessInfo { pid, name: format!("pid-{}", pid), path: String::new() }
    }
}
