use std::{io, os::windows::io::AsRawSocket};
use windows::{
    Win32::{
        Foundation::GetLastError,
        Networking::WinSock::{
            IP_MULTICAST_IF, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF,
            IPV6_UNICAST_IF, SO_TYPE, SOCK_DGRAM, SOCKET, SOL_SOCKET, WINSOCK_SOCKET_TYPE,
            getsockopt, setsockopt,
        },
    },
    core::PSTR,
};

use crate::proxy::tun::OutboundInterface;

fn new_io_error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}

pub fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());
    let is_udp = is_udp_socket(handle)?;
    let (proto, unicast_opt, multicast_opt, bytes) = match family {
        socket2::Domain::IPV4 => (IPPROTO_IP.0, IP_UNICAST_IF, IP_MULTICAST_IF, iface.index.to_be_bytes()),
        socket2::Domain::IPV6 => (IPPROTO_IPV6.0, IPV6_UNICAST_IF, IPV6_MULTICAST_IF, iface.index.to_ne_bytes()),
        _ => return Err(io::Error::other("unsupported socket family")),
    };
    let apply = |opt: i32| -> io::Result<()> {
        let errno = unsafe { setsockopt(handle, proto, opt, Some(&bytes)) };
        if errno != 0 {
            let err = unsafe { GetLastError().to_hresult().message() };
            tracing::warn!("bind socket to interface failed: {}, errno: {}", err, errno);
            return Err(new_io_error(err));
        }
        Ok(())
    };
    apply(unicast_opt)?;
    if is_udp {
        apply(multicast_opt)?;
    }
    Ok(())
}

fn is_udp_socket(socket: SOCKET) -> io::Result<bool> {
    let mut optval = [0u8; 4];
    let mut optlen: i32 = 4;
    let ret = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_TYPE,
            PSTR::from_raw(optval.as_mut_ptr()),
            &mut optlen,
        )
    };
    if ret != 0 {
        let last_err = io::Error::last_os_error();
        tracing::warn!(
            "getsockopt failed when determining socket type: {:?}",
            last_err
        );
        return Err(last_err);
    }
    Ok(WINSOCK_SOCKET_TYPE(i32::from_ne_bytes(optval)) == SOCK_DGRAM)
}
