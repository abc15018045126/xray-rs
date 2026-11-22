use std::{io, os::windows::io::AsRawSocket};
use windows::Win32::Networking::WinSock::{
    IP_MULTICAST_IF, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF,
    IPV6_UNICAST_IF, SOCKET, setsockopt,
};

use crate::proxy::tun::OutboundInterface;

pub fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());
    let is_udp = socket.r#type()? == socket2::Type::DGRAM;
    let (proto, unicast_opt, multicast_opt, bytes) = match family {
        socket2::Domain::IPV4 => (IPPROTO_IP.0, IP_UNICAST_IF, IP_MULTICAST_IF, iface.index.to_be_bytes()),
        socket2::Domain::IPV6 => (IPPROTO_IPV6.0, IPV6_UNICAST_IF, IPV6_MULTICAST_IF, iface.index.to_ne_bytes()),
        _ => return Err(io::Error::other("unsupported socket family")),
    };
    let apply = |opt: i32| -> io::Result<()> {
        #[allow(unsafe_code)]
        let errno = unsafe { setsockopt(handle, proto, opt, Some(&bytes)) };
        if errno != 0 {
            let err = io::Error::last_os_error();
            tracing::warn!("bind socket to interface failed: {}, errno: {}", err, errno);
            return Err(err);
        }
        Ok(())
    };
    apply(unicast_opt)?;
    if is_udp { apply(multicast_opt)?; }
    Ok(())
}
