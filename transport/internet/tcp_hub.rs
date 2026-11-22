use crate::common::errors::{Error, Result};
use crate::common::net::Address;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::net::{TcpListener, UdpSocket};

pub use super::tcp::TcpHub;

type ListenCallback = Arc<dyn Fn(SocketAddr) -> Result<TcpListener> + Send + Sync>;

static TRANSPORT_LISTENERS: LazyLock<Mutex<HashMap<String, ListenCallback>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn register_transport_listener<F>(protocol: &str, listener: F) -> Result<()>
where
    F: Fn(SocketAddr) -> Result<TcpListener> + Send + Sync + 'static,
{
    let mut map = TRANSPORT_LISTENERS.lock().unwrap();
    if map.contains_key(protocol) { return Err(Error::Protocol(format!("{} listener already registered", protocol))); }
    map.insert(protocol.to_string(), Arc::new(listener));
    Ok(())
}

pub async fn listen_tcp(address: &Address, port: u16) -> Result<TcpListener> {
    let ip = match address {
        Address::Ipv4(ip) => std::net::IpAddr::V4(*ip),
        Address::Ipv6(ip) => std::net::IpAddr::V6(*ip),
        Address::Domain(d) if d == "localhost" => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Address::Domain(d) => return Err(Error::Protocol(format!("Domain address not allowed for listening: {}", d))),
    };
    TcpListener::bind(SocketAddr::new(ip, port)).await.map_err(Into::into)
}

pub async fn listen_system(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr).await.map_err(Into::into)
}

pub async fn listen_system_packet(addr: SocketAddr) -> Result<UdpSocket> {
    UdpSocket::bind(addr).await.map_err(Into::into)
}
