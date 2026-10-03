pub mod config;
pub mod tcp;
pub mod udp;

pub use config::{CustomHeaderConfig, TCPConfig, TCPItem, TCPSequence, UDPConfig, UDPItem};
pub use tcp::{client_handshake, server_handshake, TcpCustomConn, TCP_CUSTOM_MAGIC};
pub use udp::{UdpCustomClient, UdpCustomServer, UDP_CUSTOM_MAGIC};
