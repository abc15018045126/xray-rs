pub mod destination;
pub mod dialer;
pub mod error;
pub mod handler;
pub mod logger;
pub mod packet;
pub mod pipe;
pub mod reader;

#[cfg(test)]
pub mod singbridge_test;

pub use destination::{from_destination, to_destination, to_network, to_socksaddr, Socksaddr};
pub use dialer::{dial_singbox_bridge, SingDialer, SingDialerTrait, XrayDialer, XrayOutboundDialer};
pub use error::{is_closed_or_canceled, return_error, return_result, wrap_sing_error};
pub use handler::{Dispatcher, Metadata, SingHandler, TcpConnectionHandler, UdpConnectionHandler};
pub use logger::{ContextLogger, SingLogger, XrayLogger};
pub use packet::{copy_packet_conn, PacketConnWrapper, SingPacket};
pub use pipe::{bridge_pipe, copy_conn, PipeConnWrapper};
pub use reader::{Conn, SingReader};
