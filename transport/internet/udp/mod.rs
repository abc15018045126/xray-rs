pub mod config;
#[path = "config.pb.rs"]
pub mod config_pb;
pub mod dialer;
pub mod dispatcher;
pub mod hub;
pub mod hub_darwin;
pub mod hub_freebsd;
pub mod hub_linux;
pub mod hub_openbsd;
pub mod hub_other;
pub mod udp;

#[cfg(test)]
pub mod dispatcher_test;

pub use config::UdpConfig;
pub use dialer::UdpDialer;
pub use dispatcher::{
    ConnEntry, Dispatcher, DispatcherConn, LinkDispatcher, ResponseCallback, UdpDispatcher,
    dial_dispatcher,
};
pub use hub::{Hub, HubOption, UdpHub, UdpPacket};
pub use udp::PROTOCOL_NAME;
#[cfg(test)]
mod uot_doh_test;
#[cfg(test)]
mod config_test;
