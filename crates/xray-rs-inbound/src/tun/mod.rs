pub mod config;
pub mod net;
pub mod platform;
pub mod routes;
pub mod runner;
#[cfg(windows)]
pub mod tun_windows;

pub use config::TunConfig;
pub use net::{
    DEFAULT_OUTBOUND_INTERFACE, OutboundInterface, get_outbound_interface, init_net_config,
};
pub use runner::{DispatchCallback, TunRunner};
