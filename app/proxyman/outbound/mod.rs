pub mod handler;
pub mod outbound;
pub mod uot;
#[cfg(test)]
pub mod handler_test;

pub use handler::DefaultOutboundHandler;
pub use outbound::*;
pub use uot::{
    UOT_LEGACY_MAGIC_ADDRESS, UOT_MAGIC_ADDRESS, UotPacket, UotVersion, is_uot_destination,
};
