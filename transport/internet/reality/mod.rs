pub mod config;
pub mod reality;

#[cfg(test)]
pub mod reality_test;

pub use config::RealityConfig;
pub use reality::{
    derive_auth_key, open_session_id, seal_session_id, RealityAuthSession, RealityClient,
    RealityServer,
};
