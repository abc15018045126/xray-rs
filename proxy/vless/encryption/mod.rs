pub mod client;
pub mod common;
pub mod server;
pub mod xor;

#[cfg(test)]
pub mod common_test;

pub use client::VlessXorClient;
pub use common::{
    create_padding, decode_header, encode_header, increase_nonce, parse_padding, CommonConn,
    VlessAead, ENCRYPTION_VERSION,
};
pub use server::VlessXorServer;
pub use xor::xor_inplace;
