pub mod tagged;
pub mod taggedimpl;

#[cfg(test)]
pub mod tagged_test;

pub use tagged::{DialFunc, TaggedDialer, dial, set_dialer};
