pub mod lru;

#[cfg(test)]
pub mod lru_test;

pub use lru::{Lru, LruCache, new_lru};
#[cfg(test)]
mod cache_peer_test;
