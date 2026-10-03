// Module: features\dns\mod.rs

pub mod client;
pub mod fakedns;
pub mod localdns;

pub use client::{client_type, DnsClient, IPOption, RCodeError, DEFAULT_TTL};
pub use fakedns::{fake_dns_type, FakeDnsEngine, FakeDnsFeature, FAKE_IPV4_POOL, FAKE_IPV6_POOL};
pub use localdns::LocalDnsClient;
