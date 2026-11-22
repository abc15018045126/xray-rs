pub mod fake;
pub mod fakedns;

#[cfg(test)]
pub mod fakedns_test;

pub use fake::FakeDnsHolder;
pub use fakedns::FakeDnsConfig;
#[cfg(test)]
mod fakedns_sniffer_leastload_test;
#[cfg(test)]
mod scen_fakedns_test;
