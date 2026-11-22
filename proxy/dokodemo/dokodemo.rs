use super::config::DokodemoConfig;
use crate::common::net::{Destination, Network};

pub struct DokodemoHandler {
    config: DokodemoConfig,
}

impl DokodemoHandler {
    pub fn new(config: DokodemoConfig) -> Self { Self { config } }
    pub fn destination(&self) -> Destination { Destination::tcp(self.config.address.clone(), self.config.port) }
    pub fn get_predefined_address(&self) -> Destination { self.destination() }
    pub fn network(&self) -> Network { Network::Tcp }
}
