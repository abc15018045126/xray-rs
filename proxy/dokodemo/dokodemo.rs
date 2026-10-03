// Module: proxy\dokodemo\dokodemo.rs
// 1:1 Rust implementation corresponding to Go proxy\dokodemo\dokodemo.go

use crate::common::net::Destination;
use super::config::DokodemoConfig;

pub struct DokodemoHandler {
    config: DokodemoConfig,
}

impl DokodemoHandler {
    pub fn new(config: DokodemoConfig) -> Self {
        Self { config }
    }

    pub fn destination(&self) -> Destination {
        Destination::tcp(self.config.address.clone(), self.config.port)
    }
}
