use super::config::HysteriaTransportConfig;
use super::conn::HysteriaConn;
use std::net::SocketAddr;

pub struct HysteriaDialer {
    pub config: HysteriaTransportConfig,
}

impl HysteriaDialer {
    pub fn new(config: HysteriaTransportConfig) -> Self {
        Self { config }
    }

    pub async fn dial(&self, _addr: SocketAddr) -> HysteriaConn {
        HysteriaConn::new()
    }
}
