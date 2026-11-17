use std::collections::BTreeSet;
use std::net::SocketAddr;

use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery};

use xray_rs_types::{Error, Result};

/// Cloudflare `pingora-load-balancing` wrapper for RoundRobin selection across upstreams.
pub struct PingoraUpstreamBalancer {
    lb: LoadBalancer<RoundRobin>,
}

impl PingoraUpstreamBalancer {
    pub fn from_addrs(addrs: &[SocketAddr]) -> Result<Self> {
        let mut set = BTreeSet::new();
        for addr in addrs {
            set.insert(Backend::new(&addr.to_string()).map_err(|e| {
                Error::Config(format!("Invalid backend address {}: {}", addr, e))
            })?);
        }
        let backends = Backends::new(discovery::Static::new(set));
        let lb = LoadBalancer::from_backends(backends);
        let _ = futures::executor::block_on(lb.update());
        Ok(Self { lb })
    }

    pub fn select(&self) -> Option<Backend> {
        self.lb.select(b"", 256)
    }
}
