pub mod command;
pub mod config;
pub mod inbound;
pub mod outbound;

use crate::app::dispatcher::DefaultDispatcher;
use crate::app::pingora_bridge::spawn_pingora_inbound;
use crate::common::errors::Result;
use crate::features::inbound::InboundHandler;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub use config::{InboundHandlerConfig, KnownProtocols, OutboundHandlerConfig, SniffingConfig};
pub use inbound::DefaultInboundManager;
pub use outbound::DefaultOutboundManager;

pub struct InboundManager {
    inbounds: Vec<(SocketAddr, Arc<dyn InboundHandler>)>,
}

impl InboundManager {
    pub fn new(inbounds: Vec<(SocketAddr, Arc<dyn InboundHandler>)>) -> Self {
        Self { inbounds }
    }

    pub async fn start(&self, dispatcher: Arc<DefaultDispatcher>) -> Result<Vec<JoinHandle<()>>> {
        let mut tasks = Vec::new();

        for (addr, handler) in &self.inbounds {
            if let Some(task) = spawn_pingora_inbound(*addr, handler.clone(), dispatcher.clone()) {
                tasks.push(task);
            }
        }

        Ok(tasks)
    }
}
