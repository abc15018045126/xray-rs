use std::net::SocketAddr;

use crate::net::Destination;

/// Per-connection metadata flowing from Inbound -> Route -> Outbound.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub inbound_tag: String,
    pub outbound_tag: Option<String>,
    pub source: Option<SocketAddr>,
    pub destination: Destination,
    pub sniffed_domain: Option<String>,
    pub sniffed_protocol: Option<String>,
}

impl SessionContext {
    pub fn new(inbound_tag: impl Into<String>, destination: Destination) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            outbound_tag: None,
            source: None,
            destination,
            sniffed_domain: None,
            sniffed_protocol: None,
        }
    }
}
