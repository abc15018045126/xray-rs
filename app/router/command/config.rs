use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::{SessionContext, User};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct CommandRoutingContext {
    pub inbound_tag: String,
    pub source_ip: Option<IpAddr>,
    pub source_port: u16,
    pub target_ip: Option<IpAddr>,
    pub target_domain: Option<String>,
    pub target_port: u16,
    pub network: Network,
    pub user: Option<String>,
}

impl CommandRoutingContext {
    pub fn to_session_context(&self) -> SessionContext {
        let addr = self.target_domain.as_ref().map(|d| Address::Domain(d.clone()))
            .or_else(|| self.target_ip.map(Address::from))
            .unwrap_or_else(|| Address::Domain("localhost".into()));
        let mut session = SessionContext::new(&self.inbound_tag, Destination::new(addr, self.target_port));
        session.user = self.user.as_ref().map(|e| User { id: Uuid::nil(), email: e.clone(), level: 0 });
        session
    }
}
