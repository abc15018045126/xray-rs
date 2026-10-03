use std::sync::Arc;
use tracing::debug;
use crate::app::dispatcher::DefaultDispatcher;
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::common::session::SniffingRequest;

pub async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,
    dispatcher: Arc<DefaultDispatcher>,
    sniffing: Option<SniffingRequest>,
) {
    let destination = Destination {
        network: Network::Tcp,
        address: Address::ip(stream.remote_addr().ip()),
        port: stream.remote_addr().port(),
    };
    let mut session = SessionContext::new("tun-in", destination);
    session.source = Some(stream.local_addr());
    session.sniffing_request = sniffing;

    debug!("new tun TCP session: {} -> {}", stream.local_addr(), session.destination);
    if let Err(e) = dispatcher.dispatch(Box::pin(stream), session).await {
        debug!("tun TCP session closed: {}", e);
    }
}
