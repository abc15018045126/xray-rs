#[cfg(not(target_os = "android"))]
mod imp {
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::connectors::{ConnectorOptions, L4Connect, TransportConnector};
use pingora_core::listeners::{L4BufferSettings, ListenerConfig};
use pingora_core::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora_core::protocols::l4::stream::Stream as PingoraL4Stream;
use pingora_core::protocols::Stream as PingoraStream;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::Service as PingoraServiceTrait;
use pingora_core::services::listening::Service as PingoraListeningService;
use pingora_core::upstreams::peer::BasicPeer;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::app::dispatcher::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::features::inbound::InboundHandler;

#[derive(Debug, Clone, Copy, Default)]
struct TunAwareL4Connect;

#[async_trait]
impl L4Connect for TunAwareL4Connect {
    async fn connect(&self, addr: &PingoraSocketAddr) -> pingora_core::Result<PingoraL4Stream> {
        let inet = addr.as_inet().copied().ok_or_else(|| {
            pingora_core::Error::explain(pingora_core::ConnectError, format!("non-inet address not supported: {}", addr))
        })?;
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let tcp = {
            let iface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.read().await;
            crate::proxy::tun::socket_helpers::new_tcp_stream(inet, iface.as_ref()).await
                .map_err(|e| pingora_core::Error::because(pingora_core::ConnectError, format!("TUN-safe TCP connect to {} failed", inet), e))?
        };
        #[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
        let tcp = tokio::net::TcpStream::connect(inet).await
            .map_err(|e| pingora_core::Error::because(pingora_core::ConnectError, format!("TCP connect to {} failed", inet), e))?;
        let _ = tcp.set_nodelay(true);
        Ok(PingoraL4Stream::from(tcp))
    }
}

static GLOBAL_TRANSPORT_CONNECTOR: LazyLock<TransportConnector> =
    LazyLock::new(|| TransportConnector::new(Some(ConnectorOptions::new(128))));

static TUN_L4_CONNECTOR: LazyLock<Arc<TunAwareL4Connect>> =
    LazyLock::new(|| Arc::new(TunAwareL4Connect));

pub struct PingoraCoreConnector;

impl PingoraCoreConnector {
    pub async fn dial_tcp(addr: SocketAddr) -> Result<BoxStream> {
        let mut peer = BasicPeer::new(&addr.to_string());
        peer.options.custom_l4 = Some(TUN_L4_CONNECTOR.clone());
        let stream: PingoraStream = GLOBAL_TRANSPORT_CONNECTOR
            .new_stream(&peer)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        Ok(Box::pin(stream))
    }
}

pub struct PingoraInboundApp {
    handler: Arc<dyn InboundHandler>,
    dispatcher: Arc<DefaultDispatcher>,
}

impl PingoraInboundApp {
    pub fn new(handler: Arc<dyn InboundHandler>, dispatcher: Arc<DefaultDispatcher>) -> Self {
        Self {
            handler,
            dispatcher,
        }
    }
}

#[async_trait]
impl ServerApp for PingoraInboundApp {
    async fn process_new(self: &Arc<Self>, session: PingoraStream, _shutdown: &ShutdownWatch) -> Option<PingoraStream> {
        let remote_addr = session.get_socket_digest()
            .and_then(|d| d.peer_addr().cloned())
            .and_then(|a| a.as_inet().copied())
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        match self.handler.handle_connection(Box::pin(session), remote_addr).await {
            Ok(res) => { if let Err(e) = self.dispatcher.dispatch(res.stream, res.session).await { warn!("Dispatch error: {}", e); } }
            Err(Error::Closed) => {}
            Err(e) => warn!("[{}] Handshake failed from {}: {}", self.handler.tag(), remote_addr, e),
        }
        None
    }
}

pub fn spawn_pingora_inbound(
    addr: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    dispatcher: Arc<DefaultDispatcher>,
) -> Option<JoinHandle<()>> {
    if let Err(e) = std::net::TcpListener::bind(addr) {
        warn!(
            "Inbound [{}] could not bind to {} ({}). Continuing other inbounds...",
            handler.tag(),
            addr,
            e
        );
        return None;
    }

    let tag = handler.tag().to_string();
    let app = PingoraInboundApp::new(handler, dispatcher);
    let mut service = PingoraListeningService::new(format!("xray-inbound-{}", tag), app);
    service.add_listener(
        ListenerConfig::tcp(addr.to_string()).l4_buffer(L4BufferSettings::unbuffered()),
    );

    info!(
        "Inbound [{}] listening on {} (powered by pingora-core)",
        tag, addr
    );

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let _keep_tx = _shutdown_tx;
        service
            .start_service(
                #[cfg(unix)]
                None,
                shutdown_rx,
                1,
            )
            .await;
    });

    Some(handle)
}
}

#[cfg(not(target_os = "android"))]
pub use imp::{PingoraCoreConnector, PingoraInboundApp, spawn_pingora_inbound};

#[cfg(target_os = "android")]
mod android_imp {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tracing::{info, warn};

    use crate::app::dispatcher::DefaultDispatcher;
    use crate::common::errors::{Error, Result};
    use crate::common::net::BoxStream;
    use crate::features::inbound::InboundHandler;

    pub struct PingoraCoreConnector;

    impl PingoraCoreConnector {
        pub async fn dial_tcp(addr: SocketAddr) -> Result<BoxStream> {
            let iface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.read().await;
            let tcp = crate::proxy::tun::socket_helpers::new_tcp_stream(addr, iface.as_ref())
                .await
                .map_err(Error::Io)?;
            let _ = tcp.set_nodelay(true);
            Ok(Box::pin(tcp))
        }
    }

    pub fn spawn_pingora_inbound(
        addr: SocketAddr,
        handler: Arc<dyn InboundHandler>,
        dispatcher: Arc<DefaultDispatcher>,
    ) -> Option<JoinHandle<()>> {
        let std_listener = std::net::TcpListener::bind(addr)
            .inspect_err(|e| warn!("Inbound [{}] could not bind to {} ({}). Continuing...", handler.tag(), addr, e))
            .ok()?;
        let _ = std_listener.set_nonblocking(true);
        let listener = TcpListener::from_std(std_listener).ok()?;
        info!("Inbound [{}] listening on {} (Android Tokio)", handler.tag(), addr);

        Some(tokio::spawn(async move {
            while let Ok((stream, remote_addr)) = listener.accept().await {
                let _ = stream.set_nodelay(true);
                let (h, d) = (handler.clone(), dispatcher.clone());
                tokio::spawn(async move {
                    match h.handle_connection(Box::pin(stream), remote_addr).await {
                        Ok(res) => {
                            if let Err(e) = d.dispatch(res.stream, res.session).await {
                                warn!("Dispatch error: {}", e);
                            }
                        }
                        Err(Error::Closed) => {}
                        Err(e) => warn!("[{}] Handshake failed from {}: {}", h.tag(), remote_addr, e),
                    }
                });
            }
        }))
    }
}

#[cfg(target_os = "android")]
pub use android_imp::{PingoraCoreConnector, spawn_pingora_inbound};
