//! Pingora-core (`pingora-core 0.9.1`) inbound listening service & outbound L4 transport gateway.
//!
//! - **Inbound**: `PingoraInboundApp` implements `pingora_core::apps::ServerApp` and runs inside
//!   `pingora_core::services::listening::Service`, accepting local proxy connections (SOCKS/HTTP/Mixed)
//!   with Pingora's L4 buffering, keepalive, and timeout management before handing off to Xray's
//!   `InboundHandler` and `DefaultDispatcher`.
//! - **Outbound**: `PingoraCoreConnector` wraps `pingora_core::connectors::TransportConnector` with
//!   a custom `L4Connect` implementation (`TunAwareL4Connect`) that binds sockets to the Windows
//!   physical outbound interface (`DEFAULT_OUTBOUND_INTERFACE`) to prevent global TUN loopback.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::connectors::{ConnectorOptions, L4Connect, TransportConnector};
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

/// Custom Pingora `L4Connect` that preserves Windows physical interface binding (`IP_UNICAST_IF`)
/// so `pingora-core::connectors::TransportConnector` works seamlessly alongside global TUN mode.
#[derive(Debug, Clone, Copy, Default)]
struct TunAwareL4Connect;

#[async_trait]
impl L4Connect for TunAwareL4Connect {
    async fn connect(&self, addr: &PingoraSocketAddr) -> pingora_core::Result<PingoraL4Stream> {
        let inet = addr.as_inet().copied().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ConnectError,
                format!("non-inet address not supported: {}", addr),
            )
        })?;

        #[cfg(target_os = "windows")]
        let tcp = {
            let iface = crate::proxy::tun::DEFAULT_OUTBOUND_INTERFACE.read().await;
            crate::proxy::tun::socket_helpers::new_tcp_stream(inet, iface.as_ref())
                .await
                .map_err(|e| {
                    pingora_core::Error::because(
                        pingora_core::ConnectError,
                        format!("Windows physical-interface TCP connect to {} failed", inet),
                        e,
                    )
                })?
        };

        #[cfg(not(target_os = "windows"))]
        let tcp = tokio::net::TcpStream::connect(inet).await.map_err(|e| {
            pingora_core::Error::because(
                pingora_core::ConnectError,
                format!("TCP connect to {} failed", inet),
                e,
            )
        })?;

        let _ = tcp.set_nodelay(true);
        Ok(PingoraL4Stream::from(tcp))
    }
}

static GLOBAL_TRANSPORT_CONNECTOR: LazyLock<TransportConnector> =
    LazyLock::new(|| TransportConnector::new(Some(ConnectorOptions::new(128))));

static TUN_L4_CONNECTOR: LazyLock<Arc<TunAwareL4Connect>> =
    LazyLock::new(|| Arc::new(TunAwareL4Connect));

/// Outbound L4 gateway powered by `pingora-core::connectors::TransportConnector`.
pub struct PingoraCoreConnector;

impl PingoraCoreConnector {
    /// Connects to `addr` through Pingora's `TransportConnector` with TUN-safe L4 binding.
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

/// Pingora `ServerApp` adapter that accepts incoming connections from `pingora-core`
/// and dispatches them into Xray's `InboundHandler` + `DefaultDispatcher`.
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
    async fn process_new(
        self: &Arc<Self>,
        session: PingoraStream,
        _shutdown: &ShutdownWatch,
    ) -> Option<PingoraStream> {
        let remote_addr = session
            .get_socket_digest()
            .and_then(|d| d.peer_addr().cloned())
            .and_then(|a| a.as_inet().copied())
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

        let stream: BoxStream = Box::pin(session);
        match self.handler.handle_connection(stream, remote_addr).await {
            Ok(res) => {
                if let Err(e) = self.dispatcher.dispatch(res.stream, res.session).await {
                    warn!("Dispatch error: {}", e);
                }
            }
            Err(e) => {
                warn!(
                    "[{}] Handshake failed from {}: {}",
                    self.handler.tag(),
                    remote_addr,
                    e
                );
            }
        }
        None
    }
}

/// Spawns a `pingora-core` listening service for a single Xray inbound `(addr, handler)`.
/// Returns `Ok(None)` (with a warning) if the address cannot be bound, matching Xray-core's
/// graceful multi-inbound startup behavior.
pub fn spawn_pingora_inbound(
    addr: SocketAddr,
    handler: Arc<dyn InboundHandler>,
    dispatcher: Arc<DefaultDispatcher>,
) -> Option<JoinHandle<()>> {
    // Pre-check bindability so an occupied port logs a clean warning instead of panicking inside Pingora
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
    service.add_tcp(&addr.to_string());

    info!(
        "Inbound [{}] listening on {} (powered by pingora-core)",
        tag, addr
    );

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        // Keep `_shutdown_tx` alive for the lifetime of the inbound task
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
