// Module: proxy\tun\stream.rs
// SOCKS5 stream handling for tun2proxy internal bridge

use crate::app::dispatcher::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::common::session::SniffingRequest;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

pub async fn handle_inbound_stream(
    mut stream: TcpStream,
    dispatcher: Arc<DefaultDispatcher>,
    sniffing: Option<SniffingRequest>,
) -> Result<()> {
    let ver = stream.read_u8().await.map_err(Error::Io)?;
    if ver != 0x05 {
        return Err(Error::Protocol(format!(
            "unsupported SOCKS version: {}",
            ver
        )));
    }

    let nmethods = stream.read_u8().await.map_err(Error::Io)? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await.map_err(Error::Io)?;

    stream.write_all(&[0x05, 0x00]).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let ver = stream.read_u8().await.map_err(Error::Io)?;
    if ver != 0x05 {
        return Err(Error::Protocol(format!(
            "invalid SOCKS5 version in request: {}",
            ver
        )));
    }

    let cmd = stream.read_u8().await.map_err(Error::Io)?;
    let _rsv = stream.read_u8().await.map_err(Error::Io)?;
    let atyp = stream.read_u8().await.map_err(Error::Io)?;

    let address = match atyp {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes).await.map_err(Error::Io)?;
            Address::Ipv4(std::net::Ipv4Addr::from(ip_bytes))
        }
        0x03 => {
            let len = stream.read_u8().await.map_err(Error::Io)? as usize;
            let mut domain_bytes = vec![0u8; len];
            stream
                .read_exact(&mut domain_bytes)
                .await
                .map_err(Error::Io)?;
            Address::Domain(String::from_utf8_lossy(&domain_bytes).to_string())
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes).await.map_err(Error::Io)?;
            Address::Ipv6(std::net::Ipv6Addr::from(ip_bytes))
        }
        _ => {
            return Err(Error::Protocol(format!(
                "unsupported SOCKS5 ATYP: {}",
                atyp
            )));
        }
    };

    let port = stream.read_u16().await.map_err(Error::Io)?;

    if cmd != 0x01 {
        return Err(Error::Protocol(format!(
            "unsupported SOCKS5 command in stream handler: {}",
            cmd
        )));
    }

    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        .await
        .map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let destination = Destination {
        network: Network::Tcp,
        address,
        port,
    };

    let mut session = SessionContext::new("tun-in", destination);
    session.source = stream.peer_addr().ok();
    session.sniffing_request = sniffing;

    debug!(
        "new tun TCP session: {} -> {}",
        stream
            .peer_addr()
            .unwrap_or(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
        session.destination
    );
    if let Err(e) = dispatcher.dispatch(Box::pin(stream), session).await {
        debug!("tun TCP session closed: {}", e);
    }
    Ok(())
}
