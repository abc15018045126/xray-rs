use super::config_pb::{Config, ConnectionConfig};
use super::noop::{NoOpConnectionHeader, NoOpHeader};
use crate::transport::internet::header::{ConnectionAuthenticator, Header, PacketHeader};

#[test]
fn test_noop_headers() {
    let h = NoOpHeader::new();
    assert_eq!(Header::size(&h), 0);
    let mut buf = [0u8; 10];
    assert_eq!(Header::serialize(&h, &mut buf), 0);
    assert_eq!(PacketHeader::size(&h), 0);
    PacketHeader::serialize(&h, &mut buf);

    let ch = NoOpConnectionHeader::new();
    let (client, _server) = tokio::io::duplex(64);
    let _boxed = ch.client(Box::pin(client));
    let _cfg = Config::default();
    let _conn_cfg = ConnectionConfig::default();
}
