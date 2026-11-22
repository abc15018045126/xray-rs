use crate::common::net::{Destination, Network};

#[test]
fn test_udp_destination_parse() {
    let d = Destination::parse_str("1.1.1.1:53", Network::Udp).unwrap();
    assert_eq!(d.port, 53);
    assert_eq!(d.network, Network::Udp);
}
