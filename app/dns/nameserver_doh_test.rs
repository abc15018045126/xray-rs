#[cfg(test)]
mod tests {
    use super::super::nameserver_doh::DohNameServer;

    #[test]
    fn test_doh_nameserver_creation() {
        let doh = DohNameServer::new("https://1.1.1.1/dns-query");
        assert_eq!(doh.url(), "https://1.1.1.1/dns-query");
    }

    #[test]
    fn test_edns0_client_subnet_encoding() {
        use super::super::nameserver::{build_dns_query_typed, build_dns_query_with_ecs};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let plain = build_dns_query_typed("example.com", 1);
        assert_eq!(&plain[10..12], &[0x00, 0x00]);

        let v4 = build_dns_query_with_ecs(
            "example.com",
            1,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        );
        assert_eq!(&v4[10..12], &[0x00, 0x01]);
        assert_eq!(v4.len(), plain.len() + 22);
        assert_eq!(&v4[v4.len() - 3..], &[1, 2, 3]);

        let v6 = build_dns_query_with_ecs(
            "example.com",
            28,
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x1234, 0x5600, 0, 0, 0, 1,
            ))),
        );
        assert_eq!(&v6[10..12], &[0x00, 0x01]);
        assert_eq!(v6.len(), plain.len() + 26);
        assert_eq!(&v6[v6.len() - 7..], &[0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56]);
    }
}
