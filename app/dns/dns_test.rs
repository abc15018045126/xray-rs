#[cfg(test)]
mod tests {
    use super::super::dns::DnsClient;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_dns_client_lookup_hosts() {
        let client = DnsClient::new();
        let target_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        client.add_host("custom.internal", vec![target_ip]);

        let ips = client.lookup_ip("custom.internal").await.unwrap();
        assert_eq!(ips, vec![target_ip]);
    }

    #[tokio::test]
    async fn test_dns_client_fakedns_and_domain_matching() {
        use super::super::dns::DnsServerConfig;

        let mut client = DnsClient::new();
        client.add_server(DnsServerConfig {
            address: "fakedns".into(),
            domains: vec!["geosite:google".into()],
            skip_fallback: true,
            ..Default::default()
        });

        use crate::features::dns::IPOption;
        let fake_opt = IPOption { ipv4_enable: true, ipv6_enable: true, fake_enable: true };
        let (ips, _) = client.lookup_ip_with_option("www.google.com", fake_opt).await.unwrap();
        assert_eq!(ips.len(), 1);
        match ips[0] {
            IpAddr::V4(v4) => {
                assert_eq!(v4.octets()[0], 198);
                assert!(v4.octets()[1] == 18 || v4.octets()[1] == 19);
            }
            _ => panic!("expected IPv4 from FakeDNS"),
        }
    }

    #[tokio::test]
    async fn test_dns_client_expect_ips_fallback() {
        use super::super::dns::DnsServerConfig;

        let mut client = DnsClient::new();
        client.set_disable_fallback(false);
        client.add_server(DnsServerConfig {
            address: "fakedns".into(),
            domains: vec!["domain:example.org".into()],
            expect_ips: vec!["10.0.0.0/8".into()],
            ..Default::default()
        });
        client.add_server(DnsServerConfig {
            address: "fakedns".into(),
            ..Default::default()
        });

        use crate::features::dns::IPOption;
        let fake_opt = IPOption { ipv4_enable: true, ipv6_enable: true, fake_enable: true };
        let (ips, _) = client.lookup_ip_with_option("sub.example.org", fake_opt).await.unwrap();
        assert_eq!(ips.len(), 1);
    }

    #[tokio::test]
    async fn test_dns_client_disable_fallback_if_match() {
        use super::super::dns::DnsServerConfig;

        let mut client = DnsClient::new();
        client.set_disable_fallback_if_match(true);
        client.add_server(DnsServerConfig {
            address: "fakedns".into(),
            domains: vec!["domain:blocked.test".into()],
            expect_ips: vec!["10.0.0.0/8".into()],
            ..Default::default()
        });
        client.add_server(DnsServerConfig {
            address: "fakedns".into(),
            ..Default::default()
        });

        let res = client.lookup_ip("a.blocked.test").await;
        assert!(res.is_err());
    }
}
