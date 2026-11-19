// Module: proxy\dns\dns_test.rs
#[cfg(test)]
mod tests {
    use super::super::{DefaultDnsHandler, DnsOutbound};
    use crate::app::dns::DnsClient;
    use crate::common::net::{Address, Destination, Network};
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_dns_proxy_creation() {
        let h = DefaultDnsHandler::new("dns-out");
        assert_eq!(h.tag, "dns-out");
    }

    fn build_query(id: u16, domain: &str, rtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.queries
            .push(Query::query(Name::from_str(domain).unwrap(), rtype));
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn test_dns_outbound_a_aaaa_https_multi_query() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "example.test".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ],
        );
        let dns_client = Arc::new(DnsClient::with_hosts(hosts));
        let outbound = DnsOutbound::new("dns".into(), dns_client);

        let (mut client_io, server_io) = tokio::io::duplex(8192);
        let dest = Destination {
            network: Network::Udp,
            address: Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 53,
        };
        let task = tokio::spawn(async move { outbound.process(server_io, dest).await });

        // 1. Type A query
        let q_a = build_query(0x1111, "example.test.", RecordType::A);
        client_io.write_all(&q_a).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = client_io.read(&mut buf).await.unwrap();
        let resp_a = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(resp_a.metadata.id, 0x1111);
        assert_eq!(resp_a.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp_a.additionals.len(), 0);
        assert_eq!(resp_a.answers.len(), 1);
        assert!(matches!(resp_a.answers[0].data, RData::A(_)));

        // 2. Type AAAA query on SAME stream (multi-query!)
        let q_aaaa = build_query(0x2222, "example.test.", RecordType::AAAA);
        client_io.write_all(&q_aaaa).await.unwrap();
        let n = client_io.read(&mut buf).await.unwrap();
        let resp_aaaa = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(resp_aaaa.metadata.id, 0x2222);
        assert_eq!(resp_aaaa.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp_aaaa.answers.len(), 1);
        assert!(matches!(resp_aaaa.answers[0].data, RData::AAAA(_)));

        // 3. Non-IP (HTTPS) query -> immediate empty NoError
        let q_https = build_query(0x3333, "example.test.", RecordType::HTTPS);
        client_io.write_all(&q_https).await.unwrap();
        let n = client_io.read(&mut buf).await.unwrap();
        let resp_https = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(resp_https.metadata.id, 0x3333);
        assert_eq!(resp_https.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp_https.answers.len(), 0);

        drop(client_io);
        let _ = task.await;
    }
}
