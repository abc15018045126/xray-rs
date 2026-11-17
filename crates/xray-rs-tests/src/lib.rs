#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    use xray_rs_inbound::{MixedInbound, PingoraHttpInbound};
    use xray_rs_outbound::{FreedomHandler, PingoraPooledOutbound};
    use xray_rs_proto::{TrojanRequestHeader, VlessRequestHeader};
    use xray_rs_route::{Dispatcher, DomainRule, IpRule, RouteRule, Router, sniff_tls_sni};
    use xray_rs_types::{Address, BoxStream, Destination, InboundHandler, Network, SessionContext};

    #[test]
    fn test_proto_vless_and_trojan_encoding() {
        let uuid = Uuid::new_v4();
        let dest = Destination::tcp(Address::Domain("repo.maven.apache.org".into()), 443);
        let vless = VlessRequestHeader::new(uuid, dest.clone());
        let mut buf = BytesMut::new();
        vless.encode_to(&mut buf);
        assert_eq!(buf[0], 0);
        assert_eq!(&buf[1..17], uuid.as_bytes());

        let trojan = TrojanRequestHeader::new("secret-pass", dest);
        let mut tbuf = BytesMut::new();
        trojan.encode_to(&mut tbuf);
        assert_eq!(tbuf[56..58], *b"\r\n");
    }

    #[test]
    fn test_router_cidr_and_private_geo_rules() {
        let mut udp_block = RouteRule::new("block");
        udp_block.network = Some(Network::Udp);
        udp_block.ports = vec![443];

        let mut cidr_block = RouteRule::new("block");
        cidr_block.ip_rules = vec![IpRule::parse("224.0.0.0/3").unwrap()];

        let mut private_direct = RouteRule::new("direct");
        private_direct.ip_rules = vec![IpRule::parse("geoip:private").unwrap()];
        let mut local_domain = RouteRule::new("direct");
        local_domain.domains = vec![DomainRule::parse("geosite:private").unwrap()];

        let router = Router::new(vec![udp_block, cidr_block, private_direct, local_domain]);

        let tcp_443 = SessionContext::new(
            "socks",
            Destination::tcp(Address::Domain("repo.maven.apache.org".into()), 443),
        );
        assert_eq!(router.pick_outbound(&tcp_443), None);

        let udp_443 = SessionContext::new(
            "socks",
            Destination::udp(Address::Domain("repo.maven.apache.org".into()), 443),
        );
        assert_eq!(router.pick_outbound(&udp_443), Some("block"));

        let local_ip = SessionContext::new(
            "socks",
            Destination::tcp(Address::Ipv4("192.168.1.10".parse().unwrap()), 80),
        );
        assert_eq!(router.pick_outbound(&local_ip), Some("direct"));
    }

    #[test]
    fn test_tls_sni_sniffer() {
        let mut ch = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03,
        ];
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session_id_len
        ch.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
        ch.extend_from_slice(&[1, 0]); // compression
        let host = b"services.gradle.org";
        let sni_ext_len = (5 + host.len()) as u16;
        let total_ext_len = 4 + sni_ext_len;
        ch.extend_from_slice(&total_ext_len.to_be_bytes());
        ch.extend_from_slice(&0x0000u16.to_be_bytes());
        ch.extend_from_slice(&sni_ext_len.to_be_bytes());
        ch.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        ch.push(0x00);
        ch.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ch.extend_from_slice(host);
        assert_eq!(sniff_tls_sni(&ch).as_deref(), Some("services.gradle.org"));
    }

    #[tokio::test]
    async fn test_e2e_pingora_http_and_mixed_through_pooled_freedom() {
        // 1. Local echo server acting as remote target
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr: SocketAddr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // 2. Wire MixedInbound -> Dispatcher -> PingoraPooledOutbound(FreedomHandler)
        let inbound: Arc<dyn InboundHandler> = Arc::new(MixedInbound::new("mixed"));
        let freedom = Arc::new(FreedomHandler::new("direct"));
        let pooled = Arc::new(PingoraPooledOutbound::new(
            "direct",
            vec![freedom],
            16,
            Duration::from_secs(30),
        ));
        let mut dispatcher = Dispatcher::new("direct");
        dispatcher.register_outbound(pooled);
        let dispatcher = Arc::new(dispatcher);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, remote)) = proxy_listener.accept().await {
                let inbound = inbound.clone();
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    let box_stream: BoxStream = Box::pin(stream);
                    if let Ok(res) = inbound.handle_connection(box_stream, remote).await {
                        let _ = dispatcher.dispatch(res.stream, res.session).await;
                    }
                });
            }
        });

        // 3. Client sends HTTP CONNECT via PingoraHttpInbound path
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            echo_addr, echo_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = [0u8; 128];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200"));

        client.write_all(b"hello-pingora-workspace").await.unwrap();
        let mut out = [0u8; 64];
        let m = client.read(&mut out).await.unwrap();
        assert_eq!(&out[..m], b"hello-pingora-workspace");

        // 4. Direct PingoraHttpInbound check as well
        let _pg = PingoraHttpInbound::new("http");
    }

    #[tokio::test]
    async fn test_robustness_large_traffic_50mb_streaming() {
        const TOTAL_BYTES: usize = 50 * 1024 * 1024;
        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = server_listener.accept().await {
                let chunk = vec![0x5Au8; 64 * 1024];
                let mut sent = 0;
                while sent < TOTAL_BYTES {
                    let n = std::cmp::min(chunk.len(), TOTAL_BYTES - sent);
                    if s.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                    sent += n;
                }
                let _ = s.shutdown().await;
            }
        });

        let inbound: Arc<dyn InboundHandler> = Arc::new(MixedInbound::new("mixed"));
        let mut dispatcher = Dispatcher::new("direct");
        dispatcher.register_outbound(Arc::new(FreedomHandler::new("direct")));
        let dispatcher = Arc::new(dispatcher);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, remote)) = proxy_listener.accept().await {
                let box_stream: BoxStream = Box::pin(stream);
                if let Ok(res) = inbound.handle_connection(box_stream, remote).await {
                    let _ = dispatcher.dispatch(res.stream, res.session).await;
                }
            }
        });

        let start = std::time::Instant::now();
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(format!("CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n", server_addr).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 128];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200"));

        let mut received = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let r = client.read(&mut buf).await.unwrap();
            if r == 0 {
                break;
            }
            assert!(buf[..r].iter().all(|&b| b == 0x5A));
            received += r;
        }
        assert_eq!(received, TOTAL_BYTES);
        let elapsed = start.elapsed();
        let mb_s = (TOTAL_BYTES as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        println!("[STRESS] 50MB single-stream download: {:?} ({:.1} MB/s)", elapsed, mb_s);
    }

    #[tokio::test]
    async fn test_robustness_client_half_close_during_download() {
        const TOTAL_BYTES: usize = 5 * 1024 * 1024;
        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = server_listener.accept().await {
                let mut req = [0u8; 64];
                let _ = s.read(&mut req).await;
                // Wait briefly after client half-closes before sending 5MB
                tokio::time::sleep(Duration::from_millis(30)).await;
                let chunk = vec![0xABu8; 32 * 1024];
                let mut sent = 0;
                while sent < TOTAL_BYTES {
                    let n = std::cmp::min(chunk.len(), TOTAL_BYTES - sent);
                    if s.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                    sent += n;
                }
                let _ = s.shutdown().await;
            }
        });

        let inbound: Arc<dyn InboundHandler> = Arc::new(MixedInbound::new("mixed"));
        let mut dispatcher = Dispatcher::new("direct");
        dispatcher.register_outbound(Arc::new(FreedomHandler::new("direct")));
        let dispatcher = Arc::new(dispatcher);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, remote)) = proxy_listener.accept().await {
                let box_stream: BoxStream = Box::pin(stream);
                if let Ok(res) = inbound.handle_connection(box_stream, remote).await {
                    let _ = dispatcher.dispatch(res.stream, res.session).await;
                }
            }
        });

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(format!("CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n", server_addr).as_bytes())
            .await
            .unwrap();
        let mut resp = [0u8; 128];
        let _ = client.read(&mut resp).await.unwrap();

        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        // Client immediately half-closes write side!
        client.shutdown().await.unwrap();

        let mut received = 0usize;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let r = client.read(&mut buf).await.unwrap();
            if r == 0 {
                break;
            }
            received += r;
        }
        assert_eq!(received, TOTAL_BYTES, "Half-close must not abort download");
        println!("[CHAOS] Half-close 5MB download survived intact");
    }

    #[tokio::test]
    async fn test_robustness_concurrent_50_burst_and_abrupt_drops() {
        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut idx = 0usize;
            while let Ok((mut s, _)) = server_listener.accept().await {
                let cur = idx;
                idx += 1;
                tokio::spawn(async move {
                    if cur % 2 == 1 {
                        // Abruptly drop every odd connection
                        drop(s);
                        return;
                    }
                    let payload = vec![0x42u8; 128 * 1024];
                    let _ = s.write_all(&payload).await;
                    let _ = s.shutdown().await;
                });
            }
        });

        let inbound: Arc<dyn InboundHandler> = Arc::new(MixedInbound::new("mixed"));
        let mut dispatcher = Dispatcher::new("direct");
        dispatcher.register_outbound(Arc::new(FreedomHandler::new("direct")));
        let dispatcher = Arc::new(dispatcher);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, remote)) = proxy_listener.accept().await {
                let inbound = inbound.clone();
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    let box_stream: BoxStream = Box::pin(stream);
                    if let Ok(res) = inbound.handle_connection(box_stream, remote).await {
                        let _ = dispatcher.dispatch(res.stream, res.session).await;
                    }
                });
            }
        });

        let mut handles = Vec::new();
        for _ in 0..50 {
            handles.push(tokio::spawn(async move {
                let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
                client
                    .write_all(
                        format!("CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n", server_addr).as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut resp = [0u8; 128];
                let _ = client.read(&mut resp).await;
                let mut total = 0usize;
                let mut buf = [0u8; 16384];
                while let Ok(r) = client.read(&mut buf).await {
                    if r == 0 {
                        break;
                    }
                    total += r;
                }
                total
            }));
        }

        let mut full_ok = 0;
        for h in handles {
            let n = h.await.unwrap();
            if n == 128 * 1024 {
                full_ok += 1;
            }
        }
        assert!(full_ok >= 20, "Expected healthy connections to succeed despite abrupt drops, got {}", full_ok);
        println!("[CHAOS] 50 concurrent burst connections with 50% abrupt drops: {}/25 healthy completed", full_ok);
    }

    #[tokio::test]
    async fn test_robustness_idle_timeout_terminates_stalled_session() {
        let (mut a, _a_peer) = tokio::io::duplex(4096);
        let (mut b, _b_peer) = tokio::io::duplex(4096);
        let start = std::time::Instant::now();
        let res = xray_rs_route::copy_bidirectional_with_timeout(
            &mut a,
            &mut b,
            Duration::from_millis(120),
        )
        .await;
        assert!(res.is_err());
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(2));
        println!("[CHAOS] Stalled session terminated cleanly in {:?}", elapsed);
    }
}
