pub mod core_gateway;
pub mod inbound;
pub mod outbound;
pub mod pool;

pub use core_gateway::{PingoraCoreConnector, PingoraInboundApp, spawn_pingora_inbound};
pub use inbound::PingoraHttpInbound;
pub use outbound::PingoraPooledOutbound;
pub use pool::{PingoraStreamPool, PingoraUpstreamBalancer, pool_key};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::common::net::BoxStream;
    use crate::features::inbound::InboundHandler;

    #[tokio::test]
    async fn test_pingora_pool_put_and_get() {
        let pool = PingoraStreamPool::new(16, Duration::from_secs(30));
        let (a, _b) = tokio::io::duplex(4096);
        let key = pool_key("worker-a3:443");
        pool.put(key, Box::pin(a));
        assert!(pool.get(key).is_some(), "Expected pooled stream to be returned");
        assert!(pool.get(key).is_none(), "Expected pool to be empty after get");

        // Verify idle_timeout actively evicts expired streams AND releases the semaphore permit
        let short_pool = PingoraStreamPool::new(4, Duration::from_millis(60));
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = sem.clone().acquire_owned().await.unwrap();
        let (c, _d) = tokio::io::duplex(1024);
        short_pool.put_with_permit(key, Box::pin(c), permit);
        assert_eq!(sem.available_permits(), 0);
        tokio::time::sleep(Duration::from_millis(140)).await;
        assert!(
            short_pool.get(key).is_none(),
            "Expired stream should be actively removed by pingora-pool::idle_timeout"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "Semaphore permit must be released automatically on idle expiration"
        );
    }

    #[tokio::test]
    async fn test_pingora_load_balancer_round_robin() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:10002".parse().unwrap(),
        ];
        let lb = PingoraUpstreamBalancer::from_addrs(&addrs).expect("LB init");
        let b1 = lb.select().expect("first backend");
        let b2 = lb.select().expect("second backend");
        assert_ne!(b1.addr, b2.addr, "RoundRobin should alternate backends");

        // Verify pingora-ketama consistent hashing sticks identical domains to the same upstream
        let ketama = PingoraUpstreamBalancer::from_labels_ketama(vec![
            "worker-a1.dev:443".into(),
            "worker-a2.dev:443".into(),
            "worker-a3.dev:443".into(),
        ])
        .expect("Ketama LB init");
        let k1 = ketama.select_index_for_key(b"www.google.com").unwrap();
        let k2 = ketama.select_index_for_key(b"www.google.com").unwrap();
        assert_eq!(k1, k2, "Ketama consistent hashing should stick same domain");
    }

    #[tokio::test]
    async fn test_pingora_http_inbound_connect_and_plain_http() {
        let handler = PingoraHttpInbound::new("pg-http");

        // 1. Plain HTTP test: verifies Proxy-Connection stripping via pingora-http
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            client
                .write_all(
                    b"GET http://example.com/file.jar HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let (sock, remote) = listener.accept().await.unwrap();
        let mut res = handler.handle_connection(Box::pin(sock), remote).await.unwrap();
        assert_eq!(res.session.destination.port, 80);
        let mut out = [0u8; 256];
        let n = res.stream.read(&mut out).await.unwrap();
        let forwarded = String::from_utf8_lossy(&out[..n]);
        assert!(forwarded.contains("GET http://example.com/file.jar HTTP/1.1"));
        assert!(
            !forwarded.to_ascii_lowercase().contains("proxy-connection"),
            "Proxy-Connection should be stripped, got: {}",
            forwarded
        );
        client_task.await.unwrap();

        // 2. CONNECT benchmark (50 roundtrips)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let start = Instant::now();
        for _ in 0..50 {
            let client_task = tokio::spawn(async move {
                let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
                client
                    .write_all(
                        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let mut resp = [0u8; 128];
                let n = client.read(&mut resp).await.unwrap();
                assert!(String::from_utf8_lossy(&resp[..n]).contains("200"));
                client.write_all(b"ping-payload").await.unwrap();
                let mut echo = [0u8; 16];
                let en = client.read(&mut echo).await.unwrap();
                assert_eq!(&echo[..en], b"pong-payload");
            });

            let (sock, remote) = listener.accept().await.unwrap();
            let box_sock: BoxStream = Box::pin(sock);
            let mut res = handler.handle_connection(box_sock, remote).await.unwrap();
            assert_eq!(res.session.destination.port, 443);

            let mut buf = [0u8; 16];
            let n = res.stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping-payload");
            res.stream.write_all(b"pong-payload").await.unwrap();
            res.stream.flush().await.unwrap();
            client_task.await.unwrap();
        }
        println!("[BENCH] pingora-http x50 CONNECT roundtrips: {:?}", start.elapsed());
    }

    #[tokio::test]
    async fn test_pingora_core_inbound_to_outbound_e2e() {
        use crate::app::dispatcher::DefaultDispatcher;
        use crate::app::router::Router;
        use crate::features::outbound::OutboundHandler;
        use crate::proxy::freedom::Handler as FreedomHandler;
        use std::collections::HashMap;
        use std::sync::Arc;

        // 1. Target echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut s, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
            s.flush().await.unwrap();
        });

        // 2. Pick a free local port for Pingora-core inbound service
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let inbound_addr = probe.local_addr().unwrap();
        drop(probe);

        let mut outbounds: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        outbounds.insert("direct".to_string(), Arc::new(FreedomHandler::new("direct")));
        let dispatcher = Arc::new(
            DefaultDispatcher::new(outbounds, Arc::new(Router::new(Vec::new(), Some("direct".into()))))
                .with_default_outbound("direct"),
        );
        let inbound_handler = Arc::new(PingoraHttpInbound::new("pg-core-in"));

        let inbound_task = spawn_pingora_inbound(inbound_addr, inbound_handler, dispatcher)
            .expect("Pingora-core inbound should spawn");

        // Give Pingora listener a brief moment to bind
        tokio::time::sleep(Duration::from_millis(80)).await;

        // 3. Connect through Pingora-core Inbound -> Dispatcher -> Freedom -> PingoraCoreConnector Outbound -> Echo
        let mut client = PingoraCoreConnector::dial_tcp(inbound_addr)
            .await
            .expect("PingoraCoreConnector dial to inbound");
        let req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", echo_addr, echo_addr);
        client.write_all(req.as_bytes()).await.unwrap();
        let mut hdr = [0u8; 128];
        let hn = client.read(&mut hdr).await.unwrap();
        assert!(String::from_utf8_lossy(&hdr[..hn]).contains("200"));

        client.write_all(b"hello-pingora-core").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 64];
        let rn = client.read(&mut reply).await.unwrap();
        assert_eq!(&reply[..rn], b"hello-pingora-core");

        inbound_task.abort();
        echo_task.await.unwrap();
    }
}
