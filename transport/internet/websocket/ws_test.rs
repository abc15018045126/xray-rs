#[cfg(test)]
mod tests {
    use super::super::config::WebSocketConfig;
    use super::super::dialer::WebSocketDialer;
    use super::super::hub::WebSocketHub;
    use crate::common::net::{Address, Destination};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_listen_ws_and_dial_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let hub = WebSocketHub::listen(addr)
            .await
            .expect("Listen on local port");
        let local_addr = hub.local_addr();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = hub.accept().await.expect("Accept WS connection");
            let mut buf = vec![0u8; 128];
            let n = stream.read(&mut buf).await.expect("Read request");
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("Test connection"));

            stream.write_all(b"Response").await.expect("Write response");
            stream.flush().await.expect("Flush response");
        });

        let config = WebSocketConfig {
            path: "ws".into(),
            ..Default::default()
        };
        let dest = Destination::tcp(Address::ip(local_addr.ip()), local_addr.port());

        let mut client_stream = WebSocketDialer::dial(&dest, &config)
            .await
            .expect("Dial WS server");
        client_stream
            .write_all(b"Test connection 1")
            .await
            .expect("Write request");
        client_stream.flush().await.expect("Flush request");

        let mut resp_buf = vec![0u8; 128];
        let n = client_stream
            .read(&mut resp_buf)
            .await
            .expect("Read response");
        assert_eq!(&resp_buf[..n], b"Response");

        server_task.await.expect("Server task should complete");
    }

    #[tokio::test]
    async fn test_ws_multiple_frames_flow() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let hub = WebSocketHub::listen(addr).await.unwrap();
        let local_addr = hub.local_addr();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = hub.accept().await.unwrap();
            for i in 0..5 {
                let mut buf = vec![0u8; 64];
                let n = stream.read(&mut buf).await.unwrap();
                let expected = format!("frame-{}", i);
                assert_eq!(&buf[..n], expected.as_bytes());

                let reply = format!("ack-{}", i);
                stream.write_all(reply.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        let config = WebSocketConfig {
            path: "test".into(),
            ..Default::default()
        };
        let dest = Destination::tcp(Address::ip(local_addr.ip()), local_addr.port());
        let mut client = WebSocketDialer::dial(&dest, &config).await.unwrap();

        for i in 0..5 {
            let msg = format!("frame-{}", i);
            client.write_all(msg.as_bytes()).await.unwrap();
            client.flush().await.unwrap();

            let mut buf = vec![0u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            let expected_ack = format!("ack-{}", i);
            assert_eq!(&buf[..n], expected_ack.as_bytes());
        }

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_delay_dial_ws_early_data_with_vless_split_write() {
        use super::super::dialer::{DelayDialConn, DialWsFn, parse_ws_early_data};
        use super::super::ws::WebSocketStream;
        use crate::proxy::vless::outbound::VlessStream;
        use base64::Engine as _;
        use std::sync::Arc;
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

        assert_eq!(parse_ws_early_data("/?ed=2048"), ("/".to_string(), 2048));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let captured_ed = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let captured_ed_cb = captured_ed.clone();

            let ws = accept_hdr_async(tcp, move |req: &Request, resp: Response| {
                if let Some(val) = req.headers().get("sec-websocket-protocol") {
                    let s = val.to_str().unwrap();
                    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(s)
                        .unwrap();
                    *captured_ed_cb.lock().unwrap() = decoded;
                }
                Ok(resp)
            })
            .await
            .expect("WS server accept failed");

            let (mut ws_tx, mut ws_rx) = futures::StreamExt::split(ws);
            use futures::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message;

            let ed = captured_ed.lock().unwrap().clone();
            assert_eq!(ed.len(), 4 + 1360);
            assert_eq!(&ed[0..4], b"\x00\xaa\xbb\xcc");

            let part2 = match ws_rx.next().await.unwrap().unwrap() {
                Message::Binary(b) => b,
                other => panic!("Expected binary frame, got {:?}", other),
            };
            assert_eq!(part2.len(), 377);

            ws_tx
                .send(Message::Binary(b"\x00\x00ECHO_OK".to_vec()))
                .await
                .unwrap();
        });

        let dial_fn: DialWsFn = Arc::new(move |ed| {
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                let url = format!("ws://{}/", addr);
                let res = WebSocketStream::client_handshake_with_options(
                    &url,
                    Some("localhost"),
                    Box::pin(tcp),
                    0,
                    ed.as_deref(),
                )
                .await;
                if let Err(ref e) = res {
                    eprintln!("DIAL_FN ERROR: {}", e);
                }
                res
            })
        });

        let delay_conn = DelayDialConn::new(dial_fn, 2048);
        let mut vless =
            VlessStream::with_pending_header(Box::pin(delay_conn), false, b"\x00\xaa\xbb\xcc".to_vec());

        let part1 = vec![0x11u8; 1360];
        vless.write_all(&part1).await.unwrap();

        let (mut rd, mut wr) = tokio::io::split(vless);
        let write_fut = async {
            let part2 = vec![0x22u8; 377];
            wr.write_all(&part2).await.unwrap();
            wr.flush().await.unwrap();
        };
        let read_fut = async {
            let mut out = vec![0u8; 64];
            let n = rd.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"ECHO_OK");
        };

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            async { tokio::join!(write_fut, read_fut) },
        )
        .await
        .expect("DelayDialConn + VlessStream deadlocked!");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_ws_coalesced_large_first_frame_single_binary_message() {
        use super::super::ws::WebSocketStream;
        use crate::proxy::vless::outbound::VlessStream;
        use futures::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;
        use tokio_tungstenite::tungstenite::Message;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let header = b"\x00\x11\x22\x33\x44".to_vec();
        let payload = vec![0xABu8; 2048];
        let expected_len = header.len() + payload.len();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = accept_async(tcp).await.expect("WS server accept failed");
            let (mut ws_tx, mut ws_rx) = ws.split();

            let first_frame = match ws_rx.next().await.unwrap().unwrap() {
                Message::Binary(b) => b,
                other => panic!("Expected binary frame, got {:?}", other),
            };
            assert_eq!(first_frame.len(), expected_len);
            assert_eq!(&first_frame[..5], b"\x00\x11\x22\x33\x44");
            assert!(first_frame[5..].iter().all(|&b| b == 0xAB));

            ws_tx
                .send(Message::Binary(b"\x00\x00OK".to_vec()))
                .await
                .unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let url = format!("ws://{}/", addr);
        let ws_client = WebSocketStream::client_handshake(&url, Some("localhost"), Box::pin(tcp))
            .await
            .unwrap();

        let mut vless = VlessStream::with_pending_header(ws_client, false, header);
        vless.write_all(&payload).await.unwrap();
        vless.flush().await.unwrap();

        let mut resp = [0u8; 16];
        let n = vless.read(&mut resp).await.unwrap();
        assert_eq!(&resp[..n], b"OK");

        server_task.await.unwrap();
    }
}
