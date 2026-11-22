#[cfg(test)]
mod tests {
    use super::super::{AlwaysOnInboundHandler, InboundWorker, always::ALWAYS_ON};
    use crate::app::stats::StatsManager;
    use crate::features::inbound::InboundHandler;

    #[tokio::test]
    async fn test_always_on_inbound_handler_lifecycle() {
        let _ = ALWAYS_ON;
        let stats_mgr = StatsManager::new();
        let handler = AlwaysOnInboundHandler::new(
            "socks-in",
            Some(&stats_mgr),
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
        );

        assert_eq!(handler.tag(), "socks-in");
        assert_eq!(handler.receiver_settings(), Some(vec![1, 2, 3]));
        assert_eq!(handler.proxy_settings(), Some(vec![4, 5, 6]));

        assert!(handler.uplink_counter().is_some());
        assert!(handler.downlink_counter().is_some());

        let up = handler.uplink_counter().unwrap();
        up.add(1024);
        assert_eq!(up.value(), 1024);

        let worker1 = InboundWorker::new("socks-in", "127.0.0.1", 1080);
        let worker2 = InboundWorker::new("socks-in", "127.0.0.1", 1081);
        handler.add_worker(worker1).await;
        handler.add_worker(worker2).await;

        handler.start().await.expect("start handler");
        handler.close().await.expect("close handler");
    }

    #[tokio::test]
    async fn test_vless_ws_tls_server_end_to_end() {
        use crate::common::net::Destination;
        use crate::common::protocol::SessionContext;
        use crate::core::Instance;
        use crate::infra::conf::Config;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cert_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem_lines: Vec<String> = cert_key
            .cert
            .pem()
            .lines()
            .map(|s| s.to_string())
            .collect();
        let key_pem_lines: Vec<String> = cert_key
            .key_pair
            .serialize_pem()
            .lines()
            .map(|s| s.to_string())
            .collect();

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = probe.local_addr().unwrap().port();
        drop(probe);

        let uuid = "11111111-2222-3333-4444-555555555555";
        let server_json = serde_json::json!({
            "inbounds": [{
                "tag": "vless-ws-tls-in",
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{ "id": uuid }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": "/"
                    },
                    "tlsSettings": {
                        "alpn": ["http/1.1"],
                        "certificates": [{
                            "certificate": cert_pem_lines,
                            "key": key_pem_lines
                        }]
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        });

        let server_cfg: Config = serde_json::from_value(server_json).unwrap();
        let server_instance = Instance::from_config(server_cfg).unwrap();
        let server_tasks = server_instance.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let client_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{ "id": uuid, "testpre": 2 }]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": "/"
                    },
                    "tlsSettings": {
                        "serverName": "localhost",
                        "allowInsecure": true
                    }
                }
            }]
        });
        let client_cfg: Config = serde_json::from_value(client_json).unwrap();
        let built_client = client_cfg.build().unwrap();
        let proxy_out = built_client.outbounds.get("proxy").unwrap().clone();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        for idx in 0..2 {
            let dest = Destination::from_ip_port(echo_addr.ip(), echo_addr.port());
            let session = SessionContext::new("test-client", dest);
            let mut tunnel = proxy_out.connect(&session).await.unwrap();

            let msg = format!("hello-from-xray-rs-server-pool-{}", idx);
            tunnel.write_all(msg.as_bytes()).await.unwrap();
            tunnel.flush().await.unwrap();

            let mut echoed = vec![0u8; msg.len()];
            tunnel.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, msg.as_bytes());
        }

        for t in server_tasks {
            t.abort();
        }
        echo_task.abort();
    }

    #[tokio::test]
    async fn test_vless_xhttp_tls_end_to_end() {
        use crate::common::net::Destination;
        use crate::common::protocol::SessionContext;
        use crate::core::Instance;
        use crate::infra::conf::Config;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cert_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem_lines: Vec<String> = cert_key
            .cert
            .pem()
            .lines()
            .map(|s| s.to_string())
            .collect();
        let key_pem_lines: Vec<String> = cert_key
            .key_pair
            .serialize_pem()
            .lines()
            .map(|s| s.to_string())
            .collect();

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = probe.local_addr().unwrap().port();
        drop(probe);

        let uuid = "22222222-3333-4444-5555-666666666666";
        let server_json = serde_json::json!({
            "inbounds": [{
                "tag": "vless-xhttp-in",
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{ "id": uuid }]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": "/xhttp",
                        "mode": "packet-up"
                    },
                    "tlsSettings": {
                        "alpn": ["http/1.1"],
                        "certificates": [{
                            "certificate": cert_pem_lines,
                            "key": key_pem_lines
                        }]
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        });

        let server_cfg: Config = serde_json::from_value(server_json).unwrap();
        let server_instance = Instance::from_config(server_cfg).unwrap();
        let server_tasks = server_instance.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let client_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{ "id": uuid }]
                    }]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": "/xhttp",
                        "mode": "packet-up"
                    },
                    "tlsSettings": {
                        "serverName": "localhost",
                        "allowInsecure": true
                    }
                }
            }]
        });
        let client_cfg: Config = serde_json::from_value(client_json).unwrap();
        let built_client = client_cfg.build().unwrap();
        let proxy_out = built_client.outbounds.get("proxy").unwrap().clone();

        let dest = Destination::from_ip_port(echo_addr.ip(), echo_addr.port());
        let session = SessionContext::new("test-xhttp-client", dest);
        let mut tunnel = proxy_out.connect(&session).await.unwrap();

        let msg = b"hello-from-xray-rs-xhttp-tls-e2e";
        tunnel.write_all(msg).await.unwrap();
        tunnel.flush().await.unwrap();

        let mut echoed = vec![0u8; msg.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, msg);

        drop(tunnel);
        for t in server_tasks {
            t.abort();
        }
        echo_task.abort();
    }

    #[tokio::test]
    async fn test_vless_vision_tls_end_to_end() {
        use crate::common::net::Destination;
        use crate::common::protocol::SessionContext;
        use crate::core::Instance;
        use crate::infra::conf::Config;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cert_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem_lines: Vec<String> = cert_key
            .cert
            .pem()
            .lines()
            .map(|s| s.to_string())
            .collect();
        let key_pem_lines: Vec<String> = cert_key
            .key_pair
            .serialize_pem()
            .lines()
            .map(|s| s.to_string())
            .collect();

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = probe.local_addr().unwrap().port();
        drop(probe);

        let uuid = "33333333-4444-5555-6666-777777777777";
        let server_json = serde_json::json!({
            "inbounds": [{
                "tag": "vless-vision-in",
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{ "id": uuid, "flow": "xtls-rprx-vision" }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{
                            "certificate": cert_pem_lines,
                            "key": key_pem_lines
                        }]
                    }
                }
            }],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        });
        let server_cfg: Config = serde_json::from_value(server_json).unwrap();
        let server_instance = Instance::from_config(server_cfg).unwrap();
        let server_tasks = server_instance.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let client_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{ "id": uuid, "flow": "xtls-rprx-vision" }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "allowInsecure": true
                    }
                }
            }]
        });
        let client_cfg: Config = serde_json::from_value(client_json).unwrap();
        let built_client = client_cfg.build().unwrap();
        let proxy_out = built_client.outbounds.get("proxy").unwrap().clone();

        let dest = Destination::from_ip_port(echo_addr.ip(), echo_addr.port());
        let session = SessionContext::new("test-vision-client", dest);
        let mut tunnel = proxy_out.connect(&session).await.unwrap();

        let msg = b"hello-from-xray-rs-xtls-vision-e2e";
        tunnel.write_all(msg).await.unwrap();
        tunnel.flush().await.unwrap();

        let mut echoed = vec![0u8; msg.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, msg);

        drop(tunnel);
        for t in server_tasks {
            t.abort();
        }
        echo_task.abort();
    }

    #[tokio::test]
    async fn test_vless_httpupgrade_tls_end_to_end() {
        use crate::common::net::Destination;
        use crate::common::protocol::SessionContext;
        use crate::core::Instance;
        use crate::infra::conf::Config;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cert_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem_lines: Vec<String> = cert_key
            .cert
            .pem()
            .lines()
            .map(|s| s.to_string())
            .collect();
        let key_pem_lines: Vec<String> = cert_key
            .key_pair
            .serialize_pem()
            .lines()
            .map(|s| s.to_string())
            .collect();

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = probe.local_addr().unwrap().port();
        drop(probe);

        let uuid = "44444444-5555-6666-7777-888888888888";
        let server_json = serde_json::json!({
            "inbounds": [{
                "tag": "vless-hu-in",
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{ "id": uuid }]
                },
                "streamSettings": {
                    "network": "httpupgrade",
                    "security": "tls",
                    "httpupgradeSettings": { "path": "/hu" },
                    "tlsSettings": {
                        "certificates": [{
                            "certificate": cert_pem_lines,
                            "key": key_pem_lines
                        }]
                    }
                }
            }],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        });
        let server_cfg: Config = serde_json::from_value(server_json).unwrap();
        let server_instance = Instance::from_config(server_cfg).unwrap();
        let server_tasks = server_instance.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let client_json = serde_json::json!({
            "inbounds": [],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{ "id": uuid }]
                    }]
                },
                "streamSettings": {
                    "network": "httpupgrade",
                    "security": "tls",
                    "httpupgradeSettings": { "path": "/hu" },
                    "tlsSettings": {
                        "serverName": "localhost",
                        "allowInsecure": true
                    }
                }
            }]
        });
        let client_cfg: Config = serde_json::from_value(client_json).unwrap();
        let built_client = client_cfg.build().unwrap();
        let proxy_out = built_client.outbounds.get("proxy").unwrap().clone();

        let dest = Destination::from_ip_port(echo_addr.ip(), echo_addr.port());
        let session = SessionContext::new("test-hu-client", dest);
        let mut tunnel = proxy_out.connect(&session).await.unwrap();

        let msg = b"hello-from-xray-rs-httpupgrade-tls-e2e";
        tunnel.write_all(msg).await.unwrap();
        tunnel.flush().await.unwrap();

        let mut echoed = vec![0u8; msg.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, msg);

        drop(tunnel);
        for t in server_tasks {
            t.abort();
        }
        echo_task.abort();
    }

    #[tokio::test]
    async fn test_reality_server_probe_mirrors_to_dest() {
        use crate::core::Instance;
        use crate::infra::conf::Config;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();
        let dest_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = dest_listener.accept().await {
                let mut buf = [0u8; 256];
                if let Ok(n) = sock.read(&mut buf).await
                    && n > 0
                {
                    let mut reply = b"CAMOUFLAGE:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&reply).await;
                    let _ = sock.flush().await;
                }
            }
        });

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = probe.local_addr().unwrap().port();
        drop(probe);

        let priv_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let server_json = serde_json::json!({
            "inbounds": [{
                "tag": "vless-reality-in",
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{ "id": "55555555-6666-7777-8888-999999999999" }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": dest_addr.to_string(),
                        "serverNames": ["www.microsoft.com"],
                        "privateKey": priv_hex,
                        "shortIds": ["a1b2c3d4"]
                    }
                }
            }],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        });
        let server_cfg: Config = serde_json::from_value(server_json).unwrap();
        let server_instance = Instance::from_config(server_cfg).unwrap();
        let server_tasks = server_instance.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let mut prober = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let probe_bytes = b"GET / HTTP/1.1\r\nHost: www.microsoft.com\r\n\r\n";
        prober.write_all(probe_bytes).await.unwrap();
        prober.flush().await.unwrap();

        let mut resp = vec![0u8; 11 + probe_bytes.len()];
        prober.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp[..11], b"CAMOUFLAGE:");
        assert_eq!(&resp[11..], probe_bytes);

        for t in server_tasks {
            t.abort();
        }
        dest_task.abort();
    }
}
