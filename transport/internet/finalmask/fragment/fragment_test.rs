#[cfg(test)]
mod tests {
    use super::super::config_pb::Config;
    use super::super::conn::FragmentConn;
    use crate::transport::internet::finalmask::finalmask::TcpMaskConn;
    use tokio::io::{AsyncReadExt, duplex};

    #[test]
    fn test_fragment_config_defaults() {
        let config = Config::default();
        assert_eq!(config.packets_from, 0);
        assert_eq!(config.packets_to, 0);
        assert_eq!(config.length_min, 0);
        assert_eq!(config.length_max, 0);
        assert_eq!(config.delay_min, 0);
        assert_eq!(config.delay_max, 0);
        assert_eq!(config.max_split_min, 0);
        assert_eq!(config.max_split_max, 0);
    }

    #[tokio::test]
    async fn test_fragment_conn_client_server_wrap() {
        let (client_io, server_io) = duplex(1024);
        let config = Config {
            packets_from: 0,
            packets_to: 1,
            length_min: 10,
            length_max: 20,
            delay_min: 0,
            delay_max: 0,
            max_split_min: 3,
            max_split_max: 5,
            ..Default::default()
        };

        let client_conn = config.wrap_conn_client(Box::pin(client_io)).unwrap();
        let server_conn = config.wrap_conn_server(Box::pin(server_io)).unwrap();

        assert!(!client_conn.server);
        assert!(server_conn.server);
        assert!(TcpMaskConn::splice(&client_conn));
        assert!(!TcpMaskConn::splice(&server_conn));
    }

    #[tokio::test]
    async fn test_fragment_conn_tls_client_hello() {
        let (client_io, mut server_io) = duplex(4096);
        let config = Config {
            packets_from: 0,
            packets_to: 1,
            length_min: 5,
            length_max: 10,
            delay_min: 0,
            delay_max: 0,
            max_split_min: 2,
            max_split_max: 4,
            ..Default::default()
        };

        let mut client_conn = FragmentConn::new_client(config, Box::pin(client_io));

        let mut tls_record = vec![22, 0x03, 0x01, 0x00, 20];
        let payload = b"0123456789abcdefghij";
        tls_record.extend_from_slice(payload);

        let write_task = tokio::spawn(async move {
            client_conn.write_fragmented(&tls_record).await.unwrap();
        });

        let read_task = tokio::spawn(async move {
            let mut received_payload = Vec::new();
            let mut buf = vec![0u8; 1024];
            let mut total_read = 0;
            while received_payload.len() < payload.len() {
                let n = server_io.read(&mut buf).await.unwrap();
                assert!(n > 0);
                total_read += n;
                let mut offset = 0;
                while offset + 5 <= n {
                    assert_eq!(buf[offset], 22);
                    assert_eq!(buf[offset + 1], 0x03);
                    assert_eq!(buf[offset + 2], 0x01);
                    let chunk_len = ((buf[offset + 3] as usize) << 8) | (buf[offset + 4] as usize);
                    let chunk_end = offset + 5 + chunk_len;
                    assert!(chunk_end <= n);
                    received_payload.extend_from_slice(&buf[offset + 5..chunk_end]);
                    offset = chunk_end;
                }
            }
            assert_eq!(received_payload, payload);
            assert!(total_read > 25);
        });

        write_task.await.unwrap();
        read_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fragment_conn_generic_packets() {
        let (client_io, mut server_io) = duplex(4096);
        let config = Config {
            packets_from: 1,
            packets_to: 2,
            length_min: 8,
            length_max: 12,
            delay_min: 0,
            delay_max: 0,
            max_split_min: 2,
            max_split_max: 3,
            ..Default::default()
        };

        let mut client_conn = FragmentConn::new_client(config, Box::pin(client_io));
        let data = b"Hello, this is a generic packet stream destined to be fragmented into chunks!";

        let data_clone = data.to_vec();
        let write_task = tokio::spawn(async move {
            client_conn.write_fragmented(&data_clone).await.unwrap();
        });

        let read_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buf = vec![0u8; 256];
            while received.len() < data.len() {
                let n = server_io.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(received, data);
        });

        write_task.await.unwrap();
        read_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_fragment_conn_poll_write_and_segment_arrays() {
        use tokio::io::AsyncWriteExt;
        let (client_io, mut server_io) = duplex(4096);
        let config = Config {
            packets_from: 0,
            packets_to: 1,
            lengths_min: vec![4, 6],
            lengths_max: vec![4, 6],
            delays_min: vec![1, 1],
            delays_max: vec![2, 2],
            max_split_min: 3,
            max_split_max: 3,
            ..Default::default()
        };
        assert_eq!(config.length_for_segment(0), (4, 4));
        assert_eq!(config.length_for_segment(1), (6, 6));
        assert_eq!(config.length_for_segment(5), (6, 6));
        assert!(!config.merge_tls_hello_segments());

        let mut client_conn = FragmentConn::new_client(config, Box::pin(client_io));
        let mut tls_record = vec![22, 0x03, 0x01, 0x00, 20];
        let payload = b"0123456789abcdefghij";
        tls_record.extend_from_slice(payload);

        let write_task = tokio::spawn(async move {
            client_conn.write_all(&tls_record).await.unwrap();
            client_conn.flush().await.unwrap();
        });

        let read_task = tokio::spawn(async move {
            let mut raw = Vec::new();
            let mut buf = [0u8; 256];
            while raw.len() < 35 {
                let n = server_io.read(&mut buf).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&buf[..n]);
            }
            assert_eq!(raw.len(), 35);
            assert_eq!(&raw[0..5], &[22, 0x03, 0x01, 0x00, 4]);
            assert_eq!(&raw[5..9], b"0123");
            assert_eq!(&raw[9..14], &[22, 0x03, 0x01, 0x00, 6]);
            assert_eq!(&raw[14..20], b"456789");
            assert_eq!(&raw[20..25], &[22, 0x03, 0x01, 0x00, 10]);
            assert_eq!(&raw[25..35], b"abcdefghij");
        });

        write_task.await.unwrap();
        read_task.await.unwrap();
    }
}
