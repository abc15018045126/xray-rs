use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::io::AsyncReadExt;

use super::client::{DefaultDialerClient, DialerClient};
use super::config::SplitHttpConfig;
use super::connection::SplitConn;
use crate::common::errors::Result;
use crate::common::net::{BoxStream, Destination};
use crate::transport::internet::dialer::Dialer;

pub struct SplitHttpDialer {
    config: SplitHttpConfig,
}

impl SplitHttpDialer {
    pub fn new(config: SplitHttpConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SplitHttpConfig {
        &self.config
    }

    pub async fn dial_with_client(
        &self,
        client: Arc<dyn DialerClient>,
        dest: &Destination,
    ) -> Result<BoxStream> {
        let mode = if self.config.mode.is_empty() || self.config.mode == "auto" { "packet-up" } else { &self.config.mode };
        let session_id = if mode != "stream-one" { uuid::Uuid::new_v4().to_string() } else { String::new() };
        let norm_path = self.config.get_normalized_path();
        let target_url = if self.config.host.is_empty() {
            format!("http://{}{}", dest.address, norm_path)
        } else {
            format!("http://{}{}", self.config.host, norm_path)
        };

        let (down_reader, local_addr, remote_addr) = client.open_stream(&target_url, &session_id, None, false).await?;
        let (upload_tx, mut upload_rx) = tokio::io::duplex(64 * 1024);
        let max_post = self.config.get_normalized_sc_max_each_post_bytes().rand() as usize;
        let max_chunk = if max_post > 0 { max_post } else { 1024 * 1024 };

        tokio::spawn(async move {
            let seq = AtomicI64::new(0);
            let mut buf = vec![0u8; max_chunk];
            while let Ok(n) = upload_rx.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let cur_seq = seq.fetch_add(1, Ordering::SeqCst).to_string();
                if client.post_packet(&target_url, &session_id, &cur_seq, buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });

        Ok(Box::pin(SplitConn::new(down_reader, Box::pin(upload_tx), local_addr, remote_addr, None)))
    }
}

#[async_trait]
impl Dialer for SplitHttpDialer {
    async fn dial(&self, dest: &Destination) -> Result<BoxStream> {
        let client = Arc::new(DefaultDialerClient::new(
            self.config.clone(),
            dest.clone(),
            "1.1",
        ));
        self.dial_with_client(client, dest).await
    }
}
