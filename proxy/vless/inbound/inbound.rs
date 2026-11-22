use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use uuid::Uuid;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::protocol::{RequestCommand, SessionContext, User};
use crate::features::inbound::{InboundHandler, InboundResult};
use crate::features::policy::PolicyManager;
use crate::features::stats::StatsManagerTrait;
use crate::proxy::vless::encoding::{RequestHeader, ResponseHeader};
use crate::proxy::vless::flow::{FLOW_VISION, FLOW_VISION_UDP443, VisionContext, VisionStream};
use crate::proxy::vless::validator::{MemoryValidator, Validator};
use crate::transport::internet::websocket::ws::PrefixedStream;

struct RecordingReader<'a, R> {
    inner: &'a mut R,
    recorded: Vec<u8>,
}

impl<'a, R: AsyncRead + Unpin> AsyncRead for RecordingReader<'a, R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let filled = buf.filled();
            if filled.len() > before { self.recorded.extend_from_slice(&filled[before..]); }
        }
        poll
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fallback {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(default)]
    pub path: String,
    pub dest: String,
    #[serde(default)]
    pub xver: u64,
}

pub struct Handler {
    tag: String,
    validator: Arc<dyn Validator>,
    fallbacks: Vec<Fallback>,
    policy_manager: Option<Arc<dyn PolicyManager>>,
    stats_manager: Option<Arc<dyn StatsManagerTrait>>,
    fallback_map: HashMap<String, HashMap<String, HashMap<String, Fallback>>>,
}

impl Handler {
    pub fn new(tag: impl Into<String>, users: Vec<Uuid>) -> Self {
        let validator = MemoryValidator::new();
        for u in users { let _ = validator.add(User::new(u)); }
        Self::with_validator(tag, Arc::new(validator))
    }
    pub fn with_validator(tag: impl Into<String>, validator: Arc<dyn Validator>) -> Self {
        Self {
            tag: tag.into(),
            validator,
            fallbacks: Vec::new(),
            policy_manager: None,
            stats_manager: None,
            fallback_map: HashMap::new(),
        }
    }
    pub fn with_fallbacks(mut self, fallbacks: Vec<Fallback>) -> Self {
        self.fallbacks = fallbacks.clone();
        let mut map: HashMap<String, HashMap<String, HashMap<String, Fallback>>> = HashMap::new();
        for fb in fallbacks {
            map.entry(fb.name.to_lowercase())
                .or_default().entry(fb.alpn.to_lowercase()).or_default().insert(fb.path.clone(), fb);
        }
        self.fallback_map = map;
        self
    }
    pub fn with_policy_manager(mut self, policy_manager: Arc<dyn PolicyManager>) -> Self {
        self.policy_manager = Some(policy_manager);
        self
    }
    pub fn with_stats_manager(mut self, stats_manager: Arc<dyn StatsManagerTrait>) -> Self {
        self.stats_manager = Some(stats_manager);
        self
    }
    pub fn add_user(&self, user: User) -> Result<()> { self.validator.add(user) }
    pub fn del_user(&self, email: &str) -> Result<()> { self.validator.del(email) }
    pub fn get_user(&self, uuid: &Uuid) -> Option<User> { self.validator.get(uuid) }
    pub fn get_user_count(&self) -> usize { self.validator.get_count() }
    pub fn match_fallback(&self, name: &str, alpn: &str, path: &str) -> Option<&Fallback> {
        let (name_lower, alpn_lower) = (name.to_lowercase(), alpn.to_lowercase());
        if let Some(by_name) = self.fallback_map.get(&name_lower).or_else(|| self.fallback_map.get(""))
            && let Some(by_alpn) = by_name.get(&alpn_lower).or_else(|| by_name.get(""))
            && let Some(fb) = by_alpn.get(path).or_else(|| by_alpn.get(""))
        {
            return Some(fb);
        }
        None
    }
}

#[async_trait]
impl InboundHandler for Handler {
    fn tag(&self) -> &str { &self.tag }
    async fn handle_connection(&self, mut stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let (req_result, recorded) = {
            let mut rec = RecordingReader { inner: &mut stream, recorded: Vec::with_capacity(64) };
            (RequestHeader::decode(&mut rec).await, rec.recorded)
        };
        let make_fallback = |recorded: Vec<u8>, stream: BoxStream| -> Option<Result<InboundResult>> {
            let fb = self.match_fallback("", "", "")?;
            Some(Destination::parse_str(&fb.dest, Network::Tcp).map(|dest| {
                let mut session = SessionContext::new(&self.tag, dest);
                session.source = Some(remote_addr);
                let out = if recorded.is_empty() {
                    stream
                } else {
                    Box::pin(PrefixedStream { prefix: recorded, offset: 0, inner: stream })
                };
                InboundResult { stream: out, session }
            }))
        };
        let req = match req_result {
            Ok(r) => r,
            Err(e) => return make_fallback(recorded, stream).unwrap_or(Err(e)),
        };
        let user = if self.validator.get_count() > 0 {
            match self.validator.get(&req.user_id) {
                Some(u) => Some(u),
                None => {
                    return make_fallback(recorded, stream).unwrap_or_else(|| {
                        Err(Error::AuthFailed(format!("Unauthorized VLESS user UUID: {}", req.user_id)))
                    });
                }
            }
        } else {
            None
        };
        ResponseHeader::new().encode(&mut stream).await?;
        let mut session = SessionContext::new(&self.tag, req.destination);
        session.source = Some(remote_addr);
        session.destination.network = if matches!(req.command, RequestCommand::Udp) {
            Network::Udp
        } else {
            Network::Tcp
        };
        session.user = Some(user.unwrap_or_else(|| User::new(req.user_id)));
        let final_stream: BoxStream =
            if req.addons.flow == FLOW_VISION || req.addons.flow == FLOW_VISION_UDP443 {
                session.sniffed_protocol = Some("tls".into());
                Box::pin(VisionStream::new(stream, VisionContext::new(req.user_id.into_bytes().to_vec(), false), true))
            } else {
                stream
            };
        Ok(InboundResult { stream: final_stream, session })
    }
}

pub use Handler as Server;
pub use Handler as VlessInboundServer;
