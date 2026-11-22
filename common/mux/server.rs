use super::frame::{Frame, SessionStatus};
use super::session::{Session, SessionManager};
use crate::common::errors::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct MuxServer {
    session_manager: Arc<SessionManager>,
}

impl MuxServer {
    pub fn new() -> Self {
        Self {
            session_manager: Arc::new(SessionManager::new()),
        }
    }

    pub fn session_count(&self) -> usize {
        self.session_manager.size()
    }

    pub async fn dispatch_frame(&self, frame: Frame) -> Result<Option<Session>> {
        match frame.status {
            SessionStatus::New if frame.target.is_some() => {
                let (tx, _rx) = mpsc::channel(128);
                return Ok(Some(self.session_manager.allocate_channel(frame.target.unwrap(), tx).await?));
            }
            SessionStatus::Keep => if let Some(s) = self.session_manager.get(frame.session_id) {
                if let Some(ref sender) = s.sender { let _ = sender.send(frame.payload).await; }
                return Ok(Some(s));
            },
            SessionStatus::End => { self.session_manager.remove(false, frame.session_id); }
            _ => {}
        }
        Ok(None)
    }

    pub fn close(&self) {
        self.session_manager.close();
    }
}

impl Default for MuxServer {
    fn default() -> Self {
        Self::new()
    }
}

pub type Server = MuxServer;
