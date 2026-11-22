use crate::app::observatory::config_pb::ObservationResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetOutboundStatusRequest {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetOutboundStatusResponse {
    pub status: Option<ObservationResult>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusItem {
    pub outbound_tag: String,
    pub alive: bool,
    pub delay: i64,
    pub last_seen_time: i64,
    pub last_try_time: i64,
}
