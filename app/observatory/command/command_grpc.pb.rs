// Module: app\observatory\command\command_grpc.pb.rs
use async_trait::async_trait;
use crate::common::errors::Result;
use super::command_pb::{GetOutboundStatusRequest, GetOutboundStatusResponse};

#[async_trait]
pub trait ObservatoryService: Send + Sync {
    async fn get_outbound_status(&self, req: GetOutboundStatusRequest) -> Result<GetOutboundStatusResponse>;
}
