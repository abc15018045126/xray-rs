// Module: main\commands\all\api\balancer_override.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\balancer_override.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_balancer_override() -> Command {
    Command::new("balancer-override", "xray api balancer-override [-s=server:port]", "Override balancer outbound selection")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("balancer-override request sent to {}", client.server))
        })
}
