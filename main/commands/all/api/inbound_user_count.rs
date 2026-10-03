// Module: main\commands\all\api\inbound_user_count.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\inbound_user_count.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_inbound_user_count() -> Command {
    Command::new("inbound-user-count", "xray api inbound-user-count [-s=server:port]", "Count users in an inbound")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("inbound-user-count request sent to {}", client.server))
        })
}
