// Module: main\commands\all\api\stats_get_all_online_users.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\stats_get_all_online_users.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_stats_get_all_online_users() -> Command {
    Command::new("get-online-users", "xray api get-online-users [-s=server:port]", "Get list of online users")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("get-online-users request sent to {}", client.server))
        })
}
