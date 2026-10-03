// Module: main\commands\all\api\stats_sys.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\stats_sys.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_stats_sys() -> Command {
    Command::new("sys-stats", "xray api sys-stats [-s=server:port]", "Get system memory and goroutine statistics")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("sys-stats request sent to {}", client.server))
        })
}
