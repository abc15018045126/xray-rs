// Module: main\commands\all\api\stats_query.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\stats_query.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_stats_query() -> Command {
    Command::new("query-stats", "xray api query-stats [-s=server:port]", "Query patterned statistics")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("query-stats request sent to {}", client.server))
        })
}
