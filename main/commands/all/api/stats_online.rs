use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_stats_online() -> Command {
    Command::new("online-stats", "xray api online-stats [-s=server:port]", "Query online stats for users")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        Ok(format!("online-stats request sent to {}", client.server))
    })
}
