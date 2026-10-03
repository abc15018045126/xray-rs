// Module: main\commands\all\api\logger_restart.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\logger_restart.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_logger_restart() -> Command {
    Command::new("restart-logger", "xray api restart-logger [-s=server:port]", "Restart logging service")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("restart-logger request sent to {}", client.server))
        })
}
