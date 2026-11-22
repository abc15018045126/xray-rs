use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_logger_restart() -> Command {
    Command::new("restart-logger", "xray api restart-logger [-s=server:port]", "Restart logging service")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        Ok(format!("restart-logger request sent to {}", client.server))
    })
}
