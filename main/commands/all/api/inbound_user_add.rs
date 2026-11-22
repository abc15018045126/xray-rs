use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_inbound_user_add() -> Command {
    Command::new(
        "add-inbound-user",
        "xray api add-inbound-user [-s=server:port]",
        "Add user to inbound",
    )
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        Ok(format!(
            "add-inbound-user request sent to {}",
            client.server
        ))
    })
}
