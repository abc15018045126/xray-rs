use super::shared::ApiClientConfig;
use crate::main::commands::base::command::Command;

pub fn cmd_balancer_info() -> Command {
    Command::new("balancer-info", "xray api balancer-info [-s=server:port]", "Query balancer information via API")
    .with_run(|args| {
        let client = ApiClientConfig::parse(args);
        Ok(format!("balancer-info request sent to {}", client.server))
    })
}
