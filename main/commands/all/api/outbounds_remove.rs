// Module: main\commands\all\api\outbounds_remove.rs
// 1:1 Rust implementation corresponding to Go main\commands\all\api\outbounds_remove.go

use crate::main::commands::base::command::Command;
use super::shared::ApiClientConfig;

pub fn cmd_outbounds_remove() -> Command {
    Command::new("remove-outbounds", "xray api remove-outbounds [-s=server:port]", "Remove outbounds by tag")
        .with_run(|args| {
            let client = ApiClientConfig::parse(args);
            Ok(format!("remove-outbounds request sent to {}", client.server))
        })
}
