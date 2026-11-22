use super::command::Command;

pub fn create_root_command() -> Command {
    Command::new("xray", "xray <command> [arguments]", "Xray core proxy and routing tool")
}
