use super::command::Command;

pub fn execute_command(cmd: &Command, args: &[&str]) -> Result<String, String> {
    cmd.execute(args).map_err(|e| e.to_string())
}
