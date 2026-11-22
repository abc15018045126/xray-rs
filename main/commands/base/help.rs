use super::command::Command;

pub fn generate_help_text(cmd: &Command) -> String {
    format!("{}\nUsage: {}\n", cmd.short, cmd.usage)
}
