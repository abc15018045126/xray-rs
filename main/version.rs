pub const VERSION: &str = "26.3.27";

pub fn version() -> &'static str { VERSION }

pub fn print_version() -> String { format!("Xray-core-rust {}", version()) }
