use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;

pub const YAML_FORMAT: &str = "YAML";
pub const FORMAT_YAML: &str = YAML_FORMAT;

pub fn load_yaml_from_str(content: &str) -> Result<Config> {
    serde_json::from_str(content).map_err(|_| {
        Error::Config("YAML decoding requires yaml structure or serde converter".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_format_const() {
        assert_eq!(YAML_FORMAT, "YAML");
    }
}
