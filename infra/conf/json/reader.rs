use crate::common::errors::Result;
use serde_json::Value;

pub fn parse_json_value(s: &str) -> Result<Value> {
    serde_json::from_str(s).map_err(|e| crate::common::errors::Error::Config(e.to_string()))
}
