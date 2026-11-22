use crate::common::serial::TypedMessage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub service: Vec<TypedMessage>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectionConfig {}
