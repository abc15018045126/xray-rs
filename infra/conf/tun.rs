use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfig {
    pub name: String,
    #[serde(default)]
    pub mtu: Option<usize>,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub strict_route: bool,
}
