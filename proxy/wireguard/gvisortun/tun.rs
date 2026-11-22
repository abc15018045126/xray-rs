pub struct GVisorWireguardTun {
    pub name: String,
}

impl GVisorWireguardTun {
    pub fn new() -> Self { Self { name: "wg0".into() } }
    pub fn device_name(&self) -> &str { &self.name }
}

impl Default for GVisorWireguardTun {
    fn default() -> Self { Self::new() }
}

pub type GVisorTunDevice = GVisorWireguardTun;
