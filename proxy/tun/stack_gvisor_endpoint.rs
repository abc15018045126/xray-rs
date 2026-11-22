pub struct GVisorEndpoint {
    pub channel_id: u64,
}

impl GVisorEndpoint {
    pub fn new() -> Self {
        Self { channel_id: 1 }
    }

    pub fn id(&self) -> u64 {
        self.channel_id
    }
}

impl Default for GVisorEndpoint {
    fn default() -> Self {
        Self::new()
    }
}
