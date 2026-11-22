pub struct CustomServiceName {
    pub name: String,
}

impl CustomServiceName {
    pub fn new(name: impl Into<String>) -> Self { Self { name: name.into() } }
    pub fn method_path(&self) -> String { format!("/{}/Tun", self.name) }
}
