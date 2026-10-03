// Module: proxy\tun\stack.rs
// 1:1 Rust implementation corresponding to Go proxy\tun\stack.go

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunStack {
    System,
    GVisor,
    Mixed,
}

impl Default for TunStack {
    fn default() -> Self {
        TunStack::System
    }
}
