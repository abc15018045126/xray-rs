#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunStack {
    #[default]
    System,
    GVisor,
    Mixed,
}
