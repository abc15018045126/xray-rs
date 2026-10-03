pub mod drain;
pub mod drainer;

#[cfg(test)]
pub mod drain_test;

pub use drain::{drain_read_n, Drainer};
pub use drainer::{with_error, BehaviorSeedLimitedDrainer, NopDrainer};
