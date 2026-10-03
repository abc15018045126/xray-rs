// Module: core\\mocks.rs
// 1:1 Rust implementation corresponding to Go core\\mocks.go

use std::sync::Arc;
use crate::core::Instance;

pub fn create_mock_instance() -> Arc<Instance> {
    Arc::new(Instance::from_config(Default::default()).unwrap())
}
