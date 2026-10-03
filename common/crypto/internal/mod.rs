pub mod chacha;
#[path = "chacha_core.generated.rs"]
pub mod chacha_core_generated;
pub mod chacha_core_gen;

pub use chacha::ChaChaCore;
pub use chacha_core_generated::CHACHA_ROUNDS;
