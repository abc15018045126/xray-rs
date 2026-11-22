use std::time::Instant;

#[derive(Clone)]
pub struct Clock {
    start: Instant,
}

impl Clock {
    pub fn new() -> Self { Self { start: Instant::now(), } }
    pub fn now(&self) -> Instant { Instant::now() }
    pub fn elapsed(&self) -> std::time::Duration { self.start.elapsed() }
}

impl Default for Clock {
    fn default() -> Self { Self::new() }
}
