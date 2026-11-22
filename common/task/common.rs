use crate::common::common::Closable;
use crate::common::errors::Result;

pub const DEFAULT_TASK_TIMEOUT_SECS: u64 = 60;

pub fn close_task<C: Closable>(closable: C) -> impl Fn() -> Result<()> {
    move || closable.close()
}
