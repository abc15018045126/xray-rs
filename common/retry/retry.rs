use crate::common::errors::{Error, Result};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub const ERR_RETRY_FAILED: &str = "all retry attempts failed";

pub trait Strategy: Send + Sync {
    fn on<F: FnMut() -> Result<()>>(&self, method: F) -> Result<()>;
}

#[derive(Clone)]
pub struct Retryer {
    total_attempt: usize,
    next_delay_fn: Arc<dyn Fn(usize) -> u32 + Send + Sync>,
}

impl Retryer {
    pub fn new<D>(total_attempt: usize, delay_fn: D) -> Self
    where
        D: Fn(usize) -> u32 + Send + Sync + 'static,
    {
        Self {
            total_attempt,
            next_delay_fn: Arc::new(delay_fn),
        }
    }

    pub fn on<F: FnMut() -> Result<()>>(&self, mut method: F) -> Result<()> {
        let mut attempt = 0;
        let mut accumulated_errors = Vec::new();
        while attempt < self.total_attempt {
            match method() {
                Ok(()) => return Ok(()),
                Err(err) => {
                    accumulated_errors.push(err.to_string());
                    let delay = (self.next_delay_fn)(attempt);
                    if delay > 0 && attempt + 1 < self.total_attempt {
                        std::thread::sleep(Duration::from_millis(delay as u64));
                    }
                    attempt += 1;
                }
            }
        }
        Err(Error::Other(format!(
            "{}: {}",
            ERR_RETRY_FAILED,
            accumulated_errors.join(" > ")
        )))
    }

    pub async fn on_async<F: FnMut() -> Fut, Fut: Future<Output = Result<T>>, T>(&self, mut method: F) -> Result<T> {
        let mut errs = Vec::new();
        for attempt in 0..self.total_attempt {
            match method().await {
                Ok(val) => return Ok(val),
                Err(err) => {
                    errs.push(err.to_string());
                    let delay = (self.next_delay_fn)(attempt);
                    if delay > 0 && attempt + 1 < self.total_attempt {
                        sleep(Duration::from_millis(delay as u64)).await;
                    }
                }
            }
        }
        Err(Error::Other(format!("{}: {}", ERR_RETRY_FAILED, errs.join(" > "))))
    }
}

impl Strategy for Retryer {
    fn on<F: FnMut() -> Result<()>>(&self, method: F) -> Result<()> {
        self.on(method)
    }
}

pub fn timed(attempts: usize, delay_ms: u32) -> Retryer {
    Retryer::new(attempts, move |_| delay_ms)
}

pub fn exponential_backoff(attempts: usize, delay_ms: u32) -> Retryer {
    Retryer::new(attempts, move |attempt| (attempt as u32) * delay_ms)
}

pub enum RetryStrategy {
    Timed {
        attempts: usize,
        delay: Duration,
    },
    ExponentialBackoff {
        attempts: usize,
        base_delay: Duration,
    },
}

impl RetryStrategy {
    pub fn timed(attempts: usize, delay: Duration) -> Self {
        Self::Timed { attempts, delay }
    }

    pub fn exponential_backoff(attempts: usize, base_delay: Duration) -> Self {
        Self::ExponentialBackoff {
            attempts,
            base_delay,
        }
    }

    pub async fn run<F: FnMut() -> Fut, Fut: Future<Output = Result<T>>, T>(&self, mut operation: F) -> Result<T> {
        let (attempts, is_exp, base) = match self {
            Self::Timed { attempts, delay } => (*attempts, false, *delay),
            Self::ExponentialBackoff { attempts, base_delay } => (*attempts, true, *base_delay),
        };
        let mut last_err = Error::Other("No attempts made".into());
        for attempt in 0..attempts {
            match operation().await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < attempts { sleep(if is_exp { base * (1 << attempt) } else { base }).await; }
                }
            }
        }
        Err(Error::Other(format!("All {} retry attempts failed: {}", attempts, last_err)))
    }
}
