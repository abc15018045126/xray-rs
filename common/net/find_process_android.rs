use crate::common::errors::{Error, Result};
use std::sync::{Arc, RwLock};

pub type AndroidProcessFinderFn =
    Arc<dyn Fn(&str, &str, u16, &str, u16) -> Result<(i32, String, String)> + Send + Sync>;

static ANDROID_PROCESS_FINDER: RwLock<Option<AndroidProcessFinderFn>> = RwLock::new(None);

pub fn register_android_process_finder(finder: Option<AndroidProcessFinderFn>) {
    if let Ok(mut guard) = ANDROID_PROCESS_FINDER.write() {
        *guard = finder;
    }
}

pub fn find_android_process(
    network: &str,
    src_ip: &str,
    src_port: u16,
    dest_ip: &str,
    dest_port: u16,
) -> Result<(i32, String, String)> {
    if let Ok(guard) = ANDROID_PROCESS_FINDER.read()
        && let Some(ref f) = *guard
    {
        return f(network, src_ip, src_port, dest_ip, dest_port);
    }
    Err(Error::NotFound(
        "android process lookup must be registered before use".into(),
    ))
}
