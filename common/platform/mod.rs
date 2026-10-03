pub mod filesystem;
pub mod others;
pub mod platform;
pub mod windows;

#[cfg(test)]
pub mod platform_test;

pub use platform::{
    get_asset_location, get_cert_location, get_conf_dir_path, get_configuration_path,
    get_executable_dir, get_os_name, line_separator, normalize_env_name, EnvFlag,
    ASSET_LOCATION, BUFFER_SIZE, CERT_LOCATION, CONFIG_LOCATION, CONFDIR_LOCATION,
    MPH_CACHE_PATH, TUN_FD_KEY, USE_CONE, USE_FREEDOM_SPLICE, USE_READ_V, USE_VMESS_PADDING,
    XUDP_BASE_KEY, XUDP_LOG,
};
