// Module: core\mod.rs

pub mod annotations;
pub mod config;
#[path = "config.pb.rs"]
pub mod config_pb;
pub mod context;
pub mod core;
pub mod format;
pub mod functions;
pub mod mocks;
pub mod proto;
pub mod xray;

#[cfg(test)]
pub mod context_test;
#[cfg(test)]
pub mod functions_test;
#[cfg(test)]
pub mod xray_test;

pub use annotations::{Annotation, ApiStability};
pub use config::{
    get_extension, get_format, get_format_by_extension, get_merged_config, load_config,
    register_config_loader, ConfigFormat, ConfigLoader, ConfigSource, CoreConfig,
};
pub use context::{
    from_context, must_from_context, to_background_detached_context, to_context, CoreContext,
};
pub use core::{
    version, version_statement, Instance, Server, BUILD, CODENAME, INTRO, VERSION_X, VERSION_Y,
    VERSION_Z,
};
pub use functions::{create_object, dial, dial_udp, start_instance};
pub use mocks::create_mock_instance;
pub use proto::PROTO_CORE_VERSION;
pub use xray::server_type;
