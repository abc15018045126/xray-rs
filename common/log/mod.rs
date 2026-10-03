pub mod access;
pub mod dns;
pub mod log;
pub mod logger;

#[path = "log.pb.rs"]
pub mod log_pb;

#[cfg(test)]
pub mod log_test;
#[cfg(test)]
pub mod logger_test;

pub use access::{
    access_message_from_context, context_with_access_message, AccessLogMessage, AccessMessage,
    AccessStatus, ACCESS_ACCEPTED, ACCESS_REJECTED,
};
pub use dns::{format_dns_log, DnsLog, DnsStatus, DNS_CACHE_HIT, DNS_CACHE_OPTIMISTE, DNS_QUERIED};
pub use log::{
    get_log_handler, record, register_handler, GeneralMessage, Handler, LogLevel, Message,
    SyncHandler,
};
pub use log_pb::Severity;
pub use logger::{
    create_file_log_writer, create_stderr_log_writer, create_stdout_log_writer, new_logger,
    replace_with_severity_logger, GeneralLogger, Logger, SeverityLogger, Writer, WriterCreator,
};
