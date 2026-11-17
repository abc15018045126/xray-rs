use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Connection closed")]
    Closed,

    #[error("Operation timed out")]
    Timeout,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;
