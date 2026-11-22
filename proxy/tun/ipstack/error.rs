#[derive(thiserror::Error, Debug)]
pub enum IpStackError {
    #[error("The transport protocol is not supported")]
    UnsupportedTransportProtocol,

    #[error("The packet is invalid")]
    InvalidPacket,

    #[error("ValueTooBigError<u16> {0}")]
    ValueTooBigErrorU16(#[from] etherparse::err::ValueTooBigError<u16>),

    #[error("ValueTooBigError<usize> {0}")]
    ValueTooBigErrorUsize(#[from] etherparse::err::ValueTooBigError<usize>),

    #[error("Invalid Tcp packet")]
    InvalidTcpPacket,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Accept Error")]
    AcceptError,

    #[error("Send Error {0}")]
    SendError(#[from] Box<tokio::sync::mpsc::error::SendError<crate::proxy::tun::ipstack::stream::IpStackStream>>),

    #[error("Invalid MTU size: {0} (bytes). Minimum MTU is 1280 bytes.")]
    InvalidMtuSize(u16),
}

impl From<tokio::sync::mpsc::error::SendError<crate::proxy::tun::ipstack::stream::IpStackStream>> for IpStackError {
    fn from(e: tokio::sync::mpsc::error::SendError<crate::proxy::tun::ipstack::stream::IpStackStream>) -> Self {
        IpStackError::SendError(Box::new(e))
    }
}

unsafe impl Send for IpStackError {}

unsafe impl Sync for IpStackError {}

impl From<IpStackError> for std::io::Error {
    fn from(e: IpStackError) -> Self {
        match e {
            IpStackError::IoError(e) => e,
            _ => std::io::Error::other(e),
        }
    }
}

pub type Result<T, E = IpStackError> = std::result::Result<T, E>;
