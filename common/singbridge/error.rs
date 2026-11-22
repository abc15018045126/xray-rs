use crate::common::errors::Error;
use std::io;

pub fn is_closed_or_canceled(err: &Error) -> bool {
    match err {
        Error::Io(e) => matches!(
            e.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected | io::ErrorKind::UnexpectedEof | io::ErrorKind::Interrupted
        ),
        Error::Other(msg) => {
            let m = msg.to_lowercase();
            ["closed", "canceled", "cancelled", "broken pipe", "eof", "connection reset"].iter().any(|k| m.contains(k))
        }
        _ => false,
    }
}

pub fn return_error(err: Option<Error>) -> Option<Error> {
    match err {
        Some(e) if is_closed_or_canceled(&e) => None,
        other => other,
    }
}

pub fn return_result<T>(res: Result<T, Error>) -> Result<Option<T>, Error> {
    match res {
        Ok(v) => Ok(Some(v)),
        Err(e) if is_closed_or_canceled(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn wrap_sing_error(err_str: impl Into<String>) -> Error {
    Error::Protocol(format!("sing-box bridge error: {}", err_str.into()))
}
