use crate::common::errors::Error;

pub fn err_proto_need_more_data() -> Error {
    Error::Protocol("protocol matches, but need more data to complete sniffing".into())
}
