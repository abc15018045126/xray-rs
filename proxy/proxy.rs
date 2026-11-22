use crate::common::net::Network;
use rand::Rng;
use std::collections::HashMap;
use std::sync::LazyLock;

pub const PROXY_VERSION: &str = "26.3.27";

pub const TLS13_SUPPORTED_VERSIONS: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
pub const TLS_CLIENT_HANDSHAKE_START: &[u8] = &[0x16, 0x03];
pub const TLS_SERVER_HANDSHAKE_START: &[u8] = &[0x16, 0x03, 0x03];
pub const TLS_APPLICATION_DATA_START: &[u8] = &[0x17, 0x03, 0x03];

pub const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub const COMMAND_PADDING_END: u8 = 0x01;
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

pub const BUFFER_SIZE: usize = 2048;

pub static TLS13_CIPHER_SUITE_DIC: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(0x1301, "TLS_AES_128_GCM_SHA256");
    m.insert(0x1302, "TLS_AES_256_GCM_SHA384");
    m.insert(0x1303, "TLS_CHACHA20_POLY1305_SHA256");
    m.insert(0x1304, "TLS_AES_128_CCM_SHA256");
    m.insert(0x1305, "TLS_AES_128_CCM_8_SHA256");
    m
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundState {
    pub within_padding_buffers: bool,
    pub uplink_reader_direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub downlink_writer_direct_copy: bool,
}

impl Default for InboundState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            uplink_reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            downlink_writer_direct_copy: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundState {
    pub within_padding_buffers: bool,
    pub downlink_reader_direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub uplink_writer_direct_copy: bool,
}

impl Default for OutboundState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            downlink_reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            uplink_writer_direct_copy: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrafficState {
    pub user_uuid: Vec<u8>,
    pub number_of_packet_to_filter: i32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub inbound: InboundState,
    pub outbound: OutboundState,
}

impl TrafficState {
    pub fn new(user_uuid: &[u8]) -> Self {
        Self {
            user_uuid: user_uuid.to_vec(),
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
            inbound: InboundState::default(),
            outbound: OutboundState::default(),
        }
    }
}

pub fn is_complete_record(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        if i + 5 > data.len() || data[i] != 0x17 || data[i + 1] != 0x03 || data[i + 2] != 0x03 { return false; }
        let record_len = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
        if record_len == 0 || data.len() - (i + 5) < record_len { return false; }
        i += 5 + record_len;
    }
    true
}

pub fn xtls_padding(
    content: Option<&[u8]>,
    command: u8,
    user_uuid: Option<&[u8]>,
    long_padding: bool,
    testseed: Option<&[u32]>,
) -> Vec<u8> {
    let seed = testseed.unwrap_or(&[900, 500, 900, 256]);
    let content_len = content.map_or(0, |c| c.len()) as i32;
    let mut rng = rand::thread_rng();
    let mut pad = if (content_len as u32) < seed[0] && long_padding {
        (if seed[1] > 0 { rng.gen_range(0..seed[1]) as i32 } else { 0 }) + seed[2] as i32 - content_len
    } else if seed[3] > 0 { rng.gen_range(0..seed[3]) as i32 } else { 0 };
    pad = pad.min(((BUFFER_SIZE as i32) - 21 - content_len).max(0)).max(0);
    let mut out = Vec::new();
    if let Some(u) = user_uuid { out.extend_from_slice(u); }
    out.extend_from_slice(&[command, (content_len >> 8) as u8, content_len as u8, (pad >> 8) as u8, pad as u8]);
    if let Some(c) = content { out.extend_from_slice(c); }
    if pad > 0 { out.resize(out.len() + pad as usize, 0); }
    out
}

pub fn xtls_unpadding(data: &[u8], state: &mut TrafficState, is_uplink: bool) -> Vec<u8> {
    let (rem_cmd, rem_content, rem_pad, cur_cmd) = if is_uplink {
        let s = &mut state.inbound;
        (&mut s.remaining_command, &mut s.remaining_content, &mut s.remaining_padding, &mut s.current_command)
    } else {
        let s = &mut state.outbound;
        (&mut s.remaining_command, &mut s.remaining_content, &mut s.remaining_padding, &mut s.current_command)
    };
    let (mut cursor, len) = (0, data.len());
    if *rem_cmd == -1 && *rem_content == -1 && *rem_pad == -1 {
        if len >= 21 && &data[..16] == state.user_uuid.as_slice() {
            cursor = 16;
            *rem_cmd = 5;
        } else {
            return data.to_vec();
        }
    }
    let mut result = Vec::new();
    while cursor < len {
        if *rem_cmd > 0 {
            let b = data[cursor] as i32;
            cursor += 1;
            match *rem_cmd {
                5 => *cur_cmd = b,
                4 => *rem_content = b << 8,
                3 => *rem_content |= b,
                2 => *rem_pad = b << 8,
                1 => *rem_pad |= b,
                _ => {}
            }
            *rem_cmd -= 1;
        } else if *rem_content > 0 {
            let n = (*rem_content as usize).min(len - cursor);
            result.extend_from_slice(&data[cursor..cursor + n]);
            cursor += n;
            *rem_content -= n as i32;
        } else if *rem_pad > 0 {
            let n = (*rem_pad as usize).min(len - cursor);
            cursor += n;
            *rem_pad -= n as i32;
        }
        if *rem_cmd <= 0 && *rem_content <= 0 && *rem_pad <= 0 {
            if *cur_cmd == COMMAND_PADDING_CONTINUE as i32 {
                *rem_cmd = 5;
            } else {
                (*rem_cmd, *rem_content, *rem_pad) = (-1, -1, -1);
                result.extend_from_slice(&data[cursor..]);
                break;
            }
        }
    }
    result
}

pub fn xtls_filter_tls(data: &[u8], s: &mut TrafficState) {
    if data.is_empty() { return; }
    s.number_of_packet_to_filter -= 1;
    if data.len() >= 6 {
        if &data[..3] == TLS_SERVER_HANDSHAKE_START && data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO {
            s.remaining_server_hello = u16::from_be_bytes([data[3], data[4]]) as i32 + 5;
            s.is_tls12_or_above = true;
            s.is_tls = true;
            if data.len() >= 79 && s.remaining_server_hello >= 79 {
                let off = 44 + data[43] as usize;
                if data.len() >= off + 2 { s.cipher = u16::from_be_bytes([data[off], data[off + 1]]); }
            }
        } else if &data[..2] == TLS_CLIENT_HANDSHAKE_START && data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
            s.is_tls = true;
        }
    }
    if s.remaining_server_hello > 0 {
        let end = (s.remaining_server_hello as usize).min(data.len());
        s.remaining_server_hello -= data.len() as i32;
        if data[..end].windows(TLS13_SUPPORTED_VERSIONS.len()).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
            if TLS13_CIPHER_SUITE_DIC.get(&s.cipher).is_some_and(|&v| v != "TLS_AES_128_CCM_8_SHA256") {
                s.enable_xtls = true;
            }
            s.number_of_packet_to_filter = 0;
        } else if s.remaining_server_hello <= 0 {
            s.number_of_packet_to_filter = 0;
        }
    }
}

pub trait Inbound: Send + Sync {
    fn network(&self) -> Vec<Network>;
}

pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
}

pub trait UserManager: Send + Sync {
    fn add_user(&self, email: &str, level: u32) -> crate::common::errors::Result<()>;
    fn remove_user(&self, email: &str) -> crate::common::errors::Result<()>;
    fn get_users_count(&self) -> usize;
}

#[derive(Default)]
pub struct DefaultUserManager {
    users: std::sync::RwLock<HashMap<String, u32>>,
}

impl DefaultUserManager {
    pub fn new() -> Self { Self { users: std::sync::RwLock::new(HashMap::new()), } }
}

impl UserManager for DefaultUserManager {
    fn add_user(&self, email: &str, level: u32) -> crate::common::errors::Result<()> {
        let mut map = self.users.write().unwrap();
        map.insert(email.to_string(), level);
        Ok(())
    }
    fn remove_user(&self, email: &str) -> crate::common::errors::Result<()> {
        let mut map = self.users.write().unwrap();
        map.remove(email);
        Ok(())
    }
    fn get_users_count(&self) -> usize { self.users.read().map(|m| m.len()).unwrap_or(0) }
}
