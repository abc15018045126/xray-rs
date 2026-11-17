/// Extracts TLS SNI hostname from a TLS ClientHello record if present.
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }
    let mut pos = 43; // skip record header(5) + handshake(4) + version(2) + random(32)
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > data.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = std::cmp::min(pos + ext_total_len, data.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            let name_type = data[pos + 2];
            let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            if name_type == 0 && pos + 5 + name_len <= ext_end {
                return std::str::from_utf8(&data[pos + 5..pos + 5 + name_len])
                    .ok()
                    .map(|s| s.to_string());
            }
        }
        pos += ext_len;
    }
    None
}

/// Extracts HTTP `Host` header from plain HTTP requests.
pub fn sniff_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("Host")
        {
            let host = v.trim();
            return Some(
                host.split_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(host)
                    .to_string(),
            );
        }
    }
    None
}
