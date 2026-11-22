use std::collections::HashMap;

pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";
pub const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";

pub fn is_browser_user_agent(ua: &str) -> bool {
    ua.contains("Mozilla")
        || ua.contains("Chrome")
        || ua.contains("Safari")
        || ua.contains("Firefox")
}

pub fn chrome_version() -> u32 {

    144u32
}

const CLIENT_HINT_GREASE_NA: &[&str] = &[" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const CLIENT_HINT_VERSION_NA: &[&str] = &["8", "99", "24"];
const CLIENT_HINT_SHUFFLE_3: &[[usize; 3]] = &[
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];
const CLIENT_HINT_SHUFFLE_4: &[[usize; 4]] = &[
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

pub fn get_greased_ch_invalid_brand(seed: usize) -> String {
    let g1 = CLIENT_HINT_GREASE_NA[seed % CLIENT_HINT_GREASE_NA.len()];
    let g2 = CLIENT_HINT_GREASE_NA[(seed + 1) % CLIENT_HINT_GREASE_NA.len()];
    let ver = CLIENT_HINT_VERSION_NA[seed % CLIENT_HINT_VERSION_NA.len()];
    format!("\"Not{}A{}Brand\";v=\"{}\"", g1, g2, ver)
}

pub fn get_greased_ch_order(brand_length: usize, seed: usize) -> Vec<usize> {
    match brand_length {
        1 => vec![0],
        2 => vec![seed % brand_length, (seed + 1) % brand_length],
        3 => CLIENT_HINT_SHUFFLE_3[seed % CLIENT_HINT_SHUFFLE_3.len()].to_vec(),
        _ => CLIENT_HINT_SHUFFLE_4[seed % CLIENT_HINT_SHUFFLE_4.len()].to_vec(),
    }
}

pub fn get_ungreased_ch_ua(major_version: u32, fork_name: &str) -> Vec<String> {
    let mut base = Vec::with_capacity(4);
    base.push(get_greased_ch_invalid_brand(major_version as usize));
    base.push(format!("\"Chromium\";v=\"{}\"", major_version));
    match fork_name {
        "chrome" => base.push(format!("\"Google Chrome\";v=\"{}\"", major_version)),
        "edge" => base.push(format!("\"Microsoft Edge\";v=\"{}\"", major_version)),
        _ => {}
    }
    base
}

pub fn get_greased_ch_ua(major_version: u32, fork_name: &str) -> String {
    let ungreased = get_ungreased_ch_ua(major_version, fork_name);
    let order = get_greased_ch_order(ungreased.len(), major_version as usize);
    let mut shuffled = vec![String::new(); ungreased.len()];
    for (i, &pos) in order.iter().enumerate() {
        if pos < shuffled.len() && i < ungreased.len() {
            shuffled[pos] = ungreased[i].clone();
        }
    }
    shuffled.join(", ")
}

pub fn chrome_ua() -> String {
    let ver = chrome_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
        ver
    )
}

pub fn chrome_uach() -> String {
    get_greased_ch_ua(chrome_version(), "chrome")
}

pub fn msedge_ua() -> String {
    let ver = chrome_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36 Edg/{}.0.0.0",
        ver, ver
    )
}

pub fn msedge_uach() -> String {
    get_greased_ch_ua(chrome_version(), "edge")
}

pub fn apply_masqueraded_headers(
    headers: &mut HashMap<String, String>,
    browser: &str,
    variant: &str,
) {
    let set = |h: &mut HashMap<String, String>, k: &str, v: &str| {
        h.insert(k.into(), v.into());
    };
    let set_def = |h: &mut HashMap<String, String>, k: &str, v: &str| {
        h.entry(k.into()).or_insert_with(|| v.into());
    };

    match browser {
        "chrome" | "edge" => {
            let (uach, ua) = if browser == "chrome" {
                (chrome_uach(), chrome_ua())
            } else {
                (msedge_uach(), msedge_ua())
            };
            headers.insert("Sec-CH-UA".into(), uach);
            set(headers, "Sec-CH-UA-Mobile", "?0");
            set(headers, "Sec-CH-UA-Platform", "\"Windows\"");
            set(headers, "DNT", "1");
            headers.insert("User-Agent".into(), ua);
            set(headers, "Accept-Language", "en-US,en;q=0.9");
        }
        "firefox" => {
            set(headers, "User-Agent", FIREFOX_UA);
            set(headers, "DNT", "1");
            set(headers, "Accept-Language", "en-US,en;q=0.5");
        }
        "golang" => {
            headers.remove("User-Agent");
            return;
        }
        _ => {}
    }

    match variant {
        "nav" => {
            if matches!(browser, "chrome" | "edge") {
                set_def(headers, "Cache-Control", "max-age=0");
            }
            set(headers, "Upgrade-Insecure-Requests", "1");
            match browser {
                "chrome" | "edge" => set_def(headers, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                "firefox" => set_def(headers, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                _ => {}
            }
            for (k, v) in [("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-User", "?1"), ("Sec-Fetch-Dest", "document"), ("Priority", "u=0, i")] {
                set(headers, k, v);
            }
        }
        "ws" | "fetch" => {
            set(headers, "Sec-Fetch-Mode", if variant == "ws" { "websocket" } else { "cors" });
            set(headers, "Sec-Fetch-Dest", "empty");
            set(headers, "Sec-Fetch-Site", "same-origin");
            if variant == "fetch" {
                match browser {
                    "chrome" | "edge" => set_def(headers, "Priority", "u=1, i"),
                    "firefox" => set_def(headers, "Priority", "u=4"),
                    _ => {}
                }
            }
            for (k, v) in [("Cache-Control", "no-cache"), ("Pragma", "no-cache"), ("Accept", "*/*")] {
                set_def(headers, k, v);
            }
        }
        _ => {}
    }
}

pub fn try_default_headers_with(headers: &mut HashMap<String, String>, variant: &str) {
    let ua = headers.get("User-Agent").cloned();
    match ua.as_deref() {
        None | Some("") => apply_masqueraded_headers(headers, "chrome", variant),
        Some("chrome") => apply_masqueraded_headers(headers, "chrome", variant),
        Some("firefox") => apply_masqueraded_headers(headers, "firefox", variant),
        Some("edge") => apply_masqueraded_headers(headers, "edge", variant),
        Some("golang") => apply_masqueraded_headers(headers, "golang", variant),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_version_and_ua() {
        let ver = chrome_version();
        assert!(ver >= 144);
        let ua = chrome_ua();
        assert!(ua.contains(&format!("Chrome/{}.0.0.0", ver)));
        assert!(is_browser_user_agent(&ua));
    }

    #[test]
    fn test_greased_ch_ua() {
        let ch = chrome_uach();
        assert!(ch.contains("Chromium"));
        assert!(ch.contains("Google Chrome"));
        assert!(ch.contains("Not"));
    }

    #[test]
    fn test_apply_masqueraded_headers() {
        let mut headers = HashMap::new();
        try_default_headers_with(&mut headers, "nav");
        assert!(headers.contains_key("User-Agent"));
        assert!(headers.contains_key("Sec-CH-UA"));
        assert_eq!(headers.get("Sec-Fetch-Mode"), Some(&"navigate".to_string()));

        let mut ws_headers = HashMap::new();
        headers.insert("User-Agent".into(), "firefox".into());
        try_default_headers_with(&mut ws_headers, "ws");
        assert_eq!(
            ws_headers.get("Sec-Fetch-Mode"),
            Some(&"websocket".to_string())
        );
    }
}
