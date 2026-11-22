use super::condition::{DomainMatcher, IpMatcher};
use crate::common::errors::{Error, Result};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct GeoSiteGroup {
    pub country_code: String,
    pub matchers: Vec<DomainMatcher>,
}

#[derive(Debug, Clone)]
pub struct GeoIpGroup {
    pub country_code: String,
    pub matchers: Vec<IpMatcher>,
}

#[derive(Debug, Default)]
struct GeoSiteIndex {
    full: HashSet<String>,
    domain: HashSet<String>,
    substr: Vec<String>,
    regex: Vec<Regex>,
}

impl GeoSiteIndex {
    fn matches(&self, domain_lower: &str) -> bool {
        let d = domain_lower.trim_end_matches('.');
        if d.is_empty() { return false; }
        if self.full.contains(d) { return true; }
        if !self.domain.is_empty() {
            let mut cur = d;
            loop {
                if self.domain.contains(cur) { return true; }
                let Some(idx) = cur.find('.') else { break; };
                cur = &cur[idx + 1..];
            }
        }
        self.substr.iter().any(|s| d.contains(s.as_str())) || self.regex.iter().any(|re| re.is_match(d))
    }
}

#[derive(Debug, Default)]
struct GeoIpIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    reverse_match: bool,
}

impl GeoIpIndex {
    fn finalize(&mut self) {
        merge_intervals_u32(&mut self.v4);
        merge_intervals_u128(&mut self.v6);
    }
    fn matches(&self, ip: &IpAddr) -> bool {
        let hit = match ip {
            IpAddr::V4(v4) => {
                let x = u32::from_be_bytes(v4.octets());
                let idx = self.v4.partition_point(|&(start, _)| start <= x);
                idx > 0 && x <= self.v4[idx - 1].1
            }
            IpAddr::V6(v6) => {
                let x = u128::from_be_bytes(v6.octets());
                let idx = self.v6.partition_point(|&(start, _)| start <= x);
                idx > 0 && x <= self.v6[idx - 1].1
            }
        };
        if self.reverse_match { !hit } else { hit }
    }
}

fn merge_intervals_u32(v: &mut Vec<(u32, u32)>) {
    if v.len() <= 1 { return; }
    v.sort_unstable();
    let mut write = 0usize;
    for i in 1..v.len() {
        let (s, e) = v[i];
        if s <= v[write].1.saturating_add(1) {
            if e > v[write].1 { v[write].1 = e; }
        } else {
            write += 1;
            v[write] = (s, e);
        }
    }
    v.truncate(write + 1);
}

fn merge_intervals_u128(v: &mut Vec<(u128, u128)>) {
    if v.len() <= 1 { return; }
    v.sort_unstable();
    let mut write = 0usize;
    for i in 1..v.len() {
        let (s, e) = v[i];
        if s <= v[write].1.saturating_add(1) {
            if e > v[write].1 { v[write].1 = e; }
        } else {
            write += 1;
            v[write] = (s, e);
        }
    }
    v.truncate(write + 1);
}

fn cidr_v4_range(ip: [u8; 4], prefix: u32) -> (u32, u32) {
    let addr = u32::from_be_bytes(ip);
    if prefix == 0 { return (0, u32::MAX); }
    if prefix >= 32 { return (addr, addr); }
    let mask = !((1u32 << (32 - prefix)) - 1);
    let start = addr & mask;
    let end = start | !mask;
    (start, end)
}

fn cidr_v6_range(ip: [u8; 16], prefix: u32) -> (u128, u128) {
    let addr = u128::from_be_bytes(ip);
    if prefix == 0 { return (0, u128::MAX); }
    if prefix >= 128 { return (addr, addr); }
    let mask = !((1u128 << (128 - prefix)) - 1);
    let start = addr & mask;
    let end = start | !mask;
    (start, end)
}

pub fn find_asset_file(filename: &str) -> Option<PathBuf> {
    for k in ["XRAY_LOCATION_ASSET", "xray.location.asset"] {
        if let Ok(dir) = std::env::var(k) && !dir.is_empty() {
            let p = PathBuf::from(dir).join(filename);
            if p.is_file() { return Some(p); }
        }
    }
    if let Ok(exe) = std::env::current_exe() && let Some(p) = exe.parent().map(|d| d.join(filename)) && p.is_file() {
        return Some(p);
    }
    [PathBuf::from(filename), PathBuf::from("configs").join(filename)].into_iter().find(|p| p.is_file())
}

pub struct GeoDatabase {
    geosites: RwLock<HashMap<String, GeoSiteIndex>>,
    geoips: RwLock<HashMap<String, GeoIpIndex>>,
    geosite_path: RwLock<Option<PathBuf>>,
    geoip_path: RwLock<Option<PathBuf>>,
    attempted_geosites: RwLock<HashSet<String>>,
    attempted_geoips: RwLock<HashSet<String>>,
}

impl GeoDatabase {
    pub fn new() -> Self {
        let (geosite_path, geoip_path) = (find_asset_file("geosite.dat"), find_asset_file("geoip.dat"));
        if let Some(ref p) = geosite_path { tracing::info!("Found geosite.dat at {}", p.display()); }
        if let Some(ref p) = geoip_path { tracing::info!("Found geoip.dat at {}", p.display()); }
        Self::with_asset_paths(geoip_path, geosite_path)
    }
    pub fn with_asset_paths(geoip_path: Option<PathBuf>, geosite_path: Option<PathBuf>) -> Self {
        let db = Self {
            geosites: RwLock::new(HashMap::new()), geoips: RwLock::new(HashMap::new()),
            geosite_path: RwLock::new(geosite_path), geoip_path: RwLock::new(geoip_path),
            attempted_geosites: RwLock::new(HashSet::new()), attempted_geoips: RwLock::new(HashSet::new()),
        };
        db.init_builtin_rules();
        db
    }
    fn init_builtin_rules(&self) {
        let mut gs = self.geosites.write().unwrap();
        let mut gi = self.geoips.write().unwrap();
        let mut private_gs = GeoSiteIndex::default();
        for d in ["localhost", "local", "lan", "home.arpa"] { private_gs.domain.insert(d.into()); }
        gs.insert("private".into(), private_gs);
        let mut cn_gs = GeoSiteIndex::default();
        for d in [
            "cn",
            "baidu.com",
            "qq.com",
            "taobao.com",
            "jd.com",
            "alipay.com",
            "aliyun.com",
            "bilibili.com",
            "zhihu.com",
            "163.com",
            "sina.com.cn",
        ] {
            cn_gs.domain.insert(d.into());
        }
        gs.insert("cn".into(), cn_gs);
        let mut google_gs = GeoSiteIndex::default();
        for d in [
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "googlevideo.com",
            "youtube.com",
            "ytimg.com",
            "1e100.net",
            "google.co.jp",
            "google.com.hk",
        ] {
            google_gs.domain.insert(d.into());
        }
        gs.insert("google".into(), google_gs);
        let mut private_gi = GeoIpIndex::default();
        for (ip, p) in [
            (Ipv4Addr::new(10, 0, 0, 0), 8),
            (Ipv4Addr::new(172, 16, 0, 0), 12),
            (Ipv4Addr::new(192, 168, 0, 0), 16),
            (Ipv4Addr::new(127, 0, 0, 0), 8),
        ] {
            private_gi.v4.push(cidr_v4_range(ip.octets(), p));
        }
        for (ip, p) in [
            (Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0000u128), 10),
            (Ipv6Addr::from(0xfc00_0000_0000_0000_0000_0000_0000_0000u128), 7),
            (Ipv6Addr::LOCALHOST, 128),
        ] {
            private_gi.v6.push(cidr_v6_range(ip.octets(), p));
        }
        private_gi.finalize();
        gi.insert("private".into(), private_gi);
        let mut cn_gi = GeoIpIndex::default();
        for ip in [
            Ipv4Addr::new(114, 114, 114, 0),
            Ipv4Addr::new(223, 5, 5, 0),
            Ipv4Addr::new(119, 29, 29, 0),
            Ipv4Addr::new(180, 76, 76, 0),
            Ipv4Addr::new(1, 12, 12, 0),
        ] {
            cn_gi.v4.push(cidr_v4_range(ip.octets(), 24));
        }
        cn_gi.finalize();
        gi.insert("cn".into(), cn_gi);
    }
    pub fn load_geosite_file(&self, path: &Path) -> Result<()> {
        if !path.is_file() { return Err(Error::Config(format!("geosite file not found: {:?}", path))); }
        *self.geosite_path.write().unwrap() = Some(path.to_path_buf());
        self.attempted_geosites.write().unwrap().clear();
        Ok(())
    }
    pub fn load_geoip_file(&self, path: &Path) -> Result<()> {
        if !path.is_file() { return Err(Error::Config(format!("geoip file not found: {:?}", path))); }
        *self.geoip_path.write().unwrap() = Some(path.to_path_buf());
        self.attempted_geoips.write().unwrap().clear();
        Ok(())
    }
    fn ensure_geosite_loaded(&self, group_key: &str) {
        if self.attempted_geosites.read().unwrap().contains(group_key) { return; }
        let path_opt = self.geosite_path.read().unwrap().clone();
        if !self.attempted_geosites.write().unwrap().insert(group_key.to_string()) { return; }
        let Some(path) = path_opt else { return };
        let (code, attr) = group_key.split_once('@').map_or((group_key, None), |(c, a)| (c, Some(a)));
        match load_geosite_code_from_dat(&path, code, attr) {
            Ok(Some(idx)) => {
                tracing::info!(
                    "Loaded geosite:{} (full={}, domain={}, substr={}, regex={}) from {}",
                    group_key, idx.full.len(), idx.domain.len(), idx.substr.len(), idx.regex.len(), path.display()
                );
                self.geosites.write().unwrap().insert(group_key.to_string(), idx);
            }
            Ok(None) => tracing::warn!("geosite:{} not found in {}; keeping fallback if any", group_key, path.display()),
            Err(e) => tracing::warn!("Failed to load geosite:{} from {}: {}", group_key, path.display(), e),
        }
    }
    fn ensure_geoip_loaded(&self, group_key: &str) {
        if self.attempted_geoips.read().unwrap().contains(group_key) { return; }
        let path_opt = self.geoip_path.read().unwrap().clone();
        if !self.attempted_geoips.write().unwrap().insert(group_key.to_string()) { return; }
        let Some(path) = path_opt else { return };
        match load_geoip_code_from_dat(&path, group_key) {
            Ok(Some(idx)) => {
                tracing::info!(
                    "Loaded geoip:{} (v4_ranges={}, v6_ranges={}) from {}",
                    group_key, idx.v4.len(), idx.v6.len(), path.display()
                );
                self.geoips.write().unwrap().insert(group_key.to_string(), idx);
            }
            Ok(None) => tracing::warn!("geoip:{} not found in {}; keeping fallback if any", group_key, path.display()),
            Err(e) => tracing::warn!("Failed to load geoip:{} from {}: {}", group_key, path.display(), e),
        }
    }
    pub fn match_geosite(&self, group: &str, domain: &str) -> bool {
        let key = group.to_lowercase();
        self.ensure_geosite_loaded(&key);
        let guard = self.geosites.read().unwrap();
        guard.get(&key).is_some_and(|idx| idx.matches(domain))
    }
    pub fn match_geoip(&self, group: &str, ip: &IpAddr) -> bool {
        let key = group.to_lowercase();
        self.ensure_geoip_loaded(&key);
        let guard = self.geoips.read().unwrap();
        guard.get(&key).is_some_and(|idx| idx.matches(ip))
    }
}

impl Default for GeoDatabase {
    fn default() -> Self { Self::new() }
}

struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
    fn is_eof(&self) -> bool { self.pos >= self.buf.len() }
    fn read_varint(&mut self) -> Option<u64> {
        let mut res = 0u64;
        let mut shift = 0u32;
        while self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            self.pos += 1;
            res |= ((b & 0x7f) as u64) << shift;
            if (b & 0x80) == 0 { return Some(res); }
            shift += 7;
            if shift >= 64 { return None; }
        }
        None
    }
    fn read_tag(&mut self) -> Option<(u32, u8)> {
        let v = self.read_varint()?;
        Some(((v >> 3) as u32, (v & 0x07) as u8))
    }
    fn read_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.buf.len() { return None; }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Some(slice)
    }
    fn skip_field(&mut self, wire_type: u8) -> Option<()> {
        match wire_type {
            0 => self.read_varint().map(|_| ()),
            1 => (self.pos + 8 <= self.buf.len()).then(|| self.pos += 8),
            2 => self.read_bytes().map(|_| ()),
            5 => (self.pos + 4 <= self.buf.len()).then(|| self.pos += 4),
            _ => None,
        }
    }
}

fn load_geoip_code_from_dat(path: &Path, target_code: &str) -> Result<Option<GeoIpIndex>> {
    let data = std::fs::read(path)?;
    let mut r = ProtoReader::new(&data);
    while let Some((field, wt)) = (!r.is_eof()).then(|| r.read_tag()).flatten() {
        if field == 1 && wt == 2 {
            let Some(eb) = r.read_bytes() else { break; };
            if let Some(idx) = parse_geoip_entry_if_match(eb, target_code) { return Ok(Some(idx)); }
        } else if r.skip_field(wt).is_none() { break; }
    }
    Ok(None)
}

fn parse_geoip_entry_if_match(entry: &[u8], target_code: &str) -> Option<GeoIpIndex> {
    let mut r = ProtoReader::new(entry);
    let mut matched = false;
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        if field == 1 && wt == 2 {
            matched = std::str::from_utf8(r.read_bytes()?).is_ok_and(|code| code.eq_ignore_ascii_case(target_code));
            break;
        }
        r.skip_field(wt)?;
    }
    if !matched { return None; }
    let mut idx = GeoIpIndex::default();
    let mut r2 = ProtoReader::new(entry);
    while !r2.is_eof() {
        let (field, wt) = r2.read_tag()?;
        match (field, wt) {
            (2, 2) => {
                let mut cr = ProtoReader::new(r2.read_bytes()?);
                let (mut ip_slice, mut prefix) = (None, 0u32);
                while !cr.is_eof() {
                    let Some((cf, cwt)) = cr.read_tag() else { break };
                    match (cf, cwt) {
                        (1, 2) => ip_slice = cr.read_bytes(),
                        (2, 0) => prefix = cr.read_varint().unwrap_or(0) as u32,
                        _ if cr.skip_field(cwt).is_none() => break,
                        _ => {}
                    }
                }
                if let Some(ip) = ip_slice {
                    if let Ok(arr) = <[u8; 4]>::try_from(ip) {
                        idx.v4.push(cidr_v4_range(arr, prefix));
                    } else if let Ok(arr) = <[u8; 16]>::try_from(ip) {
                        idx.v6.push(cidr_v6_range(arr, prefix));
                    }
                }
            }
            (3, 0) => idx.reverse_match = r2.read_varint().unwrap_or(0) != 0,
            _ => r2.skip_field(wt)?,
        }
    }
    idx.finalize();
    Some(idx)
}

fn load_geosite_code_from_dat(path: &Path, target_code: &str, attr_filter: Option<&str>) -> Result<Option<GeoSiteIndex>> {
    let data = std::fs::read(path)?;
    let mut r = ProtoReader::new(&data);
    while let Some((field, wt)) = (!r.is_eof()).then(|| r.read_tag()).flatten() {
        if field == 1 && wt == 2 {
            let Some(eb) = r.read_bytes() else { break; };
            if let Some(idx) = parse_geosite_entry_if_match(eb, target_code, attr_filter) { return Ok(Some(idx)); }
        } else if r.skip_field(wt).is_none() { break; }
    }
    Ok(None)
}

fn parse_geosite_entry_if_match(entry: &[u8], target_code: &str, attr_filter: Option<&str>) -> Option<GeoSiteIndex> {
    let mut r = ProtoReader::new(entry);
    let mut matched = false;
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        if field == 1 && wt == 2 {
            matched = std::str::from_utf8(r.read_bytes()?).is_ok_and(|code| code.eq_ignore_ascii_case(target_code));
            break;
        }
        r.skip_field(wt)?;
    }
    if !matched { return None; }
    let (negate_attr, want_attr) = match attr_filter {
        Some(a) if let Some(s) = a.strip_prefix('!') => (true, Some(s)),
        Some(a) => (false, Some(a)),
        None => (false, None),
    };
    let mut idx = GeoSiteIndex::default();
    let mut r2 = ProtoReader::new(entry);
    while !r2.is_eof() {
        let (field, wt) = r2.read_tag()?;
        if field != 2 || wt != 2 {
            r2.skip_field(wt)?;
            continue;
        }
        let mut dr = ProtoReader::new(r2.read_bytes()?);
        let (mut dtype, mut val, mut has_attr) = (0u64, None, false);
        while !dr.is_eof() {
            let Some((df, dwt)) = dr.read_tag() else { break };
            match (df, dwt) {
                (1, 0) => dtype = dr.read_varint().unwrap_or(0),
                (2, 2) => val = dr.read_bytes().and_then(|b| std::str::from_utf8(b).ok()),
                (3, 2) => {
                    if let (Some(ab), Some(target_attr)) = (dr.read_bytes(), want_attr) {
                        let mut ar = ProtoReader::new(ab);
                        while !ar.is_eof() {
                            let Some((af, awt)) = ar.read_tag() else { break };
                            if af == 1 && awt == 2 {
                                if ar.read_bytes().and_then(|b| std::str::from_utf8(b).ok()).is_some_and(|k| k.eq_ignore_ascii_case(target_attr)) {
                                    has_attr = true;
                                }
                            } else if ar.skip_field(awt).is_none() {
                                break;
                            }
                        }
                    }
                }
                _ if dr.skip_field(dwt).is_none() => break,
                _ => {}
            }
        }
        if want_attr.is_some() && has_attr == negate_attr { continue; }
        if let Some(v) = val.filter(|s| !s.is_empty()) {
            let v_lower = v.to_lowercase();
            match dtype {
                0 => idx.substr.push(v_lower),
                1 => { if let Ok(re) = Regex::new(v) { idx.regex.push(re); } }
                2 => { idx.domain.insert(v_lower.trim_end_matches('.').to_string()); }
                3 => { idx.full.insert(v_lower.trim_end_matches('.').to_string()); }
                _ => {}
            }
        }
    }
    Some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_real_dat_files_if_present() {
        let geoip = PathBuf::from("testing/geoip.dat");
        let geosite = PathBuf::from("testing/geosite.dat");
        if !geoip.is_file() || !geosite.is_file() { return; }
        let db = GeoDatabase::with_asset_paths(Some(geoip), Some(geosite));
        assert!(db.match_geoip("cn", &"120.232.56.106".parse().unwrap()));
        assert!(db.match_geoip("cn", &"58.63.233.33".parse().unwrap()));
        assert!(!db.match_geoip("cn", &"8.8.8.8".parse().unwrap()));
        assert!(!db.match_geoip("cn", &"1.1.1.1".parse().unwrap()));
        assert!(db.match_geosite("cn", "www.doubao.com"));
        assert!(db.match_geosite("cn", "mcs.doubao.com"));
        assert!(db.match_geosite("cn", "dig.bdurl.net"));
        assert!(db.match_geosite("cn", "www.baidu.com"));
        assert!(!db.match_geosite("cn", "www.google.com"));
        assert!(db.match_geosite("google", "www.googleapis.com"));
    }
}
