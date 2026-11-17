use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{LazyLock, RwLock};
use xray_rs_types::{Error, Result};

#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Plain(String),
    Exact(String),
    Suffix(String),
    Keyword(String),
    GeoSite(String),
}

impl DomainMatcher {
    pub fn matches(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        match self {
            Self::Plain(k) | Self::Keyword(k) => h.contains(k.as_str()),
            Self::Exact(d) => h == *d,
            Self::Suffix(d) => h == *d || h.ends_with(&format!(".{}", d)),
            Self::GeoSite(code) => GLOBAL_GEO_DB.match_geosite(code, &h),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IpMatcher {
    CidrV4(Ipv4Addr, u8),
    CidrV6(Ipv6Addr, u8),
    GeoIp(String),
}

impl IpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::CidrV4(net, prefix), IpAddr::V4(addr)) => {
                if *prefix == 0 {
                    return true;
                }
                if *prefix > 32 {
                    return false;
                }
                let mask = !0u32 << (32 - *prefix);
                (u32::from(*net) & mask) == (u32::from(addr) & mask)
            }
            (Self::CidrV6(net, prefix), IpAddr::V6(addr)) => {
                if *prefix == 0 {
                    return true;
                }
                if *prefix > 128 {
                    return false;
                }
                let mask = !0u128 << (128 - *prefix);
                (u128::from(*net) & mask) == (u128::from(addr) & mask)
            }
            (Self::GeoIp(code), ip) => GLOBAL_GEO_DB.match_geoip(code, &ip),
            _ => false,
        }
    }
}

pub static GLOBAL_GEO_DB: LazyLock<GeoDatabase> = LazyLock::new(GeoDatabase::new);

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

pub struct GeoDatabase {
    geosites: RwLock<HashMap<String, Vec<DomainMatcher>>>,
    geoips: RwLock<HashMap<String, Vec<IpMatcher>>>,
}

impl GeoDatabase {
    pub fn new() -> Self {
        let db = Self {
            geosites: RwLock::new(HashMap::new()),
            geoips: RwLock::new(HashMap::new()),
        };
        db.init_builtin_rules();
        db
    }

    fn init_builtin_rules(&self) {
        let mut gs = self.geosites.write().unwrap();
        let mut gi = self.geoips.write().unwrap();

        // Built-in geosite:private
        gs.insert(
            "private".into(),
            vec![
                DomainMatcher::Suffix("localhost".into()),
                DomainMatcher::Suffix("local".into()),
                DomainMatcher::Suffix("lan".into()),
                DomainMatcher::Suffix("home.arpa".into()),
            ],
        );

        // Built-in geosite:cn (top common domains)
        gs.insert(
            "cn".into(),
            vec![
                DomainMatcher::Suffix("cn".into()),
                DomainMatcher::Suffix("baidu.com".into()),
                DomainMatcher::Suffix("qq.com".into()),
                DomainMatcher::Suffix("taobao.com".into()),
                DomainMatcher::Suffix("jd.com".into()),
                DomainMatcher::Suffix("alipay.com".into()),
                DomainMatcher::Suffix("aliyun.com".into()),
                DomainMatcher::Suffix("bilibili.com".into()),
                DomainMatcher::Suffix("zhihu.com".into()),
                DomainMatcher::Suffix("163.com".into()),
                DomainMatcher::Suffix("sina.com.cn".into()),
            ],
        );

        // Built-in geosite:google
        gs.insert(
            "google".into(),
            vec![
                DomainMatcher::Suffix("google.com".into()),
                DomainMatcher::Suffix("googleapis.com".into()),
                DomainMatcher::Suffix("gstatic.com".into()),
                DomainMatcher::Suffix("googlevideo.com".into()),
                DomainMatcher::Suffix("youtube.com".into()),
                DomainMatcher::Suffix("ytimg.com".into()),
                DomainMatcher::Suffix("1e100.net".into()),
                DomainMatcher::Suffix("google.co.jp".into()),
                DomainMatcher::Suffix("google.com.hk".into()),
            ],
        );

        // Built-in geoip:private
        gi.insert(
            "private".into(),
            vec![
                IpMatcher::CidrV4(Ipv4Addr::new(10, 0, 0, 0), 8),
                IpMatcher::CidrV4(Ipv4Addr::new(172, 16, 0, 0), 12),
                IpMatcher::CidrV4(Ipv4Addr::new(192, 168, 0, 0), 16),
                IpMatcher::CidrV4(Ipv4Addr::new(127, 0, 0, 0), 8),
                IpMatcher::CidrV6(
                    Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0000u128),
                    10,
                ),
                IpMatcher::CidrV6(
                    Ipv6Addr::from(0xfc00_0000_0000_0000_0000_0000_0000_0000u128),
                    7,
                ),
                IpMatcher::CidrV6(Ipv6Addr::LOCALHOST, 128),
            ],
        );

        // Built-in geoip:cn common IP ranges
        gi.insert(
            "cn".into(),
            vec![
                IpMatcher::CidrV4(Ipv4Addr::new(114, 114, 114, 0), 24),
                IpMatcher::CidrV4(Ipv4Addr::new(223, 5, 5, 0), 24),
                IpMatcher::CidrV4(Ipv4Addr::new(119, 29, 29, 0), 24),
                IpMatcher::CidrV4(Ipv4Addr::new(180, 76, 76, 0), 24),
                IpMatcher::CidrV4(Ipv4Addr::new(1, 12, 12, 0), 24),
            ],
        );
    }

    pub fn load_geosite_file(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::Config(format!("geosite file not found: {:?}", path)));
        }
        // If dat file exists, parse raw entries
        let content = std::fs::read(path)?;
        let mut pos = 0;
        let mut group_map = HashMap::new();

        while pos < content.len() {
            // Read tag length and name
            if pos + 2 > content.len() {
                break;
            }
            let tag_len = content[pos] as usize;
            pos += 1;
            if pos + tag_len > content.len() {
                break;
            }
            if let Ok(tag_name) = std::str::from_utf8(&content[pos..pos + tag_len]) {
                let tag_lower = tag_name.to_lowercase();
                pos += tag_len;
                group_map.entry(tag_lower).or_insert_with(Vec::new);
            } else {
                pos += tag_len;
            }
        }

        let mut guard = self.geosites.write().unwrap();
        for (k, v) in group_map {
            guard.entry(k).or_default().extend(v);
        }
        Ok(())
    }

    pub fn match_geosite(&self, group: &str, domain: &str) -> bool {
        let guard = self.geosites.read().unwrap();
        if let Some(matchers) = guard.get(group) {
            for m in matchers {
                if m.matches(domain) {
                    return true;
                }
            }
        }
        false
    }

    pub fn match_geoip(&self, group: &str, ip: &IpAddr) -> bool {
        let guard = self.geoips.read().unwrap();
        if let Some(matchers) = guard.get(group) {
            for m in matchers {
                if m.matches(*ip) {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for GeoDatabase {
    fn default() -> Self {
        Self::new()
    }
}
