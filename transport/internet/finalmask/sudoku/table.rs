use super::config::SudokuConfig;
use super::rng_cooked::RNG_COOKED;
use crate::common::errors::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const RNG_LEN: usize = 607;
const RNG_TAP: usize = 273;
const RNG_MASK: u64 = (1 << 63) - 1;
const INT32_MAX: i32 = i32::MAX;

#[derive(Clone)]
pub struct GoRand {
    tap: usize,
    feed: usize,
    vec: [i64; RNG_LEN],
}

fn seedrand(mut x: i32) -> i32 {
    const A: i32 = 48271;
    const Q: i32 = 44488;
    const R: i32 = 3399;
    let hi = x / Q;
    let lo = x % Q;
    x = A * lo - R * hi;
    if x < 0 { x += INT32_MAX; }
    x
}

impl GoRand {
    pub fn new(mut seed: i64) -> Self {
        seed %= INT32_MAX as i64;
        if seed < 0 { seed += INT32_MAX as i64; }
        if seed == 0 { seed = 89482311; }
        let (mut x, mut vec) = (seed as i32, [0i64; RNG_LEN]);
        for i in -20..(RNG_LEN as isize) {
            x = seedrand(x);
            if i >= 0 {
                let mut u = (x as i64) << 40;
                x = seedrand(x); u ^= (x as i64) << 20;
                x = seedrand(x); u ^= (x as i64) ^ RNG_COOKED[i as usize];
                vec[i as usize] = u;
            }
        }
        Self { tap: 0, feed: RNG_LEN - RNG_TAP, vec }
    }
    pub fn new_seeded() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as i64;
        Self::new(nanos)
    }
    pub fn uint64(&mut self) -> u64 {
        if self.tap == 0 {
            self.tap = RNG_LEN - 1;
        } else {
            self.tap -= 1;
        }
        if self.feed == 0 {
            self.feed = RNG_LEN - 1;
        } else {
            self.feed -= 1;
        }
        let x = self.vec[self.feed].wrapping_add(self.vec[self.tap]);
        self.vec[self.feed] = x;
        x as u64
    }
    pub fn int63(&mut self) -> i64 { (self.uint64() & RNG_MASK) as i64 }
    pub fn int31(&mut self) -> i32 { (self.int63() >> 32) as i32 }
    pub fn int31n(&mut self, n: i32) -> i32 {
        if n <= 0 { return 0; }
        if (n & (n - 1)) == 0 { return self.int31() & (n - 1); }
        let max = ((1i64 << 31) - 1 - ((1i64 << 31) % (n as i64))) as i32;
        loop {
            let v = self.int31();
            if v <= max { return v % n; }
        }
    }
    pub fn intn(&mut self, n: usize) -> usize {
        if n == 0 { return 0; }
        self.int31n(n as i32) as usize
    }
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let n = slice.len();
        for i in (1..n).rev() {
            let j = self.intn(i + 1);
            slice.swap(i, j);
        }
    }
}

pub type EncodeGroupFn = Arc<dyn Fn(u8) -> u8 + Send + Sync>;
pub type DecodeGroupFn = Arc<dyn Fn(u8) -> Option<u8> + Send + Sync>;

#[derive(Clone)]
pub struct ByteLayout {
    pub hint_mask: u8,
    pub hint_value: u8,
    pub pad_marker: u8,
    pub padding_pool: Vec<u8>,
    pub encode_hint: EncodeGroupFn,
    pub encode_group: EncodeGroupFn,
    pub decode_group: DecodeGroupFn,
}

impl ByteLayout {
    pub fn is_hint(&self, b: u8) -> bool {
        if (b & self.hint_mask) == self.hint_value { return true; }
        self.hint_mask == 0x40 && b == b'\n'
    }
}

pub fn ascii_layout() -> ByteLayout {
    let encode_group: EncodeGroupFn = Arc::new(|g| { let b = 0x40 | (g & 0x3f); if b == 0x7f { b'\n' } else { b } });
    let decode_group: DecodeGroupFn = Arc::new(|b| if b == b'\n' { Some(0x3f) } else { ((b & 0x40) != 0).then_some(b & 0x3f) });
    ByteLayout {
        hint_mask: 0x40, hint_value: 0x40, pad_marker: 0x3f, padding_pool: (0x20..0x40).collect(),
        encode_hint: encode_group.clone(), encode_group, decode_group,
    }
}

pub fn entropy_layout() -> ByteLayout {
    let padding: Vec<u8> = (0..8).flat_map(|i| [0x80 + i, 0x10 + i]).collect();
    let encode_group: EncodeGroupFn = Arc::new(|g| { let v = g & 0x3f; ((v & 0x30) << 1) | (v & 0x0f) });
    let decode_group: DecodeGroupFn = Arc::new(|b| ((b & 0x90) == 0).then(|| ((b >> 1) & 0x30) | (b & 0x0f)));
    ByteLayout {
        hint_mask: 0x90, hint_value: 0x00, pad_marker: 0x80, padding_pool: padding,
        encode_hint: encode_group.clone(), encode_group, decode_group,
    }
}

pub fn custom_layout(pattern: &str) -> Result<ByteLayout> {
    let pattern = SudokuConfig::normalize_custom_table(pattern)?;
    let (mut x_bits, mut p_bits, mut v_bits) = (Vec::new(), Vec::new(), Vec::new());
    for (i, c) in pattern.chars().enumerate() {
        let bit = (7 - i) as u8;
        match c {
            'x' => x_bits.push(bit),
            'p' => p_bits.push(bit),
            'v' => v_bits.push(bit),
            _ => {}
        }
    }
    let x_mask = x_bits.iter().fold(0u8, |acc, &bit| acc | (1 << bit));
    let (p_enc, v_enc) = (p_bits.clone(), v_bits.clone());
    let encode_group: EncodeGroupFn = Arc::new(move |group: u8| {
        let (mut out, val, pos) = (x_mask, (group >> 4) & 0x03, group & 0x0f);
        if (val & 0x02) != 0 { out |= 1 << p_enc[0]; }
        if (val & 0x01) != 0 { out |= 1 << p_enc[1]; }
        for (i, &bit) in v_enc.iter().enumerate() { if ((pos >> (3 - i)) & 0x01) == 1 { out |= 1 << bit; } }
        out
    });
    let mut padding = Vec::new();
    let mut padding_set = std::collections::HashSet::new();
    for &drop_bit in &x_bits {
        for group in 0..64u8 {
            let b = encode_group(group) & !(1 << drop_bit);
            if b.count_ones() >= 5 && padding_set.insert(b) { padding.push(b); }
        }
    }
    padding.sort();
    if padding.is_empty() { return Err(Error::Config("customTable produced empty padding pool".to_string())); }
    let decode_group: DecodeGroupFn = Arc::new(move |b: u8| {
        if (b & x_mask) != x_mask { return None; }
        let val = (((b & (1 << p_bits[0])) != 0) as u8) << 1 | (((b & (1 << p_bits[1])) != 0) as u8);
        let pos = v_bits.iter().enumerate().fold(0u8, |acc, (i, &bit)| {
            if (b & (1 << bit)) != 0 { acc | (1 << (3 - i)) } else { acc }
        });
        Some((val << 4) | pos)
    });
    Ok(ByteLayout {
        hint_mask: x_mask,
        hint_value: x_mask,
        pad_marker: padding[0],
        padding_pool: padding,
        encode_hint: encode_group.clone(),
        encode_group,
        decode_group,
    })
}

pub fn sort4(mut in_b: [u8; 4]) -> [u8; 4] {
    if in_b[0] > in_b[1] { in_b.swap(0, 1); }
    if in_b[2] > in_b[3] { in_b.swap(2, 3); }
    if in_b[0] > in_b[2] { in_b.swap(0, 2); }
    if in_b[1] > in_b[3] { in_b.swap(1, 3); }
    if in_b[1] > in_b[2] { in_b.swap(1, 2); }
    in_b
}

pub fn pack_key(in_b: [u8; 4]) -> u32 {
    ((in_b[0] as u32) << 24) | ((in_b[1] as u32) << 16) | ((in_b[2] as u32) << 8) | (in_b[3] as u32)
}

fn generate_all_grids() -> Vec<[u8; 16]> {
    let (mut grids, mut g) = (Vec::with_capacity(288), [0u8; 16]);
    fn dfs(idx: usize, g: &mut [u8; 16], grids: &mut Vec<[u8; 16]>) {
        if idx == 16 { grids.push(*g); return; }
        let (row, col) = (idx / 4, idx % 4);
        let (br, bc) = ((row / 2) * 2, (col / 2) * 2);
        for num in 1..=4u8 {
            if (0..4).any(|i| g[row * 4 + i] == num || g[i * 4 + col] == num)
                || (0..2).any(|r| (0..2).any(|c| g[(br + r) * 4 + bc + c] == num))
            { continue; }
            g[idx] = num;
            dfs(idx + 1, g, grids);
            g[idx] = 0;
        }
    }
    dfs(0, &mut g, &mut grids);
    grids
}

fn hint_positions() -> Vec<[u8; 4]> {
    let mut positions = Vec::with_capacity(1820);
    for a in 0..13 {
        for b in (a + 1)..14 {
            for c in (b + 1)..15 { for d in (c + 1)..16 { positions.push([a as u8, b as u8, c as u8, d as u8]); } }
        }
    }
    positions
}

fn clue_group(g: &[u8; 16], pos: u8) -> u8 { ((g[pos as usize] - 1) << 4) | (pos & 0x0f) }

fn build_base_patterns() -> Result<Vec<Vec<[u8; 4]>>> {
    let grids = generate_all_grids();
    let mut patterns = vec![Vec::new(); grids.len()];
    for ps in hint_positions() {
        let mut counts: HashMap<u32, u16> = HashMap::with_capacity(grids.len());
        let items: Vec<_> = grids.iter().map(|g| {
            let groups = sort4(ps.map(|p| clue_group(g, p)));
            let key = pack_key(groups);
            *counts.entry(key).or_insert(0) += 1;
            (key, groups)
        }).collect();
        for (gi, (key, groups)) in items.into_iter().enumerate() {
            if counts.get(&key) == Some(&1) { patterns[gi].push(groups); }
        }
    }
    if let Some(gi) = patterns.iter().position(|list| list.is_empty()) {
        return Err(Error::Config(format!("grid {} has no uniquely decodable clue set", gi)));
    }
    Ok(patterns)
}

static BASE_PATTERNS: OnceLock<Vec<Vec<[u8; 4]>>> = OnceLock::new();

fn get_base_patterns() -> &'static [Vec<[u8; 4]>] {
    BASE_PATTERNS.get_or_init(|| build_base_patterns().expect("failed to build sudoku base patterns"))
}

#[derive(Clone)]
pub struct SudokuTable {
    pub encode: Vec<Vec<[u8; 4]>>,
    pub decode: HashMap<u32, u8>,
    pub layout: Arc<ByteLayout>,
}

impl SudokuTable {
    pub fn build(password: &str, layout: Arc<ByteLayout>) -> Result<Self> {
        let patterns = get_base_patterns();
        if patterns.len() < 256 { return Err(Error::Config(format!("not enough sudoku grids: {}", patterns.len()))); }
        let mut order: Vec<usize> = (0..patterns.len()).collect();
        let hash = Sha256::digest(password.as_bytes());
        GoRand::new(i64::from_be_bytes(hash[..8].try_into().unwrap())).shuffle(&mut order);
        let mut decode = HashMap::with_capacity(1 << 16);
        let mut encode = vec![Vec::new(); 256];
        for b in 0..256 {
            let pat_list = &patterns[order[b]];
            if pat_list.is_empty() { return Err(Error::Config(format!("grid {} has no valid clue set", order[b]))); }
            let mut enc = Vec::with_capacity(pat_list.len());
            for g in pat_list {
                let hints = g.map(|x| (layout.encode_hint)(x));
                let key = pack_key(sort4(hints));
                if let Some(&old) = decode.get(&key) && old != b as u8
                { return Err(Error::Config(format!("decode key collision for byte {} and {}", old, b))); }
                decode.insert(key, b as u8);
                enc.push(hints);
            }
            encode[b] = enc;
        }
        Ok(Self { encode, decode, layout })
    }
}

static TABLE_SET_CACHE: OnceLock<Mutex<HashMap<String, Vec<Arc<SudokuTable>>>>> = OnceLock::new();

fn get_table_cache() -> &'static Mutex<HashMap<String, Vec<Arc<SudokuTable>>>> {
    TABLE_SET_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn resolve_layout(mode: &str, custom_table: &str) -> Result<ByteLayout> {
    if mode == "prefer_ascii" { return Ok(ascii_layout()); }
    if !custom_table.is_empty() { return custom_layout(custom_table); }
    Ok(entropy_layout())
}

pub fn get_tables(config: &SudokuConfig) -> Result<Vec<Arc<SudokuTable>>> {
    let mode = config.normalized_ascii()?;
    let patterns = config.normalized_custom_patterns(&mode)?;
    let key = format!("{}:{}:{}", config.password, mode, patterns.join("\0"));
    let cache = get_table_cache();
    if let Some(cached) = cache.lock().unwrap().get(&key).cloned() { return Ok(cached); }
    let tables: Result<Vec<_>> = patterns.into_iter().map(|p| {
        Ok(Arc::new(SudokuTable::build(&config.password, Arc::new(resolve_layout(&mode, &p)?))?))
    }).collect();
    let tables = tables?;
    cache.lock().unwrap().insert(key, tables.clone());
    Ok(tables)
}
