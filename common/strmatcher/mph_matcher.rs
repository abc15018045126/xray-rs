use super::ac_automaton_matcher::AcAutomatonMatcher;
use super::matchers::RegexMatcher;
use super::strmatcher::MatcherType;
use crate::common::errors::Result;
use std::collections::HashMap;

pub const PRIME_RK: u32 = 16777619;

pub fn rolling_hash(s: &str) -> u32 {
    let mut h = 0u32;
    for &b in s.as_bytes().iter().rev() { h = h.wrapping_mul(PRIME_RK).wrapping_add(b as u32); }
    h
}

#[derive(Default)]
pub struct MphMatcherGroup {
    ac: Option<AcAutomatonMatcher>,
    other_matchers: Vec<(RegexMatcher, u32)>,
    rule_map: HashMap<String, u32>,
    rules: Vec<String>,
    count: u32,
}

impl MphMatcherGroup {
    pub fn new() -> Self {
        Self {
            ac: None,
            other_matchers: Vec::new(),
            rule_map: HashMap::new(),
            rules: Vec::new(),
            count: 1,
        }
    }
    pub fn add_full_or_domain_pattern(&mut self, pattern: &str, t: MatcherType) {
        let h = rolling_hash(pattern);
        if t == MatcherType::Domain {
            self.rule_map.insert(format!(".{}", pattern), h.wrapping_mul(PRIME_RK).wrapping_add(b'.' as u32));
        }
        if matches!(t, MatcherType::Domain | MatcherType::Full) { self.rule_map.insert(pattern.to_string(), h); }
    }
    pub fn add_pattern(&mut self, pattern: &str, t: MatcherType) -> Result<u32> {
        match t {
            MatcherType::Substr => self.ac.get_or_insert_with(AcAutomatonMatcher::new).add(pattern, t),
            MatcherType::Full | MatcherType::Domain => self.add_full_or_domain_pattern(&pattern.to_lowercase(), t),
            MatcherType::Regex => self.other_matchers.push((RegexMatcher::new(pattern)?, self.count)),
        }
        Ok(self.count)
    }
    pub fn build(&mut self) {
        if let Some(ac) = &mut self.ac { ac.build(); }
        self.rules = self.rule_map.keys().cloned().collect();
    }
    pub fn lookup(&self, s: &str) -> bool { self.rule_map.contains_key(s) }
    pub fn match_pattern(&self, pattern: &str) -> Vec<u32> {
        if pattern.as_bytes().iter().enumerate().any(|(i, &b)| b == b'.' && self.lookup(&pattern[i..]))
            || self.lookup(pattern)
            || self.ac.as_ref().is_some_and(|ac| ac.match_str(pattern))
        { return vec![1]; }
        self.other_matchers.iter().find(|(m, _)| super::strmatcher::Matcher::match_str(m, pattern)).map_or_else(Vec::new, |(_, id)| vec![*id])
    }
    pub fn size(&self) -> u32 { self.count }
}
