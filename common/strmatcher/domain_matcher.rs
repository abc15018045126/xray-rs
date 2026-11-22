use super::strmatcher::{Matcher, MatcherType};
use std::collections::HashMap;

pub struct DomainMatcher {
    pattern: String,
}

impl DomainMatcher {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into().to_lowercase(),
        }
    }
}

impl Matcher for DomainMatcher {
    fn match_str(&self, input: &str) -> bool {
        let pattern = &self.pattern;
        let s = input.to_lowercase();
        if !s.ends_with(pattern) {
            return false;
        }
        s.len() == pattern.len() || s.as_bytes()[s.len() - pattern.len() - 1] == b'.'
    }

    fn pattern(&self) -> &str {
        &self.pattern
    }

    fn matcher_type(&self) -> MatcherType {
        MatcherType::Domain
    }
}

#[derive(Default)]
struct Node {
    values: Vec<u32>,
    sub: HashMap<String, Node>,
}

#[derive(Default)]
pub struct DomainMatcherGroup {
    root: Node,
}

impl DomainMatcherGroup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, domain: &str, value: u32) {
        let parts: Vec<&str> = domain.split('.').collect();
        let mut current = &mut self.root;
        for part in parts.into_iter().rev() {
            current = current.sub.entry(part.to_string()).or_default();
        }
        current.values.push(value);
    }

    pub fn match_domain(&self, domain: &str) -> Vec<u32> {
        if domain.is_empty() { return Vec::new(); }
        let (mut matches, mut cur) = (Vec::new(), &self.root);
        for part in domain.rsplit('.') {
            let Some(next) = cur.sub.get(part) else { break; };
            cur = next;
            if !cur.values.is_empty() { matches.push(cur.values.as_slice()); }
        }
        match matches.len() {
            0 => Vec::new(),
            1 => matches[0].to_vec(),
            _ => matches.into_iter().rev().flat_map(|s| s.iter().copied()).collect(),
        }
    }
}
