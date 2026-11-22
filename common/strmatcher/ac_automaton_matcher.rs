use super::strmatcher::MatcherType;
use std::collections::VecDeque;

const VALID_CHAR_COUNT: usize = 53;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchType {
    pub m_type: MatcherType,
    pub exist: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Edge {
    pub edge_type: bool,
    pub next_node: usize,
}

pub struct AcAutomatonMatcher {
    trie: Vec<[Edge; VALID_CHAR_COUNT]>,
    fail: Vec<usize>,
    exists: Vec<MatchType>,
    count: usize,
}

fn char_to_index(c: u8) -> Option<usize> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as usize),
        b'a'..=b'z' => Some((c - b'a') as usize),
        b'!' => Some(26),
        b'$' => Some(27),
        b'&' => Some(28),
        b'\'' => Some(29),
        b'(' => Some(30),
        b')' => Some(31),
        b'*' => Some(32),
        b'+' => Some(33),
        b',' => Some(34),
        b';' => Some(35),
        b'=' => Some(36),
        b':' => Some(37),
        b'%' => Some(38),
        b'-' => Some(39),
        b'.' => Some(40),
        b'_' => Some(41),
        b'~' => Some(42),
        b'0'..=b'9' => Some(43 + (c - b'0') as usize),
        _ => None,
    }
}

impl AcAutomatonMatcher {
    pub fn new() -> Self {
        Self {
            trie: vec![[Edge::default(); VALID_CHAR_COUNT]],
            fail: vec![0],
            exists: vec![MatchType {
                m_type: MatcherType::Full,
                exist: false,
            }],
            count: 0,
        }
    }

    pub fn add(&mut self, domain: &str, t: MatcherType) {
        let step = |s: &mut Self, node: usize, idx: usize| -> usize {
            if s.trie[node][idx].next_node == 0 {
                s.count += 1;
                while s.trie.len() < s.count + 1 {
                    s.trie.push([Edge::default(); VALID_CHAR_COUNT]);
                    s.fail.push(0);
                    s.exists.push(MatchType { m_type: MatcherType::Full, exist: false });
                }
                s.trie[node][idx] = Edge { edge_type: true, next_node: s.count };
            }
            s.trie[node][idx].next_node
        };

        let mut node = 0;
        for &b in domain.as_bytes().iter().rev() {
            let Some(idx) = char_to_index(b) else { return };
            node = step(self, node, idx);
        }

        if t == MatcherType::Domain {
            self.exists[node] = MatchType { m_type: MatcherType::Full, exist: true };
            node = step(self, node, char_to_index(b'.').unwrap());
        }
        self.exists[node] = MatchType { m_type: t, exist: true };
    }

    pub fn build(&mut self) {
        let mut queue: VecDeque<Edge> = self.trie[0].iter().copied().filter(|e| e.next_node != 0).collect();
        while let Some(front) = queue.pop_front() {
            let (node, fail_node) = (front.next_node, self.fail[front.next_node]);
            for i in 0..VALID_CHAR_COUNT {
                let next = self.trie[node][i].next_node;
                let fail_next = self.trie[fail_node][i].next_node;
                if next != 0 {
                    self.fail[next] = fail_next;
                    queue.push_back(self.trie[node][i]);
                } else {
                    self.trie[node][i] = Edge { edge_type: false, next_node: fail_next };
                }
            }
        }
    }

    pub fn match_str(&self, s: &str) -> bool {
        let bytes = s.as_bytes();
        let mut node = 0;
        let mut full_match = true;

        for &b in bytes.iter().rev() {
            let idx = match char_to_index(b) {
                Some(i) => i,
                None => return false,
            };

            full_match = full_match && self.trie[node][idx].edge_type;
            node = self.trie[node][idx].next_node;

            match self.exists[node].m_type {
                MatcherType::Substr => return true,
                MatcherType::Domain if full_match => {
                    return true;
                }
                _ => {}
            }
        }

        full_match && self.exists[node].exist
    }
}

impl Default for AcAutomatonMatcher {
    fn default() -> Self {
        Self::new()
    }
}
