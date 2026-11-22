use crate::common::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SudokuConfig {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ascii: String,
    #[serde(default)]
    pub custom_table: String,
    #[serde(default)]
    pub padding_min: u32,
    #[serde(default)]
    pub padding_max: u32,
    #[serde(default)]
    pub custom_tables: Vec<String>,
}

impl SudokuConfig {
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            ascii: String::new(),
            custom_table: String::new(),
            padding_min: 0,
            padding_max: 0,
            custom_tables: Vec::new(),
        }
    }
    pub fn normalized_ascii(&self) -> Result<String> {
        let mode = self.ascii.trim().to_ascii_lowercase();
        match mode.as_str() {
            "" | "entropy" | "prefer_entropy" => Ok("prefer_entropy".to_string()),
            "ascii" | "prefer_ascii" => Ok("prefer_ascii".to_string()),
            _ => Err(Error::Config(format!("invalid sudoku ascii mode: {}", self.ascii))),
        }
    }
    pub fn normalized_custom_patterns(&self, mode: &str) -> Result<Vec<String>> {
        if mode == "prefer_ascii" { return Ok(vec![String::new()]); }
        let mut raw = self.custom_tables.clone();
        if raw.is_empty() && !self.custom_table.is_empty() { raw.push(self.custom_table.clone()); }
        let (mut patterns, mut seen) = (Vec::new(), HashSet::new());
        for r in raw {
            let p = r.trim();
            let norm = if p.is_empty() { String::new() } else { Self::normalize_custom_table(p)? };
            if seen.insert(norm.clone()) { patterns.push(norm); }
        }
        if patterns.is_empty() { patterns.push(String::new()); }
        Ok(patterns)
    }
    pub fn normalize_custom_table(pattern: &str) -> Result<String> {
        let cleaned: String = pattern.trim().to_ascii_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
        if cleaned.len() != 8 { return Err(Error::Config(format!("customTable must be 8 chars, got {}", cleaned.len()))); }
        let (mut x, mut p, mut v) = (0, 0, 0);
        for ch in cleaned.chars() {
            match ch {
                'x' => x += 1,
                'p' => p += 1,
                'v' => v += 1,
                _ => return Err(Error::Config(format!("customTable has invalid char {:?}", ch))),
            }
        }
        if (x, p, v) != (2, 2, 4) {
            return Err(Error::Config("customTable must contain exactly 2 x, 2 p and 4 v".into()));
        }
        Ok(cleaned)
    }
    pub fn normalized_padding(&self) -> (usize, usize) {
        let p_min = self.padding_min.min(100) as usize;
        let mut p_max = self.padding_max.min(100) as usize;
        if p_max < p_min { p_max = p_min; }
        (p_min, p_max)
    }
}
