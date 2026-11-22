use super::balancing::BalancingStrategy;
use crate::app::observatory::Observatory;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StrategyLeastLoadConfig {
    #[serde(default)]
    pub costs: Vec<String>,
    #[serde(default)]
    pub baselines: Vec<i64>,
    #[serde(default)]
    pub expected: i32,
    #[serde(default, rename = "maxRTT")]
    pub max_rtt: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeastLoadNode {
    pub tag: String,
    pub count_all: usize,
    pub count_fail: usize,
    pub rtt_average: Duration,
    pub rtt_deviation: Duration,
    pub rtt_deviation_cost: Duration,
}

impl LeastLoadNode {
    pub fn new(tag: impl Into<String>, rtt_ms: u64, deviation_cost_ms: u64) -> Self {
        Self {
            tag: tag.into(),
            count_all: 1,
            count_fail: 0,
            rtt_average: Duration::from_millis(rtt_ms),
            rtt_deviation: Duration::from_millis(rtt_ms),
            rtt_deviation_cost: Duration::from_millis(deviation_cost_ms),
        }
    }
}

pub fn leastload_sort(nodes: &mut [LeastLoadNode]) {
    nodes.sort_by(|left, right| {
        if left.rtt_deviation_cost != right.rtt_deviation_cost {
            left.rtt_deviation_cost.cmp(&right.rtt_deviation_cost)
        } else if left.rtt_average != right.rtt_average {
            left.rtt_average.cmp(&right.rtt_average)
        } else if left.count_fail != right.count_fail {
            left.count_fail.cmp(&right.count_fail)
        } else if left.count_all != right.count_all {
            right.count_all.cmp(&left.count_all)
        } else {
            left.tag.cmp(&right.tag)
        }
    });
}

pub fn select_least_load(nodes: &[LeastLoadNode], baselines: &[i64], expected_count: i32) -> Vec<LeastLoadNode> {
    if nodes.is_empty() { return Vec::new(); }
    let expected = if expected_count <= 0 { 1 } else { expected_count as usize };
    if expected > nodes.len() { return nodes.to_vec(); }
    if baselines.is_empty() { return nodes[..expected].to_vec(); }
    let mut count = 0;
    for &b in baselines {
        let baseline = Duration::from_millis(b as u64);
        while count < nodes.len() && nodes[count].rtt_deviation_cost < baseline { count += 1; }
        if count >= expected { break; }
    }
    if expected_count > 0 && count < expected { count = expected; }
    nodes[..count.min(nodes.len())].to_vec()
}

pub struct LeastLoadStrategy {
    pub settings: StrategyLeastLoadConfig,
    pub observatory: Option<Arc<Observatory>>,
    pub fallback_tag: Option<String>,
}

impl LeastLoadStrategy {
    pub fn new(observatory: Arc<Observatory>, fallback_tag: Option<String>) -> Self {
        Self {
            settings: StrategyLeastLoadConfig::default(),
            observatory: Some(observatory),
            fallback_tag,
        }
    }
    pub fn with_config(
        settings: StrategyLeastLoadConfig,
        fallback_tag: Option<String>,
        observatory: Option<Arc<Observatory>>,
    ) -> Self {
        Self {
            settings,
            observatory,
            fallback_tag,
        }
    }
}

impl BalancingStrategy for LeastLoadStrategy {
    fn name(&self) -> &str { "leastLoad" }
    fn pick_outbound(&self, tags: &[String]) -> Option<String> {
        if tags.is_empty() { return self.fallback_tag.clone(); }
        if let Some(best) = self.observatory.as_ref().and_then(|o| o.select_best_outbound(tags)) { return Some(best); }
        let mut nodes: Vec<LeastLoadNode> = tags.iter().enumerate()
            .map(|(i, tag)| { let c = 100 + (i as u64 * 50); LeastLoadNode::new(tag, c, c) }).collect();
        leastload_sort(&mut nodes);
        select_least_load(&nodes, &self.settings.baselines, self.settings.expected)
            .first().map(|n| n.tag.clone()).or_else(|| self.fallback_tag.clone())
    }
}
