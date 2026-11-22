//! Debug-only process resource monitor (CPU %, cumulative avg CPU %, peak CPU %,
//! Kernel/User split, per-thread CPU attribution, and Memory MB).
//! Compiled exclusively under `#[cfg(debug_assertions)]`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const HISTORY_LIMIT: usize = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageStats {
    pub name: String,
    pub calls: u64,
    pub total_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    pub share_percent: f64,
}

#[derive(Default)]
struct StageAccum {
    calls: u64,
    total_us: u64,
    max_us: u64,
}

static STAGE_PROFILER: OnceLock<Mutex<HashMap<&'static str, StageAccum>>> = OnceLock::new();

pub fn record_stage(name: &'static str, dur: Duration) {
    let us = dur.as_micros() as u64;
    let map = STAGE_PROFILER.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
    let e = guard.entry(name).or_default();
    e.calls += 1;
    e.total_us = e.total_us.saturating_add(us);
    if us > e.max_us {
        e.max_us = us;
    }
}

pub fn stage_stats_snapshot() -> Vec<StageStats> {
    let Some(map) = STAGE_PROFILER.get() else {
        return Vec::new();
    };
    let guard = map.lock().unwrap_or_else(|e| e.into_inner());
    let sum_us: u64 = guard.values().map(|a| a.total_us).sum();
    let mut out: Vec<StageStats> = guard
        .iter()
        .map(|(name, a)| {
            let total_ms = round2(a.total_us as f64 / 1000.0);
            let avg_ms = if a.calls > 0 {
                round2((a.total_us as f64 / a.calls as f64) / 1000.0)
            } else {
                0.0
            };
            let max_ms = round2(a.max_us as f64 / 1000.0);
            let share_percent = if sum_us > 0 {
                round2((a.total_us as f64 / sum_us as f64) * 100.0)
            } else {
                0.0
            };
            StageStats {
                name: (*name).to_string(),
                calls: a.calls,
                total_ms,
                avg_ms,
                max_ms,
                share_percent,
            }
        })
        .collect();
    out.sort_by(|a, b| b.total_ms.total_cmp(&a.total_ms));
    out
}

pub fn friendly_thread_name(raw: &str, tid: u32) -> String {
    match raw {
        "tokio-rt-worker" => format!("Tokio 异步工作线程 (TID {})", tid),
        "wintun-recv" => "Wintun 网卡收包线程".to_string(),
        "main" => "主线程 (main)".to_string(),
        other if other.starts_with("thread-") => format!("系统/后台线程 (TID {})", tid),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadCpuInfo {
    pub tid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub avg_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub cpu_share_percent: f64,
    pub kernel_cpu_percent: f64,
    pub user_cpu_percent: f64,
    pub total_cpu_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub pid: u32,
    pub cpu_percent: f64,
    pub avg_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub kernel_cpu_percent: f64,
    pub avg_kernel_cpu_percent: f64,
    pub peak_kernel_cpu_percent: f64,
    pub user_cpu_percent: f64,
    pub avg_user_cpu_percent: f64,
    pub peak_user_cpu_percent: f64,
    pub thread_count: usize,
    pub memory_rss_mb: f64,
    pub memory_private_mb: f64,
    pub memory_peak_mb: f64,
    pub cpu_cores: usize,
    pub uptime_secs: u64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReport {
    pub current: ResourceSnapshot,
    pub history: Vec<ResourceSnapshot>,
    pub threads: Vec<ThreadCpuInfo>,
}

struct CpuSampleState {
    last_wall: Instant,
    last_thread_wall: Instant,
    start_instant: Instant,
    start_kernel_100ns: u64,
    start_user_100ns: u64,
    last_kernel_100ns: u64,
    last_user_100ns: u64,
    peak_cpu_percent: f64,
    peak_kernel_cpu_percent: f64,
    peak_user_cpu_percent: f64,
    last_threads: HashMap<u32, (u64, u64)>,
    thread_peaks: HashMap<u32, f64>,
    latest_threads: Vec<ThreadCpuInfo>,
    history: VecDeque<ResourceSnapshot>,
}

pub struct ResourceMonitor {
    state: Mutex<CpuSampleState>,
    cores: usize,
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceMonitor {
    pub fn new() -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let now = Instant::now();
        let (init_k, init_u) = read_process_cpu_100ns();
        let init_raw_threads = read_threads_cpu_100ns();
        let mut last_threads = HashMap::with_capacity(init_raw_threads.len());
        for (tid, _name, k, u) in init_raw_threads {
            last_threads.insert(tid, (k, u));
        }
        Self {
            state: Mutex::new(CpuSampleState {
                last_wall: now,
                last_thread_wall: now,
                start_instant: now,
                start_kernel_100ns: init_k,
                start_user_100ns: init_u,
                last_kernel_100ns: init_k,
                last_user_100ns: init_u,
                peak_cpu_percent: 0.0,
                peak_kernel_cpu_percent: 0.0,
                peak_user_cpu_percent: 0.0,
                last_threads,
                thread_peaks: HashMap::new(),
                latest_threads: Vec::new(),
                history: VecDeque::with_capacity(HISTORY_LIMIT),
            }),
            cores,
        }
    }

    /// Take a fresh 1-second process CPU + Memory sample (cheap `GetProcessTimes`),
    /// and refresh per-thread CPU every 5 seconds so `CreateToolhelp32Snapshot` doesn't dominate CPU.
    pub fn sample(&self) -> ResourceSnapshot {
        let now = Instant::now();
        let (proc_k, proc_u) = read_process_cpu_100ns();
        let (rss_mb, private_mb, peak_mb) = read_process_memory_mb();

        let need_thread_scan = {
            let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.latest_threads.is_empty()
                || now.duration_since(guard.last_thread_wall).as_secs_f64() >= 5.0
        };
        let raw_threads_opt = if need_thread_scan {
            let _t0 = Instant::now();
            let v = read_threads_cpu_100ns();
            record_stage("Debug 线程采样 (每5s一次)", _t0.elapsed());
            Some(v)
        } else {
            None
        };

        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed_secs = now.duration_since(guard.last_wall).as_secs_f64();
        let total_uptime_secs = now.duration_since(guard.start_instant).as_secs_f64().max(0.05);
        let total_denom = total_uptime_secs * self.cores as f64;

        let cum_k = proc_k.saturating_sub(guard.start_kernel_100ns) as f64 / 1e7;
        let cum_u = proc_u.saturating_sub(guard.start_user_100ns) as f64 / 1e7;
        let avg_kernel_cpu_percent = round2((cum_k / total_denom * 100.0).clamp(0.0, 100.0));
        let avg_user_cpu_percent = round2((cum_u / total_denom * 100.0).clamp(0.0, 100.0));
        let avg_cpu_percent = round2(((cum_k + cum_u) / total_denom * 100.0).clamp(0.0, 100.0));

        let (cpu_percent, kernel_cpu_percent, user_cpu_percent) = if elapsed_secs >= 0.25 {
            let denom = elapsed_secs * self.cores as f64;
            let dk = proc_k.saturating_sub(guard.last_kernel_100ns) as f64 / 1e7;
            let du = proc_u.saturating_sub(guard.last_user_100ns) as f64 / 1e7;
            guard.last_wall = now;
            guard.last_kernel_100ns = proc_k;
            guard.last_user_100ns = proc_u;

            let k_pct = round2((dk / denom * 100.0).clamp(0.0, 100.0));
            let u_pct = round2((du / denom * 100.0).clamp(0.0, 100.0));
            let tot = round2(((dk + du) / denom * 100.0).clamp(0.0, 100.0));

            if tot > guard.peak_cpu_percent {
                guard.peak_cpu_percent = tot;
            }
            if k_pct > guard.peak_kernel_cpu_percent {
                guard.peak_kernel_cpu_percent = k_pct;
            }
            if u_pct > guard.peak_user_cpu_percent {
                guard.peak_user_cpu_percent = u_pct;
            }

            if let Some(raw_threads) = raw_threads_opt {
                let th_elapsed = now.duration_since(guard.last_thread_wall).as_secs_f64().max(0.25);
                let th_denom = th_elapsed * self.cores as f64;
                guard.last_thread_wall = now;

                let sum_all_threads_100ns: u64 = raw_threads
                    .iter()
                    .map(|(_, _, tk, tu)| tk.saturating_add(*tu))
                    .sum();

                let mut next_map = HashMap::with_capacity(raw_threads.len());
                let mut next_peaks = HashMap::with_capacity(raw_threads.len());
                let mut thread_infos = Vec::with_capacity(raw_threads.len());
                for (tid, name, tk, tu) in &raw_threads {
                    let (prev_k, prev_u) = guard.last_threads.get(tid).copied().unwrap_or((*tk, *tu));
                    let dtk = tk.saturating_sub(prev_k) as f64 / 1e7;
                    let dtu = tu.saturating_sub(prev_u) as f64 / 1e7;
                    let tk_pct = round2((dtk / th_denom * 100.0).clamp(0.0, 100.0));
                    let tu_pct = round2((dtu / th_denom * 100.0).clamp(0.0, 100.0));
                    let tot_pct = round2(((dtk + dtu) / th_denom * 100.0).clamp(0.0, 100.0));

                    let prev_peak = guard.thread_peaks.get(tid).copied().unwrap_or(0.0);
                    let th_peak = prev_peak.max(tot_pct);

                    let th_total_100ns = tk.saturating_add(*tu);
                    let th_total_secs = th_total_100ns as f64 / 1e7;
                    let th_avg_pct = round2((th_total_secs / total_denom * 100.0).clamp(0.0, 100.0));
                    let th_share_pct = if sum_all_threads_100ns > 0 {
                        round2((th_total_100ns as f64 / sum_all_threads_100ns as f64) * 100.0)
                    } else {
                        0.0
                    };
                    let total_ms = round2(th_total_100ns as f64 / 10_000.0);

                    next_map.insert(*tid, (*tk, *tu));
                    next_peaks.insert(*tid, th_peak);
                    thread_infos.push(ThreadCpuInfo {
                        tid: *tid,
                        name: friendly_thread_name(name, *tid),
                        cpu_percent: tot_pct,
                        avg_cpu_percent: th_avg_pct,
                        peak_cpu_percent: th_peak,
                        cpu_share_percent: th_share_pct,
                        kernel_cpu_percent: tk_pct,
                        user_cpu_percent: tu_pct,
                        total_cpu_ms: total_ms,
                    });
                }
                thread_infos.sort_by(|a, b| {
                    b.avg_cpu_percent
                        .total_cmp(&a.avg_cpu_percent)
                        .then_with(|| b.peak_cpu_percent.total_cmp(&a.peak_cpu_percent))
                        .then_with(|| b.cpu_percent.total_cmp(&a.cpu_percent))
                });
                guard.last_threads = next_map;
                guard.thread_peaks = next_peaks;
                guard.latest_threads = thread_infos;
            }

            (tot, k_pct, u_pct)
        } else if let Some(last) = guard.history.back() {
            (
                last.cpu_percent,
                last.kernel_cpu_percent,
                last.user_cpu_percent,
            )
        } else {
            (0.0, 0.0, 0.0)
        };

        let thread_count = guard.latest_threads.len();

        let snap = ResourceSnapshot {
            pid: std::process::id(),
            cpu_percent,
            avg_cpu_percent,
            peak_cpu_percent: guard.peak_cpu_percent,
            kernel_cpu_percent,
            avg_kernel_cpu_percent,
            peak_kernel_cpu_percent: guard.peak_kernel_cpu_percent,
            user_cpu_percent,
            avg_user_cpu_percent,
            peak_user_cpu_percent: guard.peak_user_cpu_percent,
            thread_count,
            memory_rss_mb: round2(rss_mb),
            memory_private_mb: round2(private_mb),
            memory_peak_mb: round2(peak_mb),
            cpu_cores: self.cores,
            uptime_secs: now.duration_since(guard.start_instant).as_secs(),
            timestamp_ms: now_epoch_ms(),
        };

        if guard.history.len() >= HISTORY_LIMIT {
            guard.history.pop_front();
        }
        guard.history.push_back(snap.clone());
        snap
    }

    /// Return the latest cached snapshot without triggering an extra mid-second OS snapshot.
    pub fn latest(&self) -> ResourceSnapshot {
        {
            let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(last) = guard.history.back() {
                return last.clone();
            }
        }
        self.sample()
    }

    pub fn report(&self) -> ResourceReport {
        let current = self.latest();
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ResourceReport {
            current,
            history: guard.history.iter().cloned().collect(),
            threads: guard.latest_threads.clone(),
        }
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------- Windows Implementation ----------------

#[cfg(target_os = "windows")]
use xray_rs_window::{read_process_cpu_100ns, read_process_memory_mb, read_threads_cpu_100ns};

// ---------------- Unix Fallback Implementation ----------------

#[cfg(not(target_os = "windows"))]
fn read_process_cpu_100ns() -> (u64, u64) {
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(end_comm) = stat.rfind(')') {
            let fields: Vec<&str> = stat[end_comm + 1..].split_whitespace().collect();
            if fields.len() > 13 {
                let utime: u64 = fields[11].parse().unwrap_or(0);
                let stime: u64 = fields[12].parse().unwrap_or(0);
                return (stime * 100_000, utime * 100_000);
            }
        }
    }
    (0, 0)
}

#[cfg(not(target_os = "windows"))]
fn read_threads_cpu_100ns() -> Vec<(u32, String, u64, u64)> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
fn read_process_memory_mb() -> (f64, f64, f64) {
    let mut rss_kb = 0.0f64;
    let mut peak_kb = 0.0f64;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("VmRSS:") {
                rss_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
            } else if let Some(val) = line.strip_prefix("VmHWM:") {
                peak_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
            }
        }
    }
    (rss_kb / 1024.0, rss_kb / 1024.0, peak_kb / 1024.0)
}
