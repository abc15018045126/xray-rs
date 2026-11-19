//! Debug-only process resource monitor (CPU % and Memory MB).
//! Compiled exclusively under `#[cfg(debug_assertions)]`.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

const HISTORY_LIMIT: usize = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub pid: u32,
    pub cpu_percent: f64,
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
}

struct CpuSampleState {
    last_wall: Instant,
    last_proc_100ns: u64,
    start_instant: Instant,
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
        let initial_proc = read_process_cpu_100ns();
        Self {
            state: Mutex::new(CpuSampleState {
                last_wall: now,
                last_proc_100ns: initial_proc,
                start_instant: now,
                history: VecDeque::with_capacity(HISTORY_LIMIT),
            }),
            cores,
        }
    }

    /// Take a fresh CPU + Memory sample and push it into the rolling history.
    pub fn sample(&self) -> ResourceSnapshot {
        let now = Instant::now();
        let proc_100ns = read_process_cpu_100ns();
        let (rss_mb, private_mb, peak_mb) = read_process_memory_mb();

        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed_secs = now.duration_since(guard.last_wall).as_secs_f64();
        let cpu_percent = if elapsed_secs >= 0.05 {
            let delta_proc_secs = proc_100ns.saturating_sub(guard.last_proc_100ns) as f64 / 1e7;
            guard.last_wall = now;
            guard.last_proc_100ns = proc_100ns;
            let pct = (delta_proc_secs / (elapsed_secs * self.cores as f64)) * 100.0;
            (pct.clamp(0.0, 100.0) * 100.0).round() / 100.0
        } else {
            guard
                .history
                .back()
                .map(|s| s.cpu_percent)
                .unwrap_or(0.0)
        };

        let snap = ResourceSnapshot {
            pid: std::process::id(),
            cpu_percent,
            memory_rss_mb: (rss_mb * 100.0).round() / 100.0,
            memory_private_mb: (private_mb * 100.0).round() / 100.0,
            memory_peak_mb: (peak_mb * 100.0).round() / 100.0,
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

    pub fn report(&self) -> ResourceReport {
        let current = self.sample();
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ResourceReport {
            current,
            history: guard.history.iter().cloned().collect(),
        }
    }
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------- Windows Implementation ----------------

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct FILETIME {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct PROCESS_MEMORY_COUNTERS_EX {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivateUsage: usize,
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
#[link(name = "psapi")]
unsafe extern "system" {
    fn GetCurrentProcess() -> isize;
    fn GetProcessTimes(
        hProcess: isize,
        lpCreationTime: *mut FILETIME,
        lpExitTime: *mut FILETIME,
        lpKernelTime: *mut FILETIME,
        lpUserTime: *mut FILETIME,
    ) -> i32;
    fn GetProcessMemoryInfo(
        hProcess: isize,
        ppsmemCounters: *mut PROCESS_MEMORY_COUNTERS_EX,
        cb: u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

#[cfg(target_os = "windows")]
fn read_process_cpu_100ns() -> u64 {
    unsafe {
        let handle = GetCurrentProcess();
        let mut creation = std::mem::zeroed::<FILETIME>();
        let mut exit = std::mem::zeroed::<FILETIME>();
        let mut kernel = std::mem::zeroed::<FILETIME>();
        let mut user = std::mem::zeroed::<FILETIME>();
        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) != 0 {
            filetime_to_u64(kernel).saturating_add(filetime_to_u64(user))
        } else {
            0
        }
    }
}

#[cfg(target_os = "windows")]
fn read_process_memory_mb() -> (f64, f64, f64) {
    unsafe {
        let handle = GetCurrentProcess();
        let mut counters = std::mem::zeroed::<PROCESS_MEMORY_COUNTERS_EX>();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        if GetProcessMemoryInfo(handle, &mut counters, counters.cb) != 0 {
            let mb = 1024.0 * 1024.0;
            (
                counters.WorkingSetSize as f64 / mb,
                counters.PrivateUsage as f64 / mb,
                counters.PeakWorkingSetSize as f64 / mb,
            )
        } else {
            (0.0, 0.0, 0.0)
        }
    }
}

// ---------------- Unix Fallback Implementation ----------------

#[cfg(not(target_os = "windows"))]
fn read_process_cpu_100ns() -> u64 {
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(end_comm) = stat.rfind(')') {
            let fields: Vec<&str> = stat[end_comm + 1..].split_whitespace().collect();
            if fields.len() > 13 {
                let utime: u64 = fields[11].parse().unwrap_or(0);
                let stime: u64 = fields[12].parse().unwrap_or(0);
                // Assume 100 ticks/sec -> each tick is 100_000 * 100ns
                return (utime + stime) * 100_000;
            }
        }
    }
    0
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
