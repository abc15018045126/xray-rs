use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

const ECHO_HOST: &str = "127.0.0.1";
const ECHO_PORT: u16 = 29999;
const XRAY_PORT: u16 = 20808;
const CLASH_PORT: u16 = 20809;

const PING_ROUNDS: usize = 100;
const CONCURRENT_CLIENTS: usize = 100;
const THROUGHPUT_BYTES: usize = 50 * 1024 * 1024; // 50MB

// Windows Memory Stats via psapi.dll
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
#[link(name = "psapi")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
    fn CloseHandle(handle: isize) -> i32;
    fn GetProcessMemoryInfo(handle: isize, counters: *mut PROCESS_MEMORY_COUNTERS_EX, cb: u32) -> i32;
}

fn get_process_memory_mb(pid: u32) -> f64 {
    #[cfg(target_os = "windows")]
    unsafe {
        let handle = OpenProcess(0x0400 | 0x0010, 0, pid);
        if handle == 0 {
            return 0.0;
        }
        let mut counters: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let ok = GetProcessMemoryInfo(handle, &mut counters, counters.cb);
        CloseHandle(handle);
        if ok != 0 {
            counters.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        0.0
    }
}

// SOCKS5 Connector
async fn socks5_connect(proxy_port: u16, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.set_nodelay(true)?;

    // 1. Handshake greeting: NO_AUTH
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(anyhow!("SOCKS5 negotiation failed: {:?}", resp));
    }

    // 2. CONNECT request
    let ip: std::net::Ipv4Addr = target_host.parse()?;
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(anyhow!("SOCKS5 connect error code: {}", reply[1]));
    }

    Ok(stream)
}

// High-speed Echo Server
async fn start_echo_server() -> Result<()> {
    let listener = TcpListener::bind((ECHO_HOST, ECHO_PORT)).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (reader, mut writer) = stream.split();
                let mut buf_reader = BufReader::new(reader);
                let mut line = String::new();

                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let cmd = line.trim();
                    if cmd == "PING" {
                        if writer.write_all(b"PONG\n").await.is_err() {
                            break;
                        }
                    } else if let Some(rest) = cmd.strip_prefix("UP:") {
                        let len: usize = rest.parse().unwrap_or(0);
                        let mut received = 0;
                        let mut buf = vec![0u8; 65536];
                        while received < len {
                            let to_read = (len - received).min(buf.len());
                            match buf_reader.read_exact(&mut buf[..to_read]).await {
                                Ok(_) => received += to_read,
                                Err(_) => break,
                            }
                        }
                        let resp = format!("OK:{}\n", received);
                        if writer.write_all(resp.as_bytes()).await.is_err() {
                            break;
                        }
                    } else if let Some(rest) = cmd.strip_prefix("DOWN:") {
                        let len: usize = rest.parse().unwrap_or(0);
                        let chunk = vec![b'X'; 65536];
                        let mut sent = 0;
                        while sent < len {
                            let to_send = (len - sent).min(chunk.len());
                            if writer.write_all(&chunk[..to_send]).await.is_err() {
                                break;
                            }
                            sent += to_send;
                        }
                    } else {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

#[derive(Default, Debug, Clone, serde::Serialize)]
struct Scorecard {
    idle_mb: f64,
    active_mb: f64,
    lat_avg: f64,
    lat_med: f64,
    lat_p95: f64,
    lat_min: f64,
    up_mbps: f64,
    down_mbps: f64,
    qps: f64,
    succ_rate: f64,
}

// Latency benchmark
async fn bench_latency(proxy_port: u16) -> (f64, f64, f64, f64) {
    let mut latencies = Vec::with_capacity(PING_ROUNDS);

    for _ in 0..PING_ROUNDS {
        let t0 = Instant::now();
        if let Ok(mut stream) = socks5_connect(proxy_port, ECHO_HOST, ECHO_PORT).await {
            if stream.write_all(b"PING\n").await.is_ok() {
                let mut resp = [0u8; 5];
                if stream.read_exact(&mut resp).await.is_ok() && &resp == b"PONG\n" {
                    latencies.push(t0.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    }

    if latencies.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let med = latencies[latencies.len() / 2];
    let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    let min = latencies[0];

    (avg, med, p95, min)
}

// Upload throughput
async fn bench_upload(proxy_port: u16, size_bytes: usize) -> f64 {
    let Ok(mut stream) = socks5_connect(proxy_port, ECHO_HOST, ECHO_PORT).await else {
        return 0.0;
    };

    let header = format!("UP:{}\n", size_bytes);
    if stream.write_all(header.as_bytes()).await.is_err() {
        return 0.0;
    }

    let chunk = vec![b'A'; 65536];
    let t0 = Instant::now();
    let mut sent = 0;
    while sent < size_bytes {
        let to_send = (size_bytes - sent).min(chunk.len());
        if stream.write_all(&chunk[..to_send]).await.is_err() {
            return 0.0;
        }
        sent += to_send;
    }

    let mut resp = [0u8; 32];
    let _ = stream.read(&mut resp).await;
    let elapsed = t0.elapsed().as_secs_f64();

    if elapsed > 0.0 {
        (size_bytes as f64 * 8.0 / (1024.0 * 1024.0)) / elapsed
    } else {
        0.0
    }
}

// Download throughput
async fn bench_download(proxy_port: u16, size_bytes: usize) -> f64 {
    let Ok(mut stream) = socks5_connect(proxy_port, ECHO_HOST, ECHO_PORT).await else {
        return 0.0;
    };

    let header = format!("DOWN:{}\n", size_bytes);
    if stream.write_all(header.as_bytes()).await.is_err() {
        return 0.0;
    }

    let mut buf = vec![0u8; 65536];
    let t0 = Instant::now();
    let mut received = 0;
    while received < size_bytes {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => received += n,
            Err(_) => break,
        }
    }
    let elapsed = t0.elapsed().as_secs_f64();

    if elapsed > 0.0 {
        (received as f64 * 8.0 / (1024.0 * 1024.0)) / elapsed
    } else {
        0.0
    }
}

// Concurrency test
async fn bench_concurrency(proxy_port: u16, clients: usize) -> (f64, f64) {
    let barrier = Arc::new(Barrier::new(clients));
    let mut handles = Vec::with_capacity(clients);

    let t0 = Instant::now();
    for _ in 0..clients {
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            if let Ok(mut stream) = socks5_connect(proxy_port, ECHO_HOST, ECHO_PORT).await {
                if stream.write_all(b"PING\n").await.is_ok() {
                    let mut resp = [0u8; 5];
                    if stream.read_exact(&mut resp).await.is_ok() && &resp == b"PONG\n" {
                        return true;
                    }
                }
            }
            false
        }));
    }

    let mut success_count = 0;
    for h in handles {
        if let Ok(true) = h.await {
            success_count += 1;
        }
    }
    let total_time = t0.elapsed().as_secs_f64();
    let qps = success_count as f64 / total_time;
    let rate = (success_count as f64 / clients as f64) * 100.0;

    (qps, rate)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", "=".repeat(85));
    println!("      Rust High-Precision Benchmark: Xray-core vs clash-rs (Windows)      ");
    println!("{}", "=".repeat(85));

    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let xray_go_bin = root_dir.join("xray-go.exe");
    let xray_rust_bin = root_dir.join("xray-rust").join("xray.exe");
    let clash_bin = root_dir.join("clash-rs-x86_64-pc-windows-msvc-static-crt (1).exe");

    let xray_cfg = root_dir.join("xray_bench.json");
    let clash_cfg = root_dir.join("clash_bench.yaml");

    fs::write(
        &xray_cfg,
        serde_json::json!({
            "log": {"loglevel": "error"},
            "inbounds": [{
                "port": XRAY_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": true}
            }],
            "outbounds": [{"protocol": "freedom"}]
        })
        .to_string(),
    )?;

    fs::write(
        &clash_cfg,
        format!(
            "port: 0\nsocks-port: {}\nmode: rule\nlog-level: error\nproxies:\n  - name: direct\n    type: direct\nrules:\n  - MATCH,direct\n",
            CLASH_PORT
        ),
    )?;

    start_echo_server().await?;
    println!("[*] High-speed Async Echo Server listening on {}:{}", ECHO_HOST, ECHO_PORT);

    let mut targets = Vec::new();
    if xray_go_bin.exists() {
        targets.push(("Xray-Go (原版)", xray_go_bin, vec!["run".to_string(), "-c".to_string(), xray_cfg.to_str().unwrap().to_string()], XRAY_PORT));
    }
    if xray_rust_bin.exists() {
        targets.push(("Xray-Rust (1:1版)", xray_rust_bin, vec!["-c".to_string(), xray_cfg.to_str().unwrap().to_string()], XRAY_PORT));
    }
    if clash_bin.exists() {
        targets.push(("Clash-rs (官方版)", clash_bin, vec!["-c".to_string(), clash_cfg.to_str().unwrap().to_string()], CLASH_PORT));
    }

    let mut results: BTreeMap<String, Scorecard> = BTreeMap::new();

    for (name, exe, args, port) in targets {
        println!("\n>>> Testing [{}] ...", name);
        let mut child = Command::new(&exe)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child.id();
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Readiness check
        let mut ready = false;
        for _ in 0..15 {
            if socks5_connect(port, ECHO_HOST, ECHO_PORT).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        if !ready {
            println!("[-] {} failed to start on port {}", name, port);
            let _ = child.kill();
            continue;
        }

        let idle_mem = get_process_memory_mb(pid);
        println!("    [1/5] Idle Memory (RSS)          : {:.2} MB", idle_mem);

        println!("    [2/5] Benchmarking Latency ({} rounds)...", PING_ROUNDS);
        let (lat_avg, lat_med, lat_p95, lat_min) = bench_latency(port).await;
        println!(
            "          Avg: {:.2} ms | Median: {:.2} ms | P95: {:.2} ms | Min: {:.2} ms",
            lat_avg, lat_med, lat_p95, lat_min
        );

        println!("    [3/5] Upload Throughput ({} MB)...", THROUGHPUT_BYTES / (1024 * 1024));
        let up_mbps = bench_upload(port, THROUGHPUT_BYTES).await;
        println!("          Speed: {:.2} Mbps ({:.2} MB/s)", up_mbps, up_mbps / 8.0);

        println!("    [4/5] Download Throughput ({} MB)...", THROUGHPUT_BYTES / (1024 * 1024));
        let down_mbps = bench_download(port, THROUGHPUT_BYTES).await;
        println!("          Speed: {:.2} Mbps ({:.2} MB/s)", down_mbps, down_mbps / 8.0);

        println!("    [5/5] Concurrency Stress ({} workers)...", CONCURRENT_CLIENTS);
        let (qps, succ_rate) = bench_concurrency(port, CONCURRENT_CLIENTS).await;
        println!("          QPS: {:.1} req/s | Success Rate: {:.1}%", qps, succ_rate);

        let active_mem = get_process_memory_mb(pid);
        println!("          Active Memory (Peak RSS)   : {:.2} MB", active_mem);

        results.insert(
            name.to_string(),
            Scorecard {
                idle_mb: idle_mem,
                active_mb: active_mem,
                lat_avg,
                lat_med,
                lat_p95,
                lat_min,
                up_mbps,
                down_mbps,
                qps,
                succ_rate,
            },
        );

        let _ = child.kill();
        let _ = child.wait();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = fs::remove_file(&xray_cfg);
    let _ = fs::remove_file(&clash_cfg);

    // Render Final Scorecard
    println!("\n{}", "=".repeat(95));
    println!("                           FINAL BENCHMARK SCORECARD                               ");
    println!("{}", "=".repeat(95));

    let cand_names: Vec<String> = results.keys().cloned().collect();
    let header_cols = cand_names
        .iter()
        .map(|n| format!("{:<18}", n))
        .collect::<Vec<_>>()
        .join(" | ");
    println!("{:<26} | {}", "Metric", header_cols);
    println!("{}", "-".repeat(28 + 21 * cand_names.len()));

    let metrics: Vec<(&str, Box<dyn Fn(&Scorecard) -> f64>, &str, &str)> = vec![
        ("Idle Memory (MB)", Box::new(|s| s.idle_mb), "{:.2} MB", "lower"),
        ("Active Memory (MB)", Box::new(|s| s.active_mb), "{:.2} MB", "lower"),
        ("Latency Avg (ms)", Box::new(|s| s.lat_avg), "{:.2} ms", "lower"),
        ("Latency P95 (ms)", Box::new(|s| s.lat_p95), "{:.2} ms", "lower"),
        ("Upload Speed (Mbps)", Box::new(|s| s.up_mbps), "{:.2} Mbps", "higher"),
        ("Download Speed (Mbps)", Box::new(|s| s.down_mbps), "{:.2} Mbps", "higher"),
        ("Concurrent QPS", Box::new(|s| s.qps), "{:.1} req/s", "higher"),
        ("Success Rate (%)", Box::new(|s| s.succ_rate), "{:.1}%", "higher"),
    ];

    for (label, getter, fmt, direction) in metrics {
        let vals: Vec<f64> = cand_names.iter().map(|n| getter(&results[n])).collect();
        let best_val = if direction == "lower" {
            vals.iter().cloned().filter(|&v| v > 0.0).fold(f64::INFINITY, f64::min)
        } else {
            vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
        };

        let row_cols: Vec<String> = vals
            .iter()
            .map(|&v| {
                let s = if fmt.ends_with("MB") {
                    format!("{:.2} MB", v)
                } else if fmt.ends_with("ms") {
                    format!("{:.2} ms", v)
                } else if fmt.ends_with("Mbps") {
                    format!("{:.2} Mbps", v)
                } else if fmt.ends_with("req/s") {
                    format!("{:.1} req/s", v)
                } else {
                    format!("{:.1}%", v)
                };
                if (v - best_val).abs() < 0.001 && vals.len() > 1 && v > 0.0 {
                    format!("{:<18}", format!("{} ★", s))
                } else {
                    format!("{:<18}", s)
                }
            })
            .collect();

        println!("{:<26} | {}", label, row_cols.join(" | "));
    }
    println!("{}", "=".repeat(95));

    let json_output = serde_json::to_string_pretty(&results)?;
    fs::write(root_dir.join("benchmark_results.json"), json_output)?;
    println!("[+] Detailed report saved to benchmark_results.json");

    Ok(())
}
