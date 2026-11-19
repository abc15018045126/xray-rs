# `debug_panel/` — xray-rs Debug-Only Dioxus 监控面板 & 极简 AI 接口

> **仅在 Debug 模式生效 (`#[cfg(debug_assertions)]`)**。
> 使用 `cargo build --release` 编译发布版时，整个 `debug_panel` 模块及其所有埋点都会被完全裁剪，零体积、零开销。

## 功能一览

1. **按网站统计连接与复用**
   - 每个目标网站 (`host`) 的**新建连接数**、**复用连接数**、**复用率 (%)**、**当前活跃连接**、**建连耗时 (avg / min / max ms)**、**上下行流量**。
2. **实时进程资源占用**
   - 采集当前 `xray-rs` 进程的 **CPU %** 和 **内存 (RSS / Private / Peak MB)** 及 60 秒历史。
3. **直接过内核不代理 (Direct Kernel Bypass) & 正常流量特征**
   - **实时直连开关**：一键点击「开启直连内核 (不代理)」，让 `DefaultDispatcher` 跳过代理出站，直接经由 OS 内核 TCP 直连，同时抓取正常流量特征（TLS 版本、SNI、ALPN、Cipher 数量、Extension 数量、ClientHello 长度、HTTP 方法与 Host）。支持全局或指定域名白名单。
   - **一键直连探测**：输入任意网站，直接走内核 TCP + TLS + HTTP HEAD，测试 DNS/TCP/TLS/首包耗时与 Keep-Alive 复用耗时对比。
4. **Dioxus 桌面面板 (`debug_panel/dioxus_app/`)**
   - 基于 Dioxus 0.6 Desktop 构建的实时可视化调试面板。
5. **极简 AI 接口 (`http://127.0.0.1:19876/ai/...`)**
   - 无需鉴权、支持单条 `GET` 或 `POST` 调用，提供低 token 的 `?format=text` 和结构化 JSON 输出。

---

## 启动方式

### 1. 以 Debug 模式运行 `xray-rs`
```powershell
cargo run -- -c config.json
```
启动后会自动监听 Debug API：`http://127.0.0.1:19876`（可通过环境变量 `XRAY_DEBUG_ADDR` 修改）。

### 2. 启动 Dioxus 桌面界面
```powershell
cargo run --manifest-path debug_panel/dioxus_app/Cargo.toml
```

---

## 极简 AI 接口速查

| 接口 | 说明 | 示例 |
|---|---|---|
| `GET /ai` | 查看所有接口说明 | `curl http://127.0.0.1:19876/ai` |
| `GET /ai/summary` | 一次性获取 CPU/内存/直连状态/全站汇总/探测结果 | `curl http://127.0.0.1:19876/ai/summary` |
| `GET /ai/summary?format=text` | **极简文本汇总（最省 AI Token）** | `curl "http://127.0.0.1:19876/ai/summary?format=text"` |
| `GET /ai/sites` | 各网站新建/复用/耗时/流量特征（支持 `?host=xxx`） | `curl "http://127.0.0.1:19876/ai/sites?host=cloudflare"` |
| `GET /ai/resources` | 进程 CPU %、内存 MB 及最近 60 秒历史 | `curl http://127.0.0.1:19876/ai/resources` |
| `GET/POST /ai/bypass` | 开启/关闭**直连内核不代理** | `curl "http://127.0.0.1:19876/ai/bypass?on=1"` 或 `?off=1` 或 `?on=1&domains=github.com` |
| `GET/POST /ai/probe` | **直连内核探测**网站正常流量特征 + 连接复用测试 | `curl "http://127.0.0.1:19876/ai/probe?target=www.cloudflare.com"` |
| `GET/POST /ai/capture` | **Wireshark 风格抓包开关** | `curl "http://127.0.0.1:19876/ai/capture?on=1"`（关闭用 `?off=1`） |
| `GET /ai/packets` | 查看抓到的包（L7 解析 + Hex/ASCII，支持 `?host=xxx&limit=50&format=text`） | `curl "http://127.0.0.1:19876/ai/packets?format=text"` |
| `GET /ai/capture.pcap` | **导出标准 `.pcap` 文件**（可直接用 Wireshark 打开） | `curl -o xray_capture.pcap http://127.0.0.1:19876/ai/capture.pcap` |
| `POST /ai/capture/clear` | 清空抓包缓冲 | `curl -X POST http://127.0.0.1:19876/ai/capture/clear` |
| `POST /ai/reset` | 清空统计数据 | `curl -X POST http://127.0.0.1:19876/ai/reset` |
