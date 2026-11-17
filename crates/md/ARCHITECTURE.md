# `xray-rs` 清晰高可维护架构设计（功能隔离 + 数据流驱动）

结合两套方案的优点：
1. **用 Cargo Workspace 做硬边界隔离**（改入站不重编协议/密码学，编译快、职责清），共 **6 个 Crate**（`xray-rs-types`、`xray-rs-proto`、`xray-rs-inbound`、`xray-rs-route`、`xray-rs-outbound`、`xray-rs-cli`），兼顾低样板代码与 `crates.io` 独立 SDK 发布能力；
2. **目录与依赖完全顺着“入站 → 路由 → 出站”单向数据流排布**，彻底去掉 Go 时代的 `features/`、`core/` 注册表和 `#[path = "../..."]` hack；
3. **底层全部优先用 Cloudflare Pingora / Tokio / Rust 官方及半官方库**，自研只保留路由规则与代理协议头。

---

## 一、单向依赖与数据流图

```text
                ┌─────────────────────────┐
                │      xray-rs-cli        │  (读取 v2rayN JSON 配置 + stats 统计 + 启动入口)
                └────┬───────┬───────┬────┘
                     │       │       │
          ┌──────────▼─┐   ┌─▼───────▼───┐   ┌──────────────────┐
          │xray-rs-    ├──▶│xray-rs-     ├──▶│xray-rs-          │
          │inbound     │   │route        │   │outbound          │
          └──────┬─────┘   └──────┬──────┘   └────────┬─────────┘
                 │                │                   │
                 │                │          ┌────────▼─────────┐
                 │                │          │  xray-rs-proto   │  (纯协议 SDK：VLESS/Trojan/Reality)
                 │                │          └────────┬─────────┘
                 │                │                   │
                 └────────────────┼───────────────────┘
                                  ▼
                         ┌─────────────────┐
                         │  xray-rs-types  │  (BoxStream, Session, Destination, Error)
                         └─────────────────┘
```

* **零循环依赖**：所有子 crate 只向下依赖 `xray-rs-types`（及 `xray-rs-proto`），最后由 `xray-rs-cli` 把三条线拼在一起。
* **唯一交接边界**：`Inbound` 吐出 `(BoxStream, SessionContext)` → `Route` 选出目标与出站并做 `relay` 双向转发 → `Outbound` 负责传输与协议握手连向远端。
* **SDK 独立发布**：外部项目只需要 `cargo add xray-rs-types xray-rs-proto` 即可复用纯协议编解码，无需拉入 Pingora、TUN 或 DNS 等重依赖。

---

## 二、完整文件夹与文件清单

```text
xray-rs/
├── Cargo.toml                          # [workspace] 统一锁定 [workspace.package] 与 [workspace.dependencies]
├── docs/                               # 架构文档与迁移记录（不放根目录）
├── tests/                              # 跨模块端到端集成测试（如 Gradle/HTTP/VLESS 实测）
└── crates/
    │
    ├── xray-rs-types/                  # 【1. 基础契约层】极轻量、秒编译、无重依赖
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── error.rs                # 统一 Error / Result（基于 thiserror）
    │       ├── net.rs                  # Address, Destination, Network, BoxStream (AsyncRead+AsyncWrite)
    │       ├── session.rs              # SessionContext（源地址、目标、嗅探结果、用户等级）
    │       └── traits.rs               # InboundHandler / OutboundHandler 两个核心 Trait
    │
    ├── xray-rs-proto/                  # 【2. 纯协议 SDK 层】只做字节流编解码与加密握手，可独立发 crates.io
    │   ├── Cargo.toml                  # 只依赖 xray-rs-types, tokio(io-util), bytes, 密码学 crate
    │   └── src/
    │       ├── lib.rs
    │       ├── vless/                  # VLESS 请求/响应头 + Vision 流控
    │       ├── reality/                # Reality 握手伪装
    │       ├── trojan.rs               # Trojan 协议头
    │       ├── shadowsocks.rs          # Shadowsocks AEAD
    │       └── vmess/                  # VMess（可选 feature）
    │
    ├── xray-rs-inbound/                # 【3. 入站层】只负责“把本地流量接进来”
    │   ├── Cargo.toml                  # 依赖：pingora-http, tokio, tun-rs, wintun-rs, ipstack
    │   └── src/
    │       ├── lib.rs
    │       ├── http.rs                 # PingoraHttpInbound（基于 pingora-http，处理 CONNECT/HTTP/去 Proxy-Connection）
    │       ├── socks.rs                # SOCKS5 入站握手
    │       ├── mixed.rs                # 首字节分流器（0x04/0x05 -> socks, 其余 -> http）
    │       └── tun/                    # Windows/Linux 虚拟网卡入站
    │           ├── mod.rs
    │           ├── runner.rs           # Wintun / tun-rs 生命周期与路由配置
    │           └── stack.rs            # TCP/UDP 包转成 BoxStream（ipstack / tun2proxy）
    │
    ├── xray-rs-route/                  # 【4. 中间层：路由 + 转发 + DNS + 均衡】
    │   ├── Cargo.toml                  # 依赖：tokio, pingora-timeout, pingora-load-balancing, hickory-resolver
    │   └── src/
    │       ├── lib.rs
    │       ├── dispatcher.rs           # 核心调度：嗅探 -> 路由匹配 -> 选出站 -> 调 relay
    │       ├── relay.rs                # 双向转发：tokio + pingora-timeout 空闲超时 + UnexpectedEof 优雅半关闭
    │       ├── sniffer.rs              # TLS ClientHello / HTTP Host / FakeDNS 域名嗅探
    │       ├── router.rs               # 路由规则引擎（Domain / IP / Port -> outbound_tag）
    │       ├── geo.rs                  # GeoIP / GeoSite 匹配与按需加载
    │       ├── balancer.rs             # 基于 pingora-load-balancing 的多节点轮询与故障切换（如 a1~a4）
    │       └── dns/
    │           ├── mod.rs
    │           ├── resolver.rs         # 基于 hickory-resolver（统一接管 UDP/TCP/DoH/DoQ/hosts/缓存）
    │           └── fakedns.rs          # FakeDNS IP 池映射
    │
    ├── xray-rs-outbound/               # 【5. 出站层：传输通道 + 协议组装】
    │   ├── Cargo.toml                  # 依赖：xray-rs-proto, tokio, socket2, tokio-rustls, tokio-tungstenite, pingora-pool
    │   └── src/
    │       ├── lib.rs
    │       ├── transport/              # 底层传输通道（可自由组合：TCP -> TLS/Reality -> WS）
    │       │   ├── mod.rs
    │       │   ├── tcp.rs              # TcpDialer + Windows/Linux socket2 保活与绑定网卡
    │       │   ├── tls.rs              # tokio-rustls + 浏览器指纹伪装（uTLS profile）
    │       │   ├── ws.rs               # tokio-tungstenite（含 Ping/Pong 刷出、半关闭保活）
    │       │   └── pool.rs             # 基于 pingora-pool 的连接复用池
    │       └── handlers/               # 组装 OutboundHandler（freedom, blackhole, vless, trojan, ss, vmess）
    │
    └── xray-rs-cli/                    # 【6. 组装与入口层】兼容 v2rayN 启动参数与配置
        ├── Cargo.toml                  # 依赖以上 crate + clap + serde_json + tracing
        └── src/
            ├── main.rs                 # 命令行入口（兼容 `xray.exe run -c config.json`）
            ├── app.rs                  # 组装 Inbound + Route + Outbound 并启动监听
            ├── stats.rs                # 流量计数器（供 v2rayN 面板显示上下行速率）
            └── config/                 # 解析 v2rayN 下发的 Xray JSON（serde）
                ├── mod.rs
                ├── inbound.rs
                ├── outbound.rs
                ├── routing.rs
                └── dns.rs
```

---

## 三、这套结构为什么清晰且好维护

1. **按“数据流”找文件，零心智负担**：
   * 浏览器/Gradle 连不上？直接看 `xray-inbound/src/http.rs`；
   * 下载中途断流/超时？直接看 `xray-route/src/relay.rs` 或 `xray-outbound/src/transport/ws.rs`；
   * 分流规则不对？直接看 `xray-route/src/router.rs`；
   * v2rayN 配置字段不认识？直接看 `xray-cli/src/config/`。
2. **Pingora / Tokio 官方库与自研边界分明**：
   * `xray-inbound`、`xray-route/relay.rs`、`xray-route/dns/`、`xray-outbound/transport/` 几乎全是 **Pingora + Tokio + Rustls + Hickory** 的胶水组装，代码极少；
   * 真正需要自己维护的只有 `xray-outbound/src/protocol/`（VLESS/Reality 等）和 `xray-route/src/router.rs`。
3. **编译隔离刚刚好**：
   * 5 个 crate 既不会像 8~10 个 crate 那样满屏配置，又能保证改 `xray-cli` 或 `xray-inbound` 时不触发 `xray-outbound`（密码学/TLS）重编。
4. **随时可按需裁剪**：
   * 不用的协议（例如 `kcp`、`reverse`、`splithttp`、`hysteria`）直接不迁入 `xray-outbound`，整个项目总行数可以从 **5.7 万行降到约 1 万行以内**。
