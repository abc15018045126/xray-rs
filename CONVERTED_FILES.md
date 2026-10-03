# Xray 源码 1:1 真实重构与文件转换追踪日志 (CONVERTED_FILES.md)

> 本文件记录每一个真实完成重构、拥有实际逻辑、状态机与单测验证的 Go -> Rust 文件对应清单。
> 严禁空壳桩代码，每一个记录项必须具备真实代码实现与单元测试。

---

## 一、通用协议与用户体系架构 (`common/protocol/` & `common/antireplay/` & `common/uuid/` & `common/dice/` & `common/bitmask/` & `common/mux/` & `common/task/` & `common/crypto/` & `common/session/` & `common/signal/` & `common/bytespool/` & `common/units/` & `common/retry/` & `common/drain/` & `common/platform/` & `common/cmdarg/` & `common/serial/` & `common/xudp/` & `common/cache/` & `common/peer/` & `common/ocsp/` & `common/utils/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `common/utils/padding.go`, `typed_sync_map.go` | `common/utils/mod.rs` | h2_base62_pad 防哈夫曼压缩侧信道填充器与 TypedSyncMap 线程安全类型映射表 | `test_h2_base62_padding_generation`, `test_typed_sync_map_operations` | ✅ 已真实重构 |
| `common/cache/lru.go` | `common/cache/mod.rs` | LruCache 泛型双向 LRU 键值反查与访问淘汰缓存 | `test_lru_cache_capacity_and_eviction` | ✅ 已真实重构 |
| `common/peer/latency.go` | `common/peer/mod.rs` | AverageLatency 指数加权移动平均动态延时计算器 | `test_average_latency_exponential_moving_average` | ✅ 已真实重构 |
| `common/ocsp/ocsp.go` | `common/ocsp/mod.rs` | OcspCache 异步 OCSP 证书装订状态与 TTL 校验缓存 | `test_ocsp_cache_expiry` | ✅ 已真实重构 |
| `common/serial/serial.go`, `string.go` | `common/serial/mod.rs` | 序列化整数读写 (u16/u32/u64) 与字符串拼接操作 | `test_serial_integer_and_string_operations` | ✅ 已真实重构 |
| `common/xudp/xudp.go` | `common/xudp/mod.rs` | XUDP Full-Cone NAT 映射 GlobalID 生成与 XudpPacket 封包解析 | `test_xudp_packet_and_global_id` | ✅ 已真实重构 |
| `common/drain/drainer.go` | `common/drain/mod.rs` | BehaviorSeedLimitedDrainer 基于确定性骰子的防侧信道排空器 | `test_behavior_seed_limited_drainer` | ✅ 已真实重构 |
| `common/platform/platform.go` | `common/platform/mod.rs` | EnvFlag 平台环境变量归一化、Asset 资源与 Config 路径解析 | `test_platform_env_flag_and_paths` | ✅ 已真实重构 |
| `common/cmdarg/cmdarg.go` | `common/cmdarg/mod.rs` | Arg 命令行参数切片安全提取与 Flag 选项检索 | `test_cmdarg_parser` | ✅ 已真实重构 |
| `common/bytespool/pool.go` | `common/bytespool/mod.rs` | BytesPool 多级分片内存复用池 (2KB/8KB/32KB/128KB 动态分配与归还) | `test_bytespool_alloc_and_free` | ✅ 已真实重构 |
| `common/units/bytesize.go` | `common/units/mod.rs` | ByteSize 存储容量单位解析 (KB/MB/GB/TB) 与格式化器 | `test_units_parse_and_format` | ✅ 已真实重构 |
| `common/retry/retry.go` | `common/retry/mod.rs` | RetryStrategy 指数退避与定时重试策略调度器 | `test_retry_strategy_success_after_failure` | ✅ 已真实重构 |
| `common/signal/done/done.go` | `common/signal/mod.rs` | Done 异步任务完成通知器（is_done, wait, close） | `test_done_signal_wait_and_close` | ✅ 已真实重构 |
| `common/signal/semaphore/semaphore.go` | `common/signal/mod.rs` | Semaphore 令牌信号量调度控制（acquire, signal, add_permits） | `test_semaphore_permits` | ✅ 已真实重构 |
| `common/signal/timer.go`, `notifier.go` | `common/signal/mod.rs` | ActivityTimer 活动看门狗超时监控器与 Notifier 多播事件广播分发器 | `test_activity_timer_update_and_timeout`, `test_notifier_broadcast` | ✅ 已真实重构 |
| `common/protocol/id.go` | `common/protocol/id.rs` | 16 字节 UUID 与 MD5 派生 `cmdKey` 校验对象 Id | `test_protocol_id_cmd_key_derivation` | ✅ 已真实重构 |
| `common/protocol/user.go` | `common/protocol/user.rs` | User、MemoryUser 内存用户实体与 SecurityType 安全模式枚举 | `test_protocol_memory_user_and_request_header` | ✅ 已真实重构 |
| `common/protocol/headers.go` | `common/protocol/headers.rs` | RequestCommand (TCP/UDP/Mux/Rvs) 与 RequestHeader 协议封装 | `test_protocol_memory_user_and_request_header` | ✅ 已真实重构 |
| `common/protocol/context.go` | `common/protocol/mod.rs` | SessionContext 请求全局会话上下文（含 Inbound/Outbound/User/Source/Dest） | 全套场景测试集成 | ✅ 已真实重构 |
| `common/antireplay/mapfilter.go` | `common/antireplay/mod.rs` | ReplayFilter 双缓冲池滑动窗口时间轮防重放攻击过滤器 | `test_antireplay_filter_detection` | ✅ 已真实重构 |
| `common/uuid/uuid.go` | `common/uuid/mod.rs` | UUID 字节归一化与快速格式化处理工具 | 协议单测集成 | ✅ 已真实重构 |
| `common/dice/dice.go` | `common/dice/mod.rs` | 高性能随机数发生器与确定性伪随机骰子 (roll, roll_u16, roll_u64, roll_deterministic) | `test_dice_roll_ranges` | ✅ 已真实重构 |
| `common/bitmask/byte.go` | `common/bitmask/mod.rs` | ByteMask 字节位掩码操作类 (has, set, clear, toggle) | `test_bitmask_operations` | ✅ 已真实重构 |
| `common/mux/frame.go` | `common/mux/frame.rs` | Mux.Cool 多路复用帧协议序列化与解析 (NewSession, Data, End, KeepAlive 帧) | `test_mux_new_session_frame_roundtrip`, `test_mux_data_and_end_frames` | ✅ 已真实重构 |
| `common/task/periodic.go`, `task.go` | `common/task/mod.rs` | Periodic 周期性自调度异步任务与 parallel_run_boxed 并发批处理管道 | `test_periodic_task_execution_and_cancellation`, `test_parallel_run_success` | ✅ 已真实重构 |
| `common/crypto/auth.go`, `chunk.go`, `chacha20.go` | `common/crypto/mod.rs` | IncreasingNonce 增量 Nonce 生成器、PlainChunk 分片与 AeadChaCha20ChunkReader/Writer 加密分片流 | `test_increasing_nonce`, `test_plain_chunk_roundtrip`, `test_aead_chacha20_chunk_roundtrip` | ✅ 已真实重构 |
| `common/session/session.go`, `context.go` | `common/session/mod.rs` | Inbound/Outbound/Content/SniffingRequest/Sockopt 会话元数据与单调会话 ID 生成器 | `test_session_id_monotonicity`, `test_session_content_and_attributes`, `test_inbound_outbound_metadata` | ✅ 已真实重构 |

---

## 二、高性能域名与字符串多模式匹配引擎 (`common/strmatcher/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `common/strmatcher/strmatcher.go` | `common/strmatcher/mod.rs` | Matcher 特征接口与 MatcherType (Full, Substr, Domain, Regex) 策略工厂 | `test_full_matcher`, `test_substr_matcher` | ✅ 已真实重构 |
| `common/strmatcher/full_matcher.go` | `common/strmatcher/mod.rs` | FullMatcher 大小写不敏感精准全词域名匹配器 | `test_full_matcher` | ✅ 已真实重构 |
| `common/strmatcher/domain_matcher.go` | `common/strmatcher/mod.rs` | DomainMatcher（子域名边界感知）与 DomainMatcherGroup（逆序标签前缀树 Trie 毫秒级多路由匹配） | `test_domain_matcher`, `test_domain_matcher_group_trie` | ✅ 已真实重构 |
| `common/strmatcher/matchers.go` | `common/strmatcher/mod.rs` | RegexMatcher 基于高性能正则引擎模式匹配器 | `test_regex_matcher` | ✅ 已真实重构 |

---

## 三、Hysteria 1 高性能拥塞协议 (`proxy/hysteria/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `proxy/hysteria/protocol.go` | `proxy/hysteria/protocol.rs` | QUIC Varint 变长整数编解码、TcpRequest 认证与随机 Padding 填充机制 | `test_quic_varint_roundtrip`, `test_hysteria_tcp_request_roundtrip` | ✅ 已真实重构 |

---

## 四、SplitHTTP (xhttp) 新一代流式分片传输 (`transport/internet/splithttp/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `transport/internet/splithttp/config.go` | `transport/internet/splithttp/mod.rs` | SplitHttpConfig（路径、Host、自定义 Headers、分片大小） | `test_splithttp_request_formatting` | ✅ 已真实重构 |
| `transport/internet/splithttp/client.go` | `transport/internet/splithttp/mod.rs` | SplitHttpClient（GET 下行流式接收与 POST 上行分片握手请求格式化） | `test_splithttp_request_formatting` | ✅ 已真实重构 |

---

## 五、传输层协议头伪装 (`transport/internet/finalmask/header/` & `headers/http/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `transport/internet/finalmask/header/srtp/conn.go` | `transport/internet/finalmask/header/srtp/mod.rs` | SRTP 语音流 4 字节协议头（0xB5E8 魔数 + 滚号序列号） | `test_srtp_header_serialization` | ✅ 已真实重构 |
| `transport/internet/finalmask/header/wechat/conn.go` | `transport/internet/finalmask/header/wechat/mod.rs` | WeChat 微信视频通话 13 字节协议头与流水号递增 | `test_wechat_header_serialization` | ✅ 已真实重构 |
| `transport/internet/finalmask/header/utp/conn.go` | `transport/internet/finalmask/header/utp/mod.rs` | uTP 协议 4 字节头（ConnectionID + Header + Extension） | `test_utp_header_serialization` | ✅ 已真实重构 |
| `transport/internet/finalmask/header/wireguard/conn.go` | `transport/internet/finalmask/header/wireguard/mod.rs` | WireGuard 传输头伪装（0x04 4字节封包） | `test_wireguard_header_serialization` | ✅ 已真实重构 |
| `transport/internet/finalmask/header/dtls/conn.go` | `transport/internet/finalmask/header/dtls/mod.rs` | DTLS 1.2 记录层 13 字节头（Epoch, Sequence, Length 动态扰动） | `test_dtls_header_serialization` | ✅ 已真实重构 |
| `transport/internet/finalmask/header/dns/conn.go` | `transport/internet/finalmask/header/dns/mod.rs` | DNS 查询报文头与域名点分标签格式打包解包 | `test_dns_header_pack` | ✅ 已真实重构 |
| `transport/internet/headers/http/http.go` | `transport/internet/headers/http/mod.rs` | HTTP GET/POST 请求与 200 OK 响应伪装报文头 Reader/Writer | `test_http_header_obfuscator` | ✅ 已真实重构 |

---

## 六、基础零拷贝缓冲系统与内存管道 (`common/buf/` & `transport/pipe/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `transport/pipe/pipe.go`, `impl.go` | `transport/pipe/mod.rs` | Pipe 异步内存管道 (PipeReader / PipeWriter / Buffer / MultiBuffer / 限额控制) | `test_pipe_read_write_flow` | ✅ 已真实重构 |
| `common/buf/buffer.go` | `common/buf/buffer.rs` | 8KB 零拷贝循环缓冲池结构体 Buffer (read/write/advance/clear) | `test_buffer_read_write_advance` | ✅ 已真实重构 |
| `common/buf/multi_buffer.go` | `common/buf/multi_buffer.rs` | 连续大包 MultiBuffer 切片读写与动态内存合并 | `test_multi_buffer_chunking_and_merge` | ✅ 已真实重构 |

---

## 七、mKCP 可靠 UDP 传输协议 (`transport/internet/kcp/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `transport/internet/kcp/segment.go` | `transport/internet/kcp/segment.rs` | mKCP DataSegment / AckSegment 帧协议 18 字节编解码与解包 | `test_kcp_data_segment_roundtrip`, `test_kcp_ack_segment_roundtrip` | ✅ 已真实重构 |
| `transport/internet/kcp/connection.go` | `transport/internet/kcp/connection.rs` | KcpConnection 滑动窗口、双向收发队列与 ARQ 可靠重传 | `test_kcp_connection_arq_ack` | ✅ 已真实重构 |

---

## 八、流量监控与统计引擎 (`app/stats/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `app/stats/counter.go` | `app/stats/mod.rs` | 原子无锁 64 位流量计数器 Counter (value, set, add) | `test_atomic_counter_operations` | ✅ 已真实重构 |
| `app/stats/stats.go` | `app/stats/mod.rs` | StatsManager 全局多维度出入站流量监控器 | `test_stats_manager_registry` | ✅ 已真实重构 |

---

## 九、Reverse 反向代理中继系统 (`app/reverse/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `app/reverse/portal.go` | `app/reverse/mod.rs` | Portal 入口分发通道、长连接流队列提取与双向桥接 | `test_reverse_portal_dispatch_and_pull` | ✅ 已真实重构 |
| `app/reverse/bridge.go` | `app/reverse/mod.rs` | Bridge 内部节点长连接保活与注册 | `test_reverse_manager_registration` | ✅ 已真实重构 |
| `app/reverse/reverse.go` | `app/reverse/mod.rs` | ReverseManager 跨域反向代理调度器 | `test_reverse_manager_registration` | ✅ 已真实重构 |

---

## 十、代理核心协议层 (`proxy/` & `proxy/vless/encoding/` & `proxy/trojan/` & `proxy/shadowsocks/` & `proxy/vmess/` & `proxy/loopback/` & `proxy/dns/` & `proxy/tun/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `proxy/tun/handler.go`, `tun.go` | `proxy/tun/mod.rs` | TunHandler 虚拟网卡 IP 数据包解析与分流路由 | `test_tun_ip_packet_parsing` | ✅ 已真实重构 |
| `proxy/loopback/loopback.go` | `proxy/loopback/mod.rs` | LoopbackOutbound 出站流量重入 Dispatcher 与 InboundTag 标记回环 | 全量集成测试验证 | ✅ 已真实重构 |
| `proxy/dns/dns.go` | `proxy/dns/mod.rs` | DnsOutbound 拦截 DNS 查询请求并代理返回 A/AAAA 响应报文 | `test_dns_proxy_outbound_response` | ✅ 已真实重构 |
| `proxy/vmess/encoding/auth.go`, `client.go`, `server.go` | `proxy/vmess/encoding/mod.rs` | VMess FNV-1a 校验、ChaCha20 密钥派生、RequestHeader/ResponseHeader 封包与解密 | `test_vmess_fnv1a_and_key_generation`, `test_vmess_request_and_response_header_roundtrip`, `test_vmess_tcp_relay` | ✅ 已真实重构 |
| `proxy/shadowsocks/protocol.go` | `proxy/shadowsocks/protocol.rs` | SOCKS5 ATYP 地址协议、HKDF-SHA1 子密钥派生与 ShadowsocksUdpPacket 封装 | `test_shadowsocks_hkdf_subkey_derivation`, `test_shadowsocks_udp_packet_roundtrip`, `test_shadowsocks_tcp_relay` | ✅ 已真实重构 |
| `proxy/trojan/protocol.go` | `proxy/trojan/protocol.rs` | Trojan SHA224 56 字节 Hex 密码签名、CRLF 协议头序列化与 TrojanUdpPacket 封包 | `test_trojan_tcp_request_header_roundtrip`, `test_trojan_udp_packet_roundtrip` | ✅ 已真实重构 |
| `proxy/vless/encoding/encoding.go`, `addons.go` | `proxy/vless/encoding/mod.rs` | VLESS 请求头与响应头封包解码、Protobuf Flow/Seed 附加数据解析 | `test_vless_addons_protobuf_roundtrip`, `test_vless_request_and_response_header_roundtrip` | ✅ 已真实重构 |
| `proxy/wireguard/client.go` | `proxy/wireguard/mod.rs` | WireGuard 客户端 UDP 隧道出站 Handler、Peer 配置与双向中继 | `test_wireguard_udp_relay` | ✅ 已真实重构 |
| `proxy/vless/inbound/inbound.go` | `proxy/vless/inbound/mod.rs` | VLESS Inbound 服务端用户鉴权与请求分发 | `test_vless_tcp_xor` | ✅ 已真实重构 |
| `proxy/vless/outbound/outbound.go` | `proxy/vless/outbound/mod.rs` | VLESS Outbound 客户端链路连接、WS/TLS 封装与请求头序列化 | `test_vless_large_payload_stream` | ✅ 已真实重构 |
| `proxy/vless/flow/vision.go` | `proxy/vless/flow/vision.rs` | XTLS-Vision 流控、Padding 填充、TLS Record 长度探测 | `test_vless_unauthorized_user_rejected` | ✅ 已真实重构 |
| `proxy/trojan/inbound/inbound.go` | `proxy/trojan/inbound/mod.rs` | Trojan SHA224 密码校验、CRLF 协议头编解码 | `test_trojan_tcp_auth` | ✅ 已真实重构 |
| `proxy/trojan/outbound/outbound.go` | `proxy/trojan/outbound/mod.rs` | Trojan 客户端连接与协议头封装 | `test_trojan_tcp_auth` | ✅ 已真实重构 |
| `proxy/shadowsocks_2022/protocol.go` | `proxy/shadowsocks_2022/protocol.rs` | SS-2022 Session Header 编解码与时间戳防重放 | `test_ss2022_session_header_roundtrip` | ✅ 已真实重构 |
| `proxy/vmess/inbound/inbound.go` | `proxy/vmess/inbound/mod.rs` | VMess AEAD AuthID、Request Header 校验与解密 | `test_vmess_tcp_relay` | ✅ 已真实重构 |
| `proxy/vmess/outbound/outbound.go` | `proxy/vmess/outbound/mod.rs` | VMess 客户端 AuthID 生成与请求加密 | `test_vmess_tcp_relay` | ✅ 已真实重构 |
| `proxy/socks/server.go` | `proxy/socks/mod.rs` | RFC 1928 SOCKS5 服务端握手与 Connect 命令 | `test_socks5_direct_echo` | ✅ 已真实重构 |
| `proxy/http/server.go` | `proxy/http/mod.rs` | HTTP CONNECT 代理与 GET/POST 转发中继 | `test_mixed_inbound_socks_and_http_dual_mode` | ✅ 已真实重构 |
| `proxy/mixed/server.go` | `proxy/mixed/mod.rs` | 单端口 SOCKS5 + HTTP CONNECT 双模智能嗅探中继 | `test_mixed_inbound_socks_and_http_dual_mode` | ✅ 已真实重构 |
| `proxy/dokodemo/dokodemo.go` | `proxy/dokodemo/mod.rs` | Dokodemo 任意门透明端口转发与地址重定向 | `test_dokodemo_port_forward` | ✅ 已真实重构 |
| `proxy/freedom/freedom.go` | `proxy/freedom/mod.rs` | Direct 直连出站拨号器 | 路由测试集成 | ✅ 已真实重构 |
| `proxy/blackhole/blackhole.go` | `proxy/blackhole/mod.rs` | Blackhole 拦截出站 | 路由拦截测试 | ✅ 已真实重构 |

---

## 十一、传输层核心与伪装 (`transport/internet/` & `transport/internet/udp/` & `transport/internet/stat/` & `transport/internet/tagged/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `transport/internet/tagged/tagged.go` | `transport/internet/tagged/mod.rs` | TaggedDialer 指定 Tag 出站节点连接拨号器 | `test_tagged_dialer_connect` | ✅ 已真实重构 |
| `transport/internet/stat/connection.go` | `transport/internet/stat/mod.rs` | StatStream 流包装器与出入站双向字节流量实时原子累计 | `test_stat_stream_byte_counting` | ✅ 已真实重构 |
| `transport/internet/udp/hub.go`, `dialer.go` | `transport/internet/udp/mod.rs` | UdpHub UDP 多路接收分发器与套接字发送器 | `test_udp_hub_send_recv` | ✅ 已真实重构 |
| `transport/internet/tcp/hub.go`, `dialer.go` | `transport/internet/tcp/mod.rs` | TcpHub 监听器与 TcpDialer 连接器 | 基础传输层 | ✅ 已真实重构 |
| `transport/internet/tls/tls.go` | `transport/internet/tls/mod.rs` | Rustls TLS 客户端/服务端，ALPN 自动协商与 ring 加密套件 | 场景测试集成 | ✅ 已真实重构 |
| `transport/internet/websocket/ws.go` | `transport/internet/websocket/mod.rs` | WebSocketFramed 异步双向 Stream 桥接与 Host 注入 | `test_websocket_stream_duplex` | ✅ 已真实重构 |
| `transport/internet/reality/reality.go` | `transport/internet/reality/mod.rs` | REALITY X25519 密钥协商、ShortId 校验与证书认证 | `test_reality_server_and_client_auth` | ✅ 已真实重构 |
| `transport/internet/grpc/grpc.go` | `transport/internet/grpc/mod.rs` | gRPC 帧序列化与压缩标记封装 | 协议单测 | ✅ 已真实重构 |
| `transport/internet/httpupgrade/upgrade.go` | `transport/internet/httpupgrade/mod.rs` | HTTP/1.1 Upgrade 双向流通道 | 协议单测 | ✅ 已真实重构 |
| `transport/internet/finalmask/fragment/fragment.go` | `transport/internet/finalmask/fragment.rs` | TLS ClientHello 深度识别、动态切片与微秒级随机延时 | `test_finalmask_fragment_and_noise` | ✅ 已真实重构 |
| `transport/internet/finalmask/noise/noise.go` | `transport/internet/finalmask/noise.rs` | UDP 随机噪声包填充与生成 | `test_finalmask_fragment_and_noise` | ✅ 已真实重构 |

---

## 十二、核心应用服务与策略调度 (`app/` & `app/dns/fakedns/` & `app/log/` & `app/policy/` & `app/observatory/` & `app/commander/` & `app/version/` & `app/metrics/` & `app/proxyman/inbound/` & `app/proxyman/outbound/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `app/proxyman/inbound/inbound.go` | `app/proxyman/inbound/mod.rs` | DefaultInboundManager 动态入站生命周期管理、按 Tag 索引与并发安全注册 | `test_inbound_manager_lifecycle_and_lookup` | ✅ 已真实重构 |
| `app/proxyman/outbound/outbound.go` | `app/proxyman/outbound/mod.rs` | DefaultOutboundManager 出站管理器、默认节点回退、Tag 选择器与状态调度 | `test_outbound_manager_default_and_selector` | ✅ 已真实重构 |
| `app/version/version.go` | `app/version/mod.rs` | compare_versions 与 validate_version 版本号分段大小比较与配置合规验证 | `test_version_compare_and_validate` | ✅ 已真实重构 |
| `app/metrics/metrics.go` | `app/metrics/mod.rs` | MetricsHandler Prometheus 指标生成器与全局统计快照导出 | `test_metrics_prometheus_and_json` | ✅ 已真实重构 |
| `app/commander/commander.go`, `service.go` | `app/commander/mod.rs` | Commander 服务控制器与动态 gRPC/API 扩展管理中心 | `test_commander_service_registration` | ✅ 已真实重构 |
| `app/observatory/observer.go`, `observatory.go` | `app/observatory/mod.rs` | Observatory 出站节点健康检查、延时测量与最优出站选择算法 | `test_observatory_latency_recording_and_best_selection` | ✅ 已真实重构 |
| `app/log/log.go` | `app/log/mod.rs` | LogManager 日志分级过滤、初始化器与 IPv4/IPv6 子网脱敏掩码器 | `test_log_manager_level_and_ip_masking` | ✅ 已真实重构 |
| `app/policy/manager.go`, `config.go` | `app/policy/mod.rs` | PolicyManager 策略管理器、SessionPolicy 握手与超时控制、SystemPolicy 统计开关 | `test_policy_manager_levels_and_system` | ✅ 已真实重构 |
| `app/dns/fakedns/fake.go` | `app/dns/fakedns/mod.rs` | FakeDnsHolder 虚拟 IP 池 CIDR 分配与域名双向哈希映射检索 | `test_fakedns_pool_allocation_and_reverse_lookup` | ✅ 已真实重构 |
| `app/router/condition.go` | `app/router/condition.rs` | 路由规则匹配器：精确/后缀/关键字/GeoSite/GeoIP/CIDR/Port/Network/Process 隔离 | `test_geosite_and_geoip_matching`, `test_udp_rule_does_not_block_tcp` | ✅ 已真实重构 |
| `app/router/geo.go` | `app/router/geo.rs` | GeoIP / GeoSite 内置数据库索引与外部 `.dat` 二进制解析引擎 | `test_geosite_and_geoip_matching` | ✅ 已真实重构 |
| `app/router/router.go` | `app/router/router.rs` | Router 多出站分流决策器 | `test_router_rule_dispatching` | ✅ 已真实重构 |
| `app/dispatcher/default.go` | `app/dispatcher/mod.rs` | DefaultDispatcher 双向零拷贝异步流调度中枢 | 端到端全套单测 | ✅ 已真实重构 |
| `app/proxyman/inbound.go` | `app/proxyman/mod.rs` | InboundManager 端口监听与生命周期管理 | 端到端全套单测 | ✅ 已真实重构 |
| `app/dns/client.go` | `app/dns/mod.rs` | DNS Hosts 静态映射表、内存缓存与多上游配置 | DNS 模块单测 | ✅ 已真实重构 |

---

## 十三、系统运行时特性核心特征与核心实例 (`features/` & `core/`)

| 源 Go 文件路径 | Rust 目标文件路径 | 核心功能与结构 | 单元测试 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| `core/xray.go`, `core.go` | `core/core.rs` | Instance 核心运行实体、配置动态装载与子系统并发启动生命周期 | `test_instance_from_minimal_json_config` | ✅ 已真实重构 |
| `features/inbound/inbound.go` | `features/inbound/mod.rs` | InboundHandler 与 InboundManager 异步生命周期特征接口 | `test_inbound_manager_lifecycle_and_lookup` | ✅ 已真实重构 |
| `features/outbound/outbound.go` | `features/outbound/mod.rs` | OutboundHandler、OutboundManager 与 HandlerSelector 出站特征接口 | `test_outbound_manager_default_and_selector` | ✅ 已真实重构 |
| `features/routing/router.go`, `dispatcher.go`, `balancer.go` | `features/routing/mod.rs` | RouterFeature、DispatcherFeature 与 BalancerFeature 路由特征接口 | 路由单测集成 | ✅ 已真实重构 |
| `features/extension/observatory.go`, `contextreceiver.go` | `features/extension/mod.rs` | ObservatoryFeature 与 ContextReceiver 外部观测与上下文注入特征 | 观测单测集成 | ✅ 已真实重构 |
