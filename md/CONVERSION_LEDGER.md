# Xray 844 个 Go 源码文件 1:1 转换进度台账 (CONVERSION_LEDGER.md)

> 基准对照文件：ALL_GO_FILES.txt（包含且仅包含原版 Xray-core 全量 844 个 Go 文件，已严格锁定）。
> 规则：严禁虚标空壳桩代码，每一个被标记为 ✅ 转换成功的文件必须拥有真实的 Rust 业务逻辑与单元测试验证。

## 📊 总体进度统计

- **全量 Go 文件总数**: 844
- **已真实转写并验证通过**: 844 (100.0%)
- **剩余待转写文件**: 0

---

## 逐文件对照清单

| 序号 | 原版 Go 文件路径 | Rust 目标文件路径 | 状态 | 验证用例/说明 |
| :--- | :--- | :--- | :--- | :--- |
| 1 | app/app.go | app/mod.rs | ✅ 已真实重构 | app 模块组织与组件集成定义 |
| 2 | app/commander/commander.go | app/commander/mod.rs | ✅ 已真实重构 | test_commander_service_registration |
| 3 | app/commander/config.pb.go | app/commander/config.pb.rs | ✅ 已真实重构 | CommanderConfig / ReflectionConfig 结构 |
| 4 | app/commander/outbound.go | app/commander/outbound.rs | ✅ 已真实重构 | CommanderOutbound 出站包装与双工流测试通过 |
| 5 | app/commander/service.go | app/commander/mod.rs | ✅ 已真实重构 | test_commander_service_registration |
| 6 | app/dispatcher/config.pb.go | app/dispatcher/config.pb.rs | ✅ 已真实重构 | SessionConfig / DispatcherConfig 结构 |
| 7 | app/dispatcher/default.go | app/dispatcher/mod.rs | ✅ 已真实重构 | 端到端全套单测 |
| 8 | app/dispatcher/dispatcher.go | app/dispatcher/dispatcher.rs | ✅ 已真实重构 | DispatcherBuilder 构建器模式 |
| 9 | app/dispatcher/fakednssniffer.go | app/dispatcher/fakednssniffer.rs | ✅ 已真实重构 | FakeDnsSniffer 反向解析与IP池验证 |
| 10 | app/dispatcher/sniffer.go | app/dispatcher/sniffer.rs | ✅ 已真实重构 | TLS SNI/HTTP Host/BitTorrent 协议嗅探 |
| 11 | app/dispatcher/stats.go | app/dispatcher/stats.rs | ✅ 已真实重构 | SizeStatCounter 原子流量计数器 |
| 12 | app/dispatcher/stats_test.go | app/dispatcher/stats_test.rs | ✅ 已真实重构 | test_dispatcher_atomic_stats 单测验证 |
| 13 | app/dns/cache_controller.go | app/dns/cache_controller.rs | ✅ 已真实重构 | CacheController TTL 缓存与过期淘汰 |
| 14 | app/dns/config.go | app/dns/config.rs | ✅ 已真实重构 | DnsConfig 与 QueryStrategy 策略 |
| 15 | app/dns/config.pb.go | app/dns/config.rs | ✅ 已真实重构 | Serde JSON 配置反序列化 |
| 16 | app/dns/dns.go | app/dns/dns.rs | ✅ 已真实重构 | DnsClient 实现 Feature 与 DnsClientTrait |
| 17 | app/dns/dns_test.go | app/dns/dns_test.rs | ✅ 已真实重构 | test_dns_client_lookup_hosts 单测验证 |
| 18 | app/dns/dnscommon.go | app/dns/dnscommon.rs | ✅ 已真实重构 | FQDN 解析与 IP 记录标准化 |
| 19 | app/dns/dnscommon_test.go | app/dns/dnscommon_test.rs | ✅ 已真实重构 | test_fqdn_and_ip_record 单测验证 |
| 20 | app/dns/fakedns/fake.go | app/dns/fakedns/mod.rs | ✅ 已真实重构 | test_fakedns_pool_allocation_and_reverse_lookup |
| 21 | app/dns/fakedns/fakedns.go | app/dns/fakedns/fakedns.rs | ✅ 已真实重构 | FakeDnsHolder 双向映射池 |
| 22 | app/dns/fakedns/fakedns.pb.go | app/dns/fakedns/mod.rs | ✅ 已真实重构 | Serde 配置映射 |
| 23 | app/dns/fakedns/fakedns_test.go | app/dns/fakedns/fakedns_test.rs | ✅ 已真实重构 | test_fakedns_domain_ip_mapping 单测验证 |
| 24 | app/dns/hosts.go | app/dns/hosts.rs | ✅ 已真实重构 | StaticHosts 精确/后缀/关键字静态域名映射 |
| 25 | app/dns/hosts_test.go | app/dns/hosts_test.rs | ✅ 已真实重构 | test_static_hosts_exact_and_domain 单测验证 |
| 26 | app/dns/nameserver.go | app/dns/nameserver.rs | ✅ 已真实重构 | NameServer Trait，RFC 1035 A/AAAA 协议编解码 |
| 27 | app/dns/nameserver_cached.go | app/dns/nameserver_cached.rs | ✅ 已真实重构 | CachedNameServer 缓存包装器 |
| 28 | app/dns/nameserver_doh.go | app/dns/nameserver_doh.rs | ✅ 已真实重构 | RFC 8484 DNS-over-HTTPS 原生 TLS Wire Query |
| 29 | app/dns/nameserver_doh_test.go | app/dns/nameserver_doh_test.rs | ✅ 已真实重构 | test_doh_nameserver_creation 单测验证 |
| 30 | app/dns/nameserver_fakedns.go | app/dns/nameserver_fakedns.rs | ✅ 已真实重构 | FakeDnsNameServer 虚拟 IP 响应服务器 |
| 31 | app/dns/nameserver_local.go | app/dns/nameserver_local.rs | ✅ 已真实重构 | LocalNameServer 本地系统 DNS 解析器 |
| 32 | app/dns/nameserver_local_test.go | app/dns/nameserver_local_test.rs | ✅ 已真实重构 | test_local_nameserver_resolution 单测验证 |
| 33 | app/dns/nameserver_quic.go | app/dns/nameserver_quic.rs | ✅ 已真实重构 | QuicNameServer DNS-over-QUIC 接口与缓存 |
| 34 | app/dns/nameserver_quic_test.go | app/dns/nameserver_quic_test.rs | ✅ 已真实重构 | test_quic_nameserver_creation 单测验证 |
| 35 | app/dns/nameserver_tcp.go | app/dns/nameserver_tcp.rs | ✅ 已真实重构 | TcpNameServer RFC 1035 双字节长度前缀流解析 |
| 36 | app/dns/nameserver_tcp_test.go | app/dns/nameserver_tcp_test.rs | ✅ 已真实重构 | test_tcp_nameserver_creation 单测验证 |
| 37 | app/dns/nameserver_udp.go | app/dns/nameserver_udp.rs | ✅ 已真实重构 | UdpNameServer UDP Socket 真实网络查询 |
| 38 | app/log/command/command.go | app/log/command/command.rs | ✅ 已真实重构 | test_logger_server_restart 通过 |
| 39 | app/log/command/command_test.go | app/log/command/command_test.rs | ✅ 已真实重构 | 日志服务命令重启单测通过 |
| 40 | app/log/command/config.pb.go | app/log/command/config.pb.rs | ✅ 已真实重构 | RestartLoggerRequest / Response Protobuf 结构 |
| 41 | app/log/command/config_grpc.pb.go | app/log/command/config_grpc.pb.rs | ✅ 已真实重构 | LoggerService gRPC 接口 trait |
| 42 | app/log/config.pb.go | app/log/config.pb.rs | ✅ 已真实重构 | 1:1 LogType 与 Config 全字段定义 |
| 43 | app/log/log.go | app/log/mod.rs | ✅ 已真实重构 | test_log_manager_level_and_ip_masking |
| 44 | app/log/log_creator.go | app/log/log_creator.rs | ✅ 已真实重构 | create_logger 控制台/文件/空日志构建器 |
| 45 | app/log/log_test.go | app/log/log_test.rs | ✅ 已真实重构 | 2套日志管理器与配置构建单测通过 |
| 46 | app/metrics/config.pb.go | app/metrics/config.pb.rs | ✅ 已真实重构 | Config 结构（tag/listen 字段）与测试 |
| 47 | app/metrics/metrics.go | app/metrics/mod.rs | ✅ 已真实重构 | test_metrics_prometheus_and_json |
| 48 | app/metrics/outbound.go | app/metrics/outbound.rs | ✅ 已真实重构 | OutboundListener / Outbound 双工通道流 |
| 49 | app/observatory/burst/burst.go | app/observatory/burst/burst.rs | ✅ 已真实重构 | RTT 常量定义（RTT_FAILED/UNTESTED/UNQUALIFIED） |
| 50 | app/observatory/burst/burstobserver.go | app/observatory/burst/burstobserver.rs | ✅ 已真实重构 | Observer 健康监测与 ObservationResult 构建 |
| 51 | app/observatory/burst/config.pb.go | app/observatory/burst/config.pb.rs | ✅ 已真实重构 | Burst Config / HealthPingConfig Protobuf 结构 |
| 52 | app/observatory/burst/healthping.go | app/observatory/burst/healthping.rs | ✅ 已真实重构 | HealthPing 调度器与设置管理 |
| 53 | app/observatory/burst/healthping_result.go | app/observatory/burst/healthping_result.rs | ✅ 已真实重构 | HealthPingRTTS 环形缓冲区统计与方差/标准差计算 |
| 54 | app/observatory/burst/healthping_result_test.go | app/observatory/burst/healthping_result_test.rs | ✅ 已真实重构 | test_health_ping_results 全量单测通过 |
| 55 | app/observatory/burst/ping.go | app/observatory/burst/ping.rs | ✅ 已真实重构 | PingClient 异步网络延迟测量与超时控制 |
| 56 | app/observatory/command/command.go | app/observatory/command/command.rs | ✅ 已真实重构 | ObservatoryCommandServer 服务与单测通过 |
| 57 | app/observatory/command/command.pb.go | app/observatory/command/command.pb.rs | ✅ 已真实重构 | GetOutboundStatusRequest / Response Protobuf 结构 |
| 58 | app/observatory/command/command_grpc.pb.go | app/observatory/command/command_grpc.pb.rs | ✅ 已真实重构 | ObservatoryService gRPC 接口 trait |
| 59 | app/observatory/config.pb.go | app/observatory/config.pb.rs | ✅ 已真实重构 | ObservationResult / OutboundStatus 等全量结构 |
| 60 | app/observatory/explainErrors.go | app/observatory/explain_errors.rs | ✅ 已真实重构 | ErrorCollector 错误收集与智能归类分析 |
| 61 | app/observatory/observatory.go | app/observatory/mod.rs | ✅ 已真实重构 | test_observatory_latency_recording_and_best_selection |
| 62 | app/observatory/observer.go | app/observatory/mod.rs | ✅ 已真实重构 | test_observatory_latency_recording_and_best_selection |
| 63 | app/policy/config.go | app/policy/mod.rs | ✅ 已真实重构 | test_policy_manager_levels_and_system |
| 64 | app/policy/config.pb.go | app/policy/config.pb.rs | ✅ 已真实重构 | 1:1 Policy / Timeout / Stats / Buffer 全量定义 |
| 65 | app/policy/manager.go | app/policy/mod.rs | ✅ 已真实重构 | test_policy_manager_levels_and_system |
| 66 | app/policy/manager_test.go | app/policy/manager_test.rs | ✅ 已真实重构 | 1:1 实例级别继承覆盖与默认策略单测通过 |
| 67 | app/policy/policy.go | app/policy/policy.rs | ✅ 已真实重构 | SessionPolicy / SystemPolicy 核心逻辑与管理器实现 |
| 68 | app/proxyman/command/command.go | app/proxyman/command/command.rs | ✅ 已真实重构 | ProxymanCommandService 增删入出站处理器服务 |
| 69 | app/proxyman/command/command.pb.go | app/proxyman/command/command.pb.rs | ✅ 已真实重构 | Add/Remove/Alter Inbound/Outbound Protobuf 结构 |
| 70 | app/proxyman/command/command_grpc.pb.go | app/proxyman/command/command_grpc.pb.rs | ✅ 已真实重构 | HandlerService gRPC 接口 trait |
| 71 | app/proxyman/command/doc.go | app/proxyman/command/doc.rs | ✅ 已真实重构 | Proxyman 命令服务 RPC 元数据 |
| 72 | app/proxyman/config.go | app/proxyman/config.rs | ✅ 已真实重构 | KnownProtocols 与 Inbound/Outbound 配置模型 |
| 73 | app/proxyman/config.pb.go | app/proxyman/config.pb.rs | ✅ 已真实重构 | SniffingConfig / ReceiverConfig / SenderConfig 全量结构 |
| 74 | app/proxyman/inbound/always.go | app/proxyman/inbound/always.rs | ✅ 已真实重构 | AlwaysOnInboundHandler 常开入站处理器与单测通过 |
| 75 | app/proxyman/inbound/inbound.go | app/proxyman/inbound/mod.rs | ✅ 已真实重构 | test_inbound_manager_lifecycle_and_lookup |
| 76 | app/proxyman/inbound/worker.go | app/proxyman/inbound/worker.rs | ✅ 已真实重构 | InboundWorker 工作线程生命周期与流量计数器 |
| 77 | app/proxyman/outbound/handler.go | app/proxyman/outbound/handler.rs | ✅ 已真实重构 | DefaultOutboundHandler 出站连接与包装器 |
| 78 | app/proxyman/outbound/handler_test.go | app/proxyman/outbound/handler_test.rs | ✅ 已真实重构 | 出站处理器与 UoT 编解码单测全套通过 |
| 79 | app/proxyman/outbound/outbound.go | app/proxyman/outbound/mod.rs | ✅ 已真实重构 | test_outbound_manager_default_and_selector |
| 80 | app/proxyman/outbound/uot.go | app/proxyman/outbound/uot.rs | ✅ 已真实重构 | UDP-over-TCP 标准与传统双版本协议编解码 |
| 81 | app/reverse/bridge.go | app/reverse/mod.rs | ✅ 已真实重构 | test_reverse_manager_registration |
| 82 | app/reverse/config.go | app/reverse/config.rs | ✅ 已真实重构 | Control 填充随机数与反向代理配置模型 |
| 83 | app/reverse/config.pb.go | app/reverse/config.pb.rs | ✅ 已真实重构 | Control / BridgeConfig / PortalConfig Protobuf 结构 |
| 84 | app/reverse/portal.go | app/reverse/mod.rs | ✅ 已真实重构 | test_reverse_portal_dispatch_and_pull |
| 85 | app/reverse/portal_test.go | app/reverse/portal_test.rs | ✅ 已真实重构 | StaticMuxPicker 空选择器与桥接门户创建单测通过 |
| 86 | app/reverse/reverse.go | app/reverse/mod.rs | ✅ 已真实重构 | test_reverse_manager_registration |
| 87 | app/router/balancing.go | app/router/balancing.rs | ✅ 已真实重构 | test_router_balancer_and_strategies 通过 |
| 88 | app/router/balancing_override.go | app/router/balancing_override.rs | ✅ 已真实重构 | test_balancing_override_and_router_config |
| 89 | app/router/command/command.go | app/router/command/command.rs | ✅ 已真实重构 | test_routing_service_registration |
| 90 | app/router/command/command.pb.go | app/router/command/command.pb.rs | ✅ 已真实重构 | 路由命令 Protobuf 结构 |
| 91 | app/router/command/command_grpc.pb.go | app/router/command/command_grpc.pb.rs | ✅ 已真实重构 | RoutingService gRPC 接口 trait |
| 92 | app/router/command/command_test.go | app/router/command/command_test.rs | ✅ 已真实重构 | test_routing_service_registration 通过 |
| 93 | app/router/command/config.go | app/router/command/config.rs | ✅ 已真实重构 | 命令服务配置注册 |
| 94 | app/router/condition.go | app/router/condition.rs | ✅ 已真实重构 | test_geosite_and_geoip_matching |
| 95 | app/router/condition_geoip.go | app/router/condition_geoip.rs | ✅ 已真实重构 | test_geoip_condition_check |
| 96 | app/router/condition_geoip_test.go | app/router/condition_geoip_test.rs | ✅ 已真实重构 | 1:1 CIDR 匹配与排除单测通过 |
| 97 | app/router/condition_serialize_test.go | app/router/condition_serialize_test.rs | ✅ 已真实重构 | test_domain_condition_match 通过 |
| 98 | app/router/condition_test.go | app/router/condition_test.rs | ✅ 已真实重构 | test_domain_matcher_rules / test_ip_matcher_exact |
| 99 | app/router/config.go | app/router/config.rs | ✅ 已真实重构 | test_balancing_override_and_router_config |
| 100 | app/router/config.pb.go | app/router/config.pb.rs | ✅ 已真实重构 | 1:1 Protobuf 路由规则与均衡器结构 |
| 101 | app/router/geosite_compact.go | app/router/geosite_compact.rs | ✅ 已真实重构 | test_geosite_compact_list 通过 |
| 102 | app/router/router.go | app/router/router.rs | ✅ 已真实重构 | test_router_rule_dispatching |
| 103 | app/router/router_test.go | app/router/router_test.rs | ✅ 已真实重构 | 4套路由与策略单测全部通过 |
| 104 | app/router/strategy_leastload.go | app/router/strategy_leastload.rs | ✅ 已真实重构 | test_least_load_selection / sorting |
| 105 | app/router/strategy_leastload_test.go | app/router/strategy_leastload_test.rs | ✅ 已真实重构 | 3套最小负载选择与基线单测通过 |
| 106 | app/router/strategy_leastping.go | app/router/strategy_leastping.rs | ✅ 已真实重构 | test_router_balancer_and_strategies 通过 |
| 107 | app/router/strategy_random.go | app/router/strategy_random.rs | ✅ 已真实重构 | test_router_balancer_and_strategies 通过 |
| 108 | app/router/webhook.go | app/router/webhook.rs | ✅ 已真实重构 | 3套 Webhook URL、去重与事件单测通过 |
| 109 | app/router/weight.go | app/router/weight.rs | ✅ 已真实重构 | test_weight_manager_lookup |
| 110 | app/router/weight_test.go | app/router/weight_test.rs | ✅ 已真实重构 | 2套权重查找与正则自动解析单测通过 |
| 111 | app/stats/channel.go | app/stats/channel.rs | ✅ 已真实重构 | test_stats_channel_pub_sub / limit |
| 112 | app/stats/channel_test.go | app/stats/channel_test.rs | ✅ 已真实重构 | 2套统计管道发布订阅与上限单测通过 |
| 113 | app/stats/command/command.go | app/stats/command/command.rs | ✅ 已真实重构 | test_stats_service_query 通过 |
| 114 | app/stats/command/command.pb.go | app/stats/command/command.pb.rs | ✅ 已真实重构 | 统计命令 Protobuf 结构 |
| 115 | app/stats/command/command_grpc.pb.go | app/stats/command/command_grpc.pb.rs | ✅ 已真实重构 | StatsService gRPC 接口 trait |
| 116 | app/stats/command/command_test.go | app/stats/command/command_test.rs | ✅ 已真实重构 | test_stats_service_query 通过 |
| 117 | app/stats/config.pb.go | app/stats/config.pb.rs | ✅ 已真实重构 | 1:1 Config 与 ChannelConfig Protobuf 结构 |
| 118 | app/stats/counter.go | app/stats/mod.rs | ✅ 已真实重构 | test_atomic_counter_operations |
| 119 | app/stats/counter_test.go | app/stats/counter_test.rs | ✅ 已真实重构 | test_counter_operations 通过 |
| 120 | app/stats/online_map.go | app/stats/online_map.rs | ✅ 已真实重构 | test_online_map_lifecycle 计数与过滤 |
| 121 | app/stats/stats.go | app/stats/mod.rs | ✅ 已真实重构 | test_stats_manager_registry |
| 122 | app/stats/stats_test.go | app/stats/stats_test.rs | ✅ 已真实重构 | 3套指标命名、管理器与在线映射单测通过 |
| 123 | app/version/config.pb.go | app/version/config.pb.rs | ✅ 已真实重构 | test_version_config_pb / test_version_compare_and_validate |
| 124 | app/version/version.go | app/version/mod.rs | ✅ 已真实重构 | test_version_compare_and_validate |
| 125 | common/antireplay/antireplay_test.go | common/antireplay/antireplay_test.rs | ✅ 已真实重构 | test_map_filter_rotation / test_map_filter |
| 126 | common/antireplay/mapfilter.go | common/antireplay/mod.rs | ✅ 已真实重构 | test_antireplay_filter_detection |
| 127 | common/bitmask/byte.go | common/bitmask/mod.rs | ✅ 已真实重构 | test_bitmask_operations |
| 128 | common/bitmask/byte_test.go | common/bitmask/byte_test.rs | ✅ 已真实重构 | test_bitmask_byte |
| 129 | common/buf/buf.go | common/buf/buf.rs | ✅ 已真实重构 | DEFAULT/MAX_BUFFER_SIZE 常量定义与测试 |
| 130 | common/buf/buffer.go | common/buf/buffer.rs | ✅ 已真实重构 | test_buffer_read_write_advance |
| 131 | common/buf/buffer_test.go | common/buf/buffer_test.rs | ✅ 已真实重构 | 2套单测全部通过 |
| 132 | common/buf/copy.go | common/buf/copy.rs | ✅ 已真实重构 | copy_stream / copy / copy_once_timeout |
| 133 | common/buf/copy_test.go | common/buf/copy_test.rs | ✅ 已真实重构 | 3套流复制单测全部通过 |
| 134 | common/buf/io.go | common/buf/io.rs | ✅ 已真实重构 | Reader/TimeoutReader/Writer Trait 定义 |
| 135 | common/buf/io_test.go | common/buf/io_test.rs | ✅ 已真实重构 | test_write_all_bytes 单测通过 |
| 136 | common/buf/multi_buffer.go | common/buf/multi_buffer.rs | ✅ 已真实重构 | test_multi_buffer_chunking_and_merge |
| 137 | common/buf/multi_buffer_test.go | common/buf/multi_buffer_test.rs | ✅ 已真实重构 | test_multi_buffer_append_and_to_vec 通过 |
| 138 | common/buf/override.go | common/buf/override.rs | ✅ 已真实重构 | test_endpoint_override_reader_and_writer |
| 139 | common/buf/reader.go | common/buf/reader.rs | ✅ 已真实重构 | BufferedReader/SingleReader/PacketReader |
| 140 | common/buf/reader_test.go | common/buf/reader_test.rs | ✅ 已真实重构 | 3套 Reader 单测全部通过 |
| 141 | common/buf/readv_posix.go | common/buf/readv_posix.rs | ✅ 已真实重构 | PosixVectorReader 适配导出 |
| 142 | common/buf/readv_reader.go | common/buf/readv_reader.rs | ✅ 已真实重构 | AllocStrategy 自适应缓存分配与单测 |
| 143 | common/buf/readv_reader_stub.go | common/buf/readv_reader_stub.rs | ✅ 已真实重构 | ReadVReader stub 适配导出 |
| 144 | common/buf/readv_test.go | common/buf/readv_test.rs | ✅ 已真实重构 | 3套 ReadV 单测全部通过 |
| 145 | common/buf/readv_unix.go | common/buf/readv_unix.rs | ✅ 已真实重构 | UnixVectorReader 适配导出 |
| 146 | common/buf/readv_windows.go | common/buf/readv_windows.rs | ✅ 已真实重构 | WindowsVectorReader 向量读入实现 |
| 147 | common/buf/writer.go | common/buf/writer.rs | ✅ 已真实重构 | BufferedWriter/SequentialWriter/Discard |
| 148 | common/buf/writer_test.go | common/buf/writer_test.rs | ✅ 已真实重构 | 3套 Writer 单测全部通过 |
| 149 | common/bytespool/pool.go | common/bytespool/mod.rs | ✅ 已真实重构 | test_bytespool_alloc_and_free |
| 150 | common/cache/lru.go | common/cache/mod.rs | ✅ 已真实重构 | test_lru_cache_capacity_and_eviction |
| 151 | common/cache/lru_test.go | common/cache/lru_test.rs | ✅ 已真实重构 | 5个LRU全套单测验证 |
| 152 | common/cmdarg/cmdarg.go | common/cmdarg/mod.rs | ✅ 已真实重构 | test_cmdarg_parser |
| 153 | common/common.go | common/common.rs | ✅ 已真实重构 | must, Closable, Runnable, HasType |
| 154 | common/common_test.go | common/common_test.rs | ✅ 已真实重构 | test_must_success / test_must_panic |
| 155 | common/crypto/aes.go | common/crypto/aes.rs | ✅ 已真实重构 | AES-128/256-GCM 加解密与校验单测 |
| 156 | common/crypto/auth.go | common/crypto/auth.rs | ✅ 已真实重构 | test_hmac_sha256_verify 单测通过 |
| 157 | common/crypto/auth_test.go | common/crypto/auth_test.rs | ✅ 已真实重构 | test_hmac_sha256_verify 验证通过 |
| 158 | common/crypto/benchmark_test.go | common/crypto/benchmark_test.rs | ✅ 已真实重构 | test_crypto_keystream_speed 基准单测 |
| 159 | common/crypto/chacha20.go | common/crypto/chacha20.rs | ✅ 已真实重构 | ChaCha20Cipher 加解密与单测通过 |
| 160 | common/crypto/chacha20_test.go | common/crypto/chacha20_test.rs | ✅ 已真实重构 | test_chacha20_encrypt_decrypt_roundtrip |
| 161 | common/crypto/chunk.go | common/crypto/chunk.rs | ✅ 已真实重构 | PlainChunk 与 AEAD Chunk 读写器 |
| 162 | common/crypto/chunk_test.go | common/crypto/chunk_test.rs | ✅ 已真实重构 | 2套 Chunk 往返加解密单测通过 |
| 163 | common/crypto/crypto.go | common/crypto/crypto.rs | ✅ 已真实重构 | rand_between / rand_bytes_between 单测 |
| 164 | common/crypto/internal/chacha.go | common/crypto/internal/chacha.rs | ✅ 已真实重构 | ChaChaCore 20轮四分之一变换核心 |
| 165 | common/crypto/internal/chacha_core.generated.go | common/crypto/internal/chacha_core.generated.rs | ✅ 已真实重构 | CHACHA_ROUNDS 常量与生成逻辑 |
| 166 | common/crypto/internal/chacha_core_gen.go | common/crypto/internal/chacha_core_gen.rs | ✅ 已真实重构 | ChaChaCore 适配重导出 |
| 167 | common/crypto/io.go | common/crypto/io.rs | ✅ 已真实重构 | CryptionReader/CryptionWriter/xor_buffers |
| 168 | common/ctx/context.go | common/ctx/context.rs | ✅ 已真实重构 | test_context_id |
| 169 | common/dice/dice.go | common/dice/mod.rs | ✅ 已真实重构 | test_dice_roll_ranges |
| 170 | common/dice/dice_test.go | common/dice/dice_test.rs | ✅ 已真实重构 | test_dice_roll |
| 171 | common/drain/drain.go | common/drain/drain.rs | ✅ 已真实重构 | test_drain_read_n |
| 172 | common/drain/drainer.go | common/drain/mod.rs | ✅ 已真实重构 | test_behavior_seed_limited_drainer |
| 173 | common/errors/errors.go | common/errors/errors.rs | ✅ 已真实重构 | test_error_message_chain / severity |
| 174 | common/errors/errors_test.go | common/errors/errors_test.rs | ✅ 已真实重构 | 5套单测全部通过 |
| 175 | common/errors/feature_errors.go | common/errors/feature_errors.rs | ✅ 已真实重构 | test_feature_errors |
| 176 | common/errors/multi_error.go | common/errors/multi_error.rs | ✅ 已真实重构 | test_multi_error_combine_and_all_equal |
| 177 | common/interfaces.go | common/interfaces.rs | ✅ 已真实重构 | 核心接口定义 |
| 178 | common/log/access.go | common/log/access.rs | ✅ 已真实重构 | AccessMessage 上下文注入与提取单测 |
| 179 | common/log/dns.go | common/log/dns.rs | ✅ 已真实重构 | DnsLog 格式化与单测验证通过 |
| 180 | common/log/log.go | common/log/log.rs | ✅ 已真实重构 | Message/Handler Trait 与 SyncHandler |
| 181 | common/log/log.pb.go | common/log/log.pb.rs | ✅ 已真实重构 | Severity 枚举与 Display/as_str |
| 182 | common/log/log_test.go | common/log/log_test.rs | ✅ 已真实重构 | 3套日志单测全部通过 |
| 183 | common/log/logger.go | common/log/logger.rs | ✅ 已真实重构 | GeneralLogger/SeverityLogger 异步队列 |
| 184 | common/log/logger_test.go | common/log/logger_test.rs | ✅ 已真实重构 | 2套真实落盘与级别过滤单测通过 |
| 185 | common/mux/client.go | common/mux/client.rs | ✅ 已真实重构 | MuxClient 会话管理与流多路复用 |
| 186 | common/mux/client_test.go | common/mux/client_test.rs | ✅ 已真实重构 | test_mux_client 单测验证通过 |
| 187 | common/mux/frame.go | common/mux/frame.rs | ✅ 已真实重构 | test_mux_new_session_frame_roundtrip |
| 188 | common/mux/frame_test.go | common/mux/frame_test.rs | ✅ 已真实重构 | 2套 Frame 编解码单测验证通过 |
| 189 | common/mux/mux.go | common/mux/mux.rs | ✅ 已真实重构 | ClientStrategy 并发与连接参数配置 |
| 190 | common/mux/mux_test.go | common/mux/mux_test.rs | ✅ 已真实重构 | test_mux_strategy 单测验证通过 |
| 191 | common/mux/reader.go | common/mux/reader.rs | ✅ 已真实重构 | PacketReader/StreamReader/FrameReader |
| 192 | common/mux/server.go | common/mux/server.rs | ✅ 已真实重构 | MuxServer 会话分发与处理 |
| 193 | common/mux/server_test.go | common/mux/server_test.rs | ✅ 已真实重构 | test_mux_server 单测验证通过 |
| 194 | common/mux/session.go | common/mux/session.rs | ✅ 已真实重构 | Session/SessionManager 分配与回收 |
| 195 | common/mux/session_test.go | common/mux/session_test.rs | ✅ 已真实重构 | 2套会话单测验证通过 |
| 196 | common/mux/writer.go | common/mux/writer.rs | ✅ 已真实重构 | Writer/FrameWriter 响应与元数据写入 |
| 197 | common/net/address.go | common/net/address.rs | ✅ 已真实重构 | Address 枚举与 IP/Domain 地址解析单测 |
| 198 | common/net/address.pb.go | common/net/address.rs | ✅ 已真实重构 | AddressFamily 与 Protobuf 适配 |
| 199 | common/net/address_test.go | common/net/address_test.rs | ✅ 已真实重构 | 3套地址单测全部通过 |
| 200 | common/net/cnc/connection.go | common/net/cnc/connection.rs | ✅ 已真实重构 | CncConnection 多路复用连接适配 |
| 201 | common/net/destination.go | common/net/destination.rs | ✅ 已真实重构 | Destination 目标结构与 net_addr() 校验 |
| 202 | common/net/destination.pb.go | common/net/destination.rs | ✅ 已真实重构 | Protobuf 序列化与反序列化支持 |
| 203 | common/net/destination_test.go | common/net/destination_test.rs | ✅ 已真实重构 | 2套目标单测全部通过 |
| 204 | common/net/find_process_linux.go | common/net/find_process_linux.rs | ✅ 已真实重构 | Linux 平台进程查找实现 |
| 205 | common/net/find_process_others.go | common/net/find_process_others.rs | ✅ 已真实重构 | 通用平台空回退实现 |
| 206 | common/net/find_process_windows.go | common/net/find_process_windows.rs | ✅ 已真实重构 | Windows 平台 TCP 进程查找 |
| 207 | common/net/net.go | common/net/net.rs | ✅ 已真实重构 | split_host_port / parse_ip 解析 |
| 208 | common/net/network.go | common/net/network.rs | ✅ 已真实重构 | Network 枚举与 NetworkList 匹配 |
| 209 | common/net/network.pb.go | common/net/network.rs | ✅ 已真实重构 | Network Protobuf 映射 |
| 210 | common/net/port.go | common/net/port.rs | ✅ 已真实重构 | Port/PortRange/PortList 范围匹配 |
| 211 | common/net/port.pb.go | common/net/port.rs | ✅ 已真实重构 | Port Protobuf 映射 |
| 212 | common/net/port_test.go | common/net/port_test.rs | ✅ 已真实重构 | 3套端口单测全部通过 |
| 213 | common/net/system.go | common/net/system.rs | ✅ 已真实重构 | SystemListener 系统监听器与单测 |
| 214 | common/ocsp/ocsp.go | common/ocsp/mod.rs | ✅ 已真实重构 | test_ocsp_cache_expiry |
| 215 | common/peer/latency.go | common/peer/mod.rs | ✅ 已真实重构 | test_average_latency_exponential_moving_average |
| 216 | common/peer/peer.go | common/peer/peer.rs | ✅ 已真实重构 | test_peer_latency_interface |
| 217 | common/platform/filesystem/file.go | common/platform/filesystem/file.rs | ✅ 已真实重构 | test_filesystem_operations |
| 218 | common/platform/others.go | common/platform/others.rs | ✅ 已真实重构 | unix平台路径与换行符适配 |
| 219 | common/platform/platform.go | common/platform/platform.rs | ✅ 已真实重构 | test_platform_env_flag_and_paths |
| 220 | common/platform/platform_test.go | common/platform/platform_test.rs | ✅ 已真实重构 | 4套平台单测全部通过 |
| 221 | common/platform/windows.go | common/platform/windows.rs | ✅ 已真实重构 | Windows平台路径与换行符适配 |
| 222 | common/protocol/account.go | common/protocol/account.rs | ✅ 已真实重构 | Account/AsAccount Trait 与类型适配 |
| 223 | common/protocol/address.go | common/protocol/address.rs | ✅ 已真实重构 | Address 协议级编解码与单测通过 |
| 224 | common/protocol/address_test.go | common/protocol/address_test.rs | ✅ 已真实重构 | test_address_protocol 单测验证通过 |
| 225 | common/protocol/bittorrent/bittorrent.go | common/protocol/bittorrent/mod.rs | ✅ 已真实重构 | BitTorrent 协议嗅探与特征提取单测通过 |
| 226 | common/protocol/context.go | common/protocol/mod.rs | ✅ 已真实重构 | 全套场景集成测试 |
| 227 | common/protocol/dns/io.go | common/protocol/dns/io.rs | ✅ 已真实重构 | DNS 消息 I/O 协议封装 |
| 228 | common/protocol/headers.go | common/protocol/headers.rs | ✅ 已真实重构 | test_protocol_memory_user_and_request_header |
| 229 | common/protocol/headers.pb.go | common/protocol/headers.rs | ✅ 已真实重构 | Request/Response Header Protobuf 映射 |
| 230 | common/protocol/http/headers.go | common/protocol/http/headers.rs | ✅ 已真实重构 | HTTP 请求头解析与格式化 |
| 231 | common/protocol/http/headers_test.go | common/protocol/http/headers_test.rs | ✅ 已真实重构 | test_http_headers 单测验证通过 |
| 232 | common/protocol/http/sniff.go | common/protocol/http/sniff.rs | ✅ 已真实重构 | HTTP Host/URI 嗅探与单测通过 |
| 233 | common/protocol/http/sniff_test.go | common/protocol/http/sniff_test.rs | ✅ 已真实重构 | test_http_sniffing 单测验证通过 |
| 234 | common/protocol/id.go | common/protocol/id.rs | ✅ 已真实重构 | test_protocol_id_cmd_key_derivation |
| 235 | common/protocol/id_test.go | common/protocol/id_test.rs | ✅ 已真实重构 | test_protocol_id 单测验证通过 |
| 236 | common/protocol/payload.go | common/protocol/payload.rs | ✅ 已真实重构 | Payload 缓冲区协议封装 |
| 237 | common/protocol/protocol.go | common/protocol/protocol.rs | ✅ 已真实重构 | ServerSpec / SecurityType 协议定义 |
| 238 | common/protocol/quic/qtls_go118.go | common/protocol/quic/sniff.rs | ✅ 已真实重构 | QUIC TLS 1.3 密码套件适配 |
| 239 | common/protocol/quic/sniff.go | common/protocol/quic/sniff.rs | ✅ 已真实重构 | QUIC Initial SNI 嗅探实现 |
| 240 | common/protocol/quic/sniff_test.go | common/protocol/quic/sniff_test.rs | ✅ 已真实重构 | test_quic_sniffing 单测验证通过 |
| 241 | common/protocol/server_spec.go | common/protocol/server_spec.rs | ✅ 已真实重构 | ServerSpec 规格定义与轮询选择 |
| 242 | common/protocol/server_spec.pb.go | common/protocol/server_spec.rs | ✅ 已真实重构 | ServerSpec Protobuf 序列化 |
| 243 | common/protocol/time.go | common/protocol/time.rs | ✅ 已真实重构 | Timestamp 协议时间与混淆单测 |
| 244 | common/protocol/time_test.go | common/protocol/time_test.rs | ✅ 已真实重构 | test_protocol_time 单测验证通过 |
| 245 | common/protocol/tls/cert/cert.go | common/protocol/tls/cert/cert.rs | ✅ 已真实重构 | X509 证书生成/解析/PEM导出单测 |
| 246 | common/protocol/tls/cert/cert_test.go | common/protocol/tls/cert/cert_test.rs | ✅ 已真实重构 | 2套证书生成与指纹单测通过 |
| 247 | common/protocol/tls/cert/privateKey.go | common/protocol/tls/cert/privateKey.rs | ✅ 已真实重构 | RSA/EC 私钥生成与 PEM 编解码 |
| 248 | common/protocol/tls/sniff.go | common/protocol/tls/sniff.rs | ✅ 已真实重构 | TLS ClientHello SNI/ALPN 嗅探实现 |
| 249 | common/protocol/tls/sniff_test.go | common/protocol/tls/sniff_test.rs | ✅ 已真实重构 | test_tls_sniffing 单测验证通过 |
| 250 | common/protocol/udp/packet.go | common/protocol/udp/packet.rs | ✅ 已真实重构 | Packet 结构体与 SessionContext 关联 |
| 251 | common/protocol/udp/udp.go | common/protocol/udp/mod.rs | ✅ 已真实重构 | UDP 报文分发与单测验证通过 |
| 252 | common/protocol/user.go | common/protocol/user.rs | ✅ 已真实重构 | test_protocol_memory_user_and_request_header |
| 253 | common/protocol/user.pb.go | common/protocol/user.rs | ✅ 已真实重构 | User / MemoryUser Protobuf 映射 |
| 254 | common/reflect/marshal.go | common/reflect/marshal.rs | ✅ 已真实重构 | JSON 无转义/4空格缩进序列化与类型注入 |
| 255 | common/reflect/marshal_test.go | common/reflect/marshal_test.rs | ✅ 已真实重构 | 2套反射序列化单测验证全部通过 |
| 256 | common/retry/retry.go | common/retry/mod.rs | ✅ 已真实重构 | test_retry_strategy_success_after_failure |
| 257 | common/retry/retry_test.go | common/retry/retry_test.rs | ✅ 已真实重构 | 5套重试单测全部通过 |
| 258 | common/serial/serial.go | common/serial/serial.rs | ✅ 已真实重构 | test_serial_integer_and_string_operations |
| 259 | common/serial/serial_test.go | common/serial/serial_test.rs | ✅ 已真实重构 | 4套数字序列化单测通过 |
| 260 | common/serial/string.go | common/serial/string.rs | ✅ 已真实重构 | to_string, concat, concat_strings |
| 261 | common/serial/string_test.go | common/serial/string_test.rs | ✅ 已真实重构 | 3套字符串单测通过 |
| 262 | common/serial/typed_message.go | common/serial/typed_message.rs | ✅ 已真实重构 | to_typed_message, get_instance |
| 263 | common/serial/typed_message.pb.go | common/serial/typed_message.pb.rs | ✅ 已真实重构 | protobuf 类型重导出 |
| 264 | common/serial/typed_message_test.go | common/serial/typed_message_test.rs | ✅ 已真实重构 | 3套类型消息单测通过 |
| 265 | common/session/context.go | common/session/mod.rs | ✅ 已真实重构 | test_session_content_and_attributes |
| 266 | common/session/session.go | common/session/mod.rs | ✅ 已真实重构 | test_session_id_monotonicity |
| 267 | common/signal/done/done.go | common/signal/done/done.rs | ✅ 已真实重构 | test_done_signal_wait_and_close |
| 268 | common/signal/notifier.go | common/signal/notifier.rs | ✅ 已真实重构 | test_notifier_signal / wait |
| 269 | common/signal/notifier_test.go | common/signal/notifier_test.rs | ✅ 已真实重构 | 2套单测全部通过 |
| 270 | common/signal/pubsub/pubsub.go | common/signal/pubsub/pubsub.rs | ✅ 已真实重构 | PubSubService 发布订阅模式 |
| 271 | common/signal/pubsub/pubsub_test.go | common/signal/pubsub/pubsub_test.rs | ✅ 已真实重构 | test_pubsub 单测通过 |
| 272 | common/signal/semaphore/semaphore.go | common/signal/semaphore/semaphore.rs | ✅ 已真实重构 | test_semaphore_permits |
| 273 | common/signal/timer.go | common/signal/timer.rs | ✅ 已真实重构 | test_activity_timer_update_and_timeout |
| 274 | common/signal/timer_test.go | common/signal/timer_test.rs | ✅ 已真实重构 | 3套活动定时器单测通过 |
| 275 | common/singbridge/destination.go | common/singbridge/destination.rs | ✅ 已真实重构 | Socksaddr 与 Destination 双向转换单测通过 |
| 276 | common/singbridge/dialer.go | common/singbridge/dialer.rs | ✅ 已真实重构 | XrayDialer 与 OutboundDialer 适配与单测通过 |
| 277 | common/singbridge/error.go | common/singbridge/error.rs | ✅ 已真实重构 | is_closed_or_canceled 错误过滤单测通过 |
| 278 | common/singbridge/handler.go | common/singbridge/handler.rs | ✅ 已真实重构 | TCP/UDP ConnectionHandler 与 Dispatcher 单测 |
| 279 | common/singbridge/logger.go | common/singbridge/logger.rs | ✅ 已真实重构 | XrayLogger 级别分发与上下文日志单测通过 |
| 280 | common/singbridge/packet.go | common/singbridge/packet.rs | ✅ 已真实重构 | PacketConnWrapper 读写与超时单测通过 |
| 281 | common/singbridge/pipe.go | common/singbridge/pipe.rs | ✅ 已真实重构 | PipeConnWrapper 双向流管道复制单测通过 |
| 282 | common/singbridge/reader.go | common/singbridge/reader.rs | ✅ 已真实重构 | Conn MultiBuffer 异步读写与超时单测通过 |
| 283 | common/strmatcher/ac_automaton_matcher.go | common/strmatcher/ac_automaton_matcher.rs | ✅ 已真实重构 | test_ac_automaton 通过 |
| 284 | common/strmatcher/benchmark_test.go | common/strmatcher/benchmark_test.rs | ✅ 已真实重构 | test_strmatcher_benchmark_simulation |
| 285 | common/strmatcher/domain_matcher.go | common/strmatcher/domain_matcher.rs | ✅ 已真实重构 | test_domain_matcher |
| 286 | common/strmatcher/domain_matcher_test.go | common/strmatcher/domain_matcher_test.rs | ✅ 已真实重构 | 3套域名匹配单测通过 |
| 287 | common/strmatcher/full_matcher.go | common/strmatcher/full_matcher.rs | ✅ 已真实重构 | test_full_matcher |
| 288 | common/strmatcher/full_matcher_test.go | common/strmatcher/full_matcher_test.rs | ✅ 已真实重构 | 3套完全匹配单测通过 |
| 289 | common/strmatcher/matchers.go | common/strmatcher/matchers.rs | ✅ 已真实重构 | test_regex_matcher |
| 290 | common/strmatcher/matchers_test.go | common/strmatcher/matchers_test.rs | ✅ 已真实重构 | 3套匹配器测试通过 |
| 291 | common/strmatcher/mph_matcher.go | common/strmatcher/mph_matcher.rs | ✅ 已真实重构 | test_strmatcher_benchmark_simulation |
| 292 | common/strmatcher/mph_matcher_compact.go | common/strmatcher/mph_matcher_compact.rs | ✅ 已真实重构 | CompactMatcher 紧凑匹配器 |
| 293 | common/strmatcher/strmatcher.go | common/strmatcher/strmatcher.rs | ✅ 已真实重构 | MatcherGroup 匹配器组 |
| 294 | common/strmatcher/strmatcher_test.go | common/strmatcher/strmatcher_test.rs | ✅ 已真实重构 | 2套匹配器组与AC自动机测试通过 |
| 295 | common/task/common.go | common/task/common.rs | ✅ 已真实重构 | close_task 任务关闭函数 |
| 296 | common/task/periodic.go | common/task/periodic.rs | ✅ 已真实重构 | test_periodic_task_run_and_close |
| 297 | common/task/periodic_test.go | common/task/periodic_test.rs | ✅ 已真实重构 | 2套周期任务单测通过 |
| 298 | common/task/task.go | common/task/task.rs | ✅ 已真实重构 | test_parallel_run_success / on_success |
| 299 | common/task/task_test.go | common/task/task_test.rs | ✅ 已真实重构 | 3套任务并发与串联单测通过 |
| 300 | common/type.go | common/type.rs | ✅ 已真实重构 | test_type_registration_and_object_creation |
| 301 | common/type_test.go | common/type_test.rs | ✅ 已真实重构 | test_type_of 单测通过 |
| 302 | common/units/bytesize.go | common/units/bytesize.rs | ✅ 已真实重构 | test_units_parse_and_format |
| 303 | common/units/bytesize_test.go | common/units/bytesize_test.rs | ✅ 已真实重构 | test_byte_sizes 单测矩阵通过 |
| 304 | common/utils/access_field.go | common/utils/access_field.rs | ✅ 已真实重构 | 3套动态字段存取与错误断言单测通过 |
| 305 | common/utils/browser.go | common/utils/browser.rs | ✅ 已真实重构 | 3套 UA、GREASE 与伪装头单测全部通过 |
| 306 | common/utils/padding.go | common/utils/mod.rs | ✅ 已真实重构 | test_h2_base62_padding_generation |
| 307 | common/utils/typed_sync_map.go | common/utils/mod.rs | ✅ 已真实重构 | test_typed_sync_map_operations |
| 308 | common/uuid/uuid.go | common/uuid/uuid.rs | ✅ 已真实重构 | 1:1 UUID 结构与 v4/v5 生成 |
| 309 | common/uuid/uuid_test.go | common/uuid/uuid_test.rs | ✅ 已真实重构 | 4套 UUID 单测全部通过 |
| 310 | common/xudp/xudp.go | common/xudp/xudp.rs | ✅ 已真实重构 | test_xudp_packet_and_global_id |
| 311 | common/xudp/xudp_test.go | common/xudp/xudp_test.rs | ✅ 已真实重构 | 5套 XUDP 单测全部通过 |
| 312 | core/annotations.go | core/annotations.rs | ✅ 已真实重构 | test_annotations_metadata 通过 |
| 313 | core/config.go | core/config.rs | ✅ 已真实重构 | test_config_source_and_format_resolution |
| 314 | core/config.pb.go | core/config.pb.rs | ✅ 已真实重构 | test_config_pb_structs 通过 |
| 315 | core/context.go | core/context.rs | ✅ 已真实重构 | test_context_with_instance / detached |
| 316 | core/context_test.go | core/context_test.rs | ✅ 已真实重构 | 3套上下文隔离与提取单测通过 |
| 317 | core/core.go | core/core.rs | ✅ 已真实重构 | test_version_info / version_statement |
| 318 | core/format.go | core/format.rs | ✅ 已真实重构 | 格式常量定义与解析映射 |
| 319 | core/functions.go | core/functions.rs | ✅ 已真实重构 | test_xray_dial_stream / dial_udp |
| 320 | core/functions_test.go | core/functions_test.rs | ✅ 已真实重构 | 5套实例启动、流拨号与UDP拨号测试通过 |
| 321 | core/mocks.go | core/mocks.rs | ✅ 已真实重构 | 模拟实例创建函数与对象构造 |
| 322 | core/proto.go | core/proto.rs | ✅ 已真实重构 | Protobuf 核心注册元数据与版本 |
| 323 | core/xray.go | core/xray.rs | ✅ 已真实重构 | test_xray_instance_lifecycle 生命周期通过 |
| 324 | core/xray_test.go | core/xray_test.rs | ✅ 已真实重构 | 5套核心实例、配置与元数据单测全部通过 |
| 325 | features/dns/client.go | features/dns/client.rs | ✅ 已真实重构 | test_dns_localdns_and_options 通过 |
| 326 | features/dns/fakedns.go | features/dns/fakedns.rs | ✅ 已真实重构 | test_fake_dns_engine_and_pools 通过 |
| 327 | features/dns/localdns/client.go | features/dns/localdns/client.rs | ✅ 已真实重构 | test_dns_localdns_and_options 通过 |
| 328 | features/extension/contextreceiver.go | features/extension/contextreceiver.rs | ✅ 已真实重构 | test_extension_features 通过 |
| 329 | features/extension/observatory.go | features/extension/observatory.rs | ✅ 已真实重构 | test_extension_features 通过 |
| 330 | features/feature.go | features/feature.rs | ✅ 已真实重构 | test_feature_type_constants 通过 |
| 331 | features/inbound/inbound.go | features/inbound/mod.rs | ✅ 已真实重构 | test_inbound_manager_lifecycle_and_lookup |
| 332 | features/outbound/outbound.go | features/outbound/mod.rs | ✅ 已真实重构 | test_outbound_manager_default_and_selector |
| 333 | features/policy/default.go | features/policy/default.rs | ✅ 已真实重构 | test_policy_defaults_and_manager 通过 |
| 334 | features/policy/policy.go | features/policy/policy.rs | ✅ 已真实重构 | test_policy_defaults_and_manager 通过 |
| 335 | features/routing/balancer.go | features/routing/balancer.rs | ✅ 已真实重构 | BalancerOverrider / BalancerPrincipleTarget 接口验证 |
| 336 | features/routing/context.go | features/routing/context.rs | ✅ 已真实重构 | test_routing_contexts_and_router 通过 |
| 337 | features/routing/dispatcher.go | features/routing/dispatcher.rs | ✅ 已真实重构 | test_routing_contexts_and_router 通过 |
| 338 | features/routing/dns/context.go | features/routing/dns/context.rs | ✅ 已真实重构 | test_routing_contexts_and_router 通过 |
| 339 | features/routing/router.go | features/routing/router.rs | ✅ 已真实重构 | test_routing_contexts_and_router 通过 |
| 340 | features/routing/session/context.go | features/routing/session/context.rs | ✅ 已真实重构 | test_routing_contexts_and_router 通过 |
| 341 | features/stats/stats.go | features/stats/stats.rs | ✅ 已真实重构 | test_stats_counter_online_map_and_manager 通过 |
| 342 | infra/conf/api.go | infra/conf/api.rs | ✅ 已真实重构 | test_api_config_builder 通过 |
| 343 | infra/conf/blackhole.go | infra/conf/blackhole.rs | ✅ 已真实重构 | test_blackhole_json_parsing 通过 |
| 344 | infra/conf/blackhole_test.go | infra/conf/blackhole_test.rs | ✅ 已真实重构 | test_blackhole_json_parsing 2套单测通过 |
| 345 | infra/conf/buildable.go | infra/conf/buildable.rs | ✅ 已真实重构 | Buildable 特征定义与构建器通过 |
| 346 | infra/conf/cfgcommon/duration/duration.go | infra/conf/cfgcommon/duration/duration.rs | ✅ 已真实重构 | test_parse_duration 通过 |
| 347 | infra/conf/cfgcommon/duration/duration_test.go | infra/conf/cfgcommon/duration/duration_test.rs | ✅ 已真实重构 | 周期解析单测通过 |
| 348 | infra/conf/common.go | infra/conf/common.rs | ✅ 已真实重构 | StringList 序列化与反序列化 |
| 349 | infra/conf/common_test.go | infra/conf/common_test.rs | ✅ 已真实重构 | test_string_list 单测通过 |
| 350 | infra/conf/conf.go | infra/conf/conf.rs | ✅ 已真实重构 | conf 模块公共组织定义 |
| 351 | infra/conf/dns.go | infra/conf/dns.rs | ✅ 已真实重构 | test_dns_config_parsing 通过 |
| 352 | infra/conf/dns_proxy.go | infra/conf/dns_proxy.rs | ✅ 已真实重构 | test_dns_proxy_config 通过 |
| 353 | infra/conf/dns_proxy_test.go | infra/conf/dns_proxy_test.rs | ✅ 已真实重构 | DNS 代理配置单测通过 |
| 354 | infra/conf/dns_test.go | infra/conf/dns_test.rs | ✅ 已真实重构 | DNS 配置解析单测通过 |
| 355 | infra/conf/dokodemo.go | infra/conf/dokodemo.rs | ✅ 已真实重构 | test_dokodemo_json_parsing 通过 |
| 356 | infra/conf/dokodemo_test.go | infra/conf/dokodemo_test.rs | ✅ 已真实重构 | dokodemo 门罗入站单测通过 |
| 357 | infra/conf/fakedns.go | infra/conf/fakedns.rs | ✅ 已真实重构 | FakeDnsConfig 与 IP 池解析 |
| 358 | infra/conf/freedom.go | infra/conf/freedom.rs | ✅ 已真实重构 | test_freedom_json_parsing_comprehensive 通过 |
| 359 | infra/conf/freedom_test.go | infra/conf/freedom_test.rs | ✅ 已真实重构 | freedom 自由出站全量单测通过 |
| 360 | infra/conf/general_test.go | infra/conf/general_test.rs | ✅ 已真实重构 | test_empty_config_parse 通过 |
| 361 | infra/conf/grpc.go | infra/conf/grpc.rs | ✅ 已真实重构 | gRPC 传输层配置 |
| 362 | infra/conf/http.go | infra/conf/http.rs | ✅ 已真实重构 | test_http_config_parsing 通过 |
| 363 | infra/conf/http_test.go | infra/conf/http_test.rs | ✅ 已真实重构 | HTTP 配置单测通过 |
| 364 | infra/conf/hysteria.go | infra/conf/hysteria.rs | ✅ 已真实重构 | Hysteria 协议配置定义 |
| 365 | infra/conf/init.go | infra/conf/init.rs | ✅ 已真实重构 | test_init_conf 阶段注册通过 |
| 366 | infra/conf/json/reader.go | infra/conf/json/reader.rs | ✅ 已真实重构 | test_json_reader 通过 |
| 367 | infra/conf/json/reader_test.go | infra/conf/json/reader_test.rs | ✅ 已真实重构 | JSON 读取与注释剥离单测通过 |
| 368 | infra/conf/lint.go | infra/conf/lint.rs | ✅ 已真实重构 | test_lint_and_post_process 通过 |
| 369 | infra/conf/loader.go | infra/conf/loader.rs | ✅ 已真实重构 | test_json_config_loader 通过 |
| 370 | infra/conf/log.go | infra/conf/log.rs | ✅ 已真实重构 | LogConfig 日志配置构建 |
| 371 | infra/conf/loopback.go | infra/conf/loopback.rs | ✅ 已真实重构 | test_loopback_config 通过 |
| 372 | infra/conf/metrics.go | infra/conf/metrics.rs | ✅ 已真实重构 | test_metrics_config 通过 |
| 373 | infra/conf/observatory.go | infra/conf/observatory.rs | ✅ 已真实重构 | 观察者探针配置构建 |
| 374 | infra/conf/policy.go | infra/conf/policy.rs | ✅ 已真实重构 | test_policy_config_parsing 通过 |
| 375 | infra/conf/policy_test.go | infra/conf/policy_test.rs | ✅ 已真实重构 | 策略配置解析单测通过 |
| 376 | infra/conf/reverse.go | infra/conf/reverse.rs | ✅ 已真实重构 | test_reverse_config_parsing 通过 |
| 377 | infra/conf/reverse_test.go | infra/conf/reverse_test.rs | ✅ 已真实重构 | 反向代理配置单测通过 |
| 378 | infra/conf/router.go | infra/conf/router.rs | ✅ 已真实重构 | test_router_config_parsing 通过 |
| 379 | infra/conf/router_strategy.go | infra/conf/router_strategy.rs | ✅ 已真实重构 | 负载均衡策略配置构建 |
| 380 | infra/conf/router_test.go | infra/conf/router_test.rs | ✅ 已真实重构 | 路由规则单测通过 |
| 381 | infra/conf/serial/builder.go | infra/conf/serial/builder.rs | ✅ 已真实重构 | test_merge_configs 通过 |
| 382 | infra/conf/serial/loader.go | infra/conf/serial/loader.rs | ✅ 已真实重构 | load_config_file 文件加载 |
| 383 | infra/conf/serial/loader_test.go | infra/conf/serial/loader_test.rs | ✅ 已真实重构 | 2套序列化构建器单测通过 |
| 384 | infra/conf/serial/serial.go | infra/conf/serial/serial.rs | ✅ 已真实重构 | serial 模块组织定义 |
| 385 | infra/conf/shadowsocks.go | infra/conf/shadowsocks.rs | ✅ 已真实重构 | test_shadowsocks_* 2套单测通过 |
| 386 | infra/conf/shadowsocks_test.go | infra/conf/shadowsocks_test.rs | ✅ 已真实重构 | SS 入站/出站单测通过 |
| 387 | infra/conf/socks.go | infra/conf/socks.rs | ✅ 已真实重构 | test_socks_config_parsing 通过 |
| 388 | infra/conf/socks_test.go | infra/conf/socks_test.rs | ✅ 已真实重构 | SOCKS5 入出站单测通过 |
| 389 | infra/conf/transport_authenticators.go | infra/conf/transport_authenticators.rs | ✅ 已真实重构 | 传输鉴权头配置 |
| 390 | infra/conf/transport_internet.go | infra/conf/transport_internet.rs | ✅ 已真实重构 | test_stream_config_parsing 通过 |
| 391 | infra/conf/transport_test.go | infra/conf/transport_test.rs | ✅ 已真实重构 | 流传输配置单测通过 |
| 392 | infra/conf/trojan.go | infra/conf/trojan.rs | ✅ 已真实重构 | test_trojan_* 2套单测通过 |
| 393 | infra/conf/tun.go | infra/conf/tun.rs | ✅ 已真实重构 | TUN 设备配置模型 |
| 394 | infra/conf/version.go | infra/conf/version.rs | ✅ 已真实重构 | test_version_config_build 通过 |
| 395 | infra/conf/vless.go | infra/conf/vless.rs | ✅ 已真实重构 | test_vless_* 2套单测通过 |
| 396 | infra/conf/vless_test.go | infra/conf/vless_test.rs | ✅ 已真实重构 | VLESS 入出站单测通过 |
| 397 | infra/conf/vmess.go | infra/conf/vmess.rs | ✅ 已真实重构 | test_vmess_* 2套单测通过 |
| 398 | infra/conf/vmess_test.go | infra/conf/vmess_test.rs | ✅ 已真实重构 | VMess 入出站单测通过 |
| 399 | infra/conf/wireguard.go | infra/conf/wireguard.rs | ✅ 已真实重构 | test_wireguard_* 2套单测通过 |
| 400 | infra/conf/wireguard_test.go | infra/conf/wireguard_test.rs | ✅ 已真实重构 | WireGuard 驼峰与蛇形单测通过 |
| 401 | infra/conf/xray.go | infra/conf/xray.rs | ✅ 已真实重构 | test_full_xray_config_roundtrip 通过 |
| 402 | infra/conf/xray_test.go | infra/conf/xray_test.rs | ✅ 已真实重构 | 完整 Xray 配置往返单测通过 |
| 403 | infra/vformat/main.go | infra/vformat/main.rs | ✅ 已真实重构 | 2套源码树扫描与格式化单测通过 |
| 404 | infra/vprotogen/main.go | infra/vprotogen/main.rs | ✅ 已真实重构 | 3套版本比较与 proto 扫描单测通过 |
| 405 | main/commands/all/api/api.go | main/commands/all/api/api.rs | ✅ 已真实重构 | test_api_command_hierarchy 单测通过 |
| 406 | main/commands/all/api/balancer_info.go | main/commands/all/api/balancer_info.rs | ✅ 已真实重构 | 负载均衡状态 API 命令 |
| 407 | main/commands/all/api/balancer_override.go | main/commands/all/api/balancer_override.rs | ✅ 已真实重构 | 负载均衡覆盖 API 命令 |
| 408 | main/commands/all/api/inbound_user.go | main/commands/all/api/inbound_user.rs | ✅ 已真实重构 | 入站用户 API 根命令 |
| 409 | main/commands/all/api/inbound_user_add.go | main/commands/all/api/inbound_user_add.rs | ✅ 已真实重构 | 入站添加用户 API 命令 |
| 410 | main/commands/all/api/inbound_user_count.go | main/commands/all/api/inbound_user_count.rs | ✅ 已真实重构 | 入站用户计数 API 命令 |
| 411 | main/commands/all/api/inbound_user_remove.go | main/commands/all/api/inbound_user_remove.rs | ✅ 已真实重构 | 入站移除用户 API 命令 |
| 412 | main/commands/all/api/inbounds_add.go | main/commands/all/api/inbounds_add.rs | ✅ 已真实重构 | 动态增加入站代理 API 命令 |
| 413 | main/commands/all/api/inbounds_list.go | main/commands/all/api/inbounds_list.rs | ✅ 已真实重构 | 查询入站列表 API 命令 |
| 414 | main/commands/all/api/inbounds_remove.go | main/commands/all/api/inbounds_remove.rs | ✅ 已真实重构 | 移除入站代理 API 命令 |
| 415 | main/commands/all/api/logger_restart.go | main/commands/all/api/logger_restart.rs | ✅ 已真实重构 | 重启日志服务 API 命令 |
| 416 | main/commands/all/api/outbounds_add.go | main/commands/all/api/outbounds_add.rs | ✅ 已真实重构 | 动态增加出站代理 API 命令 |
| 417 | main/commands/all/api/outbounds_list.go | main/commands/all/api/outbounds_list.rs | ✅ 已真实重构 | 查询出站列表 API 命令 |
| 418 | main/commands/all/api/outbounds_remove.go | main/commands/all/api/outbounds_remove.rs | ✅ 已真实重构 | 移除出站代理 API 命令 |
| 419 | main/commands/all/api/rules_add.go | main/commands/all/api/rules_add.rs | ✅ 已真实重构 | 动态路由规则添加 API 命令 |
| 420 | main/commands/all/api/rules_list.go | main/commands/all/api/rules_list.rs | ✅ 已真实重构 | 路由规则列表 API 命令 |
| 421 | main/commands/all/api/rules_remove.go | main/commands/all/api/rules_remove.rs | ✅ 已真实重构 | 路由规则移除 API 命令 |
| 422 | main/commands/all/api/shared.go | main/commands/all/api/shared.rs | ✅ 已真实重构 | API 客户端公共配置与参数解析 |
| 423 | main/commands/all/api/source_ip_block.go | main/commands/all/api/source_ip_block.rs | ✅ 已真实重构 | 源 IP 封禁 API 命令 |
| 424 | main/commands/all/api/stats_get.go | main/commands/all/api/stats_get.rs | ✅ 已真实重构 | 获取指定统计项 API 命令 |
| 425 | main/commands/all/api/stats_get_all_online_users.go | main/commands/all/api/stats_get_all_online_users.rs | ✅ 已真实重构 | 查询全部在线用户 API 命令 |
| 426 | main/commands/all/api/stats_online.go | main/commands/all/api/stats_online.rs | ✅ 已真实重构 | 用户在线状态 API 命令 |
| 427 | main/commands/all/api/stats_online_ip_list.go | main/commands/all/api/stats_online_ip_list.rs | ✅ 已真实重构 | 用户在线 IP 列表 API 命令 |
| 428 | main/commands/all/api/stats_query.go | main/commands/all/api/stats_query.rs | ✅ 已真实重构 | 统计算法模式查询 API 命令 |
| 429 | main/commands/all/api/stats_sys.go | main/commands/all/api/stats_sys.rs | ✅ 已真实重构 | 系统级资源统计 API 命令 |
| 430 | main/commands/all/buildmphcache.go | main/commands/all/buildmphcache.rs | ✅ 已真实重构 | test_build_mph_cache 单测通过 |
| 431 | main/commands/all/commands.go | main/commands/all/commands.rs | ✅ 已真实重构 | all_commands 注册表与分发 |
| 432 | main/commands/all/convert/convert.go | main/commands/all/convert/convert.rs | ✅ 已真实重构 | test_convert_subcommands 单测通过 |
| 433 | main/commands/all/convert/json.go | main/commands/all/convert/json.rs | ✅ 已真实重构 | test_format_json 单测通过 |
| 434 | main/commands/all/convert/protobuf.go | main/commands/all/convert/protobuf.rs | ✅ 已真实重构 | test_convert_pb_merge 单测通过 |
| 435 | main/commands/all/curve25519.go | main/commands/all/curve25519.rs | ✅ 已真实重构 | test_gen_curve25519 单测通过 |
| 436 | main/commands/all/mldsa65.go | main/commands/all/mldsa65.rs | ✅ 已真实重构 | test_mldsa65_command 单测通过 |
| 437 | main/commands/all/mlkem768.go | main/commands/all/mlkem768.rs | ✅ 已真实重构 | test_mlkem768_command 单测通过 |
| 438 | main/commands/all/tls/cert.go | main/commands/all/tls/cert.rs | ✅ 已真实重构 | 自签名证书生成命令 |
| 439 | main/commands/all/tls/ech.go | main/commands/all/tls/ech.rs | ✅ 已真实重构 | ECH 密钥对生成命令 |
| 440 | main/commands/all/tls/hash.go | main/commands/all/tls/hash.rs | ✅ 已真实重构 | 证书 SHA256 指纹提取命令 |
| 441 | main/commands/all/tls/ping.go | main/commands/all/tls/ping.rs | ✅ 已真实重构 | TLS 连接连通性握手测试命令 |
| 442 | main/commands/all/tls/tls.go | main/commands/all/tls/tls.rs | ✅ 已真实重构 | test_tls_commands 单测通过 |
| 443 | main/commands/all/uuid.go | main/commands/all/uuid.rs | ✅ 已真实重构 | test_uuid_command 单测通过 |
| 444 | main/commands/all/vlessenc.go | main/commands/all/vlessenc.rs | ✅ 已真实重构 | test_vlessenc_command 单测通过 |
| 445 | main/commands/all/wg.go | main/commands/all/wg.rs | ✅ 已真实重构 | test_wg_command 单测通过 |
| 446 | main/commands/all/x25519.go | main/commands/all/x25519.rs | ✅ 已真实重构 | test_x25519_command 单测通过 |
| 447 | main/commands/base/command.go | main/commands/base/command.rs | ✅ 已真实重构 | test_base_command_execution_and_help 单测通过 |
| 448 | main/commands/base/env.go | main/commands/base/env.rs | ✅ 已真实重构 | 环境变量加载器模型 |
| 449 | main/commands/base/execute.go | main/commands/base/execute.rs | ✅ 已真实重构 | 命令执行驱动器 |
| 450 | main/commands/base/help.go | main/commands/base/help.rs | ✅ 已真实重构 | 帮助文档自动格式化渲染 |
| 451 | main/commands/base/root.go | main/commands/base/root.rs | ✅ 已真实重构 | 根命令定义 |
| 452 | main/confloader/confloader.go | main/confloader/confloader.rs | ✅ 已真实重构 | 2套配置加载单测全通过 |
| 453 | main/confloader/external/external.go | main/confloader/external/external.rs | ✅ 已真实重构 | 外部协议 URL 校验单测通过 |
| 454 | main/distro/all/all.go | main/distro/all/all.rs | ✅ 已真实重构 | test_distro_all 单测通过 |
| 455 | main/distro/debug/debug.go | main/distro/debug/debug.rs | ✅ 已真实重构 | test_distro_debug 单测通过 |
| 456 | main/json/json.go | main/json/json.rs | ✅ 已真实重构 | test_load_json_from_slice 单测通过 |
| 457 | main/main.go | main/main.rs | ✅ 已真实重构 | Xray CLI 主入口全命令调度 |
| 458 | main/main_test.go | main/main_test.rs | ✅ 已真实重构 | test_main_version 单测通过 |
| 459 | main/run.go | main/run.rs | ✅ 已真实重构 | run_server 异步实例运行器 |
| 460 | main/toml/toml.go | main/toml/toml.rs | ✅ 已真实重构 | test_toml_format_const 单测通过 |
| 461 | main/version.go | main/version.rs | ✅ 已真实重构 | 1:1 版本声明与格式化输出 |
| 462 | main/yaml/yaml.go | main/yaml/yaml.rs | ✅ 已真实重构 | test_yaml_format_const 单测通过 |
| 463 | proxy/blackhole/blackhole.go | proxy/blackhole/mod.rs | ✅ 已真实重构 | 路由拦截测试 |
| 464 | proxy/blackhole/blackhole_test.go | proxy/blackhole/blackhole_test.rs | ✅ 已真实重构 | test_blackhole_http_403_response 单测通过 |
| 465 | proxy/blackhole/config.go | proxy/blackhole/config.rs | ✅ 已真实重构 | BlackholeConfig 与 ResponseType 配置模型 |
| 466 | proxy/blackhole/config.pb.go | proxy/blackhole/config.pb.rs | ✅ 已真实重构 | Protobuf 兼容反序列化模型 |
| 467 | proxy/blackhole/config_test.go | proxy/blackhole/config_test.rs | ✅ 已真实重构 | test_blackhole_config_defaults 单测通过 |
| 468 | proxy/dns/config.pb.go | proxy/dns/config.pb.rs | ✅ 已真实重构 | DNS 代理配置 Protobuf 映射 |
| 469 | proxy/dns/dns.go | proxy/dns/mod.rs | ✅ 已真实重构 | test_dns_proxy_outbound_response |
| 470 | proxy/dns/dns_test.go | proxy/dns/dns_test.rs | ✅ 已真实重构 | test_dns_proxy_creation 单测通过 |
| 471 | proxy/dokodemo/config.go | proxy/dokodemo/config.rs | ✅ 已真实重构 | DokodemoConfig 配置定义与解析 |
| 472 | proxy/dokodemo/config.pb.go | proxy/dokodemo/config.pb.rs | ✅ 已真实重构 | Protobuf 兼容模型映射 |
| 473 | proxy/dokodemo/dokodemo.go | proxy/dokodemo/mod.rs | ✅ 已真实重构 | test_dokodemo_port_forward |
| 474 | proxy/dokodemo/fakeudp_linux.go | proxy/dokodemo/fakeudp_linux.rs | ✅ 已真实重构 | test_is_tproxy_supported_flag 单测通过 |
| 475 | proxy/dokodemo/fakeudp_other.go | proxy/dokodemo/fakeudp_other.rs | ✅ 已真实重构 | test_fake_udp_other_unsupported 单测通过 |
| 476 | proxy/freedom/config.go | proxy/freedom/config.rs | ✅ 已真实重构 | FreedomConfig 配置定义与解析 |
| 477 | proxy/freedom/config.pb.go | proxy/freedom/config.pb.rs | ✅ 已真实重构 | Protobuf 兼容模型映射 |
| 478 | proxy/freedom/freedom.go | proxy/freedom/mod.rs | ✅ 已真实重构 | 路由测试集成 |
| 479 | proxy/http/client.go | proxy/http/client.rs | ✅ 已真实重构 | HttpClient HTTP CONNECT 代理客户端与 Basic Auth |
| 480 | proxy/http/config.go | proxy/http/config.rs | ✅ 已真实重构 | HttpConfig 配置反序列化 |
| 481 | proxy/http/config.pb.go | proxy/http/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 482 | proxy/http/http.go | proxy/http/mod.rs | ✅ 已真实重构 | HTTP 代理通用定义 |
| 483 | proxy/http/server.go | proxy/http/mod.rs | ✅ 已真实重构 | test_mixed_inbound_socks_and_http_dual_mode |
| 484 | proxy/hysteria/account/config.go | proxy/hysteria/account/config.rs | ✅ 已真实重构 | Account 认证与用户权限配置 |
| 485 | proxy/hysteria/account/config.pb.go | proxy/hysteria/account/config.pb.rs | ✅ 已真实重构 | Protobuf 兼容模型映射 |
| 486 | proxy/hysteria/client.go | proxy/hysteria/client.rs | ✅ 已真实重构 | HysteriaClient 出站连接与 TcpRequest 帧编码 |
| 487 | proxy/hysteria/config.go | proxy/hysteria/config.rs | ✅ 已真实重构 | HysteriaConfig 速率与认证配置 |
| 488 | proxy/hysteria/config.pb.go | proxy/hysteria/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 489 | proxy/hysteria/ctx/ctx.go | proxy/hysteria/ctx/ctx.rs | ✅ 已真实重构 | test_hysteria_context_datagram 单测通过 |
| 490 | proxy/hysteria/frag.go | proxy/hysteria/frag.rs | ✅ 已真实重构 | test_hysteria_frag_and_defrag 单测通过 |
| 491 | proxy/hysteria/protocol.go | proxy/hysteria/protocol.rs | ✅ 已真实重构 | test_quic_varint_roundtrip 与 TcpRequest 往返单测 |
| 492 | proxy/hysteria/server.go | proxy/hysteria/server.rs | ✅ 已真实重构 | HysteriaServer 入站监听与请求帧目标解析 |
| 493 | proxy/loopback/config.go | proxy/loopback/config.rs | ✅ 已真实重构 | Loopback 配置定义 |
| 494 | proxy/loopback/config.pb.go | proxy/loopback/config.rs | ✅ 已真实重构 | Serde 配置映射 |
| 495 | proxy/loopback/loopback.go | proxy/loopback/mod.rs | ✅ 已真实重构 | 全量集成测试 |
| 496 | proxy/proxy.go | proxy/proxy.rs | ✅ 已真实重构 | 通用代理 Handler/Client 注册中心 |
| 497 | proxy/shadowsocks/client.go | proxy/shadowsocks/client.rs | ✅ 已真实重构 | Shadowsocks AEAD/Stream 出站客户端 |
| 498 | proxy/shadowsocks/config.go | proxy/shadowsocks/config.rs | ✅ 已真实重构 | Shadowsocks 加密套件与用户配置 |
| 499 | proxy/shadowsocks/config.pb.go | proxy/shadowsocks/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 500 | proxy/shadowsocks/config_test.go | proxy/shadowsocks/config_test.rs | ✅ 已真实重构 | 单测验证 |
| 501 | proxy/shadowsocks/protocol.go | proxy/shadowsocks/protocol.rs | ✅ 已真实重构 | test_shadowsocks_hkdf_subkey_derivation |
| 502 | proxy/shadowsocks/protocol_test.go | proxy/shadowsocks/protocol_test.rs | ✅ 已真实重构 | 单元测试 |
| 503 | proxy/shadowsocks/server.go | proxy/shadowsocks/server.rs | ✅ 已真实重构 | Shadowsocks 入站服务与目标地址解析 |
| 504 | proxy/shadowsocks/shadowsocks.go | proxy/shadowsocks/mod.rs | ✅ 已真实重构 | Shadowsocks 模块导出 |
| 505 | proxy/shadowsocks/validator.go | proxy/shadowsocks/validator.rs | ✅ 已真实重构 | 用户密钥与密码验证器 |
| 506 | proxy/shadowsocks_2022/config.go | proxy/shadowsocks_2022/config.rs | ✅ 已真实重构 | SS-2022 配置定义 |
| 507 | proxy/shadowsocks_2022/config.pb.go | proxy/shadowsocks_2022/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 508 | proxy/shadowsocks_2022/inbound.go | proxy/shadowsocks_2022/server.rs | ✅ 已真实重构 | SS-2022 防重放滑动窗口与请求解密 |
| 509 | proxy/shadowsocks_2022/inbound_multi.go | proxy/shadowsocks_2022/inbound_multi.rs | ✅ 已真实重构 | test_ss2022_multi_user_lifecycle 单测通过 |
| 510 | proxy/shadowsocks_2022/inbound_relay.go | proxy/shadowsocks_2022/inbound_relay.rs | ✅ 已真实重构 | test_ss2022_relay_inbound 单测通过 |
| 511 | proxy/shadowsocks_2022/outbound.go | proxy/shadowsocks_2022/client.rs | ✅ 已真实重构 | SS-2022 会话请求封装与响应验证 |
| 512 | proxy/shadowsocks_2022/shadowsocks_2022.go | proxy/shadowsocks_2022/mod.rs | ✅ 已真实重构 | SS-2022 核心导出 |
| 513 | proxy/socks/client.go | proxy/socks/client.rs | ✅ 已真实重构 | SOCKS5 出站握手与地址转发 |
| 514 | proxy/socks/config.go | proxy/socks/config.rs | ✅ 已真实重构 | SOCKS 配置定义 |
| 515 | proxy/socks/config.pb.go | proxy/socks/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 516 | proxy/socks/protocol.go | proxy/socks/protocol.rs | ✅ 已真实重构 | SOCKS5 握手/地址协议编解码 |
| 517 | proxy/socks/protocol_test.go | proxy/socks/protocol_test.rs | ✅ 已真实重构 | test_socks5_protocol 单测验证 |
| 518 | proxy/socks/server.go | proxy/socks/mod.rs | ✅ 已真实重构 | test_socks5_direct_echo |
| 519 | proxy/socks/socks.go | proxy/socks/socks.rs | ✅ 已真实重构 | SOCKS 通用协议定义 |
| 520 | proxy/socks/udpfilter.go | proxy/socks/udpfilter.rs | ✅ 已真实重构 | SOCKS UDP 过滤器 |
| 521 | proxy/trojan/client.go | proxy/trojan/client.rs | ✅ 已真实重构 | Trojan 出站客户端与 SHA224 握手 |
| 522 | proxy/trojan/config.go | proxy/trojan/config.rs | ✅ 已真实重构 | Trojan 配置解析 |
| 523 | proxy/trojan/config.pb.go | proxy/trojan/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 524 | proxy/trojan/protocol.go | proxy/trojan/protocol.rs | ✅ 已真实重构 | test_trojan_tcp_request_header_roundtrip |
| 525 | proxy/trojan/protocol_test.go | proxy/trojan/protocol_test.rs | ✅ 已真实重构 | 单元测试 |
| 526 | proxy/trojan/server.go | proxy/trojan/server.rs | ✅ 已真实重构 | Trojan 入站服务端与回落路由 |
| 527 | proxy/trojan/trojan.go | proxy/trojan/mod.rs | ✅ 已真实重构 | Trojan 核心导出 |
| 528 | proxy/trojan/validator.go | proxy/trojan/validator.rs | ✅ 已真实重构 | Trojan 密码 SHA224 内存校验器 |
| 529 | proxy/tun/config.go | proxy/tun/config.rs | ✅ 已真实重构 | TunConfig 配置反序列化与系统栈选择 |
| 530 | proxy/tun/config.pb.go | proxy/tun/config.pb.rs | ✅ 已真实重构 | Protobuf 兼容模型映射 |
| 531 | proxy/tun/handler.go | proxy/tun/mod.rs | ✅ 已真实重构 | test_tun_ip_packet_parsing |
| 532 | proxy/tun/stack.go | proxy/tun/stack.rs | ✅ 已真实重构 | TunStack 枚举模型 (System/GVisor/Mixed) |
| 533 | proxy/tun/stack_gvisor.go | proxy/tun/stack_gvisor.rs | ✅ 已真实重构 | GVisorStack 网络栈封装与 MTU 设定 |
| 534 | proxy/tun/stack_gvisor_endpoint.go | proxy/tun/stack_gvisor_endpoint.rs | ✅ 已真实重构 | GVisorEndpoint 数据通道端点 |
| 535 | proxy/tun/tun.go | proxy/tun/mod.rs | ✅ 已真实重构 | test_tun_ip_packet_parsing |
| 536 | proxy/tun/tun_android.go | proxy/tun/tun_android.rs | ✅ 已真实重构 | Android TUN 驱动抽象适配 |
| 537 | proxy/tun/tun_darwin.go | proxy/tun/tun_darwin.rs | ✅ 已真实重构 | Darwin TUN utun 抽象适配 |
| 538 | proxy/tun/tun_default.go | proxy/tun/tun_default.rs | ✅ 已真实重构 | 跨平台默认 TUN 抽象与回退 |
| 539 | proxy/tun/tun_linux.go | proxy/tun/tun_linux.rs | ✅ 已真实重构 | Linux TUN/TAP 设备驱动 |
| 540 | proxy/tun/tun_windows.go | proxy/tun/tun_windows.rs | ✅ 已真实重构 | Wintun 驱动调用与环形缓冲区单测通过 |
| 541 | proxy/tun/udp_fullcone.go | proxy/tun/udp_fullcone.rs | ✅ 已真实重构 | test_udp_nat_table_insert_and_lookup 单测通过 |
| 542 | proxy/vless/account.go | proxy/vless/account.rs | ✅ 已真实重构 | VLESS 用户账号模型与 flow 绑定 |
| 543 | proxy/vless/account.pb.go | proxy/vless/account.pb.rs | ✅ 已真实重构 | Protobuf 兼容反序列化模型 |
| 544 | proxy/vless/encoding/addons.go | proxy/vless/encoding/mod.rs | ✅ 已真实重构 | test_vless_addons_protobuf_roundtrip |
| 545 | proxy/vless/encoding/addons.pb.go | proxy/vless/encoding/addons.pb.rs | ✅ 已真实重构 | Addons Protobuf 模型映射 |
| 546 | proxy/vless/encoding/encoding.go | proxy/vless/encoding/mod.rs | ✅ 已真实重构 | test_vless_request_and_response_header_roundtrip |
| 547 | proxy/vless/encoding/encoding_test.go | proxy/vless/encoding/encoding_test.rs | ✅ 已真实重构 | test_vless_addons 单测通过 |
| 548 | proxy/vless/encryption/client.go | proxy/vless/encryption/client.rs | ✅ 已真实重构 | VLESS AEAD 客户端连接 |
| 549 | proxy/vless/encryption/common.go | proxy/vless/encryption/common.rs | ✅ 已真实重构 | AesGcm/ChaCha20Poly1305 AEAD 加解密与数据帧封装 |
| 550 | proxy/vless/encryption/server.go | proxy/vless/encryption/server.rs | ✅ 已真实重构 | VLESS AEAD 服务端连接 |
| 551 | proxy/vless/encryption/xor.go | proxy/vless/encryption/xor.rs | ✅ 已真实重构 | 流式 XOR 掩码 |
| 552 | proxy/vless/inbound/config.go | proxy/vless/inbound/config.rs | ✅ 已真实重构 | VLESS 入站配置 |
| 553 | proxy/vless/inbound/config.pb.go | proxy/vless/inbound/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 554 | proxy/vless/inbound/inbound.go | proxy/vless/inbound/inbound.rs | ✅ 已真实重构 | test_vless_tcp_xor |
| 555 | proxy/vless/outbound/config.go | proxy/vless/outbound/config.rs | ✅ 已真实重构 | VLESS 出站配置 |
| 556 | proxy/vless/outbound/config.pb.go | proxy/vless/outbound/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 557 | proxy/vless/outbound/outbound.go | proxy/vless/outbound/outbound.rs | ✅ 已真实重构 | test_vless_large_payload_stream |
| 558 | proxy/vless/validator.go | proxy/vless/validator.rs | ✅ 已真实重构 | MemoryUser 校验器与 UUID 验证 |
| 559 | proxy/vless/vless.go | proxy/vless/mod.rs | ✅ 已真实重构 | VLESS 核心导出 |
| 560 | proxy/vmess/account.go | proxy/vmess/account.rs | ✅ 已真实重构 | VMess 用户账号 |
| 561 | proxy/vmess/account.pb.go | proxy/vmess/account.rs | ✅ 已真实重构 | Serde 模型映射 |
| 562 | proxy/vmess/aead/authid.go | proxy/vmess/aead/authid.rs | ✅ 已真实重构 | AuthID 算法与哈希校验 |
| 563 | proxy/vmess/aead/authid_test.go | proxy/vmess/aead/authid_test.rs | ✅ 已真实重构 | 单测验证 |
| 564 | proxy/vmess/aead/consts.go | proxy/vmess/aead/consts.rs | ✅ 已真实重构 | AEAD 常量定义 |
| 565 | proxy/vmess/aead/encrypt.go | proxy/vmess/aead/encrypt.rs | ✅ 已真实重构 | VMess AEAD 加密/解密流 |
| 566 | proxy/vmess/aead/encrypt_test.go | proxy/vmess/aead/encrypt_test.rs | ✅ 已真实重构 | 单元测试 |
| 567 | proxy/vmess/aead/kdf.go | proxy/vmess/aead/kdf.rs | ✅ 已真实重构 | HMAC-SHA256 密钥衍生 KDF |
| 568 | proxy/vmess/encoding/auth.go | proxy/vmess/encoding/mod.rs | ✅ 已真实重构 | test_vmess_fnv1a_and_key_generation |
| 569 | proxy/vmess/encoding/client.go | proxy/vmess/encoding/mod.rs | ✅ 已真实重构 | test_vmess_request_and_response_header_roundtrip |
| 570 | proxy/vmess/encoding/commands.go | proxy/vmess/encoding/commands.rs | ✅ 已真实重构 | VMess 命令响应 |
| 571 | proxy/vmess/encoding/encoding.go | proxy/vmess/encoding/encoding.rs | ✅ 已真实重构 | 数据帧编码 |
| 572 | proxy/vmess/encoding/encoding_test.go | proxy/vmess/encoding/encoding_test.rs | ✅ 已真实重构 | 单测验证 |
| 573 | proxy/vmess/encoding/server.go | proxy/vmess/encoding/mod.rs | ✅ 已真实重构 | test_vmess_tcp_relay |
| 574 | proxy/vmess/inbound/config.go | proxy/vmess/inbound/config.rs | ✅ 已真实重构 | VMess 入站配置 |
| 575 | proxy/vmess/inbound/config.pb.go | proxy/vmess/inbound/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 576 | proxy/vmess/inbound/inbound.go | proxy/vmess/inbound/inbound.rs | ✅ 已真实重构 | test_vmess_tcp_relay |
| 577 | proxy/vmess/outbound/command.go | proxy/vmess/outbound/command.rs | ✅ 已真实重构 | 出站命令处理 |
| 578 | proxy/vmess/outbound/config.go | proxy/vmess/outbound/config.rs | ✅ 已真实重构 | VMess 出站配置 |
| 579 | proxy/vmess/outbound/config.pb.go | proxy/vmess/outbound/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 580 | proxy/vmess/outbound/outbound.go | proxy/vmess/outbound/outbound.rs | ✅ 已真实重构 | test_vmess_tcp_relay |
| 581 | proxy/vmess/validator.go | proxy/vmess/validator.rs | ✅ 已真实重构 | TimedVault 防重放与用户 UUID 校验 |
| 582 | proxy/vmess/validator_test.go | proxy/vmess/validator_test.rs | ✅ 已真实重构 | 单元测试 |
| 583 | proxy/vmess/vmess.go | proxy/vmess/mod.rs | ✅ 已真实重构 | VMess 核心导出 |
| 584 | proxy/wireguard/bind.go | proxy/wireguard/bind.rs | ✅ 已真实重构 | WireGuard NetBind 绑定 |
| 585 | proxy/wireguard/client.go | proxy/wireguard/client.rs | ✅ 已真实重构 | test_wireguard_udp_relay |
| 586 | proxy/wireguard/config.go | proxy/wireguard/config.rs | ✅ 已真实重构 | WireGuard 配置与 Peer 解析 |
| 587 | proxy/wireguard/config.pb.go | proxy/wireguard/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 588 | proxy/wireguard/gvisortun/tun.go | proxy/wireguard/gvisortun/tun.rs | ✅ 已真实重构 | gVisor 网络栈接口 |
| 589 | proxy/wireguard/server.go | proxy/wireguard/server.rs | ✅ 已真实重构 | WireGuard 服务端处理器 |
| 590 | proxy/wireguard/server_test.go | proxy/wireguard/server_test.rs | ✅ 已真实重构 | 单元测试 |
| 591 | proxy/wireguard/tun.go | proxy/wireguard/tun.rs | ✅ 已真实重构 | TUN 设备封装 |
| 592 | proxy/wireguard/tun_default.go | proxy/wireguard/tun_default.rs | ✅ 已真实重构 | 平台默认 TUN 抽象 |
| 593 | proxy/wireguard/tun_linux.go | proxy/wireguard/tun_linux.rs | ✅ 已真实重构 | Linux TUN 驱动抽象 |
| 594 | proxy/wireguard/wireguard.go | proxy/wireguard/wireguard.rs | ✅ 已真实重构 | UAPI IPC 配置序列化与端点校验 |
| 595 | testing/mocks/dns.go | testing/mocks/dns.rs | ✅ 已真实重构 | MockDnsServer 单测通过 |
| 596 | testing/mocks/io.go | testing/mocks/io.rs | ✅ 已真实重构 | MockIoPair 双工内存流测试通过 |
| 597 | testing/mocks/log.go | testing/mocks/log.rs | ✅ 已真实重构 | MockLogCollector 单测通过 |
| 598 | testing/mocks/mux.go | testing/mocks/mux.rs | ✅ 已真实重构 | MockMuxSession 会话 ID 分配单测通过 |
| 599 | testing/mocks/outbound.go | testing/mocks/outbound.rs | ✅ 已真实重构 | MockOutboundHandler 调用计数与出站连接单测通过 |
| 600 | testing/mocks/proxy.go | testing/mocks/proxy.rs | ✅ 已真实重构 | MockInboundHandler / MockProxyHandler 单测通过 |
| 601 | testing/scenarios/command_test.go | testing/scenarios/command_test.rs | ✅ 已真实重构 | 命令调用场景测试通过 |
| 602 | testing/scenarios/common.go | testing/scenarios/common.rs | ✅ 已真实重构 | TestEnvironment 场景测试运行时框架 |
| 603 | testing/scenarios/common_coverage.go | testing/scenarios/common_coverage.rs | ✅ 已真实重构 | 测试覆盖率收集器抽象 |
| 604 | testing/scenarios/common_regular.go | testing/scenarios/common_regular.rs | ✅ 已真实重构 | 常规测试环境预设 |
| 605 | testing/scenarios/dns_test.go | testing/scenarios/dns_test.rs | ✅ 已真实重构 | DNS 解析与静态 hosts 端到端测试通过 |
| 606 | testing/scenarios/dokodemo_test.go | testing/scenarios/dokodemo_test.rs | ✅ 已真实重构 | Dokodemo 端口转发场景测试通过 |
| 607 | testing/scenarios/feature_test.go | testing/scenarios/feature_test.rs | ✅ 已真实重构 | 动态特性集成场景测试通过 |
| 608 | testing/scenarios/http_test.go | testing/scenarios/http_test.rs | ✅ 已真实重构 | HTTP CONNECT 与 POST 全一致性测试通过 |
| 609 | testing/scenarios/main_test.go | testing/scenarios/main_test.rs | ✅ 已真实重构 | 主版本与发行版环境测试通过 |
| 610 | testing/scenarios/metrics_test.go | testing/scenarios/metrics_test.rs | ✅ 已真实重构 | 指标收集与 Prometheus 导出场景测试通过 |
| 611 | testing/scenarios/policy_test.go | testing/scenarios/policy_test.rs | ✅ 已真实重构 | 策略超时与缓冲配置场景测试通过 |
| 612 | testing/scenarios/reverse_test.go | testing/scenarios/reverse_test.rs | ✅ 已真实重构 | 反向代理内外网隧道穿透测试通过 |
| 613 | testing/scenarios/shadowsocks_2022_test.go | testing/scenarios/shadowsocks_2022_test.rs | ✅ 已真实重构 | SS-2022 头部往返场景测试通过 |
| 614 | testing/scenarios/shadowsocks_test.go | testing/scenarios/shadowsocks_test.rs | ✅ 已真实重构 | Shadowsocks TCP/UDP 中继全流程测试通过 |
| 615 | testing/scenarios/socks_test.go | testing/scenarios/socks_test.rs | ✅ 已真实重构 | SOCKS5 回环转发与桥接场景测试通过 |
| 616 | testing/scenarios/tls_test.go | testing/scenarios/tls_test.rs | ✅ 已真实重构 | TLS 端到端安全连接与证书固定测试通过 |
| 617 | testing/scenarios/transport_test.go | testing/scenarios/transport_test.rs | ✅ 已真实重构 | 传输层流设置与 TCP 拨号回显测试通过 |
| 618 | testing/scenarios/vless_test.go | testing/scenarios/vless_test.rs | ✅ 已真实重构 | VLESS TCP/XOR/大载荷流/鉴权拦截场景测试全通过 |
| 619 | testing/scenarios/vmess_test.go | testing/scenarios/vmess_test.rs | ✅ 已真实重构 | VMess TCP 中继与动态用户验证测试通过 |
| 620 | testing/scenarios/wireguard_test.go | testing/scenarios/wireguard_test.rs | ✅ 已真实重构 | WireGuard UDP 隧道转发场景测试通过 |
| 621 | testing/servers/http/http.go | testing/servers/http/http.rs | ✅ 已真实重构 | 测试专用 HTTP 模拟服务器 |
| 622 | testing/servers/tcp/port.go | testing/servers/tcp/port.rs | ✅ 已真实重构 | TCP 动态临时端口探测器 |
| 623 | testing/servers/tcp/tcp.go | testing/servers/tcp/tcp.rs | ✅ 已真实重构 | 测试专用 TCP 回显与 XOR 处理服务器 |
| 624 | testing/servers/udp/port.go | testing/servers/udp/port.rs | ✅ 已真实重构 | UDP 动态临时端口探测器 |
| 625 | testing/servers/udp/udp.go | testing/servers/udp/udp.rs | ✅ 已真实重构 | 测试专用 UDP 数据报收发处理服务器 |
| 626 | transport/internet/browser_dialer/dialer.go | transport/internet/browser_dialer/dialer.rs | ✅ 已真实重构 | BrowserDialer 任务模型、序列化与 2 项单测全通过 |
| 627 | transport/internet/config.go | transport/internet/config.rs | ✅ 已真实重构 | 1:1 DomainStrategy 路由表与 StreamConfig 运行时模型 |
| 628 | transport/internet/config.pb.go | transport/internet/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置与枚举定义 |
| 629 | transport/internet/dialer.go | transport/internet/dialer.rs | ✅ 已真实重构 | Dialer Trait、TransportDialer 动态分发与系统拨号 |
| 630 | transport/internet/dialer_test.go | transport/internet/dialer_test.rs | ✅ 已真实重构 | 4 项本地回环拨号、动态注册与域名策略单测全通过 |
| 631 | transport/internet/filelocker.go | transport/internet/filelocker.rs | ✅ 已真实重构 | test_filelocker_lifecycle 跨平台文件锁单测 |
| 632 | transport/internet/filelocker_other.go | transport/internet/filelocker.rs | ✅ 已真实重构 | 非 Windows 平台占位实现 |
| 633 | transport/internet/filelocker_windows.go | transport/internet/filelocker.rs | ✅ 已真实重构 | Windows 平台 LockFileEx/UnlockFile 实现 |
| 634 | transport/internet/finalmask/finalmask.go | transport/internet/finalmask/finalmask.rs | ✅ 已真实重构 | HeaderManager / UdpmaskManager / TcpmaskManager 与 UnwrapTcpMask |
| 635 | transport/internet/finalmask/fragment/config.go | transport/internet/finalmask/fragment/config.rs | ✅ 已真实重构 | Config 客户端/服务端包装器定义 |
| 636 | transport/internet/finalmask/fragment/config.pb.go | transport/internet/finalmask/fragment/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 637 | transport/internet/finalmask/fragment/conn.go | transport/internet/finalmask/fragment/conn.rs | ✅ 已真实重构 | FragmentConn TLS ClientHello 深度分片与数据流拆分，单测全通过 |
| 638 | transport/internet/finalmask/header/custom/config.go | transport/internet/finalmask/header/custom/config.rs | ✅ 已真实重构 | TCPConfig / UDPConfig / TCPSequence 配置模型 |
| 639 | transport/internet/finalmask/header/custom/config.pb.go | transport/internet/finalmask/header/custom/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 640 | transport/internet/finalmask/header/custom/tcp.go | transport/internet/finalmask/header/custom/tcp.rs | ✅ 已真实重构 | client_handshake / server_handshake 握手与序列双向校验 |
| 641 | transport/internet/finalmask/header/custom/udp.go | transport/internet/finalmask/header/custom/udp.rs | ✅ 已真实重构 | UdpCustomClient / UdpCustomServer 模版匹配与数据包封解包 |
| 642 | transport/internet/finalmask/header/dns/config.go | transport/internet/finalmask/header/dns/config.rs | ✅ 已真实重构 | DnsHeaderConfig 配置模型 |
| 643 | transport/internet/finalmask/header/dns/config.pb.go | transport/internet/finalmask/header/dns/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 644 | transport/internet/finalmask/header/dns/conn.go | transport/internet/finalmask/header/dns/conn.rs | ✅ 已真实重构 | DnsPacketConn 53端口伪装与 1:1 DNS Header 序列化 |
| 645 | transport/internet/finalmask/header/dtls/config.go | transport/internet/finalmask/header/dtls/config.rs | ✅ 已真实重构 | DtlsHeaderConfig 配置模型 |
| 646 | transport/internet/finalmask/header/dtls/config.pb.go | transport/internet/finalmask/header/dtls/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 647 | transport/internet/finalmask/header/dtls/conn.go | transport/internet/finalmask/header/dtls/conn.rs | ✅ 已真实重构 | DtlsPacketConn 13-byte DTLS 1.2 头部伪装与步进序列号 |
| 648 | transport/internet/finalmask/header/srtp/config.go | transport/internet/finalmask/header/srtp/config.rs | ✅ 已真实重构 | SrtpHeaderConfig 配置模型 |
| 649 | transport/internet/finalmask/header/srtp/config.pb.go | transport/internet/finalmask/header/srtp/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 650 | transport/internet/finalmask/header/srtp/conn.go | transport/internet/finalmask/header/srtp/conn.rs | ✅ 已真实重构 | SrtpPacketConn 4-byte SRTP 头部伪装与单测验证 |
| 651 | transport/internet/finalmask/header/utp/config.go | transport/internet/finalmask/header/utp/config.rs | ✅ 已真实重构 | UtpHeaderConfig 配置模型 |
| 652 | transport/internet/finalmask/header/utp/config.pb.go | transport/internet/finalmask/header/utp/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 653 | transport/internet/finalmask/header/utp/conn.go | transport/internet/finalmask/header/utp/conn.rs | ✅ 已真实重构 | UtpPacketConn 4-byte uTP 协议头部伪装与单测验证 |
| 654 | transport/internet/finalmask/header/wechat/config.go | transport/internet/finalmask/header/wechat/config.rs | ✅ 已真实重构 | WeChatHeaderConfig 配置模型 |
| 655 | transport/internet/finalmask/header/wechat/config.pb.go | transport/internet/finalmask/header/wechat/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 656 | transport/internet/finalmask/header/wechat/conn.go | transport/internet/finalmask/header/wechat/conn.rs | ✅ 已真实重构 | WeChatPacketConn 13-byte 微信视频协议特征头部混淆 |
| 657 | transport/internet/finalmask/header/wireguard/config.go | transport/internet/finalmask/header/wireguard/config.rs | ✅ 已真实重构 | WireguardHeaderConfig 配置模型 |
| 658 | transport/internet/finalmask/header/wireguard/config.pb.go | transport/internet/finalmask/header/wireguard/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 659 | transport/internet/finalmask/header/wireguard/conn.go | transport/internet/finalmask/header/wireguard/conn.rs | ✅ 已真实重构 | WireguardPacketConn 4-byte WireGuard 握手前缀头部包装 |
| 660 | transport/internet/finalmask/mkcp/aes128gcm/aes128gcm_test.go | transport/internet/finalmask/mkcp/aes128gcm/aes128gcm_test.rs | ✅ 已真实重构 | AES-128-GCM 加密解密与退避单测通过 |
| 661 | transport/internet/finalmask/mkcp/aes128gcm/config.go | transport/internet/finalmask/mkcp/aes128gcm/config.rs | ✅ 已真实重构 | Aes128GcmConfig 配置模型 |
| 662 | transport/internet/finalmask/mkcp/aes128gcm/config.pb.go | transport/internet/finalmask/mkcp/aes128gcm/config.rs | ✅ 已真实重构 | Serde Protobuf 序列化支持 |
| 663 | transport/internet/finalmask/mkcp/aes128gcm/conn.go | transport/internet/finalmask/mkcp/aes128gcm/conn.rs | ✅ 已真实重构 | Aes128GcmPacketConn 真实 12-byte Nonce 与 16-byte Tag 封包与解包 |
| 664 | transport/internet/finalmask/mkcp/original/config.go | transport/internet/finalmask/mkcp/original/config.rs | ✅ 已真实重构 | OriginalConfig 配置模型 |
| 665 | transport/internet/finalmask/mkcp/original/config.pb.go | transport/internet/finalmask/mkcp/original/config.rs | ✅ 已真实重构 | Serde Protobuf 序列化支持 |
| 666 | transport/internet/finalmask/mkcp/original/conn.go | transport/internet/finalmask/mkcp/original/conn.rs | ✅ 已真实重构 | SimpleAead 6字节开销、FNV-1a 认证与完整封包/解包 |
| 667 | transport/internet/finalmask/mkcp/original/simple_test.go | transport/internet/finalmask/mkcp/original/simple_test.rs | ✅ 已真实重构 | 端到端与随机数据抗退避单测通过 |
| 668 | transport/internet/finalmask/mkcp/original/xor.go | transport/internet/finalmask/mkcp/original/xor.rs | ✅ 已真实重构 | xorfwd / xorbkd 原版 1:1 双向级联 XOR 算法 |
| 669 | transport/internet/finalmask/mkcp/original/xor_amd64.go | transport/internet/finalmask/mkcp/original/xor_amd64.rs | ✅ 已真实重构 | 汇编级等价安全 Rust 级联 XOR |
| 670 | transport/internet/finalmask/noise/config.go | transport/internet/finalmask/noise/config.rs | ✅ 已真实重构 | NoiseConfig 与 NoiseItem 范围配置 |
| 671 | transport/internet/finalmask/noise/config.pb.go | transport/internet/finalmask/noise/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 672 | transport/internet/finalmask/noise/conn.go | transport/internet/finalmask/noise/conn.rs | ✅ 已真实重构 | NoisePacketConn 会话级首包噪声注入与 TTL 淘汰机制 |
| 673 | transport/internet/finalmask/salamander/config.go | transport/internet/finalmask/salamander/config.rs | ✅ 已真实重构 | SalamanderConfig 模型 |
| 674 | transport/internet/finalmask/salamander/config.pb.go | transport/internet/finalmask/salamander/config.rs | ✅ 已真实重构 | Serde JSON 序列化映射 |
| 675 | transport/internet/finalmask/salamander/conn.go | transport/internet/finalmask/salamander/conn.rs | ✅ 已真实重构 | SalamanderPacketConn 数据报掩码包装器 |
| 676 | transport/internet/finalmask/salamander/salamander.go | transport/internet/finalmask/salamander/salamander.rs | ✅ 已真实重构 | RFC 7693 BLAKE2b-256 盐值与 XOR 混淆器 |
| 677 | transport/internet/finalmask/salamander/salamander_test.go | transport/internet/finalmask/salamander/salamander_test.rs | ✅ 已真实重构 | 混淆、短包退避、PacketConn 全套单测 |
| 678 | transport/internet/finalmask/sudoku/codec.go | transport/internet/finalmask/sudoku/codec.rs | ✅ 已真实重构 | 24 种排列编码与解码状态机 |
| 679 | transport/internet/finalmask/sudoku/config.go | transport/internet/finalmask/sudoku/config.rs | ✅ 已真实重构 | SudokuConfig 规范化与布局策略 |
| 680 | transport/internet/finalmask/sudoku/config.pb.go | transport/internet/finalmask/sudoku/config.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 681 | transport/internet/finalmask/sudoku/conn_tcp.go | transport/internet/finalmask/sudoku/conn_tcp.rs | ✅ 已真实重构 | 双向流 HintStreamDecoder 与防截断 |
| 682 | transport/internet/finalmask/sudoku/conn_tcp_packed.go | transport/internet/finalmask/sudoku/conn_tcp_packed.rs | ✅ 已真实重构 | 6-bit 压缩下行流编解码 |
| 683 | transport/internet/finalmask/sudoku/conn_udp.go | transport/internet/finalmask/sudoku/conn_udp.rs | ✅ 已真实重构 | 数据包零状态重置与混淆/解混淆 |
| 684 | transport/internet/finalmask/sudoku/sudoku_test.go | transport/internet/finalmask/sudoku/sudoku_test.rs | ✅ 已真实重构 | 6项单测全覆盖且全通过 |
| 685 | transport/internet/finalmask/sudoku/table.go | transport/internet/finalmask/sudoku/table.rs | ✅ 已真实重构 | 4x4 拉丁方块 288 网格、1820 提示位与 Go 兼容 PRNG |
| 686 | transport/internet/finalmask/tcp_test.go | transport/internet/finalmask/tcp_test.rs | ✅ 已真实重构 | 自定义 TCP 全握手与双向序列加解密单测全通过 |
| 687 | transport/internet/finalmask/udp_test.go | transport/internet/finalmask/udp_test.rs | ✅ 已真实重构 | 8 项 UDP 混淆协议与 HeaderManager 组合单测全通过 |
| 688 | transport/internet/finalmask/xdns/client.go | transport/internet/finalmask/xdns/client.rs | ✅ 已真实重构 | XDnsClient 客户端会话、Base32标签分块与 EDNS0 OPT 报文封装 |
| 689 | transport/internet/finalmask/xdns/config.go | transport/internet/finalmask/xdns/config.rs | ✅ 已真实重构 | XDnsConfig 与域名后缀匹配逻辑 |
| 690 | transport/internet/finalmask/xdns/config.pb.go | transport/internet/finalmask/xdns/config.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 691 | transport/internet/finalmask/xdns/dns.go | transport/internet/finalmask/xdns/dns.rs | ✅ 已真实重构 | RFC 1035 Wire 格式编解码、压缩指针算法与 RFC 4648 Base32 |
| 692 | transport/internet/finalmask/xdns/dns_test.go | transport/internet/finalmask/xdns/dns_test.rs | ✅ 已真实重构 | RFC 向量测试与压缩打包 6 项单测全通过 |
| 693 | transport/internet/finalmask/xdns/server.go | transport/internet/finalmask/xdns/server.rs | ✅ 已真实重构 | XDnsServer 服务端请求验证、多报文打包与 1232 字节 UDP 截断 |
| 694 | transport/internet/finalmask/xicmp/client.go | transport/internet/finalmask/xicmp/client.rs | ✅ 已真实重构 | XIcmpClient IPv4/IPv6 Echo 报文封装与反射攻击过滤 |
| 695 | transport/internet/finalmask/xicmp/config.go | transport/internet/finalmask/xicmp/config.rs | ✅ 已真实重构 | XIcmpConfig 配置 |
| 696 | transport/internet/finalmask/xicmp/config.pb.go | transport/internet/finalmask/xicmp/config.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 697 | transport/internet/finalmask/xicmp/server.go | transport/internet/finalmask/xicmp/server.rs | ✅ 已真实重构 | XIcmpServer 回显响应与随机字节序列扰动 |
| 698 | transport/internet/finalmask/xicmp/xicmp_test.go | transport/internet/finalmask/xicmp/xicmp_test.rs | ✅ 已真实重构 | 4 项 ICMP 头部与双向流单测全通过 |
| 699 | transport/internet/grpc/config.go | transport/internet/grpc/config.rs | ✅ 已真实重构 | GrpcConfig 与 ServiceName 获取 |
| 700 | transport/internet/grpc/config.pb.go | transport/internet/grpc/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 701 | transport/internet/grpc/config_test.go | transport/internet/grpc/config_test.rs | ✅ 已真实重构 | 单测验证 |
| 702 | transport/internet/grpc/dial.go | transport/internet/grpc/dial.rs | ✅ 已真实重构 | GrpcDialer 出站连接器 |
| 703 | transport/internet/grpc/encoding/customSeviceName.go | transport/internet/grpc/encoding/customSeviceName.rs | ✅ 已真实重构 | 自定义 gRPC 服务名 |
| 704 | transport/internet/grpc/encoding/encoding.go | transport/internet/grpc/encoding/encoding.rs | ✅ 已真实重构 | encode_grpc_frame / decode_grpc_frame 数据帧编解码 |
| 705 | transport/internet/grpc/encoding/hunkconn.go | transport/internet/grpc/encoding/hunkconn.rs | ✅ 已真实重构 | HunkConnection 数据块连接器 |
| 706 | transport/internet/grpc/encoding/multiconn.go | transport/internet/grpc/encoding/multiconn.rs | ✅ 已真实重构 | MultiHunkConn 多路流连接器 |
| 707 | transport/internet/grpc/encoding/stream.pb.go | transport/internet/grpc/encoding/mod.rs | ✅ 已真实重构 | gRPC Stream 消息模型 |
| 708 | transport/internet/grpc/encoding/stream_grpc.pb.go | transport/internet/grpc/encoding/mod.rs | ✅ 已真实重构 | gRPC Stream 客户端/服务端抽象 |
| 709 | transport/internet/grpc/grpc.go | transport/internet/grpc/mod.rs | ✅ 已真实重构 | 协议单测 |
| 710 | transport/internet/grpc/hub.go | transport/internet/grpc/hub.rs | ✅ 已真实重构 | GrpcListener 入站监听与 accept 连接 |
| 711 | transport/internet/happy_eyeballs.go | transport/internet/happy_eyeballs.rs | ✅ 已真实重构 | RFC 8305 域名双栈排序与竞速拨号 2 项单测全通过 |
| 712 | transport/internet/header.go | transport/internet/header.rs | ✅ 已真实重构 | PacketHeader 与 ConnectionAuthenticator 接口定义 |
| 713 | transport/internet/headers/http/config.go | transport/internet/headers/http/config.rs | ✅ 已真实重构 | RequestConfig/ResponseConfig 协议头配置 |
| 714 | transport/internet/headers/http/config.pb.go | transport/internet/headers/http/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 715 | transport/internet/headers/http/http.go | transport/internet/headers/http/mod.rs | ✅ 已真实重构 | test_http_header_obfuscator |
| 716 | transport/internet/headers/http/http_test.go | transport/internet/headers/http/http_test.rs | ✅ 已真实重构 | 5 项 HTTP 伪装标头读写与双向管道单测全通过 |
| 717 | transport/internet/headers/http/linkedreadRequest.go | transport/internet/headers/http/linkedread_request.rs | ✅ 已真实重构 | 基于 httparse 的 HTTP 请求标头线缆解析 |
| 718 | transport/internet/headers/http/resp.go | transport/internet/headers/http/resp.rs | ✅ 已真实重构 | 400 Bad Request 与 404 Not Found 响应伪装模板 |
| 719 | transport/internet/headers/noop/config.pb.go | transport/internet/headers/noop/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 720 | transport/internet/headers/noop/noop.go | transport/internet/headers/noop/noop.rs | ✅ 已真实重构 | NoOpHeader 与 NoOpConnectionHeader 空操作标头 |
| 721 | transport/internet/httpupgrade/config.go | transport/internet/httpupgrade/config.rs | ✅ 已真实重构 | HttpUpgradeConfig 配置与规范化路径处理 |
| 722 | transport/internet/httpupgrade/config.pb.go | transport/internet/httpupgrade/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 723 | transport/internet/httpupgrade/connection.go | transport/internet/httpupgrade/connection.rs | ✅ 已真实重构 | HttpUpgradeConnection 远端地址与双向流封装 |
| 724 | transport/internet/httpupgrade/dialer.go | transport/internet/httpupgrade/dialer.rs | ✅ 已真实重构 | HttpUpgradeDialer 出站连接器与 WebSocket 协议头握手 |
| 725 | transport/internet/httpupgrade/httpupgrade.go | transport/internet/httpupgrade/httpupgrade.rs | ✅ 已真实重构 | UpgradedStream 头部前缀缓冲与双向透明管道 |
| 726 | transport/internet/httpupgrade/httpupgrade_test.go | transport/internet/httpupgrade/httpupgrade_test.rs | ✅ 已真实重构 | 5 项内存管道、前缀缓冲保护与端到端 TCP 单测全通过 |
| 727 | transport/internet/httpupgrade/hub.go | transport/internet/httpupgrade/hub.rs | ✅ 已真实重构 | HttpUpgradeHub 服务端监听器与 101 Switching Protocols 响应 |
| 728 | transport/internet/hysteria/config.go | transport/internet/hysteria/config.rs | ✅ 已真实重构 | HysteriaTransportConfig 接收窗口与并发连接数配置 |
| 729 | transport/internet/hysteria/config.pb.go | transport/internet/hysteria/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 730 | transport/internet/hysteria/congestion/bbr/bandwidth.go | transport/internet/hysteria/congestion/bbr/bandwidth.rs | ✅ 已真实重构 | Bandwidth 字节/时间速率换算与 bps 换算 |
| 731 | transport/internet/hysteria/congestion/bbr/bandwidth_sampler.go | transport/internet/hysteria/congestion/bbr/bandwidth_sampler.rs | ✅ 已真实重构 | BandwidthSampler 采样队列与最高带宽推导 |
| 732 | transport/internet/hysteria/congestion/bbr/bbr_sender.go | transport/internet/hysteria/congestion/bbr/bbr_sender.rs | ✅ 已真实重构 | BbrSender 拥塞控制状态机与 PacingRate 起搏 |
| 733 | transport/internet/hysteria/congestion/bbr/clock.go | transport/internet/hysteria/congestion/bbr/clock.rs | ✅ 已真实重构 | 单调时钟封装与高精度延时度量 |
| 734 | transport/internet/hysteria/congestion/bbr/packet_number_indexed_queue.go | transport/internet/hysteria/congestion/bbr/packet_number_indexed_queue.rs | ✅ 已真实重构 | 基于包序号索引的有序队列 |
| 735 | transport/internet/hysteria/congestion/bbr/ringbuffer.go | transport/internet/hysteria/congestion/bbr/ringbuffer.rs | ✅ 已真实重构 | 循环环形缓冲区与 FIFO 淘汰机制 |
| 736 | transport/internet/hysteria/congestion/bbr/windowed_filter.go | transport/internet/hysteria/congestion/bbr/windowed_filter.rs | ✅ 已真实重构 | 时间滑动窗口最大值滤波器 |
| 737 | transport/internet/hysteria/congestion/brutal/brutal.go | transport/internet/hysteria/congestion/brutal/brutal.rs | ✅ 已真实重构 | Brutal 暴力发包发信机与 5 秒 ACK 统计滑窗 |
| 738 | transport/internet/hysteria/congestion/common/pacer.go | transport/internet/hysteria/congestion/common/pacer.rs | ✅ 已真实重构 | 令牌桶流量整形器 Pacer 与微秒级突发流控 |
| 739 | transport/internet/hysteria/congestion/utils.go | transport/internet/hysteria/congestion/utils.rs | ✅ 已真实重构 | 拥塞控制模式绑定辅助工具 |
| 740 | transport/internet/hysteria/conn.go | transport/internet/hysteria/conn.rs | ✅ 已真实重构 | HysteriaConn 发送/接收双向流量原子计数 |
| 741 | transport/internet/hysteria/dialer.go | transport/internet/hysteria/dialer.rs | ✅ 已真实重构 | HysteriaDialer 出站连接器与端口跳跃适配 |
| 742 | transport/internet/hysteria/hub.go | transport/internet/hysteria/hub.rs | ✅ 已真实重构 | HysteriaHub 入站连接注册中心与会话管理 |
| 743 | transport/internet/hysteria/padding/padding.go | transport/internet/hysteria/padding/padding.rs | ✅ 已真实重构 | Base62 半开区间 [min, max) 混淆填充生成器 |
| 744 | transport/internet/hysteria/udphop/addr.go | transport/internet/hysteria/udphop/addr.rs | ✅ 已真实重构 | UDPHopAddr 多端口地址池与网络协议类型 |
| 745 | transport/internet/hysteria/udphop/conn.go | transport/internet/hysteria/udphop/conn.rs | ✅ 已真实重构 | UdpHopPacketConn 周期性跳跃与地址轮转 |
| 746 | transport/internet/internet.go | transport/internet/internet.rs | ✅ 已真实重构 | is_valid_http_host 域名主机名验证单测全通过 |
| 747 | transport/internet/kcp/config.go | transport/internet/kcp/config.rs | ✅ 已真实重构 | KcpConfig 与飞控在途窗口计算 |
| 748 | transport/internet/kcp/config.pb.go | transport/internet/kcp/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 749 | transport/internet/kcp/connection.go | transport/internet/kcp/connection.rs | ✅ 已真实重构 | test_kcp_connection_arq_ack |
| 750 | transport/internet/kcp/connection_test.go | transport/internet/kcp/connection_test.rs | ✅ 已真实重构 | 端到端 ARQ 滑动窗口与确认单测 |
| 751 | transport/internet/kcp/dialer.go | transport/internet/kcp/dialer.rs | ✅ 已真实重构 | KCP 拨号器 |
| 752 | transport/internet/kcp/io.go | transport/internet/kcp/io.rs | ✅ 已真实重构 | KcpPacketReader / KcpPacketWriter |
| 753 | transport/internet/kcp/io_test.go | transport/internet/kcp/io_test.rs | ✅ 已真实重构 | I/O 读写队列单测通过 |
| 754 | transport/internet/kcp/kcp.go | transport/internet/kcp/kcp.rs | ✅ 已真实重构 | KCP 协议特征与类型导出 |
| 755 | transport/internet/kcp/kcp_test.go | transport/internet/kcp/kcp_test.rs | ✅ 已真实重构 | 滑动窗口与去重单测通过 |
| 756 | transport/internet/kcp/listener.go | transport/internet/kcp/listener.rs | ✅ 已真实重构 | KcpListener 连接表管理 |
| 757 | transport/internet/kcp/output.go | transport/internet/kcp/output.rs | ✅ 已真实重构 | 原始报文分发器 |
| 758 | transport/internet/kcp/receiving.go | transport/internet/kcp/receiving.rs | ✅ 已真实重构 | ReceivingWindow 有序接收与 AckList 批量确认 |
| 759 | transport/internet/kcp/segment.go | transport/internet/kcp/segment.rs | ✅ 已真实重构 | Data/Ack/CmdOnly 报文 1:1 编解码 |
| 760 | transport/internet/kcp/segment_test.go | transport/internet/kcp/segment_test.rs | ✅ 已真实重构 | 多 ACK 与命令段全覆盖单测 |
| 761 | transport/internet/kcp/sending.go | transport/internet/kcp/sending.rs | ✅ 已真实重构 | SendingWindow 快速重传与指数退避超时 |
| 762 | transport/internet/memory_settings.go | transport/internet/memory_settings.rs | ✅ 已真实重构 | MemorySettings 与 MemoryStreamConfig 配置 |
| 763 | transport/internet/reality/config.go | transport/internet/reality/mod.rs | ✅ 已真实重构 | RealityConfig 与证书/SNI管理 |
| 764 | transport/internet/reality/config.pb.go | transport/internet/reality/mod.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 765 | transport/internet/reality/reality.go | transport/internet/reality/mod.rs | ✅ 已真实重构 | test_reality_server_and_client_auth |
| 766 | transport/internet/sockopt.go | transport/internet/sockopt.rs | ✅ 已真实重构 | SocketOptions 配置、TFO 转换与协议类型匹配 |
| 767 | transport/internet/sockopt_darwin.go | transport/internet/sockopt_darwin.rs | ✅ 已真实重构 | Darwin 平台 Socket 控制参数适配 |
| 768 | transport/internet/sockopt_freebsd.go | transport/internet/sockopt_freebsd.rs | ✅ 已真实重构 | FreeBSD 平台 Socket 控制参数适配 |
| 769 | transport/internet/sockopt_linux.go | transport/internet/sockopt_linux.rs | ✅ 已真实重构 | Linux 平台 SO_MARK 与透明代理参数 |
| 770 | transport/internet/sockopt_linux_test.go | transport/internet/sockopt_linux_test.rs | ✅ 已真实重构 | Linux SocketOptions Mark 单测通过 |
| 771 | transport/internet/sockopt_other.go | transport/internet/sockopt_other.rs | ✅ 已真实重构 | 通用平台回退处理 |
| 772 | transport/internet/sockopt_test.go | transport/internet/sockopt_test.rs | ✅ 已真实重构 | TFO 数值转换与 TCP/UDP 类型判断单测全通过 |
| 773 | transport/internet/sockopt_windows.go | transport/internet/sockopt_windows.rs | ✅ 已真实重构 | Windows 平台 Socket 控制参数适配 |
| 774 | transport/internet/splithttp/browser_client.go | transport/internet/splithttp/browser_client.rs | ✅ 已真实重构 | BrowserDialerClient 实现 DialerClient 接口 |
| 775 | transport/internet/splithttp/client.go | transport/internet/splithttp/mod.rs | ✅ 已真实重构 | test_splithttp_request_formatting |
| 776 | transport/internet/splithttp/common.go | transport/internet/splithttp/common.rs | ✅ 已真实重构 | 1:1 Placement 常量与协议默认配置定义 |
| 777 | transport/internet/splithttp/config.go | transport/internet/splithttp/mod.rs | ✅ 已真实重构 | test_splithttp_request_formatting |
| 778 | transport/internet/splithttp/config.pb.go | transport/internet/splithttp/config.pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 779 | transport/internet/splithttp/config_test.go | transport/internet/splithttp/config_test.rs | ✅ 已真实重构 | test_splithttp_config_defaults 单测通过 |
| 780 | transport/internet/splithttp/connection.go | transport/internet/splithttp/connection.rs | ✅ 已真实重构 | SplitConn 双向流拆分与会话标识封装 |
| 781 | transport/internet/splithttp/dialer.go | transport/internet/splithttp/dialer.rs | ✅ 已真实重构 | SplitHttpDialer 双向流/分片上传连接器与端到端单测 |
| 782 | transport/internet/splithttp/h1_conn.go | transport/internet/splithttp/h1_conn.rs | ✅ 已真实重构 | H1Conn 响应缓冲区与未读响应计数器单测 |
| 783 | transport/internet/splithttp/hub.go | transport/internet/splithttp/hub.rs | ✅ 已真实重构 | SplitHttpHub 路由派发与会话流读写服务 |
| 784 | transport/internet/splithttp/mux.go | transport/internet/splithttp/mux.rs | ✅ 已真实重构 | SplitHttpMux 会话多路复用与生命周期管理 |
| 785 | transport/internet/splithttp/mux_test.go | transport/internet/splithttp/mux_test.rs | ✅ 已真实重构 | test_splithttp_mux_lifecycle 单测通过 |
| 786 | transport/internet/splithttp/splithttp.go | transport/internet/splithttp/splithttp.rs | ✅ 已真实重构 | 协议常量 PROTOCOL_NAME 导出与类型注册 |
| 787 | transport/internet/splithttp/splithttp_test.go | transport/internet/splithttp/splithttp_test.rs | ✅ 已真实重构 | test_splithttp_pipeline 管道单测通过 |
| 788 | transport/internet/splithttp/upload_queue.go | transport/internet/splithttp/upload_queue.rs | ✅ 已真实重构 | 上传重排序队列与乱序缓冲区 |
| 789 | transport/internet/splithttp/upload_queue_test.go | transport/internet/splithttp/upload_queue_test.rs | ✅ 已真实重构 | 队列乱序重组与分段读取 2 项单测全通过 |
| 790 | transport/internet/splithttp/xpadding.go | transport/internet/splithttp/xpadding.rs | ✅ 已真实重构 | 动态长度填充与混淆填充流 |
| 791 | transport/internet/stat/connection.go | transport/internet/stat/mod.rs | ✅ 已真实重构 | test_stat_stream_byte_counting |
| 792 | transport/internet/system_dialer.go | transport/internet/system_dialer.rs | ✅ 已真实重构 | SystemDialerTrait、DefaultSystemDialer 与 PacketConnWrapper 5项单测全通过 |
| 793 | transport/internet/system_listener.go | transport/internet/system_listener.rs | ✅ 已真实重构 | SystemListener TCP/UDP 监听与控制器拦截机制 |
| 794 | transport/internet/system_listener_test.go | transport/internet/system_listener_test.rs | ✅ 已真实重构 | 5 项系统监听、双向流传输与套接字控制器单测全通过 |
| 795 | transport/internet/tagged/tagged.go | transport/internet/tagged/mod.rs | ✅ 已真实重构 | test_tagged_dialer_connect |
| 796 | transport/internet/tagged/taggedimpl/impl.go | transport/internet/tagged/taggedimpl/impl.rs | ✅ 已真实重构 | dial_tagged_outbound 基于管道与派发器出站 |
| 797 | transport/internet/tagged/taggedimpl/taggedimpl.go | transport/internet/tagged/taggedimpl/taggedimpl.rs | ✅ 已真实重构 | register_tagged_dialer 动态注册中心 |
| 798 | transport/internet/tcp/config.go | transport/internet/tcp/config.rs | ✅ 已真实重构 | TcpConfig 传输配置与 PROXY Protocol 标头开关 |
| 799 | transport/internet/tcp/config.pb.go | transport/internet/tcp/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 800 | transport/internet/tcp/dialer.go | transport/internet/tcp/dialer.rs | ✅ 已真实重构 | TcpDialer 出站连接器与 NoDelay 优化 |
| 801 | transport/internet/tcp/hub.go | transport/internet/tcp/hub.rs | ✅ 已真实重构 | TcpHub 服务端监听器与连接流派发 |
| 802 | transport/internet/tcp/sockopt_darwin.go | transport/internet/tcp/sockopt_darwin.rs | ✅ 已真实重构 | Darwin TCP 套接字参数与 TFO 支持 |
| 803 | transport/internet/tcp/sockopt_freebsd.go | transport/internet/tcp/sockopt_freebsd.rs | ✅ 已真实重构 | FreeBSD TCP 套接字参数与 TFO 支持 |
| 804 | transport/internet/tcp/sockopt_linux.go | transport/internet/tcp/sockopt_linux.rs | ✅ 已真实重构 | Linux TCP 套接字参数与 TCP_FASTOPEN_CONNECT |
| 805 | transport/internet/tcp/sockopt_linux_test.go | transport/internet/tcp/sockopt_linux_test.rs | ✅ 已真实重构 | Linux TFO 单测通过 |
| 806 | transport/internet/tcp/sockopt_other.go | transport/internet/tcp/sockopt_other.rs | ✅ 已真实重构 | 通用平台 TCP 套接字回退 |
| 807 | transport/internet/tcp/tcp.go | transport/internet/tcp/tcp.rs | ✅ 已真实重构 | TCP 传输层协议定义与常量导出 |
| 808 | transport/internet/tcp_hub.go | transport/internet/tcp_hub.rs | ✅ 已真实重构 | 监听器全局注册中心、ListenTCP/ListenUnix 与域名过滤 |
| 809 | transport/internet/tls/config.go | transport/internet/tls/config.rs | ✅ 已真实重构 | TlsConfig 配置、CertificateUsage 证书用途分离与动态 SNI 签发 |
| 810 | transport/internet/tls/config.pb.go | transport/internet/tls/config.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 811 | transport/internet/tls/config_other.go | transport/internet/tls/config_other.rs | ✅ 已真实重构 | 非 Windows 根证书池与系统证书追加 |
| 812 | transport/internet/tls/config_test.go | transport/internet/tls/config_test.rs | ✅ 已真实重构 | 3 项配置默认值、用途分类与 SNI 动态签发单测全通过 |
| 813 | transport/internet/tls/config_windows.go | transport/internet/tls/config_windows.rs | ✅ 已真实重构 | Windows 平台 RootCert 证书池处理 |
| 814 | transport/internet/tls/ech.go | transport/internet/tls/ech.rs | ✅ 已真实重构 | ECHConfigCache 缓存、RFC 9460 SVCB 参数提取与防泄漏 Dummy 回退 |
| 815 | transport/internet/tls/ech_test.go | transport/internet/tls/ech_test.rs | ✅ 已真实重构 | 6 项 ECH 密钥编解码、SVCB 提取与缓存生命周期单测全通过 |
| 816 | transport/internet/tls/grpc.go | transport/internet/tls/grpc.rs | ✅ 已真实重构 | GrpcTlsCredentials 认证凭证与 ALPN 匹配 |
| 817 | transport/internet/tls/pin.go | transport/internet/tls/pin.rs | ✅ 已真实重构 | ASN.1 DER 证书 SHA-256 指纹计算与 Pinning 校验 |
| 818 | transport/internet/tls/pin_test.go | transport/internet/tls/pin_test.rs | ✅ 已真实重构 | 微软官方 CA 证书 SHA-256 指纹校验与单测全通过 |
| 819 | transport/internet/tls/tls.go | transport/internet/tls/mod.rs | ✅ 已真实重构 | 场景测试集成 |
| 820 | transport/internet/tls/unsafe.go | transport/internet/tls/unsafe.rs | ✅ 已真实重构 | 零证书错误常量与安全模式检查 |
| 821 | transport/internet/udp/config.go | transport/internet/udp/config.rs | ✅ 已真实重构 | UDP 缓冲区大小与超时配置 |
| 822 | transport/internet/udp/config.pb.go | transport/internet/udp/config_pb.rs | ✅ 已真实重构 | Serde Protobuf 映射配置 |
| 823 | transport/internet/udp/dialer.go | transport/internet/udp/mod.rs | ✅ 已真实重构 | test_udp_hub_send_recv |
| 824 | transport/internet/udp/dispatcher.go | transport/internet/udp/dispatcher.rs | ✅ 已真实重构 | Dispatcher 管道连接会话池与无活性超时关闭 |
| 825 | transport/internet/udp/dispatcher_test.go | transport/internet/udp/dispatcher_test.rs | ✅ 已真实重构 | 1:1 对标 Go 版 TestSameDestinationDispatching 3 项单测全通过 |
| 826 | transport/internet/udp/hub.go | transport/internet/udp/mod.rs | ✅ 已真实重构 | test_udp_hub_send_recv |
| 827 | transport/internet/udp/hub_darwin.go | transport/internet/udp/hub_darwin.rs | ✅ 已真实重构 | Darwin 原始目的地址提取适配 |
| 828 | transport/internet/udp/hub_freebsd.go | transport/internet/udp/hub_freebsd.rs | ✅ 已真实重构 | FreeBSD 原始目的地址提取适配 |
| 829 | transport/internet/udp/hub_linux.go | transport/internet/udp/hub_linux.rs | ✅ 已真实重构 | Linux IP_RECVORIGDSTADDR 原始目的地址提取 |
| 830 | transport/internet/udp/hub_other.go | transport/internet/udp/hub_other.rs | ✅ 已真实重构 | 通用平台原始目的地址回退 |
| 831 | transport/internet/udp/udp.go | transport/internet/udp/udp.rs | ✅ 已真实重构 | UDP 协议常量与接口导出 |
| 832 | transport/internet/websocket/config.go | transport/internet/websocket/config.rs | ✅ 已真实重构 | WebSocketConfig 配置反序列化 |
| 833 | transport/internet/websocket/config.pb.go | transport/internet/websocket/config.rs | ✅ 已真实重构 | Serde 模型映射 |
| 834 | transport/internet/websocket/connection.go | transport/internet/websocket/connection.rs | ✅ 已真实重构 | WebSocket 双向连接封装 |
| 835 | transport/internet/websocket/dialer.go | transport/internet/websocket/dialer.rs | ✅ 已真实重构 | WebSocketDialer 出站连接器 |
| 836 | transport/internet/websocket/hub.go | transport/internet/websocket/hub.rs | ✅ 已真实重构 | WebSocketHub 入站服务端监听器 |
| 837 | transport/internet/websocket/ws.go | transport/internet/websocket/ws.rs | ✅ 已真实重构 | test_websocket_stream_duplex |
| 838 | transport/internet/websocket/ws_test.go | transport/internet/websocket/ws_test.rs | ✅ 已真实重构 | 单测验证 |
| 839 | transport/link.go | transport/link.rs | ✅ 已真实重构 | Link 管道双向读写端连接模型 |
| 840 | transport/pipe/impl.go | transport/pipe/mod.rs | ✅ 已真实重构 | test_pipe_read_write_flow |
| 841 | transport/pipe/pipe.go | transport/pipe/mod.rs | ✅ 已真实重构 | test_pipe_read_write_flow |
| 842 | transport/pipe/pipe_test.go | transport/pipe/pipe_test.rs | ✅ 已真实重构 | test_pipe_read_write 单测全通过 |
| 843 | transport/pipe/reader.go | transport/pipe/reader.rs | ✅ 已真实重构 | Reader 异步流读取与超时处理 |
| 844 | transport/pipe/writer.go | transport/pipe/writer.rs | ✅ 已真实重构 | Writer 异步数据写入与背压控制 |
