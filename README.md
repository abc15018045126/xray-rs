# xray-rs

High-performance Rust 1:1 implementation of [Xray-core](https://github.com/XTLS/Xray-core).

## Features

- **Protocol Support**: VLESS (including XTLS Vision `xtls-rprx-vision`), VMess, Trojan, Shadowsocks, Socks5, HTTP, etc.
- **Transports**: TCP, UDP, TLS, REALITY, gRPC, WebSocket, SplitHTTP, Hysteria, KCP.
- **TUN Mode**: Kernel-level high-performance Wintun ring-buffer integration with user-space TCP/IP network stack (smoltcp).
- **Routing Engine**: Full DNS, FakeDNS, GeoIP, GeoSite, domain rule matching and balancer support.
- **Zero GC Overhead**: 100% safe Rust performance with predictable low memory footprint (~50MB) and minimal CPU utilization.

## Building

```bash
cargo build --release
```

The compiled executable will be located at `target/release/xray.exe`.

## Usage

```bash
# Run with config file
xray run -c config.json

# Test configuration
xray test -c config.json
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.
