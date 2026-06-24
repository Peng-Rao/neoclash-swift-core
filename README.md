# NeoClash Swift Core

Experimental Swift sidecar core for NeoClash.

This repository is intentionally small and package-first so the core can be
developed and tested independently from the main app.

## Build

```sh
swift build
```

## Test

```sh
swift test
```

## Run

Validate a generated Clash/mihomo-style config:

```sh
swift run NeoClashSwiftCore -t -f /path/to/config.yaml -d /path/to/runtime
```

Start the experimental core:

```sh
swift run NeoClashSwiftCore -f /path/to/config.yaml -d /path/to/runtime
```

The core supports controller compatibility, WebSocket traffic streams, HTTP
proxy, HTTPS CONNECT, minimal SOCKS5 TCP connect, and DIRECT/REJECT routing.

## Outbound proxies

Traffic can be tunneled through real upstream proxies via a pluggable outbound
adapter layer:

- **VLESS** over TCP, optionally with TLS or **REALITY** (`reality-opts` +
  `flow: xtls-rprx-vision`). REALITY runs on a from-scratch, pure-Swift TLS 1.3
  client (no system TLS), with XTLS-Vision padding and the direct splice.
- **VMess** (AEAD, `alterId: 0`) over TCP, optionally with TLS. Body ciphers:
  `auto`/`aes-128-gcm` and `chacha20-poly1305`.

Rules route to a named proxy (or a `select` proxy-group's current member), e.g.:

```yaml
proxies:
  - { name: us-vless, type: vless, server: example.com, port: 443, uuid: <uuid>, tls: true, servername: example.com }
  - { name: us-vmess, type: vmess, server: example.com, port: 443, uuid: <uuid>, alterId: 0, cipher: auto, tls: true, servername: example.com }
proxy-groups:
  - { name: Proxy, type: select, proxies: [us-vless, us-vmess, DIRECT] }
rules:
  - DOMAIN-SUFFIX,example.org,Proxy
  - MATCH,DIRECT
```

## Proxy groups

`select`, `url-test` (lowest latency), `fallback` (first alive), and
`load-balance` (consistent per-host) groups are supported. A periodic health
monitor probes proxies, and `GET /proxies/{name}/delay` measures latency on
demand (tunnels a plaintext HTTP request, so the test URL must be `http://`).

`external-controller` and `secret` are optional — when `secret` is empty,
controller authentication is disabled (mihomo behavior).

WebSocket/gRPC transports, UDP relay, and additional protocols (Shadowsocks,
Trojan, Hysteria2, WireGuard) are planned for later phases.
