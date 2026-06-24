# NeoClash Swift Core

[![macOS Build](https://github.com/Peng-Rao/neoclash-swift-core/actions/workflows/macos.yml/badge.svg)](https://github.com/Peng-Rao/neoclash-swift-core/actions/workflows/macos.yml)
[![Linux Build](https://github.com/Peng-Rao/neoclash-swift-core/actions/workflows/linux.yml/badge.svg)](https://github.com/Peng-Rao/neoclash-swift-core/actions/workflows/linux.yml)
[![Swift 6.2](https://img.shields.io/badge/Swift-6.2-F05138?logo=swift&logoColor=white)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey?logo=apple)](https://www.apple.com/macos/)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.linux.org/)
[![SwiftPM](https://img.shields.io/badge/SwiftPM-compatible-brightgreen?logo=swift&logoColor=white)](https://www.swift.org/package-manager/)

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

## Routing rules

Supported rule types: `MATCH`, `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`,
`DOMAIN-REGEX`, `IP-CIDR`, `IP-CIDR6`, `DST-PORT`, `SRC-PORT`, `GEOIP`, `GEOSITE`,
`RULE-SET`. IP rules match IP literals (domain→IP resolution for non-`no-resolve`
rules arrives with the DNS subsystem). `PROCESS-NAME` is not evaluated yet —
such rules are skipped with a warning.

`RULE-SET` rules reference a `rule-providers` entry (`domain` / `ipcidr` /
`classical` behavior, `yaml` or `text` format), loaded from a local file or an
`http` URL (cached in the runtime directory):

```yaml
rule-providers:
  cn-domains:
    type: http
    behavior: domain
    url: https://example.com/cn.yaml
    path: ./rules/cn.yaml
rules:
  - RULE-SET,cn-domains,DIRECT
  - MATCH,Proxy
```

`GEOIP`/`GEOSITE` use the v2ray-format `geoip.dat` / `geosite.dat`, downloaded
from `geox-url` (defaults to MetaCubeX's releases) into the runtime directory
and cached. Override per profile:

```yaml
geox-url:
  geoip: https://example.com/geoip.dat
  geosite: https://example.com/geosite.dat
```

The databases load asynchronously, so `GEOIP`/`GEOSITE` rules start matching once
the download completes.

## Proxy groups

`select`, `url-test` (lowest latency), `fallback` (first alive), and
`load-balance` (consistent per-host) groups are supported. A periodic health
monitor probes proxies, and `GET /proxies/{name}/delay` measures latency on
demand (tunnels a plaintext HTTP request, so the test URL must be `http://`).

`external-controller` and `secret` are optional — when `secret` is empty,
controller authentication is disabled (mihomo behavior).

WebSocket/gRPC transports, UDP relay, and additional protocols (Shadowsocks,
Trojan, Hysteria2, WireGuard) are planned for later phases.
