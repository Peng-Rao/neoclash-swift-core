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

The first implementation supports controller compatibility, WebSocket traffic
streams, HTTP proxy, HTTPS CONNECT, minimal SOCKS5 TCP connect, and v1
DIRECT/REJECT routing.
