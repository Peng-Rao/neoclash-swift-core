# NeoClash Swift Core — Development Roadmap

A staged plan for turning the current kernel into a broadly mihomo-compatible
proxy core. This document is the source of truth for *what to build next and
why*; the git history is the source of truth for *what has already shipped*.

- **Status date:** 2026-07-06
- **Scope today:** ~7.9k lines across one library target (`NeoClashSwiftCoreLib`),
  one C shim (`CSwiftCoreTun`), one executable. 148 macOS / 141 Linux tests, CI
  green on both.
- **Concurrency & style constraints (do not drift from these):** SwiftNIO
  `EventLoop` futures for network I/O (not `async/await`), `SwiftCore` type
  prefix, shared state behind an `NSLock` via a `withLock {}` helper, manual Yams
  parsing into `Equatable, Sendable` structs, XCTest with hermetic fixtures.
  See the project conventions memory for detail.

---

## 1. Where we are

| Subsystem | State | Key types |
|---|---|---|
| Inbound | HTTP / HTTPS-CONNECT / SOCKS5-TCP | `MixedProxyServer` |
| Outbound protocols | DIRECT, VLESS, VMess(AEAD) | `Outbound/{Direct,VLESS,VMess}` |
| Security | from-scratch TLS 1.3, REALITY, XTLS-Vision | `TLS/` |
| Transports | TCP, WebSocket, gRPC | `Transport/` |
| Routing | rules, GEOIP/GEOSITE, RULE-SET | `Routing/` |
| DNS | UDP/DoH/DoT resolver, fake-ip, hijack | `DNS/` |
| TUN (L3) | device, hand-rolled TCP relay, DNS-hijack | `TUN/` |
| Control plane | mihomo-compatible controller + WS streams | `Controller/` |
| Health | url-test/fallback probing | `Health/` |

**The two biggest capability gaps** are (a) UDP does not relay through any
outbound — only TCP does; and (b) the outbound catalog is three protocols wide,
so most real subscriptions can't be fully expressed yet.

---

## 2. Guiding principles

1. **Test-first and hermetic.** Every feature lands with XCTest coverage that
   runs with no network and no root. Live checks stay gated behind env flags
   (`NEOCLASH_LIVE_DNS=1`, `NEOCLASH_TUN=1`) and are excluded from CI. New
   protocols get a fake echo-server fixture the real adapter round-trips through,
   the way VLESS/VMess and the WS/gRPC transports already do.
2. **From-scratch over heavy deps.** We hand-wrote TLS 1.3 rather than bend
   BoringSSL, and a minimal userspace TCP rather than vendor a stack. Keep that
   ethos: prefer a small, testable, in-tree implementation unless a dependency is
   clearly load-bearing (Crypto, NIO).
3. **One protocol = one self-contained directory + one factory case.**
   `Outbound/<Proto>/` holds the adapter and its crypto; add a case to
   `SwiftCoreOutboundFactory`. Unsupported types stay soft failures (warn +
   `.unsupported` route), never a hard config-load error.
4. **Ship in small, stacked PRs.** Each milestone below is sized to a reviewable
   PR. Architecture refactors ship *before* the features that depend on them.

---

## 3. Milestones

Ordered by recommended sequence. Each has a rationale, concrete work items,
and an acceptance bar. Priorities: **P0** unblocks other work, **P1** high user
value, **P2** valuable but deferrable.

### M1 — Extract `TunnelRelay` from the inbound path — **P0, small**

*Rationale:* `MixedProxyServer` currently couples HTTP/SOCKS request parsing to
route dispatch, the bidirectional splice, and connection tracking. UDP relay and
any second inbound (TProxy, TUN's existing relay) all need that dispatch+splice
logic, so it must be a reusable unit first. This is step 4 of the architecture
plan, pulled forward because it unblocks M2.

- Extract route-decision → `outbound.connect` → bidi splice → conn-tracking into
  a `SwiftCoreTunnelRelay` (or similar), leaving `MixedProxyServer` responsible
  only for parsing an inbound request into a `SwiftCoreProxyTarget`.
- The TUN TCP controller already re-implements a parallel splice; converge both
  on the extracted relay where practical.
- **Done when:** existing inbound tests pass unchanged; the relay has direct unit
  tests (route → dial → splice → close) independent of HTTP/SOCKS parsing.

### M2 — General UDP relay — **P1, large**

*Rationale:* the single largest functional gap. DNS-over-UDP through TUN works,
but application UDP (QUIC/HTTP3, game traffic, WireGuard-in-UDP) has no path
through any outbound. Depends on M1's relay seam and touches both inbound and
outbound.

- **Inbound:** SOCKS5 `UDP ASSOCIATE` in `MixedProxyServer`; a UDP NAT/session
  table keyed by client 5-tuple with idle eviction.
- **Outbound UDP contract:** extend `SwiftCoreOutbound` (or add a sibling
  protocol) so an adapter can carry datagrams, not just a byte stream. VLESS UDP
  (command 0x02, length-delimited) and VMess UDP first, since those adapters
  exist.
- **TUN UDP:** today non-hijack UDP datagrams are dropped in
  `SwiftCoreTunController.handleUDP`; route them through the same UDP relay so
  fake-ip UDP flows reach their real destination.
- **Done when:** a hermetic UDP echo test drives a datagram inbound → VLESS-UDP
  outbound → echo server → back, plus a TUN-path UDP round-trip test.

### M3 — Shadowsocks outbound — **P1, medium**

*Rationale:* highest-demand protocol not yet supported and the simplest of the
remaining four, so it validates the "new protocol" workflow end to end (TCP now,
UDP once M2 lands).

- `Outbound/Shadowsocks/`: AEAD ciphers (`aes-256-gcm`, `chacha20-ietf-poly1305`)
  with HKDF subkey derivation and the length-prefixed chunk framing; reuse
  `SwiftCoreAESGCM` and the target-address encoder already in
  `SwiftCoreProxyEncoding`.
- Config parsing for `cipher`/`password`; factory case; soft-fail on unknown
  ciphers.
- **Done when:** a fake SS echo server round-trips through the real adapter
  (self-consistent), matching the VMess test pattern; live interop verified
  manually against a real ss-server and noted in the PR.

### M4 — Split the `SwiftCoreState` god object — **P1, medium (3–4 PRs)**

*Rationale:* `SwiftCoreState` is 602 lines behind a single `NSLock` — a
contention and comprehension bottleneck that every subsystem reaches into. Do
this before piling more protocol/relay state onto it. Step 2 of the architecture
plan. Sequence as small PRs, each preserving `SwiftCoreState` as a thin
composition root so `ControllerServer`/`MixedProxyServer` keep one entry point:

1. `SwiftCoreLogBuffer` (ring buffer + drain).
2. `SwiftCoreConnectionTracker` (snapshots + traffic counters).
3. `SwiftCoreProxyRegistry` (outbounds, selections, delays, LB counters,
   `chooseMember`).
4. `SwiftCoreRouter` (rules + geo + ruleset + resolver + fake-ip; owns
   `route`/`resolvedRoute`).

- Each component owns its own lock.
- **Done when:** every subsystem compiles against the composition root with no
  behavior change; the full suite passes at each step.

### M5 — Trojan outbound — **P2, small–medium**

*Rationale:* mechanically close to VLESS-over-TLS (SHA-224 password hash + the
same target-address encoding over a TLS byte stream), so it's cheap once the
protocol workflow is established.

- `Outbound/Trojan/`: password → hex(SHA-224) auth, CRLF, target address, then
  raw payload over the existing TLS transport. UDP variant after M2.
- **Done when:** fake Trojan echo-server round-trip test; TLS/REALITY reuse
  verified.

### M6 — TUN auto-route & interface automation — **P2, medium**

*Rationale:* today TUN captures packets but the operator must configure routes
and DNS by hand. `auto-route`/`auto-detect-interface` make TUN usable as a
system-wide mode. Platform-specific and harder to test hermetically, hence later.

- macOS: `route`/`ifconfig`/`scutil` (or the equivalent syscalls) to install the
  default route via the utun device and restore on teardown; detect the physical
  interface for the outbound bind.
- Linux: `ip route`/`ip rule` + policy routing table equivalents.
- Guard behind config `tun.auto-route` (already parsed) and the existing
  root-gate.
- **Done when:** integration checklist documented and manually verified on both
  platforms behind `NEOCLASH_TUN=1`; teardown restores original routing.

### M7 — Hysteria2 & WireGuard outbounds — **P2, large**

*Rationale:* the two heaviest remaining protocols. Both need UDP (M2) and new
crypto/transport stacks (QUIC for Hysteria2, Noise + a userspace WG data plane).
Sequence last; each is a multi-PR effort of its own and may warrant its own
sub-plan when picked up.

- **Hysteria2:** QUIC is the blocker — evaluate a Swift QUIC option vs. a
  scoped in-tree implementation before committing.
- **WireGuard:** Noise_IKpsk2 handshake + a minimal userspace data plane over the
  UDP relay.
- **Done when:** per-protocol hermetic round-trip tests + gated live interop.

---

## 4. Cross-cutting work (land opportunistically)

- **Config parser hardening.** Real mihomo configs omit `external-controller`
  and `secret`; the REALITY note flags the parser still being stricter than it
  should in places. Audit required-vs-optional fields against a corpus of real
  configs and loosen with tests. **P1, incremental.**
- **TUN device test coverage.** `SwiftCoreTunDevice` is at 0% because it needs a
  real fd. Refactor to accept an injected fd (e.g. a `socketpair`) so read/write
  framing — including the macOS AF-prefix normalization — is unit-testable
  without root. **P2, small.**
- **Versioning & release.** No git tags exist and the version is hard-coded as
  `0.1.0` in `SwiftCoreRuntime`. Introduce semver tags and source the version
  from one place. **P2, small.**
- **`mrs` binary ruleset format.** Deferred from Phase 3; add if real
  subscriptions need it. **P2.**
- **PROCESS-NAME rules.** Deferred (needs platform syscalls for process lookup).
  **P2.**
- **Coverage ratchet in CI.** Optional `llvm-cov` gate so new code keeps the
  suite honest; today coverage is ~74% regions / ~83% lines. **P2.**

---

## 5. Deliberately out of scope (for now)

- Full multi-target SPM split beyond the planned `NeoClashTLS` extraction —
  premature below ~20–30k lines; the subsystem directories make it mechanical
  later. (Extracting `TLS/` into its own target is step 3 of the architecture
  plan and can happen any time it's convenient; it's mostly adding `public`.)
- A GUI or app integration — this repo stays package-first and headless.
- Congestion control / retransmit timers in the TUN TCP path — intentionally
  omitted; the in-memory splice is lossless and the app layer retransmits.

---

## 6. Suggested near-term sequence

A concrete order that respects the dependencies above:

1. **M1** (TunnelRelay extraction) — unblocks UDP.
2. **M4.1–M4.2** (log buffer + connection tracker splits) — cheap, reduces risk
   before the relay/UDP churn touches connection tracking.
3. **M2** (UDP relay) — the headline capability.
4. **M3** (Shadowsocks) — high value, validates protocol workflow with UDP ready.
5. **M4.3–M4.4** (registry + router splits).
6. **M5** (Trojan), then **M6** (auto-route), then **M7** (Hysteria2/WireGuard).

Cross-cutting items (config hardening, TUN-device testability, versioning) slot
in between milestones as low-risk fillers.
