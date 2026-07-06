import Foundation
import NIOCore
import NIOPosix
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A DNS nameserver, parsed from a config string.
enum SwiftCoreNameServer: Sendable, Equatable {
    case udp(host: String, port: Int)
    case dot(host: String, port: Int)
    case doh(url: URL)

    /// Parses `1.1.1.1`, `1.1.1.1:53`, `udp://…`, `tls://…` (DoT, port 853), or
    /// `https://…/dns-query`. Trailing `#policy` hints and unsupported schemes (`tcp://`)
    /// are ignored/dropped.
    static func parse(_ string: String) -> SwiftCoreNameServer? {
        var value = string.trimmingCharacters(in: .whitespaces)
        if let hash = value.firstIndex(of: "#") { value = String(value[..<hash]) }
        if value.isEmpty { return nil }
        if value.hasPrefix("https://") {
            return URL(string: value).map { .doh(url: $0) }
        }
        if value.hasPrefix("tls://") {
            return hostPort(String(value.dropFirst(6)), defaultPort: 853).map { .dot(host: $0.host, port: $0.port) }
        }
        if value.hasPrefix("tcp://") {
            return nil // plain DNS-over-TCP not implemented
        }
        if value.hasPrefix("udp://") { value = String(value.dropFirst(6)) }
        return hostPort(value, defaultPort: 53).map { .udp(host: $0.host, port: $0.port) }
    }

    /// Splits `host[:port]`; leaves bracketed IPv6 hosts alone.
    private static func hostPort(_ value: String, defaultPort: Int) -> (host: String, port: Int)? {
        if value.isEmpty { return nil }
        if value.hasPrefix("[") {
            guard let end = value.firstIndex(of: "]") else { return nil }
            let host = String(value[value.index(after: value.startIndex)..<end])
            let rest = value[value.index(after: end)...]
            let port = rest.hasPrefix(":") ? Int(rest.dropFirst()) ?? defaultPort : defaultPort
            return (host, port)
        }
        if let colon = value.lastIndex(of: ":"), !value[..<colon].contains(":"), let port = Int(value[value.index(after: colon)...]) {
            return (String(value[..<colon]), port)
        }
        return (value, defaultPort)
    }
}

/// `nameserver-policy` matcher: maps domain patterns (exact, `+.x`, `*.x`, `.x`) to the servers
/// that should resolve them. Exact matches win over suffix matches; suffix matching walks from
/// the full name outward so the most specific suffix wins. Like the fake-ip filter, `+.x` and
/// `*.x` both match `x` itself and any subdomain depth.
struct SwiftCoreDNSNameserverPolicy: Sendable {
    private let full: [String: [SwiftCoreNameServer]]
    private let suffix: [String: [SwiftCoreNameServer]]

    init(rules: [SwiftCoreDNSPolicyRule]) {
        var full: [String: [SwiftCoreNameServer]] = [:]
        var suffix: [String: [SwiftCoreNameServer]] = [:]
        for rule in rules {
            let servers = rule.servers.compactMap(SwiftCoreNameServer.parse)
            guard !servers.isEmpty else { continue }
            let lower = rule.pattern.lowercased()
            if lower.hasPrefix("+.") || lower.hasPrefix("*.") {
                let key = String(lower.dropFirst(2))
                if suffix[key] == nil { suffix[key] = servers }
            } else if lower.hasPrefix(".") {
                let key = String(lower.dropFirst())
                if suffix[key] == nil { suffix[key] = servers }
            } else {
                if full[lower] == nil { full[lower] = servers }
            }
        }
        self.full = full
        self.suffix = suffix
    }

    var isEmpty: Bool { full.isEmpty && suffix.isEmpty }

    func servers(for host: String) -> [SwiftCoreNameServer]? {
        let host = host.lowercased()
        if let servers = full[host] { return servers }
        if let servers = suffix[host] { return servers }
        var rest = host
        while let dot = rest.firstIndex(of: ".") {
            rest = String(rest[rest.index(after: dot)...])
            if let servers = suffix[rest] { return servers }
        }
        return nil
    }
}

/// Resolves domains to IP addresses using the configured nameservers, honoring `hosts` and a
/// TTL cache. Supports plain UDP, DNS-over-HTTPS, and DNS-over-TLS (on the from-scratch TLS 1.3
/// client; note that client skips WebPKI certificate verification). `nameserver-policy` routes
/// matching domains to dedicated servers; `fallback` servers are raced against the primaries and
/// win when the `fallback-filter` distrusts the primary answer. Falls back to
/// `default-nameserver` when no primary `nameserver` is configured.
public final class SwiftCoreDNSResolver: @unchecked Sendable {
    private let servers: [SwiftCoreNameServer]
    private let fallbackServers: [SwiftCoreNameServer]
    private let bootstrapServers: [SwiftCoreNameServer]
    private let policy: SwiftCoreDNSNameserverPolicy
    private let fallbackFilter: SwiftCoreDNSFallbackFilter
    private let fallbackDomainFilter: SwiftCoreFakeIPFilter // generic domain-pattern matcher, despite the name
    private let hostsMap: [String: SwiftCoreAddress]
    private let group: EventLoopGroup
    private let lock = NSLock()
    private var cache: [String: (addresses: [SwiftCoreAddress], expires: Date)] = [:]
    private var geoIPProvider: (@Sendable () -> SwiftCoreGeoIP?)?

    public init(config: SwiftCoreDNSConfig, group: EventLoopGroup) {
        var parsed = config.nameservers.compactMap(SwiftCoreNameServer.parse)
        if parsed.isEmpty { parsed = config.defaultNameservers.compactMap(SwiftCoreNameServer.parse) }
        self.servers = parsed
        self.fallbackServers = config.fallback.compactMap(SwiftCoreNameServer.parse)
        // DoT/DoH server hostnames are resolved through the plain-UDP default-nameservers only,
        // so bootstrapping can never recurse into DoT/DoH.
        self.bootstrapServers = config.defaultNameservers.compactMap(SwiftCoreNameServer.parse).filter {
            if case .udp = $0 { return true }
            return false
        }
        self.policy = SwiftCoreDNSNameserverPolicy(rules: config.nameserverPolicy)
        self.fallbackFilter = config.fallbackFilter
        self.fallbackDomainFilter = SwiftCoreFakeIPFilter(patterns: config.fallbackFilter.domain)
        self.group = group
        var hosts: [String: SwiftCoreAddress] = [:]
        for (name, ip) in config.hosts {
            let address = SwiftCoreAddress.detect(host: ip)
            if case .domain = address { continue }
            hosts[name.lowercased()] = address
        }
        self.hostsMap = hosts
    }

    /// Supplies the GeoIP database for the fallback geoip filter. The closure is re-invoked per
    /// query so geo data that finishes downloading after startup is picked up automatically.
    func setGeoIPProvider(_ provider: @escaping @Sendable () -> SwiftCoreGeoIP?) {
        lock.lock(); defer { lock.unlock() }
        geoIPProvider = provider
    }

    /// Resolves `domain` to its addresses (empty if it can't be resolved).
    public func resolve(_ domain: String) async -> [SwiftCoreAddress] {
        let name = normalized(domain)
        if case .domain = SwiftCoreAddress.detect(host: name) {} else {
            return [SwiftCoreAddress.detect(host: name)] // already a literal IP
        }
        if let host = hostsMap[name] { return [host] }
        if let cached = cachedAddresses(name) { return cached }

        if let policyServers = policy.servers(for: name) {
            return await resolveVia(policyServers, name: name)
        }
        if fallbackServers.isEmpty {
            return await resolveVia(servers, name: name)
        }
        if fallbackDomainFilter.matches(name) {
            return await resolveVia(fallbackServers, name: name)
        }
        return await resolveWithFallback(name)
    }

    public func resolveFirst(_ domain: String) async -> SwiftCoreAddress? {
        await resolve(domain).first
    }

    // MARK: - Fallback arbitration

    /// Races the primary and fallback groups. The primary answer is kept unless the filter says
    /// it is poisoned (ipcidr hit: never used) or untrusted (geoip miss: fallback preferred, but
    /// the primary still serves as a last resort when the fallback fails).
    private func resolveWithFallback(_ name: String) async -> [SwiftCoreAddress] {
        let fallbackTask = Task { [fallbackServers] in await self.queryGroup(fallbackServers, name: name) }
        let main = await queryGroup(servers, name: name)

        let chosen: (addresses: [SwiftCoreAddress], ttl: UInt32)?
        if let main {
            if Self.isPoisoned(main.addresses, ipcidr: fallbackFilter.ipcidr) {
                chosen = await fallbackTask.value
            } else if Self.prefersFallback(main.addresses, geoIPEnabled: fallbackFilter.geoIP, isInGeoCode: geoCodeMatcher()) {
                chosen = await fallbackTask.value ?? main
            } else {
                fallbackTask.cancel() // answer not needed; let the queries wind down on their own
                chosen = main
            }
        } else {
            chosen = await fallbackTask.value
        }
        guard let chosen else { return [] }
        store(name, addresses: chosen.addresses, ttl: chosen.ttl)
        return chosen.addresses
    }

    /// A primary answer with any IP inside `fallback-filter.ipcidr` is treated as poisoned.
    static func isPoisoned(_ addresses: [SwiftCoreAddress], ipcidr: [String]) -> Bool {
        addresses.contains { address in
            ipcidr.contains { SwiftCoreRuleMatcher.cidrContains(cidr: $0, address: address) }
        }
    }

    /// With the geoip filter on, a primary answer containing any IP outside `geoip-code` is
    /// distrusted. `isInGeoCode == nil` means the geo database isn't loaded (yet); the primary
    /// answer is trusted then, since there is nothing to check against.
    static func prefersFallback(_ addresses: [SwiftCoreAddress], geoIPEnabled: Bool, isInGeoCode: ((SwiftCoreAddress) -> Bool)?) -> Bool {
        guard geoIPEnabled, let isInGeoCode else { return false }
        return addresses.contains { !isInGeoCode($0) }
    }

    private func geoCodeMatcher() -> ((SwiftCoreAddress) -> Bool)? {
        guard fallbackFilter.geoIP else { return nil }
        lock.lock()
        let provider = geoIPProvider
        lock.unlock()
        guard let geoIP = provider?() else { return nil }
        let code = fallbackFilter.geoIPCode
        return { geoIP.matches(country: code, address: $0) }
    }

    // MARK: - Internals

    private func normalized(_ domain: String) -> String {
        var name = domain.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        return name
    }

    private func cachedAddresses(_ name: String) -> [SwiftCoreAddress]? {
        lock.lock(); defer { lock.unlock() }
        if let entry = cache[name], entry.expires > Date() { return entry.addresses }
        return nil
    }

    private func store(_ name: String, addresses: [SwiftCoreAddress], ttl: UInt32) {
        lock.lock(); defer { lock.unlock() }
        cache[name] = (addresses, Date().addingTimeInterval(Double(max(1, ttl))))
    }

    private func resolveVia(_ servers: [SwiftCoreNameServer], name: String) async -> [SwiftCoreAddress] {
        guard let (addresses, ttl) = await queryGroup(servers, name: name) else { return [] }
        store(name, addresses: addresses, ttl: ttl)
        return addresses
    }

    /// Tries each server in order until one returns a non-empty answer.
    private func queryGroup(_ servers: [SwiftCoreNameServer], name: String) async -> (addresses: [SwiftCoreAddress], ttl: UInt32)? {
        for server in servers {
            if let result = await query(server, name: name) { return result }
        }
        return nil
    }

    private func query(_ server: SwiftCoreNameServer, name: String) async -> (addresses: [SwiftCoreAddress], ttl: UInt32)? {
        let query = SwiftCoreDNSMessage.encodeQuery(id: UInt16.random(in: 0...UInt16.max), name: name, type: .a)
        let response: [UInt8]?
        switch server {
        case .doh(let url):
            response = await queryDoH(url: url, query: query)
        case .udp(let host, let port):
            response = await queryUDP(host: host, port: port, query: query)
        case .dot(let host, let port):
            response = await queryDoT(host: host, port: port, query: query)
        }
        guard let response else { return nil }
        let answers = SwiftCoreDNSMessage.decodeAnswers(response)
        guard !answers.isEmpty else { return nil }
        let ttl = answers.map(\.ttl).min() ?? 300
        return (answers.map(\.address), ttl)
    }

    private func queryDoH(url: URL, query: [UInt8]) async -> [UInt8]? {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = Data(query)
        request.timeoutInterval = 5
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            return nil
        }
        return Array(data)
    }

    private func queryUDP(host: String, port: Int, query: [UInt8]) async -> [UInt8]? {
        let completion = SwiftCoreDNSCompletion()
        do {
            let channel = try await DatagramBootstrap(group: group)
                .channelInitializer { channel in
                    channel.pipeline.addHandler(SwiftCoreUDPDNSHandler(completion: completion))
                }
                .bind(host: "0.0.0.0", port: 0)
                .get()
            let loop = channel.eventLoop
            let timeout = loop.scheduleTask(in: .seconds(5)) { completion.finish(nil) }
            var buffer = channel.allocator.buffer(capacity: query.count)
            buffer.writeBytes(query)
            let remote = try SocketAddress(ipAddress: host, port: port)
            channel.writeAndFlush(AddressedEnvelope(remoteAddress: remote, data: buffer), promise: nil)
            let result = await completion.value()
            timeout.cancel()
            try? await channel.close().get()
            return result
        } catch {
            return nil
        }
    }

    // MARK: - DNS-over-TLS

    /// One query over a fresh TLS 1.3 connection (RFC 7858): TCP framing (2-byte length prefix)
    /// inside TLS, using the from-scratch `SwiftCoreTLS13ClientHandler`.
    private func queryDoT(host: String, port: Int, query: [UInt8]) async -> [UInt8]? {
        var serverName: String?
        var target: SocketAddress?
        if case .domain = SwiftCoreAddress.detect(host: host) {
            serverName = host
            // Resolve the DoT server's own hostname via the bootstrap (default-nameserver)
            // servers; when none are configured, fall back to the system resolver below.
            if let address = await bootstrapResolve(host) {
                var packed = ByteBufferAllocator().buffer(capacity: 16)
                switch address {
                case .ipv4(let bytes), .ipv6(let bytes): packed.writeBytes(bytes)
                case .domain: break
                }
                target = try? SocketAddress(packedIPAddress: packed, port: port)
            }
        } else {
            target = try? SocketAddress(ipAddress: host, port: port)
        }

        let completion = SwiftCoreDNSCompletion()
        let sni = serverName
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                do {
                    try channel.pipeline.syncOperations.addHandler(
                        SwiftCoreTLS13ClientHandler(serverName: sni, alpn: ["dot"])
                    )
                    try channel.pipeline.syncOperations.addHandler(
                        SwiftCoreDoTQueryHandler(query: query, completion: completion)
                    )
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
        do {
            let connect = target.map { bootstrap.connect(to: $0) } ?? bootstrap.connect(host: host, port: port)
            let channel = try await connect.get()
            let timeout = channel.eventLoop.scheduleTask(in: .seconds(5)) { completion.finish(nil) }
            let result = await completion.value()
            timeout.cancel()
            try? await channel.close().get()
            return result
        } catch {
            return nil
        }
    }

    /// Resolves a DoT server's hostname using only the UDP bootstrap servers (never DoT/DoH).
    private func bootstrapResolve(_ name: String) async -> SwiftCoreAddress? {
        for server in bootstrapServers {
            if let (addresses, _) = await query(server, name: name), let first = addresses.first {
                return first
            }
        }
        return nil
    }
}

/// Sends one length-prefixed DNS query as soon as TLS is established (the TLS 1.3 handler delays
/// `channelActive` until the handshake completes) and collects the length-prefixed response.
final class SwiftCoreDoTQueryHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let query: [UInt8]
    private let completion: SwiftCoreDNSCompletion
    private var received: [UInt8] = []

    init(query: [UInt8], completion: SwiftCoreDNSCompletion) {
        self.query = query
        self.completion = completion
    }

    func channelActive(context: ChannelHandlerContext) {
        var out = context.channel.allocator.buffer(capacity: query.count + 2)
        out.writeInteger(UInt16(query.count))
        out.writeBytes(query)
        context.writeAndFlush(Self.wrapOutboundOut(out), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = Self.unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            received.append(contentsOf: bytes)
        }
        guard received.count >= 2 else { return }
        let length = Int(received[0]) << 8 | Int(received[1])
        if received.count >= 2 + length {
            completion.finish(Array(received[2..<2 + length]))
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        completion.finish(nil) // no-op if the answer already arrived
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        completion.finish(nil)
        context.close(promise: nil)
    }
}

/// Single-completion async box for the UDP query (handler response vs. timeout race).
final class SwiftCoreDNSCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var result: [UInt8]??
    private var continuation: CheckedContinuation<[UInt8]?, Never>?

    func value() async -> [UInt8]? {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(returning: result)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }

    func finish(_ bytes: [UInt8]?) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = .some(bytes)
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: bytes)
    }
}

final class SwiftCoreUDPDNSHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let completion: SwiftCoreDNSCompletion

    init(completion: SwiftCoreDNSCompletion) {
        self.completion = completion
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var envelope = Self.unwrapInboundIn(data)
        let bytes = envelope.data.readBytes(length: envelope.data.readableBytes) ?? []
        completion.finish(bytes)
        context.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        completion.finish(nil)
        context.close(promise: nil)
    }
}
