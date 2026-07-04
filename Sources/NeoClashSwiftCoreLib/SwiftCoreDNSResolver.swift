import Foundation
import NIOCore
import NIOPosix
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A DNS nameserver, parsed from a config string.
enum SwiftCoreNameServer: Sendable {
    case udp(host: String, port: Int)
    case doh(url: URL)

    /// Parses `1.1.1.1`, `1.1.1.1:53`, `udp://…`, or `https://…/dns-query`. Trailing `#policy`
    /// hints and unsupported schemes (`tls://`, `tcp://`) are ignored/dropped.
    static func parse(_ string: String) -> SwiftCoreNameServer? {
        var value = string.trimmingCharacters(in: .whitespaces)
        if let hash = value.firstIndex(of: "#") { value = String(value[..<hash]) }
        if value.isEmpty { return nil }
        if value.hasPrefix("https://") {
            return URL(string: value).map { .doh(url: $0) }
        }
        if value.hasPrefix("tls://") || value.hasPrefix("tcp://") {
            return nil // DoT / DNS-over-TCP not implemented yet
        }
        if value.hasPrefix("udp://") { value = String(value.dropFirst(6)) }
        // host[:port]; leave bracketed IPv6 hosts alone.
        if value.hasPrefix("[") {
            guard let end = value.firstIndex(of: "]") else { return nil }
            let host = String(value[value.index(after: value.startIndex)..<end])
            let rest = value[value.index(after: end)...]
            let port = rest.hasPrefix(":") ? Int(rest.dropFirst()) ?? 53 : 53
            return .udp(host: host, port: port)
        }
        if let colon = value.lastIndex(of: ":"), !value[..<colon].contains(":"), let port = Int(value[value.index(after: colon)...]) {
            return .udp(host: String(value[..<colon]), port: port)
        }
        return .udp(host: value, port: 53)
    }
}

/// Resolves domains to IP addresses using the configured nameservers, honoring `hosts` and a
/// TTL cache. Supports plain UDP and DNS-over-HTTPS; falls back to `default-nameserver` when no
/// primary `nameserver` is configured.
public final class SwiftCoreDNSResolver: @unchecked Sendable {
    private let servers: [SwiftCoreNameServer]
    private let hostsMap: [String: SwiftCoreAddress]
    private let group: EventLoopGroup
    private let lock = NSLock()
    private var cache: [String: (addresses: [SwiftCoreAddress], expires: Date)] = [:]

    public init(config: SwiftCoreDNSConfig, group: EventLoopGroup) {
        var parsed = config.nameservers.compactMap(SwiftCoreNameServer.parse)
        if parsed.isEmpty { parsed = config.defaultNameservers.compactMap(SwiftCoreNameServer.parse) }
        self.servers = parsed
        self.group = group
        var hosts: [String: SwiftCoreAddress] = [:]
        for (name, ip) in config.hosts {
            let address = SwiftCoreAddress.detect(host: ip)
            if case .domain = address { continue }
            hosts[name.lowercased()] = address
        }
        self.hostsMap = hosts
    }

    /// Resolves `domain` to its addresses (empty if it can't be resolved).
    public func resolve(_ domain: String) async -> [SwiftCoreAddress] {
        let name = normalized(domain)
        if case .domain = SwiftCoreAddress.detect(host: name) {} else {
            return [SwiftCoreAddress.detect(host: name)] // already a literal IP
        }
        if let host = hostsMap[name] { return [host] }
        if let cached = cachedAddresses(name) { return cached }

        for server in servers {
            if let (addresses, ttl) = await query(server, name: name), !addresses.isEmpty {
                store(name, addresses: addresses, ttl: ttl)
                return addresses
            }
        }
        return []
    }

    public func resolveFirst(_ domain: String) async -> SwiftCoreAddress? {
        await resolve(domain).first
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

    private func query(_ server: SwiftCoreNameServer, name: String) async -> (addresses: [SwiftCoreAddress], ttl: UInt32)? {
        let query = SwiftCoreDNSMessage.encodeQuery(id: UInt16.random(in: 0...UInt16.max), name: name, type: .a)
        let response: [UInt8]?
        switch server {
        case .doh(let url):
            response = await queryDoH(url: url, query: query)
        case .udp(let host, let port):
            response = await queryUDP(host: host, port: port, query: query)
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
