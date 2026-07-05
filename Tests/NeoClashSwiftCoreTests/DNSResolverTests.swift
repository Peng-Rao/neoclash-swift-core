import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for the DNS resolver. Parsing, hosts, literal-IP passthrough, policy matching, and
/// fallback arbitration are hermetic (stub UDP/DoT servers on loopback); the actual public
/// UDP/DoH/DoT queries hit the network and only run when `NEOCLASH_LIVE_DNS=1` (kept out of CI).
final class DNSResolverTests: XCTestCase {
    func testNameServerParsing() {
        func udp(_ string: String) -> (String, Int)? {
            if case .udp(let host, let port)? = SwiftCoreNameServer.parse(string) { return (host, port) }
            return nil
        }
        func dot(_ string: String) -> (String, Int)? {
            if case .dot(let host, let port)? = SwiftCoreNameServer.parse(string) { return (host, port) }
            return nil
        }
        XCTAssertEqual(udp("223.5.5.5")?.0, "223.5.5.5")
        XCTAssertEqual(udp("223.5.5.5")?.1, 53)
        XCTAssertEqual(udp("8.8.8.8:5353")?.1, 5353)
        XCTAssertEqual(udp("udp://1.1.1.1")?.0, "1.1.1.1")
        XCTAssertEqual(udp("1.1.1.1#dns")?.0, "1.1.1.1")           // policy hint stripped
        if case .doh(let url)? = SwiftCoreNameServer.parse("https://1.1.1.1/dns-query") {
            XCTAssertEqual(url.absoluteString, "https://1.1.1.1/dns-query")
        } else {
            XCTFail("expected DoH")
        }
        XCTAssertEqual(dot("tls://8.8.8.8")?.0, "8.8.8.8")
        XCTAssertEqual(dot("tls://8.8.8.8")?.1, 853)               // DoT default port
        XCTAssertEqual(dot("tls://dns.google:8853")?.0, "dns.google")
        XCTAssertEqual(dot("tls://dns.google:8853")?.1, 8853)
        XCTAssertEqual(dot("tls://[2001:4860:4860::8888]")?.0, "2001:4860:4860::8888")
        XCTAssertNil(SwiftCoreNameServer.parse("tcp://8.8.8.8"))   // plain DNS-over-TCP unsupported
    }

    func testLiteralIPPassthrough() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let resolver = SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(), group: group)
        let result = await resolver.resolve("93.184.216.34")
        XCTAssertEqual(result, [.ipv4([93, 184, 216, 34])])
        try? await group.shutdownGracefully()
    }

    func testHostsMapping() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let config = SwiftCoreDNSConfig(hosts: ["router.local": "192.168.1.1"])
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let lower = await resolver.resolveFirst("router.local")
        let upper = await resolver.resolveFirst("ROUTER.LOCAL")
        XCTAssertEqual(lower, .ipv4([192, 168, 1, 1]))
        XCTAssertEqual(upper, .ipv4([192, 168, 1, 1]))
        try? await group.shutdownGracefully()
    }

    // MARK: - nameserver-policy matching

    func testNameserverPolicyMatching() {
        let corp: [SwiftCoreNameServer] = [.udp(host: "10.0.0.53", port: 53)]
        let exact: [SwiftCoreNameServer] = [.dot(host: "1.1.1.1", port: 853)]
        let policy = SwiftCoreDNSNameserverPolicy(rules: [
            SwiftCoreDNSPolicyRule(pattern: "+.internal.corp", servers: ["10.0.0.53"]),
            SwiftCoreDNSPolicyRule(pattern: "www.example.com", servers: ["tls://1.1.1.1"]),
        ])
        XCTAssertFalse(policy.isEmpty)
        // `+.x` matches the name itself and any subdomain depth.
        XCTAssertEqual(policy.servers(for: "internal.corp"), corp)
        XCTAssertEqual(policy.servers(for: "db.internal.corp"), corp)
        XCTAssertEqual(policy.servers(for: "a.b.internal.corp"), corp)
        // Exact patterns match only the full name.
        XCTAssertEqual(policy.servers(for: "www.example.com"), exact)
        XCTAssertEqual(policy.servers(for: "WWW.EXAMPLE.COM"), exact)
        XCTAssertNil(policy.servers(for: "api.example.com"))
        XCTAssertNil(policy.servers(for: "example.com"))
        XCTAssertNil(policy.servers(for: "corp"))
    }

    func testNameserverPolicyMostSpecificSuffixWins() {
        let policy = SwiftCoreDNSNameserverPolicy(rules: [
            SwiftCoreDNSPolicyRule(pattern: "+.corp", servers: ["1.0.0.1"]),
            SwiftCoreDNSPolicyRule(pattern: "+.internal.corp", servers: ["10.0.0.53"]),
        ])
        XCTAssertEqual(policy.servers(for: "db.internal.corp"), [.udp(host: "10.0.0.53", port: 53)])
        XCTAssertEqual(policy.servers(for: "www.corp"), [.udp(host: "1.0.0.1", port: 53)])
    }

    // MARK: - fallback-filter arbitration units

    func testFallbackPoisonDetection() {
        let poisoned: [SwiftCoreAddress] = [.ipv4([240, 0, 0, 1])]
        let clean: [SwiftCoreAddress] = [.ipv4([8, 8, 8, 8])]
        XCTAssertTrue(SwiftCoreDNSResolver.isPoisoned(poisoned, ipcidr: ["240.0.0.0/4"]))
        XCTAssertFalse(SwiftCoreDNSResolver.isPoisoned(clean, ipcidr: ["240.0.0.0/4"]))
        XCTAssertFalse(SwiftCoreDNSResolver.isPoisoned(poisoned, ipcidr: []))
    }

    func testFallbackGeoIPPreference() {
        let inside: [SwiftCoreAddress] = [.ipv4([114, 114, 114, 114])]
        let outside: [SwiftCoreAddress] = [.ipv4([8, 8, 8, 8])]
        let isCN: (SwiftCoreAddress) -> Bool = { $0 == .ipv4([114, 114, 114, 114]) }
        XCTAssertFalse(SwiftCoreDNSResolver.prefersFallback(inside, geoIPEnabled: true, isInGeoCode: isCN))
        XCTAssertTrue(SwiftCoreDNSResolver.prefersFallback(outside, geoIPEnabled: true, isInGeoCode: isCN))
        // Filter disabled, or geo database not loaded: the primary answer is trusted.
        XCTAssertFalse(SwiftCoreDNSResolver.prefersFallback(outside, geoIPEnabled: false, isInGeoCode: isCN))
        XCTAssertFalse(SwiftCoreDNSResolver.prefersFallback(outside, geoIPEnabled: true, isInGeoCode: nil))
    }

    // MARK: - hermetic end-to-end (stub UDP servers on loopback)

    func testFallbackUsedWhenPrimaryAnswerIsPoisoned() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let primary = try StubUDPDNSServer(group: group, answer: [240, 0, 0, 1])
        let fallback = try StubUDPDNSServer(group: group, answer: [93, 184, 216, 34])

        let config = SwiftCoreDNSConfig(
            nameservers: ["127.0.0.1:\(primary.port)"],
            fallback: ["127.0.0.1:\(fallback.port)"],
            fallbackFilter: SwiftCoreDNSFallbackFilter(geoIP: false, ipcidr: ["240.0.0.0/4"])
        )
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let result = await resolver.resolve("poisoned.test")
        XCTAssertEqual(result, [.ipv4([93, 184, 216, 34])])
        primary.stop(); fallback.stop()
        try? await group.shutdownGracefully()
    }

    func testPrimaryKeptWhenFallbackFilterDoesNotDistrustIt() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let primary = try StubUDPDNSServer(group: group, answer: [1, 2, 3, 4])
        let fallback = try StubUDPDNSServer(group: group, answer: [93, 184, 216, 34])

        // geoip filter is on but no geo database is loaded -> the primary answer is trusted.
        let config = SwiftCoreDNSConfig(
            nameservers: ["127.0.0.1:\(primary.port)"],
            fallback: ["127.0.0.1:\(fallback.port)"]
        )
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let result = await resolver.resolve("trusted.test")
        XCTAssertEqual(result, [.ipv4([1, 2, 3, 4])])
        primary.stop(); fallback.stop()
        try? await group.shutdownGracefully()
    }

    func testFallbackDomainFilterSkipsPrimary() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let primary = try StubUDPDNSServer(group: group, answer: [1, 2, 3, 4])
        let fallback = try StubUDPDNSServer(group: group, answer: [93, 184, 216, 34])

        let config = SwiftCoreDNSConfig(
            nameservers: ["127.0.0.1:\(primary.port)"],
            fallback: ["127.0.0.1:\(fallback.port)"],
            fallbackFilter: SwiftCoreDNSFallbackFilter(domain: ["+.google.com"])
        )
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let result = await resolver.resolve("www.google.com")
        XCTAssertEqual(result, [.ipv4([93, 184, 216, 34])])
        primary.stop(); fallback.stop()
        try? await group.shutdownGracefully()
    }

    func testNameserverPolicyRoutesQueriesToPolicyServer() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let primary = try StubUDPDNSServer(group: group, answer: [1, 2, 3, 4])
        let policyServer = try StubUDPDNSServer(group: group, answer: [10, 0, 0, 7])

        let config = SwiftCoreDNSConfig(
            nameservers: ["127.0.0.1:\(primary.port)"],
            nameserverPolicy: [SwiftCoreDNSPolicyRule(pattern: "+.corp", servers: ["127.0.0.1:\(policyServer.port)"])]
        )
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let matched = await resolver.resolve("db.corp")
        let unmatched = await resolver.resolve("example.test")
        XCTAssertEqual(matched, [.ipv4([10, 0, 0, 7])])
        XCTAssertEqual(unmatched, [.ipv4([1, 2, 3, 4])])
        primary.stop(); policyServer.stop()
        try? await group.shutdownGracefully()
    }

    // MARK: - DNS-over-TLS (hermetic: our TLS 1.3 client vs a BoringSSL server)

    func testDoTResolveAgainstLocalTLSServer() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let certificate = try NIOSSLCertificate(bytes: Array(Self.certPEM.utf8), format: .pem)
        let privateKey = try NIOSSLPrivateKey(bytes: Array(Self.keyPEM.utf8), format: .pem)
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
        serverConfig.minimumTLSVersion = .tlsv13
        let serverContext = try NIOSSLContext(configuration: serverConfig)

        let server = try await ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                do {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: serverContext))
                    try channel.pipeline.syncOperations.addHandler(StubDoTServerHandler(answer: [9, 9, 9, 9]))
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        let port = try XCTUnwrap(server.localAddress?.port)

        let config = SwiftCoreDNSConfig(nameservers: ["tls://127.0.0.1:\(port)"])
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let result = await resolver.resolve("dot.test")
        XCTAssertEqual(result, [.ipv4([9, 9, 9, 9])])
        // Second resolve is served from the TTL cache (no new connection needed).
        let cached = await resolver.resolve("dot.test")
        XCTAssertEqual(cached, [.ipv4([9, 9, 9, 9])])
        try? await server.close().get()
        try? await group.shutdownGracefully()
    }

    // MARK: - live tests (network; opt-in)

    func testLiveUDPResolve() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["NEOCLASH_LIVE_DNS"] == "1")
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let resolver = SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(nameservers: ["1.1.1.1"]), group: group)
        let result = await resolver.resolve("example.com")
        XCTAssertFalse(result.isEmpty)
        if case .ipv4 = result.first { } else { XCTFail("expected an IPv4 answer") }
        try? await group.shutdownGracefully()
    }

    func testLiveDoHResolve() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["NEOCLASH_LIVE_DNS"] == "1")
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let resolver = SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(nameservers: ["https://1.1.1.1/dns-query"]), group: group)
        let result = await resolver.resolve("example.com")
        XCTAssertFalse(result.isEmpty)
        try? await group.shutdownGracefully()
    }

    func testLiveDoTResolve() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["NEOCLASH_LIVE_DNS"] == "1")
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let resolver = SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(nameservers: ["tls://1.1.1.1"]), group: group)
        let result = await resolver.resolve("example.com")
        XCTAssertFalse(result.isEmpty)
        try? await group.shutdownGracefully()
    }

    func testLiveDoTResolveWithDomainServer() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["NEOCLASH_LIVE_DNS"] == "1")
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        // The DoT server's own hostname bootstraps through the UDP default-nameserver.
        let config = SwiftCoreDNSConfig(nameservers: ["tls://dns.google"], defaultNameservers: ["1.1.1.1"])
        let resolver = SwiftCoreDNSResolver(config: config, group: group)
        let result = await resolver.resolve("example.com")
        XCTAssertFalse(result.isEmpty)
        try? await group.shutdownGracefully()
    }

    // Self-signed P-256 certificate for CN=localhost (test only; also used by TLS13HandshakeTests).
    private static let certPEM = """
    -----BEGIN CERTIFICATE-----
    MIIBfTCCASOgAwIBAgIUO7jHrES/1fCQthrAuDvC4hxeZeMwCgYIKoZIzj0EAwIw
    FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYyMjIyMzM1OFoXDTM2MDYxOTIy
    MzM1OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
    AQcDQgAEzrUvhBP1VtxWpITwftn+4iURBlEK3K+fKWblrT+4iIokvDa8K3JXc8wK
    d0Ev7M8HLRL4Zm06NSq7y1apUO3CK6NTMFEwHQYDVR0OBBYEFKnwV4pGukaK9zIQ
    5MrGxl7XcphxMB8GA1UdIwQYMBaAFKnwV4pGukaK9zIQ5MrGxl7XcphxMA8GA1Ud
    EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgU+Htcp++UDHxYjEW/oWN5dqw
    PPT+3hgWZwBehCvTONQCIQCghNh/9f7RAEVSqZH5k2qeOgpbUXrOlIghWBHIekHi
    Cw==
    -----END CERTIFICATE-----
    """

    private static let keyPEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcJQh6NSSjJMC0qY0
    to6FSmWhmMlOpzlLebm+ucingcqhRANCAATOtS+EE/VW3FakhPB+2f7iJREGUQrc
    r58pZuWtP7iIiiS8NrwrcldzzAp3QS/szwctEvhmbTo1KrvLVqlQ7cIr
    -----END PRIVATE KEY-----
    """
}

/// A stub UDP DNS server on loopback that answers every query with one fixed A record.
private final class StubUDPDNSServer {
    private let channel: Channel
    var port: Int { channel.localAddress?.port ?? 0 }

    init(group: EventLoopGroup, answer: [UInt8], ttl: UInt32 = 60) throws {
        channel = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(Handler(answer: answer, ttl: ttl))
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
    }

    func stop() {
        try? channel.close().wait()
    }

    private final class Handler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = AddressedEnvelope<ByteBuffer>
        typealias OutboundOut = AddressedEnvelope<ByteBuffer>

        private let answer: [UInt8]
        private let ttl: UInt32

        init(answer: [UInt8], ttl: UInt32) {
            self.answer = answer
            self.ttl = ttl
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var envelope = Self.unwrapInboundIn(data)
            guard let query = envelope.data.readBytes(length: envelope.data.readableBytes) else { return }
            let answers = [SwiftCoreDNSAnswer(address: .ipv4(answer), ttl: ttl)]
            let response = SwiftCoreDNSMessage.encodeResponse(query: query, answers: answers)
            var buffer = context.channel.allocator.buffer(capacity: response.count)
            buffer.writeBytes(response)
            context.writeAndFlush(Self.wrapOutboundOut(AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: buffer)), promise: nil)
        }
    }
}

/// Speaks DNS-over-TCP framing behind the TLS server handler: reads a 2-byte-length-prefixed
/// query, replies with a length-prefixed response carrying one fixed A record.
private final class StubDoTServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let answer: [UInt8]
    private var received: [UInt8] = []

    init(answer: [UInt8]) {
        self.answer = answer
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = Self.unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            received.append(contentsOf: bytes)
        }
        guard received.count >= 2 else { return }
        let length = Int(received[0]) << 8 | Int(received[1])
        guard received.count >= 2 + length else { return }
        let query = Array(received[2..<2 + length])
        received.removeFirst(2 + length)
        let answers = [SwiftCoreDNSAnswer(address: .ipv4(answer), ttl: 60)]
        let response = SwiftCoreDNSMessage.encodeResponse(query: query, answers: answers)
        var out = context.channel.allocator.buffer(capacity: response.count + 2)
        out.writeInteger(UInt16(response.count))
        out.writeBytes(response)
        context.writeAndFlush(Self.wrapOutboundOut(out), promise: nil)
    }
}
