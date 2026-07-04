import Foundation
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for the DNS resolver. Parsing, hosts, and literal-IP passthrough are hermetic; the actual
/// UDP/DoH queries hit the network and only run when `NEOCLASH_LIVE_DNS=1` (kept out of CI).
final class DNSResolverTests: XCTestCase {
    func testNameServerParsing() {
        func udp(_ string: String) -> (String, Int)? {
            if case .udp(let host, let port)? = SwiftCoreNameServer.parse(string) { return (host, port) }
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
        XCTAssertNil(SwiftCoreNameServer.parse("tls://8.8.8.8")) // DoT not supported yet
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
}
