import Foundation
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for fake-ip mode: the response/question codec, the fake-ip filter, and the UDP DNS server
/// (driven by our own resolver as the client, so it stays hermetic).
final class DNSServerTests: XCTestCase {
    func testDecodeQuestionAndEncodeResponse() {
        let query = SwiftCoreDNSMessage.encodeQuery(id: 0xABCD, name: "example.com", type: .a)
        let question = SwiftCoreDNSMessage.decodeQuestion(query)
        XCTAssertEqual(question?.name, "example.com")
        XCTAssertEqual(question?.type, SwiftCoreDNSRecordType.a.rawValue)

        let response = SwiftCoreDNSMessage.encodeResponse(query: query, answers: [
            SwiftCoreDNSAnswer(address: .ipv4([198, 18, 0, 7]), ttl: 1)
        ])
        XCTAssertEqual(response[0], 0xAB)              // id preserved
        XCTAssertEqual(response[2] & 0x80, 0x80)       // QR set
        XCTAssertEqual(Int(response[6]) << 8 | Int(response[7]), 1) // ANCOUNT
        XCTAssertEqual(SwiftCoreDNSMessage.decodeAnswers(response), [SwiftCoreDNSAnswer(address: .ipv4([198, 18, 0, 7]), ttl: 1)])
    }

    func testFakeIPFilter() {
        let filter = SwiftCoreFakeIPFilter(patterns: ["*.lan", "+.local", "exact.example"])
        XCTAssertTrue(filter.matches("host.lan"))
        XCTAssertTrue(filter.matches("local"))            // +. matches self
        XCTAssertTrue(filter.matches("dev.local"))        // +. matches subdomain
        XCTAssertTrue(filter.matches("exact.example"))
        XCTAssertFalse(filter.matches("notexact.example"))
        XCTAssertFalse(filter.matches("example.com"))
    }

    func testDNSServerHandsOutFakeIPsAndResolvesFilteredForReal() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]
        rules: [MATCH,DIRECT]
        """))
        let pool = try XCTUnwrap(SwiftCoreFakeIPPool(cidr: "198.18.0.1/16"))
        // The server resolves filtered domains for real; give it a hosts entry so it's hermetic.
        let serverResolver = SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(hosts: ["router.local": "10.0.0.1"]), group: group)
        let filter = SwiftCoreFakeIPFilter(patterns: ["+.local"])
        let responder = SwiftCoreDNSResponder(pool: pool, resolver: serverResolver, filter: filter)
        let server = SwiftCoreDNSServer(state: state, responder: responder, group: group)
        let channel = try server.start(host: "127.0.0.1", port: 0)
        let port = try XCTUnwrap(channel.localAddress?.port)

        let client = SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(nameservers: ["127.0.0.1:\(port)"]), group: group)

        // Non-filtered domain -> fake ip, and the pool maps it back.
        let fake = await client.resolve("news.example.com")
        XCTAssertEqual(fake.count, 1)
        guard case .ipv4(let bytes) = fake.first else { return XCTFail("expected a fake IPv4") }
        XCTAssertEqual(Array(bytes[0..<2]), [198, 18])
        XCTAssertEqual(pool.domain(forIPv4: bytes), "news.example.com")

        // Filtered domain -> real answer (from the server's hosts), not a fake ip.
        let real = await client.resolve("router.local")
        XCTAssertEqual(real, [.ipv4([10, 0, 0, 1])])

        server.stop()
        try? await group.shutdownGracefully()
    }

    func testStateFakeIPReverseMapping() throws {
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]
        rules: [MATCH,DIRECT]
        """))
        let pool = try XCTUnwrap(SwiftCoreFakeIPPool(cidr: "198.18.0.1/16"))
        let ip = pool.allocate(domain: "mapped.example")
        state.setFakeIPPool(pool)

        let host = ip.map(String.init).joined(separator: ".")
        XCTAssertEqual(state.fakeIPDomain(forHost: host), "mapped.example")
        XCTAssertNil(state.fakeIPDomain(forHost: "8.8.8.8"))   // not a fake ip
        XCTAssertNil(state.fakeIPDomain(forHost: "example.com")) // not an ip
    }
}
