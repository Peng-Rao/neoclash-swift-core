import Foundation
import NIOCore
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

final class DNSHijackTests: XCTestCase {
    // MARK: UDP datagram

    func testUDPDatagramRoundTrip() {
        let payload = Array("dns-query-bytes".utf8)
        let packet = SwiftCoreUDPDatagram.build(source: [10, 0, 0, 2], destination: [198, 18, 0, 2], sourcePort: 40000, destinationPort: 53, payload: payload)
        let ip = try! XCTUnwrap(SwiftCoreIPv4Packet(packet))
        XCTAssertEqual(ip.proto, SwiftCoreIPProtocol.udp)
        XCTAssertEqual(swiftCoreInternetChecksum(packet[0..<20]), 0)  // IP header checksum valid

        let datagram = try! XCTUnwrap(SwiftCoreUDPDatagram(ip.payload))
        XCTAssertEqual(datagram.sourcePort, 40000)
        XCTAssertEqual(datagram.destinationPort, 53)
        XCTAssertEqual(datagram.length, 8 + payload.count)
        XCTAssertEqual(datagram.payload, payload)

        // UDP checksum (pseudo-header + UDP header incl. checksum + payload) verifies to zero.
        let udp = Array(ip.payload)
        let pseudo: [UInt8] = ip.source + ip.destination + [0, 17, UInt8(udp.count >> 8), UInt8(udp.count & 0xff)]
        XCTAssertEqual(swiftCoreInternetChecksum((pseudo + udp)[...]), 0)
    }

    // MARK: Hijack matcher

    func testHijackTargetParsing() {
        let targets = SwiftCoreDNSHijackTarget.parse(["any:53", "udp://198.18.0.2:53", "not-an-ip"])
        XCTAssertEqual(targets.count, 2)
        XCTAssertTrue(targets[0].matches(destination: [1, 2, 3, 4], port: 53))       // any host
        XCTAssertFalse(targets[0].matches(destination: [1, 2, 3, 4], port: 54))      // wrong port
        XCTAssertTrue(targets[1].matches(destination: [198, 18, 0, 2], port: 53))    // specific host
        XCTAssertFalse(targets[1].matches(destination: [198, 18, 0, 3], port: 53))
    }

    // MARK: Responder

    func testResponderAllocatesFakeIP() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let pool = try XCTUnwrap(SwiftCoreFakeIPPool(cidr: "198.18.0.1/16"))
        let responder = SwiftCoreDNSResponder(
            pool: pool,
            resolver: SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(hosts: ["router.local": "10.0.0.1"]), group: group),
            filter: SwiftCoreFakeIPFilter(patterns: ["+.local"])
        )

        let fake = await responder.answer(query: SwiftCoreDNSMessage.encodeQuery(id: 1, name: "news.example.com", type: .a))
        let fakeAnswers = SwiftCoreDNSMessage.decodeAnswers(fake)
        XCTAssertEqual(fakeAnswers.count, 1)
        guard case .ipv4(let bytes) = fakeAnswers.first?.address else { return XCTFail("expected a fake IPv4") }
        XCTAssertEqual(Array(bytes[0..<2]), [198, 18])
        XCTAssertEqual(pool.domain(forIPv4: bytes), "news.example.com")

        // A filtered domain is resolved for real instead of faked.
        let real = await responder.answer(query: SwiftCoreDNSMessage.encodeQuery(id: 2, name: "router.local", type: .a))
        XCTAssertEqual(SwiftCoreDNSMessage.decodeAnswers(real), [SwiftCoreDNSAnswer(address: .ipv4([10, 0, 0, 1]), ttl: 30)])

        try? await group.shutdownGracefully()
    }

    // MARK: Controller dns-hijack end-to-end

    func testControllerHijacksDNSQuery() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        defer { try? group.syncShutdownGracefully() }
        let pool = try XCTUnwrap(SwiftCoreFakeIPPool(cidr: "198.18.0.1/16"))
        let responder = SwiftCoreDNSResponder(
            pool: pool,
            resolver: SwiftCoreDNSResolver(config: SwiftCoreDNSConfig(), group: group),
            filter: SwiftCoreFakeIPFilter(patterns: [])
        )
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]
        rules: [MATCH,DIRECT]
        """))

        let loop = group.next()
        let collector = UDPEmitCollector(group: group)
        let controller = SwiftCoreTunController(
            state: state, group: group, loop: loop, emit: { collector.add($0) },
            dnsResponder: responder, dnsHijack: SwiftCoreDNSHijackTarget.parse(["any:53"])
        )

        let app: [UInt8] = [10, 0, 0, 2]
        let dnsServer: [UInt8] = [198, 18, 0, 2]
        let query = SwiftCoreDNSMessage.encodeQuery(id: 0x1234, name: "portal.example.com", type: .a)
        let packet = SwiftCoreUDPDatagram.build(source: app, destination: dnsServer, sourcePort: 45000, destinationPort: 53, payload: query)
        try loop.submit { controller.receive(packet) }.wait()

        let (reply, replyIP) = try collector.wait()
        // The response comes back from the queried address to the app.
        XCTAssertEqual(replyIP.source, dnsServer)
        XCTAssertEqual(replyIP.destination, app)
        XCTAssertEqual(reply.sourcePort, 53)
        XCTAssertEqual(reply.destinationPort, 45000)

        let answers = SwiftCoreDNSMessage.decodeAnswers(reply.payload)
        XCTAssertEqual(answers.count, 1)
        guard case .ipv4(let bytes) = answers.first?.address else { return XCTFail("expected a fake IPv4") }
        XCTAssertEqual(Array(bytes[0..<2]), [198, 18])
        XCTAssertEqual(pool.domain(forIPv4: bytes), "portal.example.com")
    }
}

/// Collects emitted UDP packets and lets the test thread await the first one.
private final class UDPEmitCollector: @unchecked Sendable {
    private let group: EventLoopGroup
    private let lock = NSLock()
    private var pending: [(SwiftCoreUDPDatagram, SwiftCoreIPv4Packet)] = []
    private var promise: EventLoopPromise<(SwiftCoreUDPDatagram, SwiftCoreIPv4Packet)>?

    init(group: EventLoopGroup) { self.group = group }

    func add(_ packet: [UInt8]) {
        guard let ip = SwiftCoreIPv4Packet(packet), ip.proto == SwiftCoreIPProtocol.udp, let datagram = SwiftCoreUDPDatagram(ip.payload) else { return }
        lock.lock()
        if let promise {
            self.promise = nil
            lock.unlock()
            promise.succeed((datagram, ip))
            return
        }
        pending.append((datagram, ip))
        lock.unlock()
    }

    func wait() throws -> (SwiftCoreUDPDatagram, SwiftCoreIPv4Packet) {
        lock.lock()
        if !pending.isEmpty {
            let value = pending.removeFirst()
            lock.unlock()
            return value
        }
        let promise = group.next().makePromise(of: (SwiftCoreUDPDatagram, SwiftCoreIPv4Packet).self)
        self.promise = promise
        group.next().scheduleTask(in: .seconds(5)) { promise.fail(SwiftCoreError.invalidConfig("timeout waiting for a UDP reply")) }
        lock.unlock()
        return try promise.futureResult.wait()
    }
}
