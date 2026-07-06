import Foundation
import NIOCore
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

final class TCPRelayTests: XCTestCase {
    private let app: [UInt8] = [10, 0, 0, 2]
    private let target: [UInt8] = [93, 184, 216, 34]

    // MARK: Segment build/parse

    func testSegmentRoundTrip() {
        let packet = SwiftCoreTCPSegment.build(
            source: [10, 0, 0, 1], destination: [10, 0, 0, 2],
            sourcePort: 1234, destinationPort: 80,
            sequenceNumber: 0x11223344, acknowledgmentNumber: 0x55667788,
            flags: SwiftCoreTCPFlag.psh | SwiftCoreTCPFlag.ack, window: 4096, payload: Array("hi".utf8)
        )
        let ip = try! XCTUnwrap(SwiftCoreIPv4Packet(packet))
        XCTAssertEqual(ip.proto, SwiftCoreIPProtocol.tcp)
        XCTAssertEqual(swiftCoreInternetChecksum(packet[0..<20]), 0)  // IP header checksum valid

        let segment = try! XCTUnwrap(SwiftCoreTCPSegment(ip.payload))
        XCTAssertEqual(segment.sourcePort, 1234)
        XCTAssertEqual(segment.destinationPort, 80)
        XCTAssertEqual(segment.sequenceNumber, 0x11223344)
        XCTAssertEqual(segment.acknowledgmentNumber, 0x55667788)
        XCTAssertEqual(segment.window, 4096)
        XCTAssertEqual(segment.payload, Array("hi".utf8))
        XCTAssertTrue(segment.isACK)
        XCTAssertFalse(segment.isSYN)
    }

    func testTCPPseudoHeaderChecksumValid() {
        let packet = SwiftCoreTCPSegment.build(
            source: [192, 168, 1, 2], destination: target,
            sourcePort: 50000, destinationPort: 443,
            sequenceNumber: 1, acknowledgmentNumber: 2,
            flags: SwiftCoreTCPFlag.ack, window: 1000, payload: Array("payload".utf8)
        )
        let ip = try! XCTUnwrap(SwiftCoreIPv4Packet(packet))
        let tcp = Array(ip.payload)
        let pseudo: [UInt8] = ip.source + ip.destination + [0, 6, UInt8(tcp.count >> 8), UInt8(tcp.count & 0xff)]
        XCTAssertEqual(swiftCoreInternetChecksum((pseudo + tcp)[...]), 0)
    }

    // MARK: Connection state machine

    func testHandshakeAndData() {
        let collected = Collected()
        let connection = SwiftCoreTCPConnection(source: app, sourcePort: 40000, destination: target, destinationPort: 80, emit: { collected.append($0) })
        var established = false
        var received: [UInt8] = []
        connection.onEstablished = { _ in established = true }
        connection.onAppData = { received.append(contentsOf: $0) }

        connection.start(with: segment(seq: 1000, ack: 0, flags: SwiftCoreTCPFlag.syn))
        let synAck = try! XCTUnwrap(collected.segments.first)
        XCTAssertTrue(synAck.isSYN && synAck.isACK)
        XCTAssertEqual(synAck.acknowledgmentNumber, 1001)     // acks the client's SYN
        let serverISN = synAck.sequenceNumber

        connection.receive(segment(seq: 1001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.ack))
        XCTAssertTrue(established)

        connection.receive(segment(seq: 1001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.psh | SwiftCoreTCPFlag.ack, payload: Array("hello".utf8)))
        XCTAssertEqual(received, Array("hello".utf8))
        XCTAssertEqual(collected.segments.last?.acknowledgmentNumber, 1006)  // acks 5 bytes of data
    }

    func testSendToAppSegmentsData() {
        let (connection, collected, serverISN) = established()
        connection.deliverToApp(Array("world".utf8))
        let dataSegment = try! XCTUnwrap(collected.segments.last { !$0.payload.isEmpty })
        XCTAssertEqual(dataSegment.payload, Array("world".utf8))
        XCTAssertEqual(dataSegment.sequenceNumber, serverISN &+ 1)  // first data byte follows our SYN
    }

    func testHalfCloseTeardown() {
        let (connection, collected, serverISN) = established()
        var closed = false
        connection.onClosed = { closed = true }

        // App finishes sending: FIN at its current sequence (1001, no data was sent).
        connection.receive(segment(seq: 1001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.fin | SwiftCoreTCPFlag.ack))
        XCTAssertEqual(collected.segments.last?.acknowledgmentNumber, 1002)  // acks the FIN

        // Proxy finishes: we send our FIN.
        connection.proxyDidClose()
        let ourFin = try! XCTUnwrap(collected.segments.last { $0.isFIN })
        XCTAssertEqual(ourFin.sequenceNumber, serverISN &+ 1)
        XCTAssertFalse(closed)

        // App acks our FIN -> fully closed.
        connection.receive(segment(seq: 1002, ack: ourFin.sequenceNumber &+ 1, flags: SwiftCoreTCPFlag.ack))
        XCTAssertTrue(closed)
        XCTAssertEqual(connection.state, .closed)
    }

    func testResetOnReset() {
        let (connection, _, serverISN) = established()
        var closed = false
        connection.onClosed = { closed = true }
        connection.receive(segment(seq: 1001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.rst))
        XCTAssertTrue(closed)
        XCTAssertEqual(connection.state, .closed)
    }

    // MARK: End-to-end through the controller + a real DIRECT outbound

    func testTCPRelayEchoesThroughDirectOutbound() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 3)
        defer { try? group.syncShutdownGracefully() }

        let echo = try ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in channel.pipeline.addHandler(EchoHandler()) }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }
        let echoPort = try XCTUnwrap(echo.localAddress?.port)

        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]
        rules: [MATCH,DIRECT]
        """))

        let loop = group.next()
        let collector = PacketCollector(group: group)
        let controller = SwiftCoreTunController(state: state, group: group, loop: loop, emit: { collector.add($0) })

        let source: [UInt8] = [10, 0, 0, 2]
        let destination: [UInt8] = [127, 0, 0, 1]
        let sourcePort = 40001
        func feed(seq: UInt32, ack: UInt32, flags: UInt8, payload: [UInt8] = []) throws {
            let packet = SwiftCoreTCPSegment.build(source: source, destination: destination, sourcePort: sourcePort, destinationPort: echoPort, sequenceNumber: seq, acknowledgmentNumber: ack, flags: flags, window: 65535, payload: payload)
            try loop.submit { controller.receive(packet) }.wait()
        }

        try feed(seq: 5000, ack: 0, flags: SwiftCoreTCPFlag.syn)
        let synAck = try collector.wait { $0.isSYN && $0.isACK }
        XCTAssertEqual(synAck.acknowledgmentNumber, 5001)
        let serverISN = synAck.sequenceNumber

        try feed(seq: 5001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.ack)
        try feed(seq: 5001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.psh | SwiftCoreTCPFlag.ack, payload: Array("relay-me".utf8))

        // The echo server's reply comes back to the app as a data-bearing segment.
        let echoed = try collector.wait { !$0.payload.isEmpty }
        XCTAssertEqual(echoed.payload, Array("relay-me".utf8))
        XCTAssertEqual(echoed.sourcePort, echoPort)          // spoofed as coming from the target
        XCTAssertEqual(echoed.destinationPort, sourcePort)
    }

    // MARK: Helpers

    private func segment(seq: UInt32, ack: UInt32, flags: UInt8, payload: [UInt8] = []) -> SwiftCoreTCPSegment {
        let packet = SwiftCoreTCPSegment.build(source: app, destination: target, sourcePort: 40000, destinationPort: 80, sequenceNumber: seq, acknowledgmentNumber: ack, flags: flags, window: 65535, payload: payload)
        return SwiftCoreTCPSegment(SwiftCoreIPv4Packet(packet)!.payload)!
    }

    /// A connection driven through the handshake, returning it plus the server ISN.
    private func established() -> (SwiftCoreTCPConnection, Collected, UInt32) {
        let collected = Collected()
        let connection = SwiftCoreTCPConnection(source: app, sourcePort: 40000, destination: target, destinationPort: 80, emit: { collected.append($0) })
        connection.start(with: segment(seq: 1000, ack: 0, flags: SwiftCoreTCPFlag.syn))
        let serverISN = collected.segments[0].sequenceNumber
        connection.receive(segment(seq: 1001, ack: serverISN &+ 1, flags: SwiftCoreTCPFlag.ack))
        return (connection, collected, serverISN)
    }
}

/// Collects packets emitted by a connection (synchronous, single-threaded use).
private final class Collected {
    private(set) var packets: [[UInt8]] = []
    func append(_ packet: [UInt8]) { packets.append(packet) }
    var segments: [SwiftCoreTCPSegment] {
        packets.compactMap { packet in SwiftCoreIPv4Packet(packet).flatMap { SwiftCoreTCPSegment($0.payload) } }
    }
}

/// Thread-safe collector for the end-to-end test: packets are emitted on the stack loop and awaited
/// from the test thread.
private final class PacketCollector: @unchecked Sendable {
    private let group: EventLoopGroup
    private let lock = NSLock()
    private var segments: [SwiftCoreTCPSegment] = []
    private var predicate: ((SwiftCoreTCPSegment) -> Bool)?
    private var promise: EventLoopPromise<SwiftCoreTCPSegment>?

    init(group: EventLoopGroup) { self.group = group }

    func add(_ packet: [UInt8]) {
        guard let ip = SwiftCoreIPv4Packet(packet), let segment = SwiftCoreTCPSegment(ip.payload) else { return }
        lock.lock()
        if let predicate, predicate(segment) {
            let promise = self.promise
            self.predicate = nil
            self.promise = nil
            lock.unlock()
            promise?.succeed(segment)
            return
        }
        segments.append(segment)
        lock.unlock()
    }

    func wait(_ predicate: @escaping (SwiftCoreTCPSegment) -> Bool) throws -> SwiftCoreTCPSegment {
        lock.lock()
        if let index = segments.firstIndex(where: predicate) {
            let segment = segments.remove(at: index)
            lock.unlock()
            return segment
        }
        let promise = group.next().makePromise(of: SwiftCoreTCPSegment.self)
        self.predicate = predicate
        self.promise = promise
        group.next().scheduleTask(in: .seconds(5)) { promise.fail(SwiftCoreError.invalidConfig("timeout waiting for packet")) }
        lock.unlock()
        return try promise.futureResult.wait()
    }
}

private final class EchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}
