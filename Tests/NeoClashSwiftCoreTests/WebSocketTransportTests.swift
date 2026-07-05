import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

final class WebSocketTransportTests: XCTestCase {
    // MARK: Pure protocol

    /// The RFC 6455 §1.3 worked example.
    func testAcceptValueVector() {
        XCTAssertEqual(
            SwiftCoreWebSocketProtocol.acceptValue(forKey: "dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        )
    }

    func testHandshakeRequestFields() {
        let request = SwiftCoreWebSocketProtocol.handshakeRequest(
            host: "cdn.example", path: "/tunnel", key: "KEY==", headers: ["X-Extra": "1"]
        )
        let text = String(decoding: request, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("GET /tunnel HTTP/1.1\r\n"))
        XCTAssertTrue(text.contains("Host: cdn.example\r\n"))
        XCTAssertTrue(text.contains("Upgrade: websocket\r\n"))
        XCTAssertTrue(text.contains("Connection: Upgrade\r\n"))
        XCTAssertTrue(text.contains("Sec-WebSocket-Key: KEY==\r\n"))
        XCTAssertTrue(text.contains("Sec-WebSocket-Version: 13\r\n"))
        XCTAssertTrue(text.contains("X-Extra: 1\r\n"))
        XCTAssertTrue(text.hasSuffix("\r\n\r\n"))
    }

    func testParseHandshakeResponse() {
        let accept = SwiftCoreWebSocketProtocol.acceptValue(forKey: "abc")
        let ok = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n".utf8)
        let parsed = SwiftCoreWebSocketProtocol.parseHandshakeResponse(ok, expectedAccept: accept)
        XCTAssertEqual(parsed?.headerEnd, ok.count)
        XCTAssertEqual(parsed?.accepted, true)

        // Wrong accept -> not accepted (but header boundary still found).
        XCTAssertEqual(SwiftCoreWebSocketProtocol.parseHandshakeResponse(ok, expectedAccept: "other")?.accepted, false)

        // Incomplete header block -> nil.
        XCTAssertNil(SwiftCoreWebSocketProtocol.parseHandshakeResponse(Array("HTTP/1.1 101\r\nUpgrade: web".utf8), expectedAccept: accept))
    }

    func testFrameRoundTrip() {
        for length in [0, 5, 125, 126, 200, 0x1_0000, 0x1_0001] {
            let payload = (0..<length).map { UInt8($0 & 0xff) }
            var wire = SwiftCoreWebSocketProtocol.encodeClientFrame(opcode: SwiftCoreWebSocketProtocol.Opcode.binary, payload: payload)
            XCTAssertEqual(wire[1] & 0x80, 0x80, "client frames must set the mask bit")
            let frame = SwiftCoreWebSocketProtocol.decodeFrame(&wire)
            XCTAssertEqual(frame?.opcode, SwiftCoreWebSocketProtocol.Opcode.binary)
            XCTAssertEqual(frame?.payload, payload)
            XCTAssertTrue(wire.isEmpty, "the frame's bytes should be fully consumed")
        }
    }

    func testDecodeFrameNeedsCompleteFrame() {
        var wire = SwiftCoreWebSocketProtocol.encodeClientFrame(opcode: SwiftCoreWebSocketProtocol.Opcode.binary, payload: [1, 2, 3, 4])
        let truncated = Array(wire.dropLast())
        var partial = truncated
        XCTAssertNil(SwiftCoreWebSocketProtocol.decodeFrame(&partial))
        XCTAssertEqual(partial.count, truncated.count, "an incomplete frame must not be consumed")
        // A second frame appended after the first is decoded independently.
        wire.append(contentsOf: SwiftCoreWebSocketProtocol.encodeClientFrame(opcode: SwiftCoreWebSocketProtocol.Opcode.ping, payload: []))
        XCTAssertEqual(SwiftCoreWebSocketProtocol.decodeFrame(&wire)?.payload, [1, 2, 3, 4])
        XCTAssertEqual(SwiftCoreWebSocketProtocol.decodeFrame(&wire)?.opcode, SwiftCoreWebSocketProtocol.Opcode.ping)
    }

    // MARK: Handler behavior (EmbeddedChannel)

    func testHandlerDelaysActiveUntilUpgradeThenFrames() throws {
        let recorder = RecordingHandler()
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(SwiftCoreWebSocketTransportHandler(host: "h", path: "/p", headers: [:]))
        try channel.pipeline.syncOperations.addHandler(recorder)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()

        // The upgrade request is sent immediately; the protocol handler is NOT yet active.
        var handshake = try XCTUnwrap(try channel.readOutbound(as: ByteBuffer.self))
        let requestBytes = handshake.readBytes(length: handshake.readableBytes) ?? []
        let key = try XCTUnwrap(Self.headerValue(requestBytes, "Sec-WebSocket-Key"))
        XCTAssertFalse(recorder.active)

        // Feed the 101; now the protocol handler becomes active.
        let accept = SwiftCoreWebSocketProtocol.acceptValue(forKey: key)
        let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n"
        try channel.writeInbound(channel.allocator.buffer(string: response))
        XCTAssertTrue(recorder.active)

        // Outbound application bytes are sent as a masked binary frame.
        try channel.pipeline.writeAndFlush(NIOAny(channel.allocator.buffer(bytes: [0xDE, 0xAD, 0xBE, 0xEF]))).wait()
        var framed = try XCTUnwrap(try channel.readOutbound(as: ByteBuffer.self))
        var frameBytes = framed.readBytes(length: framed.readableBytes) ?? []
        let decoded = SwiftCoreWebSocketProtocol.decodeFrame(&frameBytes)
        XCTAssertEqual(decoded?.payload, [0xDE, 0xAD, 0xBE, 0xEF])

        // An inbound (unmasked) server frame is surfaced as plaintext to the protocol handler.
        try channel.writeInbound(channel.allocator.buffer(bytes: Self.serverFrame([0x01, 0x02, 0x03])))
        var inbound = try XCTUnwrap(try channel.readInbound(as: ByteBuffer.self))
        XCTAssertEqual(inbound.readBytes(length: inbound.readableBytes) ?? [], [0x01, 0x02, 0x03])

        _ = try? channel.finish()
    }

    // MARK: Config

    func testConfigParsesWSOpts() throws {
        let config = try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxies:
          - name: w
            type: vless
            server: example.com
            port: 443
            uuid: 11111111-1111-1111-1111-111111111111
            network: ws
            tls: true
            ws-opts:
              path: /vpath
              headers:
                Host: cdn.example.com
        proxy-groups: [{ name: G, type: select, proxies: [w] }]
        rules: [MATCH,w]
        """)
        let proxy = try XCTUnwrap(config.proxies.first)
        XCTAssertEqual(proxy.network, "ws")
        XCTAssertEqual(proxy.wsOpts?.path, "/vpath")
        XCTAssertEqual(proxy.wsOpts?.headers["Host"], "cdn.example.com")
        // Both VLESS and VMess accept the ws network without throwing.
        XCTAssertNoThrow(try SwiftCoreVLESSOutbound(proxy: proxy))
    }

    // MARK: End-to-end (real loopback)

    func testEndToEndVLESSOverWebSocket() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        defer { try? group.syncShutdownGracefully() }

        let server = try ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(FakeWebSocketVLESSEchoServer())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? server.close().wait() }
        let port = try XCTUnwrap(server.localAddress?.port)

        let proxy = SwiftCoreProxy(
            name: "ws-vless",
            type: "vless",
            server: "127.0.0.1",
            port: port,
            uuid: "22222222-2222-2222-2222-222222222222",
            network: "ws",
            wsOpts: SwiftCoreWSOpts(path: "/tunnel", headers: ["Host": "cdn.example.com"])
        )
        let adapter = try SwiftCoreVLESSOutbound(proxy: proxy)

        let promise = group.next().makePromise(of: [UInt8].self)
        group.next().scheduleTask(in: .seconds(5)) {
            promise.fail(SwiftCoreError.invalidConfig("timeout waiting for the echo"))
        }

        let upstream = try adapter.connect(
            request: SwiftCoreOutboundRequest(host: "proxy.target", port: 443),
            group: group,
            makeTailHandler: { CollectingHandler(expectedCount: 15, promise: promise) }
        ).wait()
        defer { try? upstream.close().wait() }

        upstream.writeAndFlush(NIOAny(upstream.allocator.buffer(bytes: Array("ping-through-ws".utf8))), promise: nil)
        XCTAssertEqual(String(decoding: try promise.futureResult.wait(), as: UTF8.self), "ping-through-ws")
    }

    // MARK: Helpers

    private static func headerValue(_ request: [UInt8], _ name: String) -> String? {
        let text = String(decoding: request, as: UTF8.self)
        for line in text.split(separator: "\r\n") where line.lowercased().hasPrefix(name.lowercased() + ":") {
            return line.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    /// An unmasked server->client binary frame.
    static func serverFrame(_ payload: [UInt8]) -> [UInt8] {
        var frame: [UInt8] = [0x82] // FIN + binary
        if payload.count < 126 {
            frame.append(UInt8(payload.count))
        } else {
            frame.append(126)
            frame.append(UInt8((payload.count >> 8) & 0xff))
            frame.append(UInt8(payload.count & 0xff))
        }
        frame.append(contentsOf: payload)
        return frame
    }
}

/// Records whether it saw channelActive and forwards inbound data (so `readInbound` works).
private final class RecordingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private(set) var active = false

    func channelActive(context: ChannelHandlerContext) {
        active = true
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
}

/// Collects inbound bytes until `expectedCount` are seen, then fulfills the promise.
private final class CollectingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let expectedCount: Int
    private let promise: EventLoopPromise<[UInt8]>
    private var collected: [UInt8] = []

    init(expectedCount: Int, promise: EventLoopPromise<[UInt8]>) {
        self.expectedCount = expectedCount
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = Self.unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            collected.append(contentsOf: bytes)
        }
        if collected.count >= expectedCount {
            promise.succeed(collected)
        }
    }
}

/// A minimal WebSocket server that upgrades, unwraps the VLESS request inside the tunnel, and echoes
/// the application payload back (wrapped in server frames) with a VLESS response header.
private final class FakeWebSocketVLESSEchoServer: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var inbound: [UInt8] = []
    private var upgraded = false
    private var appStream: [UInt8] = []
    private var vlessHeaderStripped = false
    private var responseHeaderSent = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = Self.unwrapInboundIn(data)
        if let bytes = buffer.readBytes(length: buffer.readableBytes) {
            inbound.append(contentsOf: bytes)
        }

        if !upgraded {
            guard let end = findHeaderEnd(inbound) else { return }
            let request = Array(inbound[0..<end])
            inbound.removeFirst(end)
            guard let key = headerValue(request, "Sec-WebSocket-Key") else {
                context.close(promise: nil)
                return
            }
            let accept = SwiftCoreWebSocketProtocol.acceptValue(forKey: key)
            let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n"
            context.writeAndFlush(Self.wrapOutboundOut(context.channel.allocator.buffer(string: response)), promise: nil)
            upgraded = true
        }

        while let frame = SwiftCoreWebSocketProtocol.decodeFrame(&inbound) {
            switch frame.opcode {
            case SwiftCoreWebSocketProtocol.Opcode.binary,
                 SwiftCoreWebSocketProtocol.Opcode.text,
                 SwiftCoreWebSocketProtocol.Opcode.continuation:
                appStream.append(contentsOf: frame.payload)
            default:
                continue
            }
        }

        if !vlessHeaderStripped {
            guard let headerLength = vlessRequestHeaderLength(appStream) else { return }
            appStream.removeFirst(headerLength)
            vlessHeaderStripped = true
        }

        var out: [UInt8] = []
        if !responseHeaderSent {
            out.append(contentsOf: [0x00, 0x00]) // VLESS response: version, addon length
            responseHeaderSent = true
        }
        out.append(contentsOf: appStream)
        appStream.removeAll()
        if !out.isEmpty {
            let frame = WebSocketTransportTests.serverFrame(out)
            context.writeAndFlush(Self.wrapOutboundOut(context.channel.allocator.buffer(bytes: frame)), promise: nil)
        }
    }

    private func vlessRequestHeaderLength(_ bytes: [UInt8]) -> Int? {
        var index = 1 + 16 // version + uuid
        guard bytes.count > index else { return nil }
        let addonLength = Int(bytes[index])
        index += 1 + addonLength
        guard bytes.count >= index + 1 + 2 + 1 else { return nil }
        index += 1 + 2 // command + port
        let atyp = bytes[index]
        index += 1
        switch atyp {
        case 0x01: index += 4
        case 0x03: index += 16
        case 0x02:
            guard bytes.count > index else { return nil }
            index += 1 + Int(bytes[index])
        default: return nil
        }
        guard bytes.count >= index else { return nil }
        return index
    }

    private func findHeaderEnd(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else { return nil }
        for index in 0...(bytes.count - 4) where bytes[index] == 0x0d && bytes[index + 1] == 0x0a && bytes[index + 2] == 0x0d && bytes[index + 3] == 0x0a {
            return index + 4
        }
        return nil
    }

    private func headerValue(_ request: [UInt8], _ name: String) -> String? {
        let text = String(decoding: request, as: UTF8.self)
        for line in text.split(separator: "\r\n") where line.lowercased().hasPrefix(name.lowercased() + ":") {
            return line.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)
        }
        return nil
    }
}
