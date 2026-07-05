import Foundation
import NIOCore
import NIOHPACK
import NIOHTTP2
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

final class GRPCTransportTests: XCTestCase {
    // MARK: Pure framing

    func testEncodeDecodeRoundTrip() {
        let payload: [UInt8] = Array("hello grpc".utf8)
        var wire = SwiftCoreGRPCProtocol.encodeMessage(payload)
        // gRPC frame: [compressed=0][uint32 length][Hunk]; Hunk: 0x0a <varint len> <data>.
        XCTAssertEqual(wire[0], 0x00)
        XCTAssertEqual(wire[5], 0x0a)
        let messages = SwiftCoreGRPCProtocol.decodeMessages(&wire)
        XCTAssertEqual(messages, [payload])
        XCTAssertTrue(wire.isEmpty)
    }

    func testDecodeMultipleAndPartialMessages() {
        var wire = SwiftCoreGRPCProtocol.encodeMessage([1, 2, 3]) + SwiftCoreGRPCProtocol.encodeMessage([4, 5])
        let full = SwiftCoreGRPCProtocol.encodeMessage([9, 9, 9, 9])
        wire.append(contentsOf: full.dropLast()) // a third, incomplete message
        let messages = SwiftCoreGRPCProtocol.decodeMessages(&wire)
        XCTAssertEqual(messages, [[1, 2, 3], [4, 5]])
        // The incomplete trailing message is left buffered and completes once its last byte arrives.
        XCTAssertEqual(wire, Array(full.dropLast()))
        wire.append(full.last!)
        XCTAssertEqual(SwiftCoreGRPCProtocol.decodeMessages(&wire), [[9, 9, 9, 9]])
    }

    func testEmptyHunkAndVarintBoundaries() {
        XCTAssertEqual(SwiftCoreGRPCProtocol.decodeHunk(SwiftCoreGRPCProtocol.encodeHunkForTest([])), [])
        for length in [0, 1, 127, 128, 300, 16_383, 16_384, 70_000] {
            let payload = (0..<length).map { UInt8($0 & 0xff) }
            var wire = SwiftCoreGRPCProtocol.encodeMessage(payload)
            XCTAssertEqual(SwiftCoreGRPCProtocol.decodeMessages(&wire), payload.isEmpty ? [[]] : [payload])
        }
    }

    func testDecodeHunkSkipsUnknownFields() {
        // A Hunk with an extra varint field (field 2) before the data field (field 1).
        var message: [UInt8] = [0x10, 0x2a] // field 2, varint = 42
        message.append(0x0a)                // field 1, length-delimited
        SwiftCoreGRPCProtocol.appendVarint(3, to: &message)
        message.append(contentsOf: [7, 8, 9])
        XCTAssertEqual(SwiftCoreGRPCProtocol.decodeHunk(message), [7, 8, 9])
    }

    // MARK: Config

    func testConfigParsesGRPCOpts() throws {
        let config = try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxies:
          - name: g
            type: vmess
            server: example.com
            port: 443
            uuid: 11111111-1111-1111-1111-111111111111
            network: grpc
            tls: true
            grpc-opts:
              grpc-service-name: MyTun
        proxy-groups: [{ name: G, type: select, proxies: [g] }]
        rules: [MATCH,g]
        """)
        let proxy = try XCTUnwrap(config.proxies.first)
        XCTAssertEqual(proxy.network, "grpc")
        XCTAssertEqual(proxy.grpcOpts?.serviceName, "MyTun")
        XCTAssertNoThrow(try SwiftCoreVMessOutbound(proxy: proxy))
        XCTAssertNoThrow(try SwiftCoreVLESSOutbound(proxy: proxy.with(type: "vless")))
    }

    func testGRPCRejectsReality() {
        let proxy = SwiftCoreProxy(
            name: "bad", type: "vless", server: "example.com", port: 443,
            uuid: "11111111-1111-1111-1111-111111111111", network: "grpc",
            realityPublicKey: "84GHKMt8j1RvKVi0avbTNGz2Gr8pM4B8g4y8rN2r0Ho"
        )
        XCTAssertThrowsError(try SwiftCoreVLESSOutbound(proxy: proxy))
    }

    // MARK: End-to-end (real loopback, h2c)

    func testEndToEndVLESSOverGRPC() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        defer { try? group.syncShutdownGracefully() }

        let server = try ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.configureHTTP2Pipeline(mode: .server) { streamChannel in
                    streamChannel.pipeline.addHandler(FakeGRPCVLESSEchoStreamHandler())
                }.map { _ in }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? server.close().wait() }
        let port = try XCTUnwrap(server.localAddress?.port)

        let proxy = SwiftCoreProxy(
            name: "grpc-vless", type: "vless", server: "127.0.0.1", port: port,
            uuid: "22222222-2222-2222-2222-222222222222", network: "grpc",
            grpcOpts: SwiftCoreGRPCOpts(serviceName: "GunService")
        )
        let adapter = try SwiftCoreVLESSOutbound(proxy: proxy)

        let promise = group.next().makePromise(of: [UInt8].self)
        group.next().scheduleTask(in: .seconds(5)) {
            promise.fail(SwiftCoreError.invalidConfig("timeout waiting for the echo"))
        }

        let upstream = try adapter.connect(
            request: SwiftCoreOutboundRequest(host: "proxy.target", port: 443),
            group: group,
            makeTailHandler: { GRPCCollectingHandler(expectedCount: 12, promise: promise) }
        ).wait()
        defer { try? upstream.close().wait() }

        upstream.writeAndFlush(NIOAny(upstream.allocator.buffer(bytes: Array("grpc-echo-ok".utf8))), promise: nil)
        XCTAssertEqual(String(decoding: try promise.futureResult.wait(), as: UTF8.self), "grpc-echo-ok")
    }
}

private extension SwiftCoreProxy {
    func with(type: String) -> SwiftCoreProxy {
        var copy = self
        copy.type = type
        return copy
    }
}

extension SwiftCoreGRPCProtocol {
    /// Test helper: build just the inner Hunk protobuf (no gRPC length prefix).
    static func encodeHunkForTest(_ data: [UInt8]) -> [UInt8] {
        var hunk: [UInt8] = [0x0a]
        appendVarint(UInt(data.count), to: &hunk)
        hunk.append(contentsOf: data)
        return hunk
    }
}

private final class GRPCCollectingHandler: ChannelInboundHandler {
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

/// An HTTP/2 stream handler that speaks gRPC: responds 200, unwraps the VLESS request inside the
/// Hunk messages, and echoes the application payload back with a VLESS response header.
private final class FakeGRPCVLESSEchoStreamHandler: ChannelInboundHandler {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload

    private var responded = false
    private var grpcInbound: [UInt8] = []
    private var appStream: [UInt8] = []
    private var vlessHeaderStripped = false
    private var responseHeaderSent = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch Self.unwrapInboundIn(data) {
        case .headers:
            guard !responded else { return }
            var headers = HPACKHeaders()
            headers.add(name: ":status", value: "200")
            headers.add(name: "content-type", value: "application/grpc")
            context.writeAndFlush(Self.wrapOutboundOut(.headers(.init(headers: headers, endStream: false))), promise: nil)
            responded = true
        case .data(let frame):
            guard case .byteBuffer(var buffer) = frame.data, let bytes = buffer.readBytes(length: buffer.readableBytes) else {
                return
            }
            grpcInbound.append(contentsOf: bytes)
            for message in SwiftCoreGRPCProtocol.decodeMessages(&grpcInbound) {
                appStream.append(contentsOf: message)
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
            guard !out.isEmpty else { return }
            let framed = SwiftCoreGRPCProtocol.encodeMessage(out)
            var outBuffer = context.channel.allocator.buffer(capacity: framed.count)
            outBuffer.writeBytes(framed)
            context.writeAndFlush(Self.wrapOutboundOut(.data(.init(data: .byteBuffer(outBuffer), endStream: false))), promise: nil)
        default:
            break
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
}
