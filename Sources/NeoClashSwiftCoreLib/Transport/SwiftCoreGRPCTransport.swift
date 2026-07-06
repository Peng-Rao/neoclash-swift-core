import NIOCore
import NIOHPACK
import NIOHTTP2
import NIOPosix

/// Resolved gRPC transport settings for a proxy. gRPC ("gun") carries the VLESS/VMess byte stream
/// as a single long-lived bidirectional HTTP/2 stream whose DATA frames hold gRPC-framed `Hunk`
/// messages (`GunService/Tun`).
struct SwiftCoreGRPCTransport: Sendable {
    let authority: String   // :authority header
    let scheme: String      // https (TLS) or http (h2c)
    let path: String        // /<service-name>/Tun

    init(proxy: SwiftCoreProxy) throws {
        guard let server = proxy.server, !server.isEmpty else {
            throw SwiftCoreError.invalidConfig("proxy \(proxy.name) requires a server.")
        }
        let serviceName = proxy.grpcOpts?.serviceName ?? "GunService"
        self.authority = proxy.servername ?? server
        self.scheme = proxy.tls ? "https" : "http"
        self.path = "/\(serviceName)/Tun"
    }

    /// Connects to `host:port`, negotiates HTTP/2, opens the request stream, and installs the gRPC
    /// framing handler plus the application handlers (built by `makeAppHandlers`) on that stream.
    /// Returns the stream channel — writes to it become gRPC DATA frames.
    func connect(
        host: String,
        port: Int,
        group: EventLoopGroup,
        installSecurity: @escaping @Sendable (Channel) throws -> Void,
        makeAppHandlers: @escaping @Sendable () -> [ChannelHandler]
    ) -> EventLoopFuture<Channel> {
        let authority = self.authority
        let scheme = self.scheme
        let path = self.path
        return ClientBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                do {
                    try installSecurity(channel)
                    _ = try channel.pipeline.syncOperations.configureHTTP2Pipeline(
                        mode: .client,
                        connectionConfiguration: .init(),
                        streamConfiguration: .init()
                    ) { inbound in
                        inbound.eventLoop.makeSucceededVoidFuture()
                    }
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: host, port: port)
            .flatMap { base in
                base.pipeline.handler(type: NIOHTTP2Handler.self)
                    .flatMap { $0.multiplexer }
                    .flatMap { multiplexer -> EventLoopFuture<Channel> in
                        multiplexer.createStreamChannel { stream in
                            do {
                                try stream.pipeline.syncOperations.addHandler(
                                    SwiftCoreGRPCClientHandler(authority: authority, scheme: scheme, path: path)
                                )
                                for handler in makeAppHandlers() {
                                    try stream.pipeline.syncOperations.addHandler(handler)
                                }
                                return stream.eventLoop.makeSucceededVoidFuture()
                            } catch {
                                return stream.eventLoop.makeFailedFuture(error)
                            }
                        }
                    }
            }
    }
}

/// Pure gRPC "gun" wire helpers: length-prefixed messages carrying a `Hunk { bytes data = 1 }`
/// protobuf. Kept free of NIO so the framing can be exercised directly in tests.
enum SwiftCoreGRPCProtocol {
    /// Wraps `data` in a `Hunk` protobuf and then a gRPC length-prefixed message frame.
    static func encodeMessage(_ data: [UInt8]) -> [UInt8] {
        var hunk: [UInt8] = [0x0a] // field 1, wire type 2 (length-delimited)
        appendVarint(UInt(data.count), to: &hunk)
        hunk.append(contentsOf: data)

        var frame: [UInt8] = [0x00] // compressed flag: not compressed
        let length = hunk.count
        frame.append(UInt8((length >> 24) & 0xff))
        frame.append(UInt8((length >> 16) & 0xff))
        frame.append(UInt8((length >> 8) & 0xff))
        frame.append(UInt8(length & 0xff))
        frame.append(contentsOf: hunk)
        return frame
    }

    /// Consumes as many complete gRPC messages as are available in `buffer`, returning the tunneled
    /// data carried by each `Hunk`.
    static func decodeMessages(_ buffer: inout [UInt8]) -> [[UInt8]] {
        var out: [[UInt8]] = []
        while buffer.count >= 5 {
            let length = Int(buffer[1]) << 24 | Int(buffer[2]) << 16 | Int(buffer[3]) << 8 | Int(buffer[4])
            guard buffer.count >= 5 + length else { break }
            let message = Array(buffer[5..<5 + length])
            buffer.removeFirst(5 + length)
            if let data = decodeHunk(message) { out.append(data) }
        }
        return out
    }

    /// Extracts field 1 (`data`) from a `Hunk` protobuf, skipping any other fields.
    static func decodeHunk(_ message: [UInt8]) -> [UInt8]? {
        var index = 0
        var data: [UInt8] = []
        while index < message.count {
            let tag = UInt(message[index])
            index += 1
            let field = tag >> 3
            let wire = tag & 0x7
            switch wire {
            case 2: // length-delimited
                guard let (length, next) = readVarint(message, index) else { return nil }
                index = next
                guard index + Int(length) <= message.count else { return nil }
                if field == 1 { data.append(contentsOf: message[index..<index + Int(length)]) }
                index += Int(length)
            case 0: // varint
                guard let (_, next) = readVarint(message, index) else { return nil }
                index = next
            case 5: index += 4 // 32-bit
            case 1: index += 8 // 64-bit
            default: return nil
            }
        }
        return data
    }

    static func appendVarint(_ value: UInt, to bytes: inout [UInt8]) {
        var value = value
        while value >= 0x80 {
            bytes.append(UInt8((value & 0x7f) | 0x80))
            value >>= 7
        }
        bytes.append(UInt8(value))
    }

    static func readVarint(_ bytes: [UInt8], _ start: Int) -> (value: UInt, next: Int)? {
        var result: UInt = 0
        var shift: UInt = 0
        var index = start
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            result |= UInt(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return (result, index) }
            shift += 7
            if shift > 63 { return nil }
        }
        return nil
    }
}

/// Bridges an HTTP/2 request stream and the plaintext protocol stream: sends the gRPC request
/// headers on connect, wraps outbound bytes as gRPC DATA frames, and unwraps inbound DATA frames
/// back to plaintext for the VLESS/VMess handler.
final class SwiftCoreGRPCClientHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = HTTP2Frame.FramePayload

    private let authority: String
    private let scheme: String
    private let path: String
    private var inbound: [UInt8] = []

    init(authority: String, scheme: String, path: String) {
        self.authority = authority
        self.scheme = scheme
        self.path = path
    }

    func channelActive(context: ChannelHandlerContext) {
        var headers = HPACKHeaders()
        headers.add(name: ":method", value: "POST")
        headers.add(name: ":scheme", value: scheme)
        headers.add(name: ":path", value: path)
        headers.add(name: ":authority", value: authority)
        headers.add(name: "content-type", value: "application/grpc")
        headers.add(name: "te", value: "trailers")
        headers.add(name: "grpc-accept-encoding", value: "identity")
        headers.add(name: "user-agent", value: "neoclash-swift-core/grpc")
        let payload = HTTP2Frame.FramePayload.headers(.init(headers: headers, endStream: false))
        context.writeAndFlush(Self.wrapOutboundOut(payload), promise: nil)
        context.fireChannelActive()
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = Self.unwrapOutboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes), !bytes.isEmpty else {
            promise?.succeed(())
            return
        }
        let framed = SwiftCoreGRPCProtocol.encodeMessage(bytes)
        var out = context.channel.allocator.buffer(capacity: framed.count)
        out.writeBytes(framed)
        let payload = HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(out), endStream: false))
        context.write(Self.wrapOutboundOut(payload), promise: promise)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let payload = Self.unwrapInboundIn(data)
        switch payload {
        case .data(let frame):
            guard case .byteBuffer(var buffer) = frame.data, let bytes = buffer.readBytes(length: buffer.readableBytes) else {
                return
            }
            inbound.append(contentsOf: bytes)
            for message in SwiftCoreGRPCProtocol.decodeMessages(&inbound) where !message.isEmpty {
                var out = context.channel.allocator.buffer(capacity: message.count)
                out.writeBytes(message)
                context.fireChannelRead(Self.wrapInboundOut(out))
            }
            if frame.endStream {
                context.close(promise: nil)
            }
        case .headers, .rstStream, .goAway:
            break // response/trailer headers and stream teardown are handled by the h2 layer
        default:
            break
        }
    }
}
