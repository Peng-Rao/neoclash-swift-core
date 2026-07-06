import Crypto
import Foundation
import NIOCore

/// Resolved WebSocket transport settings for a proxy.
struct SwiftCoreWebSocketTransport: Sendable {
    let host: String                 // value of the HTTP Host header
    let path: String
    let headers: [String: String]    // extra request headers (Host handled separately)

    init(proxy: SwiftCoreProxy) throws {
        guard let server = proxy.server, !server.isEmpty else {
            throw SwiftCoreError.invalidConfig("proxy \(proxy.name) requires a server.")
        }
        let opts = proxy.wsOpts ?? SwiftCoreWSOpts()
        // Host precedence: ws-opts.headers Host > servername/sni > server.
        let hostHeader = opts.headers.first { $0.key.caseInsensitiveCompare("Host") == .orderedSame }?.value
        self.host = hostHeader ?? proxy.servername ?? server
        self.path = opts.path.isEmpty ? "/" : opts.path
        self.headers = opts.headers.filter { $0.key.caseInsensitiveCompare("Host") != .orderedSame }
    }

    func makeHandler() -> SwiftCoreWebSocketTransportHandler {
        SwiftCoreWebSocketTransportHandler(host: host, path: path, headers: headers)
    }
}

/// Pure WebSocket (RFC 6455) client helpers: the opening handshake and the frame codec. Kept free
/// of NIO so the wire format can be exercised directly in tests.
enum SwiftCoreWebSocketProtocol {
    static let magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    enum Opcode {
        static let continuation: UInt8 = 0x0
        static let text: UInt8 = 0x1
        static let binary: UInt8 = 0x2
        static let close: UInt8 = 0x8
        static let ping: UInt8 = 0x9
        static let pong: UInt8 = 0xA
    }

    /// A fresh base64 `Sec-WebSocket-Key` (16 random bytes).
    static func generateKey() -> String {
        Data(swiftCoreRandomBytes(16)).base64EncodedString()
    }

    /// The `Sec-WebSocket-Accept` value a server must return for `key`.
    static func acceptValue(forKey key: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data((key + magicGUID).utf8))
        return Data(digest).base64EncodedString()
    }

    /// The HTTP/1.1 upgrade request bytes.
    static func handshakeRequest(host: String, path: String, key: String, headers: [String: String]) -> [UInt8] {
        var lines = [
            "GET \(path) HTTP/1.1",
            "Host: \(host)",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: \(key)",
            "Sec-WebSocket-Version: 13"
        ]
        for (name, value) in headers {
            lines.append("\(name): \(value)")
        }
        return Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    /// Parsed opening-handshake response: the byte offset just past the header block, and whether it
    /// is a valid `101` accepting `expectedAccept`. Returns nil until the full header block arrives.
    static func parseHandshakeResponse(_ buffer: [UInt8], expectedAccept: String) -> (headerEnd: Int, accepted: Bool)? {
        guard let end = findHeaderEnd(buffer) else { return nil }
        let head = String(decoding: buffer[0..<end], as: UTF8.self)
        let lines = head.split(separator: "\r\n", omittingEmptySubsequences: true).map(String.init)
        guard let statusLine = lines.first, statusLine.contains(" 101") else {
            return (end, false)
        }
        var upgraded = false
        var acceptOK = false
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if name.caseInsensitiveCompare("Upgrade") == .orderedSame, value.caseInsensitiveCompare("websocket") == .orderedSame {
                upgraded = true
            } else if name.caseInsensitiveCompare("Sec-WebSocket-Accept") == .orderedSame, value == expectedAccept {
                acceptOK = true
            }
        }
        return (end, upgraded && acceptOK)
    }

    /// Encodes a client frame (always masked, single unfragmented frame).
    static func encodeClientFrame(opcode: UInt8, payload: [UInt8]) -> [UInt8] {
        var frame: [UInt8] = [0x80 | opcode]
        let length = payload.count
        if length < 126 {
            frame.append(0x80 | UInt8(length))
        } else if length <= 0xFFFF {
            frame.append(0x80 | 126)
            frame.append(UInt8((length >> 8) & 0xff))
            frame.append(UInt8(length & 0xff))
        } else {
            frame.append(0x80 | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                frame.append(UInt8((length >> shift) & 0xff))
            }
        }
        let mask = swiftCoreRandomBytes(4)
        frame.append(contentsOf: mask)
        frame.reserveCapacity(frame.count + length)
        for (index, byte) in payload.enumerated() {
            frame.append(byte ^ mask[index & 3])
        }
        return frame
    }

    /// Decodes one complete frame from the front of `buffer`, consuming its bytes. Returns nil if a
    /// full frame is not yet available.
    static func decodeFrame(_ buffer: inout [UInt8]) -> (fin: Bool, opcode: UInt8, payload: [UInt8])? {
        guard buffer.count >= 2 else { return nil }
        let fin = (buffer[0] & 0x80) != 0
        let opcode = buffer[0] & 0x0f
        let masked = (buffer[1] & 0x80) != 0
        var length = Int(buffer[1] & 0x7f)
        var index = 2
        if length == 126 {
            guard buffer.count >= index + 2 else { return nil }
            length = Int(buffer[index]) << 8 | Int(buffer[index + 1])
            index += 2
        } else if length == 127 {
            guard buffer.count >= index + 8 else { return nil }
            length = 0
            for offset in 0..<8 { length = (length << 8) | Int(buffer[index + offset]) }
            index += 8
        }
        var mask: [UInt8] = []
        if masked {
            guard buffer.count >= index + 4 else { return nil }
            mask = Array(buffer[index..<index + 4])
            index += 4
        }
        guard buffer.count >= index + length else { return nil }
        var payload = Array(buffer[index..<index + length])
        if masked {
            for offset in 0..<length { payload[offset] ^= mask[offset & 3] }
        }
        buffer.removeFirst(index + length)
        return (fin, opcode, payload)
    }

    private static func findHeaderEnd(_ buffer: [UInt8]) -> Int? {
        guard buffer.count >= 4 else { return nil }
        var index = 0
        while index <= buffer.count - 4 {
            if buffer[index] == 0x0d, buffer[index + 1] == 0x0a, buffer[index + 2] == 0x0d, buffer[index + 3] == 0x0a {
                return index + 4
            }
            index += 1
        }
        return nil
    }
}

/// Carries the VLESS/VMess byte stream inside a WebSocket tunnel. Performs the opening handshake on
/// connect, then delays `channelActive` to the protocol handler until the server returns `101` so
/// the protocol's request header is only sent once the tunnel is up. Outbound writes that arrive
/// before then are buffered and replayed (framed) after the handshake.
final class SwiftCoreWebSocketTransportHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let host: String
    private let path: String
    private let headers: [String: String]
    private let key: String
    private let expectedAccept: String

    private var handshakeDone = false
    private var inbound: [UInt8] = []
    private var pendingWrites: [(ByteBuffer, EventLoopPromise<Void>?)] = []

    init(host: String, path: String, headers: [String: String]) {
        self.host = host
        self.path = path
        self.headers = headers
        let key = SwiftCoreWebSocketProtocol.generateKey()
        self.key = key
        self.expectedAccept = SwiftCoreWebSocketProtocol.acceptValue(forKey: key)
    }

    func channelActive(context: ChannelHandlerContext) {
        let request = SwiftCoreWebSocketProtocol.handshakeRequest(host: host, path: path, key: key, headers: headers)
        var buffer = context.channel.allocator.buffer(capacity: request.count)
        buffer.writeBytes(request)
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        // Do not forward channelActive yet; the protocol handler must wait for the 101.
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        if let bytes = incoming.readBytes(length: incoming.readableBytes) {
            inbound.append(contentsOf: bytes)
        }

        if !handshakeDone {
            guard let result = SwiftCoreWebSocketProtocol.parseHandshakeResponse(inbound, expectedAccept: expectedAccept) else {
                return
            }
            guard result.accepted else {
                context.fireErrorCaught(SwiftCoreError.invalidConfig("WebSocket upgrade to \(host)\(path) was rejected."))
                context.close(promise: nil)
                return
            }
            inbound.removeFirst(result.headerEnd)
            handshakeDone = true
            context.fireChannelActive()          // wakes the protocol handler -> it writes its request header
            flushPendingWrites(context: context) // then replay any buffered application data
        }

        deliverFrames(context: context)
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = Self.unwrapOutboundIn(data)
        guard handshakeDone else {
            pendingWrites.append((buffer, promise))
            return
        }
        sendFramed(buffer, context: context, promise: promise)
    }

    func channelInactive(context: ChannelHandlerContext) {
        failPending()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        failPending()
        context.fireErrorCaught(error)
    }

    private func deliverFrames(context: ChannelHandlerContext) {
        while let frame = SwiftCoreWebSocketProtocol.decodeFrame(&inbound) {
            switch frame.opcode {
            case SwiftCoreWebSocketProtocol.Opcode.binary,
                 SwiftCoreWebSocketProtocol.Opcode.text,
                 SwiftCoreWebSocketProtocol.Opcode.continuation:
                guard !frame.payload.isEmpty else { continue }
                var out = context.channel.allocator.buffer(capacity: frame.payload.count)
                out.writeBytes(frame.payload)
                context.fireChannelRead(Self.wrapInboundOut(out))
            case SwiftCoreWebSocketProtocol.Opcode.ping:
                let pong = SwiftCoreWebSocketProtocol.encodeClientFrame(opcode: SwiftCoreWebSocketProtocol.Opcode.pong, payload: frame.payload)
                var out = context.channel.allocator.buffer(capacity: pong.count)
                out.writeBytes(pong)
                context.writeAndFlush(Self.wrapOutboundOut(out), promise: nil)
            case SwiftCoreWebSocketProtocol.Opcode.close:
                context.close(promise: nil)
                return
            default:
                continue // pong and unknown control frames are ignored
            }
        }
    }

    private func sendFramed(_ buffer: ByteBuffer, context: ChannelHandlerContext, promise: EventLoopPromise<Void>?) {
        var buffer = buffer
        guard let bytes = buffer.readBytes(length: buffer.readableBytes), !bytes.isEmpty else {
            promise?.succeed(())
            return
        }
        let frame = SwiftCoreWebSocketProtocol.encodeClientFrame(opcode: SwiftCoreWebSocketProtocol.Opcode.binary, payload: bytes)
        var out = context.channel.allocator.buffer(capacity: frame.count)
        out.writeBytes(frame)
        context.write(Self.wrapOutboundOut(out), promise: promise)
    }

    private func flushPendingWrites(context: ChannelHandlerContext) {
        let writes = pendingWrites
        pendingWrites.removeAll()
        for (buffer, promise) in writes {
            sendFramed(buffer, context: context, promise: promise)
        }
        if !writes.isEmpty {
            context.flush()
        }
    }

    private func failPending() {
        let writes = pendingWrites
        pendingWrites.removeAll()
        for (_, promise) in writes {
            promise?.fail(SwiftCoreError.invalidConfig("WebSocket connection closed before the handshake completed."))
        }
    }
}
