import Crypto
import Foundation
import NIOCore
import NIOPosix

/// VMess (AEAD) outbound over TCP, optionally wrapped in TLS. Targets the modern VMessAEAD
/// handshake with `alterId: 0` and AES-128-GCM or ChaCha20-Poly1305 body ciphers.
final class SwiftCoreVMessOutbound: SwiftCoreOutbound, @unchecked Sendable {
    let name: String
    private let server: String
    private let port: Int
    private let cmdKey: [UInt8]
    private let security: SwiftCoreVMessSecurity
    private let tls: SwiftCoreTLSTransport?
    private let transport: SwiftCoreStreamTransport

    init(proxy: SwiftCoreProxy) throws {
        guard let server = proxy.server, !server.isEmpty else {
            throw SwiftCoreError.invalidConfig("vmess proxy \(proxy.name) requires a server.")
        }
        guard let port = proxy.port, (1...65_535).contains(port) else {
            throw SwiftCoreError.invalidConfig("vmess proxy \(proxy.name) requires a valid port.")
        }
        guard let uuidString = proxy.uuid else {
            throw SwiftCoreError.invalidConfig("vmess proxy \(proxy.name) requires a uuid.")
        }
        if let alterId = proxy.alterId, alterId != 0 {
            throw SwiftCoreError.invalidConfig("vmess proxy \(proxy.name) alterId \(alterId) is not supported (AEAD/0 only).")
        }
        self.transport = try SwiftCoreStreamTransport.make(proxy: proxy)
        switch (proxy.cipher ?? "auto").lowercased() {
        case "auto", "aes-128-gcm":
            self.security = .aesGCM
        case "chacha20-poly1305", "chacha20-ietf-poly1305":
            self.security = .chacha20Poly1305
        case let other:
            throw SwiftCoreError.invalidConfig("vmess proxy \(proxy.name) cipher '\(other)' is not supported.")
        }
        self.name = proxy.name
        self.server = server
        self.port = port
        self.cmdKey = swiftCoreVMessCmdKey(uuid: try SwiftCoreProxyEncoding.parseUUID(uuidString))
        if proxy.tls {
            self.tls = try SwiftCoreTLSTransport(options: SwiftCoreTLSOptions(
                serverName: proxy.servername ?? server,
                alpn: proxy.alpn ?? [],
                skipCertVerify: proxy.skipCertVerify
            ))
        } else {
            self.tls = nil
        }
    }

    func connect(
        request: SwiftCoreOutboundRequest,
        group: EventLoopGroup,
        makeTailHandler: @escaping @Sendable () -> ChannelHandler
    ) -> EventLoopFuture<Channel> {
        let cmdKey = self.cmdKey
        let security = self.security
        let tls = self.tls
        let transport = self.transport
        return ClientBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                do {
                    if let tls {
                        try channel.pipeline.syncOperations.addHandler(tls.makeHandler())
                    }
                    try transport.addHandler(to: channel)
                    let session = SwiftCoreVMessSession(cmdKey: cmdKey, security: security, request: request)
                    try channel.pipeline.syncOperations.addHandler(SwiftCoreVMessClientHandler(session: session))
                    try channel.pipeline.syncOperations.addHandler(makeTailHandler())
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: server, port: port)
    }
}

/// Encapsulates the per-connection VMess state and the encode/decode steps. Kept independent of
/// the NIO handler so the wire format can be exercised directly in tests.
final class SwiftCoreVMessSession {
    private static let maxChunk = 16_384

    let cmdKey: [UInt8]
    let security: SwiftCoreVMessSecurity
    let request: SwiftCoreOutboundRequest
    let requestKey: [UInt8]
    let requestIV: [UInt8]
    let responseHeaderByte: UInt8

    private let responseKey: [UInt8]
    private let responseIV: [UInt8]
    private let requestCipher: SwiftCoreVMessBodyCipher
    private let responseCipher: SwiftCoreVMessBodyCipher
    private var requestCount: UInt16 = 0
    private var responseCount: UInt16 = 0

    init(
        cmdKey: [UInt8],
        security: SwiftCoreVMessSecurity,
        request: SwiftCoreOutboundRequest,
        requestKey: [UInt8] = swiftCoreRandomBytes(16),
        requestIV: [UInt8] = swiftCoreRandomBytes(16),
        responseHeaderByte: UInt8 = UInt8.random(in: 0...255)
    ) {
        self.cmdKey = cmdKey
        self.security = security
        self.request = request
        self.requestKey = requestKey
        self.requestIV = requestIV
        self.responseHeaderByte = responseHeaderByte
        self.responseKey = Array(SHA256.hash(data: Data(requestKey)).prefix(16))
        self.responseIV = Array(SHA256.hash(data: Data(requestIV)).prefix(16))
        self.requestCipher = SwiftCoreVMessBodyCipher(security: security, key: requestKey, iv: requestIV)
        self.responseCipher = SwiftCoreVMessBodyCipher(security: security, key: responseKey, iv: responseIV)
    }

    // MARK: Request

    /// The plaintext VMess command header (encrypted into the AEAD envelope by `encodeRequestHeader`).
    func commandHeader() -> [UInt8] {
        var header: [UInt8] = []
        header.append(0x01)                       // version
        header.append(contentsOf: requestIV)      // 16
        header.append(contentsOf: requestKey)     // 16
        header.append(responseHeaderByte)         // V
        header.append(0x01)                       // option: chunk stream
        let padding = UInt8.random(in: 0...15)
        header.append((padding << 4) | security.securityByte)
        header.append(0x00)                       // reserved
        header.append(0x01)                       // command: TCP
        SwiftCoreProxyEncoding.appendTargetAddress(request, to: &header)
        if padding > 0 {
            header.append(contentsOf: swiftCoreRandomBytes(Int(padding)))
        }
        let checksum = swiftCoreFNV1a(header)
        header.append(contentsOf: [
            UInt8((checksum >> 24) & 0xff),
            UInt8((checksum >> 16) & 0xff),
            UInt8((checksum >> 8) & 0xff),
            UInt8(checksum & 0xff)
        ])
        return header
    }

    /// The AEAD-sealed request header sent first on the connection.
    func encodeRequestHeader() throws -> [UInt8] {
        let header = commandHeader()
        let authID = try makeAuthID()
        let connectionNonce = swiftCoreRandomBytes(8)

        let lengthKey = swiftCoreVMessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
        let lengthNonce = Array(swiftCoreVMessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
        let lengthPlain: [UInt8] = [UInt8(header.count >> 8), UInt8(header.count & 0xff)]
        let lengthSealed = try SwiftCoreAESGCM.seal(key: lengthKey, nonce: lengthNonce, plaintext: lengthPlain, aad: authID)

        let payloadKey = swiftCoreVMessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key".utf8), authID, connectionNonce])
        let payloadNonce = Array(swiftCoreVMessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce".utf8), authID, connectionNonce]).prefix(12))
        let payloadSealed = try SwiftCoreAESGCM.seal(key: payloadKey, nonce: payloadNonce, plaintext: header, aad: authID)

        return authID + lengthSealed + connectionNonce + payloadSealed
    }

    /// Frames plaintext into one or more length-prefixed AEAD body chunks.
    func encodeBody(_ plaintext: [UInt8]) throws -> [UInt8] {
        var output: [UInt8] = []
        var offset = 0
        repeat {
            let end = min(offset + Self.maxChunk, plaintext.count)
            let chunk = Array(plaintext[offset..<end])
            offset = end
            let sealed = try requestCipher.seal(chunk, count: requestCount)
            requestCount = requestCount &+ 1
            output.append(UInt8(sealed.count >> 8))
            output.append(UInt8(sealed.count & 0xff))
            output.append(contentsOf: sealed)
        } while offset < plaintext.count
        return output
    }

    private func makeAuthID() throws -> [UInt8] {
        var block = [UInt8](repeating: 0, count: 16)
        let time = UInt64(Date().timeIntervalSince1970)
        for index in 0..<8 {
            block[index] = UInt8((time >> (8 * (7 - index))) & 0xff)
        }
        let random = swiftCoreRandomBytes(4)
        for index in 0..<4 {
            block[8 + index] = random[index]
        }
        let crc = swiftCoreCRC32(Array(block[0..<12]))
        block[12] = UInt8((crc >> 24) & 0xff)
        block[13] = UInt8((crc >> 16) & 0xff)
        block[14] = UInt8((crc >> 8) & 0xff)
        block[15] = UInt8(crc & 0xff)
        let key = swiftCoreVMessKDF16(key: cmdKey, path: [Array("AES Auth ID Encryption".utf8)])
        return SwiftCoreAES128Block(key: key).encrypt(block)
    }

    // MARK: Response

    /// Attempts to consume the AEAD response header from `buffer`. Returns true once the header
    /// has been fully read and verified; false if more bytes are needed.
    func decodeResponseHeader(_ buffer: inout [UInt8]) throws -> Bool {
        guard buffer.count >= 18 else { return false }
        let lengthKey = swiftCoreVMessKDF16(key: responseKey, path: [Array("AEAD Resp Header Len Key".utf8)])
        let lengthNonce = Array(swiftCoreVMessKDF(key: responseIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
        let lengthPlain = try SwiftCoreAESGCM.open(key: lengthKey, nonce: lengthNonce, ciphertextAndTag: Array(buffer[0..<18]), aad: [])
        let headerLength = Int(lengthPlain[0]) << 8 | Int(lengthPlain[1])
        let total = 18 + headerLength + 16
        guard buffer.count >= total else { return false }

        let payloadKey = swiftCoreVMessKDF16(key: responseKey, path: [Array("AEAD Resp Header Key".utf8)])
        let payloadNonce = Array(swiftCoreVMessKDF(key: responseIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
        let header = try SwiftCoreAESGCM.open(key: payloadKey, nonce: payloadNonce, ciphertextAndTag: Array(buffer[18..<total]), aad: [])
        guard let first = header.first, first == responseHeaderByte else {
            throw SwiftCoreError.invalidConfig("VMess response header does not match the request.")
        }
        buffer.removeFirst(total)
        return true
    }

    /// Decrypts as many complete body chunks as are available in `buffer`, returning the plaintext.
    func decodeBody(_ buffer: inout [UInt8]) throws -> [UInt8] {
        var plaintext: [UInt8] = []
        while buffer.count >= 2 {
            let size = Int(buffer[0]) << 8 | Int(buffer[1])
            guard buffer.count >= 2 + size else { break }
            let sealed = Array(buffer[2..<(2 + size)])
            buffer.removeFirst(2 + size)
            let chunk = try responseCipher.open(sealed, count: responseCount)
            responseCount = responseCount &+ 1
            plaintext.append(contentsOf: chunk)
        }
        return plaintext
    }
}

/// Drives a `SwiftCoreVMessSession` over the NIO pipeline: sends the AEAD request header on
/// connect, encrypts outbound writes into body chunks, and decrypts inbound chunks to plaintext.
final class SwiftCoreVMessClientHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let session: SwiftCoreVMessSession
    private var responseHeaderDone = false
    private var pending: [UInt8] = []

    init(session: SwiftCoreVMessSession) {
        self.session = session
    }

    func channelActive(context: ChannelHandlerContext) {
        do {
            let header = try session.encodeRequestHeader()
            var buffer = context.channel.allocator.buffer(capacity: header.count)
            buffer.writeBytes(header)
            context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
            context.fireChannelActive()
        } catch {
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = Self.unwrapOutboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes), !bytes.isEmpty else {
            promise?.succeed(())
            return
        }
        do {
            let framed = try session.encodeBody(bytes)
            var out = context.channel.allocator.buffer(capacity: framed.count)
            out.writeBytes(framed)
            context.writeAndFlush(Self.wrapOutboundOut(out), promise: promise)
        } catch {
            promise?.fail(error)
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        if let bytes = incoming.readBytes(length: incoming.readableBytes) {
            pending.append(contentsOf: bytes)
        }
        do {
            if !responseHeaderDone {
                responseHeaderDone = try session.decodeResponseHeader(&pending)
                guard responseHeaderDone else { return }
            }
            let plaintext = try session.decodeBody(&pending)
            if !plaintext.isEmpty {
                var out = context.channel.allocator.buffer(capacity: plaintext.count)
                out.writeBytes(plaintext)
                context.fireChannelRead(Self.wrapInboundOut(out))
            }
        } catch {
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }
}
