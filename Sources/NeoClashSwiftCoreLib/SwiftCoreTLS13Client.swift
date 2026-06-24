import Crypto
import Foundation
import NIOCore

/// Extension point for REALITY: customizes the ClientHello (splicing the auth tag into the
/// SessionId) and performs REALITY's certificate verification. Implemented in a later increment;
/// when nil the handler behaves as a plain TLS 1.3 client that accepts any certificate.
protocol SwiftCoreRealityHandshaking: AnyObject {
    var helloRandom: [UInt8] { get }
    var helloSessionId: [UInt8] { get }
    var privateKey: Curve25519.KeyAgreement.PrivateKey { get }
    func finalizeClientHello(_ message: inout [UInt8], sessionIdOffset: Int) throws
    func verifyServerCertificate(messageBody: [UInt8]) throws
}

/// A from-scratch TLS 1.3 client as a NIO duplex handler. It performs the handshake, then
/// transparently protects/unprotects application records, surfacing plaintext to downstream
/// handlers. Like `NIOSSLClientHandler`, it delays `channelActive` downstream until the handshake
/// completes so the next handler (VLESS/VMess) only writes once TLS is established.
///
/// Scope: x25519 key exchange, `TLS_AES_128_GCM_SHA256` / `TLS_CHACHA20_POLY1305_SHA256`, no
/// HelloRetryRequest, no client certificates. Standard WebPKI verification is intentionally skipped
/// (REALITY supplies its own verification; for plain use it accepts any certificate).
final class SwiftCoreTLS13ClientHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum State {
        case start
        case expectServerHello
        case expectFlight
        case established
        case failed
    }

    private static let maxRecordPlaintext = 16_384

    private let serverName: String?
    private let alpn: [String]
    private let reality: SwiftCoreRealityHandshaking?
    private let directState: SwiftCoreVisionDirectState?
    private var rawReadMode = false

    private var state: State = .start
    private var clientHello: SwiftCoreClientHello?
    private var transcript: [UInt8] = []
    private var keySchedule: SwiftCoreTLS13KeySchedule?
    private var suite: SwiftCoreTLS13CipherSuite?
    private var negotiatedHash: SwiftCoreTLS13Hash = .sha256

    private var clientHandshakeSecret: [UInt8] = []
    private var serverHandshakeSecret: [UInt8] = []
    private var serverHandshakeKeys: SwiftCoreTLS13RecordKeys?
    private var clientHandshakeKeys: SwiftCoreTLS13RecordKeys?
    private var serverApplicationKeys: SwiftCoreTLS13RecordKeys?
    private var clientApplicationKeys: SwiftCoreTLS13RecordKeys?
    private var serverSequence: UInt64 = 0
    private var clientSequence: UInt64 = 0

    private var recvBuffer: [UInt8] = []
    private var handshakeReadBuffer: [UInt8] = []
    private var pendingWrites: [(ByteBuffer, EventLoopPromise<Void>?)] = []

    init(
        serverName: String?,
        alpn: [String] = [],
        reality: SwiftCoreRealityHandshaking? = nil,
        directState: SwiftCoreVisionDirectState? = nil
    ) {
        self.serverName = serverName
        self.alpn = alpn
        self.reality = reality
        self.directState = directState
    }

    // MARK: Outbound

    func channelActive(context: ChannelHandlerContext) {
        do {
            try startHandshake(context: context)
        } catch {
            fail(context: context, error: error)
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = Self.unwrapOutboundIn(data)
        guard state == .established, let keys = clientApplicationKeys else {
            pendingWrites.append((buffer, promise))
            return
        }
        do {
            try sendApplicationData(buffer, keys: keys, context: context, promise: promise)
        } catch {
            promise?.fail(error)
            fail(context: context, error: error)
        }
    }

    // MARK: Inbound

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if rawReadMode {
            // XTLS direct splice: the server stopped outer-TLS-encrypting; pass the raw stream up.
            context.fireChannelRead(data)
            return
        }
        var incoming = Self.unwrapInboundIn(data)
        if let bytes = incoming.readBytes(length: incoming.readableBytes) {
            recvBuffer.append(contentsOf: bytes)
        }
        do {
            try processRecords(context: context)
        } catch {
            fail(context: context, error: error)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        context.fireChannelInactive()
    }

    // MARK: Handshake

    private func startHandshake(context: ChannelHandlerContext) throws {
        let hello: SwiftCoreClientHello
        if let reality {
            hello = SwiftCoreClientHello(
                serverName: serverName,
                alpn: alpn,
                random: reality.helloRandom,
                sessionId: reality.helloSessionId,
                privateKey: reality.privateKey
            )
        } else {
            hello = SwiftCoreClientHello(serverName: serverName, alpn: alpn)
        }

        var message = hello.handshakeMessage
        if let reality {
            try reality.finalizeClientHello(&message, sessionIdOffset: hello.sessionIdOffset)
        }
        self.clientHello = hello
        self.transcript = message
        self.state = .expectServerHello

        var out = context.channel.allocator.buffer(capacity: message.count + 11)
        out.writeBytes(SwiftCoreTLSMessage.record(type: .handshake, payload: message))
        out.writeBytes([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]) // change_cipher_spec
        context.writeAndFlush(Self.wrapOutboundOut(out), promise: nil)
    }

    private func processRecords(context: ChannelHandlerContext) throws {
        while recvBuffer.count >= 5 {
            // A handler above may flip this synchronously while we fire a decrypted record up.
            if directState?.readDirect == true { break }
            let length = Int(recvBuffer[3]) << 8 | Int(recvBuffer[4])
            guard recvBuffer.count >= 5 + length else { break }
            let type = recvBuffer[0]
            let fragment = Array(recvBuffer[5..<5 + length])
            recvBuffer.removeFirst(5 + length)
            try handleRecord(type: type, fragment: fragment, context: context)
        }
        if directState?.readDirect == true {
            rawReadMode = true
            if !recvBuffer.isEmpty {
                var raw = context.channel.allocator.buffer(capacity: recvBuffer.count)
                raw.writeBytes(recvBuffer)
                recvBuffer.removeAll()
                context.fireChannelRead(Self.wrapInboundOut(raw))
            }
        }
    }

    private func handleRecord(type: UInt8, fragment: [UInt8], context: ChannelHandlerContext) throws {
        switch SwiftCoreTLSRecordType(rawValue: type) {
        case .changeCipherSpec:
            return
        case .alert:
            throw SwiftCoreTLSError.handshakeFailed("Received a TLS alert during handshake.")
        case .handshake:
            handshakeReadBuffer.append(contentsOf: fragment)
            try processHandshakeMessages(context: context)
        case .applicationData:
            try handleEncryptedRecord(fragment: fragment, context: context)
        case .none:
            throw SwiftCoreTLSError.handshakeFailed("Unknown TLS record type \(type).")
        }
    }

    private func handleEncryptedRecord(fragment: [UInt8], context: ChannelHandlerContext) throws {
        let usingApplicationKeys = (state == .established)
        guard let keys = usingApplicationKeys ? serverApplicationKeys : serverHandshakeKeys else {
            throw SwiftCoreTLSError.handshakeFailed("Encrypted record before keys were derived.")
        }
        let aad: [UInt8] = [0x17, 0x03, 0x03, UInt8(fragment.count >> 8), UInt8(fragment.count & 0xff)]
        let plaintext = try keys.open(ciphertextAndTag: fragment, sequenceNumber: serverSequence, additionalData: aad)
        serverSequence &+= 1

        guard let (content, innerType) = Self.stripRecordPadding(plaintext) else {
            return
        }
        switch SwiftCoreTLSRecordType(rawValue: innerType) {
        case .handshake:
            handshakeReadBuffer.append(contentsOf: content)
            try processHandshakeMessages(context: context)
        case .applicationData:
            guard state == .established else {
                throw SwiftCoreTLSError.handshakeFailed("Application data before handshake completion.")
            }
            if !content.isEmpty {
                var out = context.channel.allocator.buffer(capacity: content.count)
                out.writeBytes(content)
                context.fireChannelRead(Self.wrapInboundOut(out))
            }
        case .alert:
            context.close(promise: nil)
        default:
            return
        }
    }

    private func processHandshakeMessages(context: ChannelHandlerContext) throws {
        while let (type, fullMessage, body) = Self.nextHandshakeMessage(handshakeReadBuffer) {
            handshakeReadBuffer.removeFirst(fullMessage.count)
            switch SwiftCoreTLSHandshakeType(rawValue: type) {
            case .serverHello:
                try handleServerHello(fullMessage: fullMessage, body: body)
            case .encryptedExtensions:
                transcript.append(contentsOf: fullMessage)
            case .certificate:
                transcript.append(contentsOf: fullMessage)
                if let reality {
                    try reality.verifyServerCertificate(messageBody: body)
                }
            case .certificateVerify:
                transcript.append(contentsOf: fullMessage)
            case .finished:
                try handleServerFinished(fullMessage: fullMessage, verifyData: body, context: context)
            case .newSessionTicket:
                continue // post-handshake ticket; ignored
            default:
                continue
            }
        }
    }

    private func handleServerHello(fullMessage: [UInt8], body: [UInt8]) throws {
        guard let clientHello, state == .expectServerHello else {
            throw SwiftCoreTLSError.handshakeFailed("Unexpected ServerHello.")
        }
        transcript.append(contentsOf: fullMessage)
        let serverHello = try SwiftCoreServerHello(body: body)
        self.suite = serverHello.cipherSuite
        self.negotiatedHash = serverHello.cipherSuite.hash

        let serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(serverHello.serverPublicKey))
        let shared = try clientHello.privateKey.sharedSecretFromKeyAgreement(with: serverKey)
        let ecdhe = shared.withUnsafeBytes { Array($0) }

        let schedule = SwiftCoreTLS13KeySchedule(ecdheSharedSecret: ecdhe, hash: negotiatedHash)
        let transcriptHash = SwiftCoreTLS13.transcriptHash(transcript, hash: negotiatedHash)
        let serverSecret = schedule.serverHandshakeTrafficSecret(transcriptHash: transcriptHash)
        let clientSecret = schedule.clientHandshakeTrafficSecret(transcriptHash: transcriptHash)

        self.keySchedule = schedule
        self.clientHandshakeSecret = clientSecret
        self.serverHandshakeSecret = serverSecret
        self.serverHandshakeKeys = SwiftCoreTLS13RecordKeys(suite: serverHello.cipherSuite, trafficSecret: serverSecret)
        self.clientHandshakeKeys = SwiftCoreTLS13RecordKeys(suite: serverHello.cipherSuite, trafficSecret: clientSecret)
        self.serverSequence = 0
        self.clientSequence = 0
        self.state = .expectFlight
    }

    private func handleServerFinished(fullMessage: [UInt8], verifyData: [UInt8], context: ChannelHandlerContext) throws {
        guard state == .expectFlight,
              let schedule = keySchedule,
              let suite,
              let clientHandshakeKeys else {
            throw SwiftCoreTLSError.handshakeFailed("Unexpected server Finished.")
        }

        // server Finished is computed over the transcript up to (but excluding) itself.
        let transcriptBeforeFinished = SwiftCoreTLS13.transcriptHash(transcript, hash: negotiatedHash)
        let serverFinishedKey = SwiftCoreTLS13.finishedKey(baseKey: serverHandshakeSecret, hash: negotiatedHash)
        let expected = SwiftCoreTLS13.hmac(key: serverFinishedKey, message: transcriptBeforeFinished, hash: negotiatedHash)
        guard expected == verifyData else {
            throw SwiftCoreTLSError.handshakeFailed("Server Finished verify_data mismatch.")
        }

        transcript.append(contentsOf: fullMessage)
        let transcriptAfterFinished = SwiftCoreTLS13.transcriptHash(transcript, hash: negotiatedHash)

        // Client Finished over the transcript through the server Finished.
        let clientFinishedKey = SwiftCoreTLS13.finishedKey(baseKey: clientHandshakeSecret, hash: negotiatedHash)
        let clientVerifyData = SwiftCoreTLS13.hmac(key: clientFinishedKey, message: transcriptAfterFinished, hash: negotiatedHash)
        let clientFinished = SwiftCoreTLSMessage.handshake(type: .finished, body: clientVerifyData)
        var innerFinished = clientFinished
        innerFinished.append(SwiftCoreTLSRecordType.handshake.rawValue)
        let aadLength = innerFinished.count + 16
        let aad: [UInt8] = [0x17, 0x03, 0x03, UInt8(aadLength >> 8), UInt8(aadLength & 0xff)]
        let sealed = try clientHandshakeKeys.seal(plaintext: innerFinished, sequenceNumber: clientSequence, additionalData: aad)
        var out = context.channel.allocator.buffer(capacity: sealed.count + 5)
        out.writeBytes(SwiftCoreTLSMessage.record(type: .applicationData, payload: sealed))
        context.writeAndFlush(Self.wrapOutboundOut(out), promise: nil)

        // Switch both directions to application keys.
        let serverAppSecret = schedule.serverApplicationTrafficSecret(transcriptHash: transcriptAfterFinished)
        let clientAppSecret = schedule.clientApplicationTrafficSecret(transcriptHash: transcriptAfterFinished)
        self.serverApplicationKeys = SwiftCoreTLS13RecordKeys(suite: suite, trafficSecret: serverAppSecret)
        self.clientApplicationKeys = SwiftCoreTLS13RecordKeys(suite: suite, trafficSecret: clientAppSecret)
        self.serverSequence = 0
        self.clientSequence = 0
        self.state = .established

        context.fireChannelActive()
        try flushPendingWrites(context: context)
    }

    // MARK: Helpers

    private func sendApplicationData(_ buffer: ByteBuffer, keys: SwiftCoreTLS13RecordKeys, context: ChannelHandlerContext, promise: EventLoopPromise<Void>?) throws {
        var input = buffer
        guard let bytes = input.readBytes(length: input.readableBytes), !bytes.isEmpty else {
            promise?.succeed(())
            return
        }
        var out = context.channel.allocator.buffer(capacity: bytes.count + 64)
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + Self.maxRecordPlaintext, bytes.count)
            var inner = Array(bytes[offset..<end])
            offset = end
            inner.append(SwiftCoreTLSRecordType.applicationData.rawValue)
            let aadLength = inner.count + 16
            let aad: [UInt8] = [0x17, 0x03, 0x03, UInt8(aadLength >> 8), UInt8(aadLength & 0xff)]
            let sealed = try keys.seal(plaintext: inner, sequenceNumber: clientSequence, additionalData: aad)
            clientSequence &+= 1
            out.writeBytes(SwiftCoreTLSMessage.record(type: .applicationData, payload: sealed))
        }
        context.writeAndFlush(Self.wrapOutboundOut(out), promise: promise)
    }

    private func flushPendingWrites(context: ChannelHandlerContext) throws {
        guard let keys = clientApplicationKeys else { return }
        let writes = pendingWrites
        pendingWrites.removeAll()
        for (buffer, promise) in writes {
            try sendApplicationData(buffer, keys: keys, context: context, promise: promise)
        }
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        guard state != .failed else { return }
        state = .failed
        for (_, promise) in pendingWrites {
            promise?.fail(error)
        }
        pendingWrites.removeAll()
        context.fireErrorCaught(error)
        context.close(promise: nil)
    }

    private static func stripRecordPadding(_ plaintext: [UInt8]) -> (content: [UInt8], type: UInt8)? {
        var end = plaintext.count - 1
        while end >= 0 && plaintext[end] == 0 {
            end -= 1
        }
        guard end >= 0 else { return nil }
        return (Array(plaintext[0..<end]), plaintext[end])
    }

    private static func nextHandshakeMessage(_ buffer: [UInt8]) -> (type: UInt8, full: [UInt8], body: [UInt8])? {
        guard buffer.count >= 4 else { return nil }
        let length = Int(buffer[1]) << 16 | Int(buffer[2]) << 8 | Int(buffer[3])
        guard buffer.count >= 4 + length else { return nil }
        return (buffer[0], Array(buffer[0..<4 + length]), Array(buffer[4..<4 + length]))
    }
}
