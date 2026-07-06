import Crypto
import Foundation
import NIOCore
import NIOEmbedded
import XCTest
@testable import NeoClashSwiftCoreLib

/// Pipeline-level tests for `SwiftCoreVMessClientHandler` on an `EmbeddedChannel`: the request
/// header sent on activation, write encryption, response decryption across fragmented reads, and
/// teardown on a tampered response. Fixed session keys make the server side reproducible.
final class VMessHandlerTests: XCTestCase {
    private let requestKey = [UInt8](repeating: 0xA1, count: 16)
    private let requestIV = [UInt8](repeating: 0xB2, count: 16)
    private let responseV: UInt8 = 0x7E

    private var responseKey: [UInt8] { Array(SHA256.hash(data: Data(requestKey)).prefix(16)) }
    private var responseIV: [UInt8] { Array(SHA256.hash(data: Data(requestIV)).prefix(16)) }

    /// An active channel whose handler has already emitted the AEAD request header.
    private func makeChannel() throws -> EmbeddedChannel {
        let cmdKey = swiftCoreVMessCmdKey(uuid: try SwiftCoreProxyEncoding.parseUUID("11111111-1111-1111-1111-111111111111"))
        let session = SwiftCoreVMessSession(
            cmdKey: cmdKey,
            security: .aesGCM,
            request: SwiftCoreOutboundRequest(host: "example.com", port: 443),
            requestKey: requestKey,
            requestIV: requestIV,
            responseHeaderByte: responseV
        )
        let channel = EmbeddedChannel(handler: SwiftCoreVMessClientHandler(session: session))
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()
        return channel
    }

    private func sealedResponseHeader(_ headerBytes: [UInt8]) throws -> [UInt8] {
        let lengthKey = swiftCoreVMessKDF16(key: responseKey, path: [Array("AEAD Resp Header Len Key".utf8)])
        let lengthNonce = Array(swiftCoreVMessKDF(key: responseIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
        let lengthSealed = try SwiftCoreAESGCM.seal(key: lengthKey, nonce: lengthNonce, plaintext: [0x00, UInt8(headerBytes.count)], aad: [])
        let payloadKey = swiftCoreVMessKDF16(key: responseKey, path: [Array("AEAD Resp Header Key".utf8)])
        let payloadNonce = Array(swiftCoreVMessKDF(key: responseIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
        let payloadSealed = try SwiftCoreAESGCM.seal(key: payloadKey, nonce: payloadNonce, plaintext: headerBytes, aad: [])
        return lengthSealed + payloadSealed
    }

    private func sealedResponseChunk(_ payload: [UInt8], count: UInt16) throws -> [UInt8] {
        let cipher = SwiftCoreVMessBodyCipher(security: .aesGCM, key: responseKey, iv: responseIV)
        let sealed = try cipher.seal(payload, count: count)
        return [UInt8(sealed.count >> 8), UInt8(sealed.count & 0xff)] + sealed
    }

    private func writeInbound(_ bytes: [UInt8], to channel: EmbeddedChannel) throws {
        var buffer = channel.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        try channel.writeInbound(buffer)
    }

    func testActivationSendsHeaderAndWritesAreEncrypted() throws {
        let channel = try makeChannel()

        // Activation emits the request header: authID(16) + sealed length(18) + nonce(8) + sealed header.
        let header = try XCTUnwrap(channel.readOutbound(as: ByteBuffer.self))
        XCTAssertGreaterThan(header.readableBytes, 42)

        var out = channel.allocator.buffer(capacity: 5)
        out.writeString("hello")
        try channel.writeOutbound(out)

        var framed = try XCTUnwrap(channel.readOutbound(as: ByteBuffer.self))
        let bytes = try XCTUnwrap(framed.readBytes(length: framed.readableBytes))
        XCTAssertEqual(Int(bytes[0]) << 8 | Int(bytes[1]), bytes.count - 2)
        let cipher = SwiftCoreVMessBodyCipher(security: .aesGCM, key: requestKey, iv: requestIV)
        XCTAssertEqual(try cipher.open(Array(bytes[2...]), count: 0), Array("hello".utf8))
        XCTAssertNoThrow(try channel.finish())
    }

    func testDecryptsResponseDeliveredInFragments() throws {
        let channel = try makeChannel()
        _ = try channel.readOutbound(as: ByteBuffer.self) // discard the request header

        let first = Array("split response ".utf8)
        let second = Array("payload".utf8)
        let wire = try sealedResponseHeader([responseV, 0x00, 0x00, 0x00])
            + sealedResponseChunk(first, count: 0)
            + sealedResponseChunk(second, count: 1)

        // Not enough for the response header yet: nothing surfaces.
        let cut = 12
        try writeInbound(Array(wire[0..<cut]), to: channel)
        XCTAssertNil(try channel.readInbound(as: ByteBuffer.self))

        // The rest arrives: header is consumed and both chunks decrypt in one read.
        try writeInbound(Array(wire[cut...]), to: channel)
        var plain = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
        XCTAssertEqual(plain.readBytes(length: plain.readableBytes), first + second)
        XCTAssertNoThrow(try channel.finish())
    }

    func testTamperedResponseHeaderClosesChannel() throws {
        let channel = try makeChannel()
        _ = try channel.readOutbound(as: ByteBuffer.self)

        var wire = try sealedResponseHeader([responseV, 0x00, 0x00, 0x00])
        wire[0] ^= 0xFF // corrupt the sealed length block
        XCTAssertThrowsError(try writeInbound(wire, to: channel))
        XCTAssertFalse(channel.isActive)
    }

    func testEmptyWriteCompletesWithoutEmittingAFrame() throws {
        let channel = try makeChannel()
        _ = try channel.readOutbound(as: ByteBuffer.self)

        try channel.writeOutbound(channel.allocator.buffer(capacity: 0))
        XCTAssertNil(try channel.readOutbound(as: ByteBuffer.self))
        XCTAssertNoThrow(try channel.finish())
    }
}
