import Foundation
import NIOCore
import NIOEmbedded
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for XTLS-Vision: the VLESS flow advertisement, the padding codec, and the read/write
/// padding state machines (including the direct-splice signal). End-to-end interop is covered by
/// manual verification against a real REALITY+Vision server.
final class VisionTests: XCTestCase {
    func testVLESSFlowAddonEncoding() {
        let uuid = [UInt8](repeating: 0xCD, count: 16)
        let request = SwiftCoreOutboundRequest(host: "example.com", port: 443)
        let header = SwiftCoreVLESSProtocol.requestHeader(uuid: uuid, request: request, flow: "xtls-rprx-vision")

        let flowBytes = Array("xtls-rprx-vision".utf8)
        let addonLength = 2 + flowBytes.count
        XCTAssertEqual(header[17], UInt8(addonLength))        // addon length
        XCTAssertEqual(header[18], 0x0a)                       // protobuf field 1, wire type 2
        XCTAssertEqual(header[19], UInt8(flowBytes.count))     // string length
        XCTAssertEqual(Array(header[20..<20 + flowBytes.count]), flowBytes)
        XCTAssertEqual(header[20 + flowBytes.count], 0x01)     // command: TCP follows addons
    }

    func testApplyPaddingLayout() {
        let uuid = [UInt8](repeating: 0x11, count: 16)
        let content = Array("payload".utf8)
        let padded = SwiftCoreVision.applyPadding(content: content, command: SwiftCoreVisionCommand.paddingContinue, uuid: uuid, paddingTLS: false)

        XCTAssertEqual(Array(padded[0..<16]), uuid)
        XCTAssertEqual(padded[16], SwiftCoreVisionCommand.paddingContinue)
        let contentLength = Int(padded[17]) << 8 | Int(padded[18])
        let paddingLength = Int(padded[19]) << 8 | Int(padded[20])
        XCTAssertEqual(contentLength, content.count)
        XCTAssertEqual(Array(padded[21..<21 + content.count]), content)
        XCTAssertEqual(padded.count, 21 + content.count + paddingLength)
    }

    func testVisionReadUnpadsAndStopsOnEnd() throws {
        let channel = EmbeddedChannel()
        let uuid = [UInt8](repeating: 0xAB, count: 16)
        let directState = SwiftCoreVisionDirectState()
        try channel.pipeline.syncOperations.addHandler(SwiftCoreVisionHandler(userUUID: uuid, directState: directState))

        let first = SwiftCoreVision.applyPadding(content: Array("hello ".utf8), command: SwiftCoreVisionCommand.paddingContinue, uuid: uuid, paddingTLS: false)
        let second = SwiftCoreVision.applyPadding(content: Array("world".utf8), command: SwiftCoreVisionCommand.paddingEnd, uuid: nil, paddingTLS: false)
        var inbound = channel.allocator.buffer(capacity: first.count + second.count)
        inbound.writeBytes(first + second)
        try channel.writeInbound(inbound)

        // After the end packet, raw bytes must pass straight through.
        var raw = channel.allocator.buffer(capacity: 4)
        raw.writeBytes(Array("!raw".utf8))
        try channel.writeInbound(raw)

        var received = ""
        while let buffer: ByteBuffer = try channel.readInbound() {
            received += String(buffer: buffer)
        }
        XCTAssertEqual(received, "hello world!raw")
        _ = try channel.finish()
    }

    func testVisionReadSignalsDirect() throws {
        let channel = EmbeddedChannel()
        let uuid = [UInt8](repeating: 0xAB, count: 16)
        let directState = SwiftCoreVisionDirectState()
        try channel.pipeline.syncOperations.addHandler(SwiftCoreVisionHandler(userUUID: uuid, directState: directState))

        let direct = SwiftCoreVision.applyPadding(content: Array("inner".utf8), command: SwiftCoreVisionCommand.paddingDirect, uuid: uuid, paddingTLS: false)
        var inbound = channel.allocator.buffer(capacity: direct.count)
        inbound.writeBytes(direct)
        try channel.writeInbound(inbound)

        XCTAssertTrue(directState.readDirect)
        var received = ""
        while let buffer: ByteBuffer = try channel.readInbound() {
            received += String(buffer: buffer)
        }
        XCTAssertEqual(received, "inner")
        _ = try channel.finish()
    }

    func testVisionWritePadsThenStopsAfterApplicationData() throws {
        let channel = EmbeddedChannel()
        let uuid = [UInt8](repeating: 0xAB, count: 16)
        let directState = SwiftCoreVisionDirectState()
        try channel.pipeline.syncOperations.addHandler(SwiftCoreVisionHandler(userUUID: uuid, directState: directState))

        // Inner TLS ClientHello-like record marks the stream as TLS.
        var handshake = channel.allocator.buffer(capacity: 10)
        handshake.writeBytes([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        try channel.writeOutbound(handshake)

        // First outbound application-data record ends padding.
        var appData = channel.allocator.buffer(capacity: 8)
        appData.writeBytes([0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC])
        try channel.writeOutbound(appData)

        // Subsequent writes pass through unpadded.
        var more = channel.allocator.buffer(capacity: 3)
        more.writeBytes([0x01, 0x02, 0x03])
        try channel.writeOutbound(more)

        guard var firstOut: ByteBuffer = try channel.readOutbound() else { return XCTFail("no first output") }
        let firstBytes = firstOut.readBytes(length: firstOut.readableBytes) ?? []
        XCTAssertEqual(Array(firstBytes[0..<16]), uuid)                      // UUID on first padded packet
        XCTAssertEqual(firstBytes[16], SwiftCoreVisionCommand.paddingContinue)

        guard var secondOut: ByteBuffer = try channel.readOutbound() else { return XCTFail("no second output") }
        let secondBytes = secondOut.readBytes(length: secondOut.readableBytes) ?? []
        XCTAssertEqual(secondBytes[0], SwiftCoreVisionCommand.paddingEnd)    // no UUID; padding ends

        guard var thirdOut: ByteBuffer = try channel.readOutbound() else { return XCTFail("no third output") }
        let thirdBytes = thirdOut.readBytes(length: thirdOut.readableBytes) ?? []
        XCTAssertEqual(thirdBytes, [0x01, 0x02, 0x03])                       // passthrough, unpadded
        _ = try channel.finish()
    }
}
