import Foundation
import NIOCore

/// XTLS-Vision (`flow: xtls-rprx-vision`) — same logic as Xray-core / mihomo's `transport/vless/vision`.
///
/// During the inner TLS handshake the client wraps each outbound chunk in a padding header to hide
/// sizes and the VLESS header; once the inner stream is flowing it stops padding. For the inbound
/// direction it un-pads, and when the server signals "direct" (command 2, used once the inner
/// connection is confirmed TLS 1.3) it stops decrypting the outer TLS and splices the raw inner
/// stream straight through — the XTLS performance trick. We splice only the read direction and keep
/// our uploads inside the outer TLS (a valid, server-accepted asymmetric mode), which avoids
/// bypassing downstream handlers for writes.

/// Shared, single-event-loop state between the Vision handler and the TLS 1.3 handler below it.
final class SwiftCoreVisionDirectState: @unchecked Sendable {
    /// Set by the Vision handler (synchronously, during a read up-call) when the server sends the
    /// direct command; the TLS 1.3 handler then stops decrypting and passes the raw stream through.
    var readDirect = false
}

enum SwiftCoreVisionCommand {
    static let paddingContinue: UInt8 = 0x00
    static let paddingEnd: UInt8 = 0x01
    static let paddingDirect: UInt8 = 0x02
}

enum SwiftCoreVision {
    static let uuidSize = 16
    static let paddingHeaderLen = uuidSize + 1 + 2 + 2 // 21 (with UUID prefix)

    /// Wraps `content` in a Vision padding header: `[uuid?] command contentLen(2) paddingLen(2) content padding`.
    static func applyPadding(content: [UInt8], command: UInt8, uuid: [UInt8]?, paddingTLS: Bool) -> [UInt8] {
        let contentLength = content.count
        var paddingLength = 0
        if contentLength < 900 {
            paddingLength = paddingTLS ? Int.random(in: 0..<500) + 900 - contentLength : Int.random(in: 0..<256)
        }
        var output: [UInt8] = []
        output.reserveCapacity((uuid?.count ?? 0) + 5 + contentLength + paddingLength)
        if let uuid {
            output.append(contentsOf: uuid)
        }
        output.append(command)
        output.append(UInt8((contentLength >> 8) & 0xff))
        output.append(UInt8(contentLength & 0xff))
        output.append(UInt8((paddingLength >> 8) & 0xff))
        output.append(UInt8(paddingLength & 0xff))
        output.append(contentsOf: content)
        output.append(contentsOf: [UInt8](repeating: 0, count: paddingLength))
        return output
    }

    /// First index of `needle` in `haystack`, or nil.
    static func firstIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        for start in 0...(haystack.count - needle.count) where Array(haystack[start..<start + needle.count]) == needle {
            return start
        }
        return nil
    }
}

/// Vision filter/padding state, shared across both directions for one connection.
final class SwiftCoreVisionState {
    var packetsToFilter = 8
    var isTLS = false
    var isTLS12orAbove = false
    var enableXTLS = false
    var cipher: UInt16 = 0
    var remainingServerHello: Int = 0

    private static let tls13SupportedVersions: [UInt8] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    private static let serverHandshakeStart: [UInt8] = [0x16, 0x03, 0x03]
    private static let clientHandshakeStart: [UInt8] = [0x16, 0x03]

    /// Port of mihomo's `FilterTLS`: inspects traffic to learn whether the inner stream is TLS and,
    /// for the inbound ServerHello, whether it is TLS 1.3 (which enables the direct splice).
    func filter(_ buffer: [UInt8]) {
        if packetsToFilter <= 0 { return }
        let length = buffer.count
        packetsToFilter -= 1

        var index = SwiftCoreVision.firstIndex(of: Self.serverHandshakeStart, in: buffer) ?? -1
        if index != -1 {
            if length > index + 5, buffer[0] == 22, buffer[1] == 3, buffer[2] == 3 {
                isTLS = true
                if buffer[5] == 0x02 { // ServerHello
                    remainingServerHello = Int(UInt16(buffer[index + 3]) << 8 | UInt16(buffer[index + 4])) + 5
                    isTLS12orAbove = true
                    if length - index >= 79, remainingServerHello >= 79 {
                        let sessionIDLength = Int(buffer[index + 43])
                        let cipherOffset = index + 43 + sessionIDLength + 1
                        if cipherOffset + 2 <= length {
                            cipher = UInt16(buffer[cipherOffset]) << 8 | UInt16(buffer[cipherOffset + 1])
                        }
                    }
                }
            }
        } else if let clientIndex = SwiftCoreVision.firstIndex(of: Self.clientHandshakeStart, in: buffer) {
            index = clientIndex
            if length > index + 5, buffer[index + 5] == 0x01 {
                isTLS = true
            }
        }

        if remainingServerHello > 0 {
            var end = remainingServerHello
            let start = max(index, 0)
            if start + end > length {
                end = length
                remainingServerHello -= (end - start)
            } else {
                remainingServerHello -= end
                end += start
            }
            if start <= end, end <= length,
               SwiftCoreVision.firstIndex(of: Self.tls13SupportedVersions, in: Array(buffer[start..<end])) != nil {
                // TLS 1.3 confirmed; enable the direct splice (CCM_8 excepted, which we don't negotiate).
                if cipher == 0x1301 || cipher == 0x1302 || cipher == 0x1303 || cipher == 0x1304 {
                    enableXTLS = true
                }
                packetsToFilter = 0
            } else if remainingServerHello <= 0 {
                packetsToFilter = 0
            }
        }
    }
}

/// NIO handler implementing XTLS-Vision over the VLESS stream. Sits above the VLESS handler.
final class SwiftCoreVisionHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum ReadPhase {
        case header        // expecting a padding header
        case content(Int)  // reading this many content bytes
        case padding(Int)  // discarding this many padding bytes
        case passthrough   // un-padding finished; forward everything raw
    }

    private let userUUID: [UInt8]
    private let directState: SwiftCoreVisionDirectState
    private let state = SwiftCoreVisionState()

    // Write side
    private var writeFiltering = true
    private var writeOnceUUID: [UInt8]?

    // Read side
    private var readBuffer: [UInt8] = []
    private var readPhase: ReadPhase = .header
    private var readFilterUUID = true
    private var currentCommand: UInt8 = SwiftCoreVisionCommand.paddingContinue

    init(userUUID: [UInt8], directState: SwiftCoreVisionDirectState) {
        self.userUUID = userUUID
        self.directState = directState
        self.writeOnceUUID = userUUID
    }

    // MARK: Outbound (padding)

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var buffer = Self.unwrapOutboundIn(data)
        guard writeFiltering else {
            context.write(data, promise: promise)
            return
        }
        guard let content = buffer.readBytes(length: buffer.readableBytes) else {
            promise?.succeed(())
            return
        }

        state.filter(content)
        var command = SwiftCoreVisionCommand.paddingContinue
        let isApplicationData = state.isTLS && content.count > 6
            && Array(content[0..<3]) == [0x17, 0x03, 0x03]
        if isApplicationData {
            command = SwiftCoreVisionCommand.paddingEnd // upload stays inside the outer TLS (asymmetric splice)
            writeFiltering = false
        } else if !state.isTLS12orAbove && state.packetsToFilter <= 1 {
            command = SwiftCoreVisionCommand.paddingEnd
            writeFiltering = false
        }

        let padded = SwiftCoreVision.applyPadding(content: content, command: command, uuid: writeOnceUUID, paddingTLS: state.isTLS)
        writeOnceUUID = nil
        var out = context.channel.allocator.buffer(capacity: padded.count)
        out.writeBytes(padded)
        context.write(Self.wrapOutboundOut(out), promise: promise)
    }

    // MARK: Inbound (un-padding + direct splice)

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .passthrough = readPhase {
            context.fireChannelRead(data)
            return
        }
        var incoming = Self.unwrapInboundIn(data)
        if let bytes = incoming.readBytes(length: incoming.readableBytes) {
            readBuffer.append(contentsOf: bytes)
        }
        process(context: context)
    }

    private func process(context: ChannelHandlerContext) {
        loop: while true {
            switch readPhase {
            case .passthrough:
                if !readBuffer.isEmpty {
                    let bytes = readBuffer
                    readBuffer.removeAll()
                    fireUp(bytes, context: context)
                }
                return
            case .header:
                let headerLength = readFilterUUID ? SwiftCoreVision.paddingHeaderLen : 5
                guard readBuffer.count >= headerLength else { return }
                var header = Array(readBuffer[0..<headerLength])
                readBuffer.removeFirst(headerLength)
                if readFilterUUID {
                    readFilterUUID = false
                    header = Array(header[SwiftCoreVision.uuidSize...]) // strip echoed UUID
                }
                currentCommand = header[0]
                let contentLength = Int(header[1]) << 8 | Int(header[2])
                let paddingLength = Int(header[3]) << 8 | Int(header[4])
                if currentCommand == SwiftCoreVisionCommand.paddingDirect {
                    directState.readDirect = true
                }
                readPhase = contentLength > 0 ? .content(contentLength) : .padding(paddingLength)
                pendingPadding = paddingLength
            case .content(let needed):
                guard readBuffer.count >= needed else { return }
                let content = Array(readBuffer[0..<needed])
                readBuffer.removeFirst(needed)
                fireUp(content, context: context)
                readPhase = .padding(pendingPadding)
            case .padding(let needed):
                guard readBuffer.count >= needed else { return }
                readBuffer.removeFirst(needed)
                if currentCommand == SwiftCoreVisionCommand.paddingEnd
                    || currentCommand == SwiftCoreVisionCommand.paddingDirect {
                    readPhase = .passthrough
                    continue loop
                }
                readPhase = .header
            }
        }
    }

    private var pendingPadding = 0

    private func fireUp(_ bytes: [UInt8], context: ChannelHandlerContext) {
        guard !bytes.isEmpty else { return }
        var out = context.channel.allocator.buffer(capacity: bytes.count)
        out.writeBytes(bytes)
        context.fireChannelRead(Self.wrapInboundOut(out))
    }
}
