import Foundation
import NIOCore
import NIOPosix

/// Matches a host against `fake-ip-filter` patterns (`+.x`, `*.x`, `.x`, or an exact name). Filtered
/// domains are resolved for real instead of getting a fake ip.
struct SwiftCoreFakeIPFilter {
    private let full: Set<String>
    private let suffix: Set<String>

    init(patterns: [String]) {
        var full: Set<String> = []
        var suffix: Set<String> = []
        for pattern in patterns {
            let lower = pattern.lowercased()
            if lower.hasPrefix("+.") || lower.hasPrefix("*.") {
                suffix.insert(String(lower.dropFirst(2)))
            } else if lower.hasPrefix(".") {
                suffix.insert(String(lower.dropFirst()))
            } else {
                full.insert(lower)
            }
        }
        self.full = full
        self.suffix = suffix
    }

    func matches(_ host: String) -> Bool {
        let host = host.lowercased()
        if full.contains(host) || suffix.contains(host) { return true }
        var rest = host
        while let dot = rest.firstIndex(of: ".") {
            rest = String(rest[rest.index(after: dot)...])
            if suffix.contains(rest) { return true }
        }
        return false
    }
}

/// A minimal UDP DNS server for fake-ip mode: A queries for non-filtered domains get a fake ip from
/// the pool (recording the domain↔ip mapping); filtered domains are resolved for real; everything
/// else (AAAA, other types) gets an empty answer.
public final class SwiftCoreDNSServer: @unchecked Sendable {
    private let state: SwiftCoreState
    private let responder: SwiftCoreDNSResponder
    private let group: EventLoopGroup
    private var channel: Channel?

    init(state: SwiftCoreState, responder: SwiftCoreDNSResponder, group: EventLoopGroup) {
        self.state = state
        self.responder = responder
        self.group = group
    }

    @discardableResult
    public func start(host: String, port: Int) throws -> Channel {
        let handler = SwiftCoreDNSServerHandler(responder: responder)
        let server = try DatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandler(handler)
            }
            .bind(host: host, port: port)
            .wait()
        channel = server
        state.appendLog(level: "info", message: "DNS server (fake-ip) listening on \(host):\(port)")
        return server
    }

    public func stop() {
        try? channel?.close().wait()
        channel = nil
    }
}

final class SwiftCoreDNSServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private let responder: SwiftCoreDNSResponder

    init(responder: SwiftCoreDNSResponder) {
        self.responder = responder
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var envelope = Self.unwrapInboundIn(data)
        let remote = envelope.remoteAddress
        guard let query = envelope.data.readBytes(length: envelope.data.readableBytes) else {
            return
        }
        let channel = context.channel
        Task { [responder] in
            let response = await responder.answer(query: query)
            channel.eventLoop.execute {
                var buffer = channel.allocator.buffer(capacity: response.count)
                buffer.writeBytes(response)
                channel.writeAndFlush(Self.wrapOutboundOut(AddressedEnvelope(remoteAddress: remote, data: buffer)), promise: nil)
            }
        }
    }
}
