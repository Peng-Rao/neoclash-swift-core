import Foundation
import NIOCore
import NIOPosix

public final class SwiftCoreMixedProxyServer: @unchecked Sendable {
    private let state: SwiftCoreState
    private let group: EventLoopGroup
    private var channel: Channel?

    public init(state: SwiftCoreState, group: EventLoopGroup) {
        self.state = state
        self.group = group
    }

    public func start() throws -> Channel {
        let server = try ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [state, group] channel in
                channel.pipeline.addHandler(SwiftCoreMixedProxyHandler(state: state, group: group))
            }
            .bind(host: state.mixedBindHost, port: state.mixedPort)
            .wait()
        channel = server
        state.appendLog(level: "info", message: "Mixed proxy listening on \(state.mixedBindHost):\(state.mixedPort)")
        return server
    }
}

struct SwiftCoreProxyTarget: Equatable, Sendable {
    var host: String
    var port: Int
}

final class SwiftCoreMixedProxyHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum Mode {
        case sniffing
        case socksGreeting
        case socksRequest
        case connecting
        case tunneled
        case closed
    }

    private let state: SwiftCoreState
    private let group: EventLoopGroup
    private var mode: Mode = .sniffing
    private var readBuffer: ByteBuffer?
    private var upstream: Channel?
    private var connectionID: String?
    private let connectionIDRef = SwiftCoreConnectionIDRef()

    init(state: SwiftCoreState, group: EventLoopGroup) {
        self.state = state
        self.group = group
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var inbound = Self.unwrapInboundIn(data)
        if case .tunneled = mode {
            let bytes = inbound.readableBytes
            state.recordUpload(id: connectionID, bytes: bytes)
            upstream?.writeAndFlush(inbound, promise: nil)
            return
        }

        append(&inbound, context: context)
        processBuffered(context: context)
    }

    func channelInactive(context: ChannelHandlerContext) {
        upstream?.close(promise: nil)
        state.removeConnection(id: connectionID)
    }

    /// Backpressure, download direction: this (client) channel's send buffer holds data relayed
    /// from the upstream, and fills when the upstream outpaces a slow client — pause upstream
    /// reads until it drains, otherwise the pending writes grow without bound.
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if let upstream {
            let writable = context.channel.isWritable
            upstream.eventLoop.execute {
                _ = upstream.setOption(ChannelOptions.autoRead, value: writable)
            }
        }
        context.fireChannelWritabilityChanged()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if SwiftCoreErrorText.isRoutineDisconnect(error) {
            state.appendLog(level: "debug", message: "Client connection closed: \(SwiftCoreErrorText.describe(error))")
        } else {
            state.appendLog(level: "warning", message: "Mixed proxy error: \(SwiftCoreErrorText.describe(error))")
        }
        close(context: context)
    }

    private func append(_ inbound: inout ByteBuffer, context: ChannelHandlerContext) {
        if readBuffer == nil {
            readBuffer = context.channel.allocator.buffer(capacity: inbound.readableBytes)
        }
        readBuffer?.writeBuffer(&inbound)
    }

    private func processBuffered(context: ChannelHandlerContext) {
        guard var buffer = readBuffer else {
            return
        }

        switch mode {
        case .sniffing:
            guard let firstByte = buffer.getInteger(at: buffer.readerIndex, as: UInt8.self) else {
                return
            }
            if firstByte == 0x05 {
                mode = .socksGreeting
                readBuffer = buffer
                processBuffered(context: context)
            } else {
                handleHTTP(context: context, buffer: buffer)
            }
        case .socksGreeting:
            guard buffer.readableBytes >= 2,
                  let version = buffer.getInteger(at: buffer.readerIndex, as: UInt8.self),
                  let methodsCount = buffer.getInteger(at: buffer.readerIndex + 1, as: UInt8.self) else {
                return
            }
            guard version == 0x05 else {
                close(context: context)
                return
            }
            let greetingLength = 2 + Int(methodsCount)
            guard buffer.readableBytes >= greetingLength else {
                return
            }
            buffer.moveReaderIndex(forwardBy: greetingLength)
            var response = context.channel.allocator.buffer(capacity: 2)
            response.writeBytes([0x05, 0x00])
            context.writeAndFlush(Self.wrapOutboundOut(response), promise: nil)
            mode = .socksRequest
            readBuffer = buffer
            if buffer.readableBytes > 0 {
                processBuffered(context: context)
            }
        case .socksRequest:
            guard let request = parseSocksRequest(buffer: &buffer) else {
                readBuffer = buffer
                return
            }
            readBuffer = buffer
            startTunnel(
                context: context,
                target: request,
                protocolName: "SOCKS5",
                initialUpstreamBytes: nil,
                clientSuccessBytes: socksReply(status: 0x00, allocator: context.channel.allocator),
                clientFailureBytes: socksReply(status: 0x01, allocator: context.channel.allocator)
            )
        case .connecting, .tunneled, .closed:
            readBuffer = buffer
        }
    }

    private func handleHTTP(context: ChannelHandlerContext, buffer: ByteBuffer) {
        guard let text = buffer.getString(at: buffer.readerIndex, length: buffer.readableBytes),
              let headerRange = text.range(of: "\r\n\r\n") else {
            readBuffer = buffer
            return
        }

        let headerText = String(text[..<headerRange.upperBound])
        let headerByteCount = headerText.utf8.count
        var remaining = buffer
        remaining.moveReaderIndex(forwardBy: headerByteCount)

        guard let request = HTTPProxyRequest(headerText: headerText, allocator: context.channel.allocator) else {
            sendHTTPError(status: "400 Bad Request", message: "Invalid proxy request", context: context)
            return
        }

        var initial = request.upstreamBytes
        if remaining.readableBytes > 0 {
            initial.writeBuffer(&remaining)
        }
        startTunnel(
            context: context,
            target: request.target,
            protocolName: request.isConnect ? "CONNECT" : "HTTP",
            initialUpstreamBytes: request.isConnect ? nil : initial,
            clientSuccessBytes: request.isConnect ? httpConnectSuccess(allocator: context.channel.allocator) : nil,
            clientFailureBytes: httpFailure(status: "502 Bad Gateway", message: "Swift core cannot proxy this route yet.", allocator: context.channel.allocator)
        )
    }

    private func startTunnel(
        context: ChannelHandlerContext,
        target: SwiftCoreProxyTarget,
        protocolName: String,
        initialUpstreamBytes: ByteBuffer?,
        clientSuccessBytes: ByteBuffer?,
        clientFailureBytes: ByteBuffer?
    ) {
        let routeContext = SwiftCoreRouteContext(
            host: target.host,
            destinationPort: target.port,
            sourcePort: context.channel.remoteAddress?.port
        )
        let decision = state.route(context: routeContext)
        let chain: [String]
        let outbound: SwiftCoreOutbound
        switch decision {
        case .outbound(let routeChain, let adapter):
            chain = routeChain
            outbound = adapter
        case .reject:
            state.appendLog(level: "info", message: "Rejected \(protocolName) connection to \(target.host):\(target.port)")
            if let failure = clientFailureBytes {
                context.writeAndFlush(Self.wrapOutboundOut(failure), promise: nil)
            }
            close(context: context)
            return
        case .unsupported(_, let proxy):
            state.appendLog(level: "warning", message: "Proxy \(proxy) is not implemented by Swift core v1")
            if let failure = clientFailureBytes {
                context.writeAndFlush(Self.wrapOutboundOut(failure), promise: nil)
            }
            close(context: context)
            return
        }

        mode = .connecting
        let clientChannel = context.channel
        let clientEventLoop = context.eventLoop
        clientChannel.setOption(ChannelOptions.autoRead, value: false).whenComplete { _ in }

        let request = SwiftCoreOutboundRequest(host: target.host, port: target.port)
        outbound.connect(request: request, group: group) { [state, connectionIDRef, clientChannel] in
            SwiftCoreUpstreamHandler(
                client: clientChannel,
                state: state,
                connectionIDRef: connectionIDRef
            )
        }
        .whenComplete { [weak self] result in
            guard let self else { return }
            clientEventLoop.execute {
                switch result {
                case .success(let upstream):
                    self.upstream = upstream
                    let id = self.state.addConnection(
                        host: "\(target.host):\(target.port)",
                        rule: outbound.name,
                        chain: chain
                    )
                    self.connectionID = id
                    self.connectionIDRef.value = id
                    self.mode = .tunneled
                    if let success = clientSuccessBytes {
                        clientChannel.writeAndFlush(success, promise: nil)
                    }
                    if let initial = initialUpstreamBytes {
                        let bytes = initial.readableBytes
                        self.state.recordUpload(id: self.connectionID, bytes: bytes)
                        upstream.writeAndFlush(initial, promise: nil)
                    }
                    clientChannel.setOption(ChannelOptions.autoRead, value: true).whenComplete { _ in }
                case .failure(let error):
                    self.state.appendLog(level: "warning", message: "Failed to connect \(target.host):\(target.port) via \(outbound.name): \(SwiftCoreErrorText.describe(error))")
                    if let failure = clientFailureBytes {
                        clientChannel.writeAndFlush(failure, promise: nil)
                    }
                    self.mode = .closed
                    clientChannel.close(promise: nil)
                }
            }
        }
    }

    private func parseSocksRequest(buffer: inout ByteBuffer) -> SwiftCoreProxyTarget? {
        let start = buffer.readerIndex
        guard buffer.readableBytes >= 4,
              buffer.getInteger(at: start, as: UInt8.self) == 0x05,
              buffer.getInteger(at: start + 1, as: UInt8.self) == 0x01,
              let addressType = buffer.getInteger(at: start + 3, as: UInt8.self) else {
            return nil
        }

        var cursor = start + 4
        let host: String
        switch addressType {
        case 0x01:
            guard buffer.readableBytes >= 10 else { return nil }
            let octets: [UInt8] = (0..<4).compactMap { buffer.getInteger(at: cursor + $0, as: UInt8.self) }
            guard octets.count == 4 else { return nil }
            host = octets.map(String.init).joined(separator: ".")
            cursor += 4
        case 0x03:
            guard let length = buffer.getInteger(at: cursor, as: UInt8.self) else { return nil }
            cursor += 1
            guard buffer.readableBytes >= 4 + 1 + Int(length) + 2,
                  let domain = buffer.getString(at: cursor, length: Int(length)) else {
                return nil
            }
            host = domain
            cursor += Int(length)
        case 0x04:
            guard buffer.readableBytes >= 22 else { return nil }
            var groups: [String] = []
            for offset in stride(from: 0, to: 16, by: 2) {
                guard let part = buffer.getInteger(at: cursor + offset, as: UInt16.self) else {
                    return nil
                }
                groups.append(String(part, radix: 16))
            }
            host = groups.joined(separator: ":")
            cursor += 16
        default:
            return nil
        }

        guard let port = buffer.getInteger(at: cursor, as: UInt16.self) else {
            return nil
        }
        cursor += 2
        buffer.moveReaderIndex(forwardBy: cursor - start)
        return SwiftCoreProxyTarget(host: host, port: Int(port))
    }

    private func sendHTTPError(status: String, message: String, context: ChannelHandlerContext) {
        let response = httpFailure(status: status, message: message, allocator: context.channel.allocator)
        let channel = context.channel
        context.writeAndFlush(Self.wrapOutboundOut(response)).whenComplete { _ in
            channel.close(promise: nil)
        }
    }

    private func close(context: ChannelHandlerContext) {
        mode = .closed
        upstream?.close(promise: nil)
        state.removeConnection(id: connectionID)
        connectionIDRef.value = nil
        context.close(promise: nil)
    }

    private func socksReply(status: UInt8, allocator: ByteBufferAllocator) -> ByteBuffer {
        var buffer = allocator.buffer(capacity: 10)
        buffer.writeBytes([0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        return buffer
    }

    private func httpConnectSuccess(allocator: ByteBufferAllocator) -> ByteBuffer {
        allocator.buffer(string: "HTTP/1.1 200 Connection Established\r\n\r\n")
    }

    private func httpFailure(status: String, message: String, allocator: ByteBufferAllocator) -> ByteBuffer {
        let body = Data(message.utf8)
        return allocator.buffer(string: "HTTP/1.1 \(status)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n\(message)")
    }
}

final class SwiftCoreUpstreamHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private weak var client: Channel?
    private let state: SwiftCoreState
    private let connectionIDRef: SwiftCoreConnectionIDRef

    init(client: Channel, state: SwiftCoreState, connectionIDRef: SwiftCoreConnectionIDRef) {
        self.client = client
        self.state = state
        self.connectionIDRef = connectionIDRef
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = Self.unwrapInboundIn(data)
        let bytes = buffer.readableBytes
        state.recordDownload(id: connectionIDRef.value, bytes: bytes)
        guard let client else {
            context.close(promise: nil)
            return
        }
        client.eventLoop.execute {
            client.writeAndFlush(buffer, promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let client {
            client.eventLoop.execute {
                client.close(mode: .output, promise: nil)
            }
        }
        state.removeConnection(id: connectionIDRef.value)
    }

    /// Backpressure, upload direction: this (upstream) channel's send buffer holds data relayed
    /// from the client, and fills when the client outpaces a slow upstream — pause client reads
    /// until it drains.
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if let client {
            let writable = context.channel.isWritable
            client.eventLoop.execute {
                _ = client.setOption(ChannelOptions.autoRead, value: writable)
            }
        }
        context.fireChannelWritabilityChanged()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if let client {
            client.eventLoop.execute {
                client.close(promise: nil)
            }
        }
        context.close(promise: nil)
    }
}

final class SwiftCoreConnectionIDRef: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: String?

    var value: String? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }
        set {
            lock.lock()
            storage = newValue
            lock.unlock()
        }
    }
}

private struct HTTPProxyRequest {
    var target: SwiftCoreProxyTarget
    var isConnect: Bool
    var upstreamBytes: ByteBuffer

    init?(headerText: String, allocator: ByteBufferAllocator) {
        let lines = headerText
            .split(separator: "\r\n", omittingEmptySubsequences: false)
            .map(String.init)
        guard let requestLine = lines.first else {
            return nil
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            return nil
        }
        let method = parts[0].uppercased()
        let targetText = parts[1]
        let version = parts[2]
        let headers = Self.parseHeaders(Array(lines.dropFirst()))

        if method == "CONNECT" {
            guard let target = Self.parseHostPort(targetText, defaultPort: 443) else {
                return nil
            }
            self.target = target
            self.isConnect = true
            self.upstreamBytes = allocator.buffer(capacity: 0)
            return
        }

        let parsed = Self.parseHTTPForwardTarget(targetText, headers: headers)
        guard let target = parsed.target else {
            return nil
        }
        self.target = target
        self.isConnect = false

        var rewritten = "\(method) \(parsed.path) \(version)\r\n"
        for line in lines.dropFirst() where !line.isEmpty {
            let lower = line.lowercased()
            if lower.hasPrefix("proxy-connection:") {
                continue
            }
            rewritten += line + "\r\n"
        }
        rewritten += "\r\n"
        self.upstreamBytes = allocator.buffer(string: rewritten)
    }

    private static func parseHeaders(_ lines: [String]) -> [String: String] {
        var headers: [String: String] = [:]
        for line in lines {
            guard let separator = line.firstIndex(of: ":") else {
                continue
            }
            let name = String(line[..<separator]).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            headers[name] = value
        }
        return headers
    }

    private static func parseHTTPForwardTarget(_ rawTarget: String, headers: [String: String]) -> (target: SwiftCoreProxyTarget?, path: String) {
        if let url = URL(string: rawTarget), let host = url.host {
            let port = url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)
            var path = url.path.isEmpty ? "/" : url.path
            if let query = url.query {
                path += "?" + query
            }
            return (SwiftCoreProxyTarget(host: host, port: port), path)
        }

        guard let hostHeader = headers["host"],
              let target = parseHostPort(hostHeader, defaultPort: 80) else {
            return (nil, rawTarget)
        }
        return (target, rawTarget.isEmpty ? "/" : rawTarget)
    }

    private static func parseHostPort(_ value: String, defaultPort: Int) -> SwiftCoreProxyTarget? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("[") {
            guard let end = trimmed.firstIndex(of: "]") else {
                return nil
            }
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<end])
            let remainder = trimmed[trimmed.index(after: end)...]
            let port = remainder.hasPrefix(":") ? Int(remainder.dropFirst()) ?? defaultPort : defaultPort
            return SwiftCoreProxyTarget(host: host, port: port)
        }
        if let separator = trimmed.lastIndex(of: ":"),
           trimmed[..<separator].contains(":") == false,
           let port = Int(trimmed[trimmed.index(after: separator)...]) {
            return SwiftCoreProxyTarget(host: String(trimmed[..<separator]), port: port)
        }
        return SwiftCoreProxyTarget(host: trimmed, port: defaultPort)
    }
}
