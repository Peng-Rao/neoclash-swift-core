import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOWebSocket

public final class SwiftCoreControllerServer: @unchecked Sendable {
    private let state: SwiftCoreState
    private let group: EventLoopGroup
    private var channel: Channel?

    public init(state: SwiftCoreState, group: EventLoopGroup) {
        self.state = state
        self.group = group
    }

    public func start() throws -> Channel {
        let httpHandlerName = "SwiftCoreHTTPControllerHandler"

        let server = try ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [state] channel in
                let upgrader = NIOWebSocketServerUpgrader(
                    shouldUpgrade: { channel, head in
                        let headers = head.headers.swiftCoreDictionary
                        let path = head.uri.swiftCorePath
                        guard ["/traffic", "/logs", "/connections"].contains(path),
                              state.isAuthorized(headers: headers) else {
                            return channel.eventLoop.makeSucceededFuture(nil)
                        }
                        return channel.eventLoop.makeSucceededFuture(HTTPHeaders())
                    },
                    upgradePipelineHandler: { channel, head in
                        channel.pipeline.addHandler(SwiftCoreWebSocketHandler(path: head.uri.swiftCorePath, state: state))
                    }
                )
                let upgradeConfiguration = NIOHTTPServerUpgradeConfiguration(
                    upgraders: [upgrader],
                    completionHandler: { context in
                        context.pipeline.removeHandler(name: httpHandlerName, promise: nil)
                    }
                )
                return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgradeConfiguration).flatMap {
                    channel.pipeline.addHandler(SwiftCoreHTTPControllerHandler(state: state), name: httpHandlerName)
                }
            }
            .bind(host: state.controllerHost, port: state.controllerPort)
            .wait()
        channel = server
        state.appendLog(level: "info", message: "Controller listening on \(state.controllerHost):\(state.controllerPort)")
        return server
    }
}

final class SwiftCoreHTTPControllerHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let state: SwiftCoreState
    private var head: HTTPRequestHead?
    private var body = ByteBuffer()

    init(state: SwiftCoreState) {
        self.state = state
    }

    func handlerAdded(context: ChannelHandlerContext) {
        body = context.channel.allocator.buffer(capacity: 0)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch Self.unwrapInboundIn(data) {
        case .head(let head):
            self.head = head
            body.clear()
        case .body(var chunk):
            body.writeBuffer(&chunk)
        case .end:
            handleRequest(context: context)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        state.appendLog(level: "warning", message: "Controller error: \(error.localizedDescription)")
        context.close(promise: nil)
    }

    private func handleRequest(context: ChannelHandlerContext) {
        guard let head else {
            send(status: .badRequest, object: ["error": "missing request"], context: context)
            return
        }

        let headers = head.headers.swiftCoreDictionary
        guard state.isAuthorized(headers: headers) else {
            send(status: .unauthorized, object: ["error": "unauthorized"], context: context)
            return
        }

        let path = head.uri.swiftCorePath
        let method = head.method

        do {
            switch (method, path) {
            case (.GET, "/version"):
                send(status: .ok, object: ["version": "neoclash-swift-core 0.1.0"], context: context)
            case (.GET, "/configs"):
                send(status: .ok, object: state.configsObject(), context: context)
            case (.PATCH, "/configs"):
                let object = try bodyJSON()
                if let mode = object["mode"] as? String {
                    state.updateMode(mode)
                }
                send(status: .noContent, body: Data(), context: context)
            case (.PUT, "/configs"):
                if let path = body.getString(at: body.readerIndex, length: body.readableBytes), !path.isEmpty {
                    let configuration = try SwiftCoreConfiguration.load(from: path)
                    state.replaceConfiguration(configuration)
                }
                send(status: .noContent, body: Data(), context: context)
            case (.GET, "/proxies"):
                send(status: .ok, object: state.proxiesObject(), context: context)
            case (.GET, let delayPath) where delayPath.hasPrefix("/proxies/") && delayPath.hasSuffix("/delay"):
                let name = delayPath
                    .dropFirst("/proxies/".count)
                    .dropLast("/delay".count)
                    .removingPercentEncoding ?? ""
                if name.uppercased() == "DIRECT" || name.uppercased() == "REJECT" {
                    send(status: .ok, object: ["delay": 0], context: context)
                } else {
                    send(status: .badGateway, object: ["error": "delay test is not implemented for \(name)"], context: context)
                }
            case (.PUT, let groupPath) where groupPath.hasPrefix("/proxies/"):
                let group = String(groupPath.dropFirst("/proxies/".count)).removingPercentEncoding ?? ""
                let object = try bodyJSON()
                guard let proxy = object["name"] as? String, state.selectProxy(group: group, proxy: proxy) else {
                    send(status: .notFound, object: ["error": "proxy group or node not found"], context: context)
                    return
                }
                send(status: .noContent, body: Data(), context: context)
            case (.GET, "/rules"):
                send(status: .ok, object: state.rulesObject(), context: context)
            case (.GET, "/connections"):
                send(status: .ok, object: state.connectionsObject(), context: context)
            case (.DELETE, "/connections"):
                state.clearConnections()
                send(status: .noContent, body: Data(), context: context)
            case (.DELETE, let connectionPath) where connectionPath.hasPrefix("/connections/"):
                state.removeConnection(id: String(connectionPath.dropFirst("/connections/".count)))
                send(status: .noContent, body: Data(), context: context)
            default:
                send(status: .notFound, object: ["error": "not found"], context: context)
            }
        } catch {
            send(status: .badRequest, object: ["error": error.localizedDescription], context: context)
        }
    }

    private func bodyJSON() throws -> [String: Any] {
        let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) ?? []
        let data = Data(bytes)
        if data.isEmpty {
            return [:]
        }
        return (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }

    private func send(status: HTTPResponseStatus, object: Any, context: ChannelHandlerContext) {
        do {
            try send(status: status, body: SwiftCoreJSON.data(object), context: context)
        } catch {
            send(status: .internalServerError, body: Data(#"{"error":"encoding failed"}"#.utf8), context: context)
        }
    }

    private func send(status: HTTPResponseStatus, body data: Data, context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Length", value: "\(data.count)")
        if !data.isEmpty {
            headers.add(name: "Content-Type", value: "application/json")
        }
        headers.add(name: "Connection", value: "close")
        let responseHead = HTTPResponseHead(version: head?.version ?? .http1_1, status: status, headers: headers)
        context.write(Self.wrapOutboundOut(.head(responseHead)), promise: nil)
        if !data.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: data.count)
            buffer.writeBytes(data)
            context.write(Self.wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        let channel = context.channel
        context.writeAndFlush(Self.wrapOutboundOut(.end(nil))).whenComplete { _ in
            channel.close(promise: nil)
        }
    }
}

final class SwiftCoreWebSocketHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame

    private let path: String
    private let state: SwiftCoreState
    private var repeatedTask: RepeatedTask?

    init(path: String, state: SwiftCoreState) {
        self.path = path
        self.state = state
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let channel = context.channel
        sendSnapshot(channel: channel)
        repeatedTask = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(1), delay: .seconds(1)) { [weak self] _ in
            guard let self else { return }
            self.sendSnapshot(channel: channel)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let frame = Self.unwrapInboundIn(data)
        switch frame.opcode {
        case .ping:
            context.writeAndFlush(Self.wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)), promise: nil)
        case .connectionClose:
            context.writeAndFlush(Self.wrapOutboundOut(frame), promise: nil)
            context.close(promise: nil)
        default:
            break
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        repeatedTask?.cancel()
        repeatedTask = nil
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        repeatedTask?.cancel()
        state.appendLog(level: "warning", message: "WebSocket error: \(error.localizedDescription)")
        context.close(promise: nil)
    }

    private func sendSnapshot(channel: Channel) {
        let object: Any
        switch path {
        case "/traffic":
            object = state.trafficObjectAndReset()
        case "/logs":
            object = state.nextLogObject()
        case "/connections":
            object = state.connectionsObject()
        default:
            object = ["type": "warning", "payload": "unknown stream"]
        }
        let buffer = channel.allocator.buffer(string: SwiftCoreJSON.string(object))
        channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .text, data: buffer), promise: nil)
    }
}

extension String {
    var swiftCorePath: String {
        if let question = firstIndex(of: "?") {
            return String(self[..<question])
        }
        return self
    }
}

private extension HTTPHeaders {
    var swiftCoreDictionary: [String: String] {
        var result: [String: String] = [:]
        for header in self {
            result[header.name] = header.value
        }
        return result
    }
}
