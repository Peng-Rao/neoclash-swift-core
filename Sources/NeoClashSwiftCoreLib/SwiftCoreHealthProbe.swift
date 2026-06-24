import Foundation
import NIOCore

/// Measures a proxy's latency by tunneling an HTTP request through its outbound adapter and timing
/// the round-trip to the first response byte. Used by the `/proxies/{name}/delay` endpoint and the
/// periodic health monitor that drives `url-test`/`fallback` group selection.
enum SwiftCoreHealthProbe {
    static let defaultTestURL = "http://www.gstatic.com/generate_204"

    struct Target {
        let host: String
        let port: Int
        let path: String
    }

    static func parse(url: String) -> Target? {
        guard let parsed = URL(string: url), let host = parsed.host else { return nil }
        let port = parsed.port ?? (parsed.scheme?.lowercased() == "https" ? 443 : 80)
        var path = parsed.path.isEmpty ? "/" : parsed.path
        if let query = parsed.query { path += "?" + query }
        return Target(host: host, port: port, path: path)
    }

    static func measure(
        outbound: SwiftCoreOutbound,
        on eventLoop: EventLoop,
        url: String = defaultTestURL,
        timeoutMilliseconds: Int = 5000
    ) -> EventLoopFuture<Int> {
        guard let target = parse(url: url) else {
            return eventLoop.makeFailedFuture(SwiftCoreError.invalidConfig("invalid delay test URL: \(url)"))
        }
        let promise = eventLoop.makePromise(of: Int.self)
        let completion = SwiftCoreProbeCompletion(promise: promise)
        let startedAt = NIODeadline.now()
        let request = "GET \(target.path) HTTP/1.1\r\nHost: \(target.host)\r\nUser-Agent: neoclash-swift-core\r\nAccept: */*\r\nConnection: close\r\n\r\n"

        let timeout = eventLoop.scheduleTask(in: .milliseconds(Int64(timeoutMilliseconds))) {
            completion.fail(SwiftCoreError.invalidConfig("delay test timed out"))
        }
        promise.futureResult.whenComplete { _ in timeout.cancel() }

        outbound.connect(
            request: SwiftCoreOutboundRequest(host: target.host, port: target.port),
            group: eventLoop
        ) {
            SwiftCoreHealthProbeHandler(completion: completion, request: request, startedAt: startedAt)
        }.whenComplete { result in
            if case .failure(let error) = result {
                completion.fail(error)
            }
        }
        return promise.futureResult
    }
}

/// Guards a probe promise so the handler and the timeout can race without double-completing it.
/// All callers run on the same event loop, so a plain flag is sufficient.
final class SwiftCoreProbeCompletion: @unchecked Sendable {
    private let promise: EventLoopPromise<Int>
    private var done = false

    init(promise: EventLoopPromise<Int>) {
        self.promise = promise
    }

    func succeed(_ milliseconds: Int) {
        guard !done else { return }
        done = true
        promise.succeed(milliseconds)
    }

    func fail(_ error: Error) {
        guard !done else { return }
        done = true
        promise.fail(error)
    }
}

final class SwiftCoreHealthProbeHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let completion: SwiftCoreProbeCompletion
    private let request: String
    private let startedAt: NIODeadline

    init(completion: SwiftCoreProbeCompletion, request: String, startedAt: NIODeadline) {
        self.completion = completion
        self.request = request
        self.startedAt = startedAt
    }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: request.utf8.count)
        buffer.writeString(request)
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let elapsed = NIODeadline.now() - startedAt
        completion.succeed(max(0, Int(elapsed.nanoseconds / 1_000_000)))
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        completion.fail(SwiftCoreError.invalidConfig("connection closed before a response"))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        completion.fail(error)
        context.close(promise: nil)
    }
}
