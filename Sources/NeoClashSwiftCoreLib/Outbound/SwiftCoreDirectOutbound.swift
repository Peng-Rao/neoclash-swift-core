import NIOCore
import NIOPosix

/// Connects straight to the target with no intermediary. Used for the built-in `DIRECT` outbound
/// and for config proxies declared with `type: direct`.
final class SwiftCoreDirectOutbound: SwiftCoreOutbound, @unchecked Sendable {
    let name: String

    init(name: String = "DIRECT") {
        self.name = name
    }

    func connect(
        request: SwiftCoreOutboundRequest,
        group: EventLoopGroup,
        makeTailHandler: @escaping @Sendable () -> ChannelHandler
    ) -> EventLoopFuture<Channel> {
        ClientBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandler(makeTailHandler())
            }
            .connect(host: request.host, port: request.port)
    }
}
