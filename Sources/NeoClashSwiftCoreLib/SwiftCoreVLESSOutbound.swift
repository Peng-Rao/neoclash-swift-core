import NIOCore
import NIOPosix

/// VLESS outbound over TCP, with an optional security layer: none, standard TLS (NIOSSL), or
/// REALITY (our from-scratch TLS 1.3 client). VLESS itself has no transport encryption.
final class SwiftCoreVLESSOutbound: SwiftCoreOutbound, @unchecked Sendable {
    /// The security layer wrapped around the VLESS stream.
    enum Security: Sendable {
        case none
        case standardTLS(SwiftCoreTLSTransport)
        case reality(publicKey: String, shortId: String, serverName: String?, alpn: [String])
    }

    let name: String
    private let server: String
    private let port: Int
    private let uuid: [UInt8]
    private let security: Security
    private let flow: String?
    private let visionEnabled: Bool

    init(proxy: SwiftCoreProxy) throws {
        guard let server = proxy.server, !server.isEmpty else {
            throw SwiftCoreError.invalidConfig("vless proxy \(proxy.name) requires a server.")
        }
        guard let port = proxy.port, (1...65_535).contains(port) else {
            throw SwiftCoreError.invalidConfig("vless proxy \(proxy.name) requires a valid port.")
        }
        guard let uuidString = proxy.uuid else {
            throw SwiftCoreError.invalidConfig("vless proxy \(proxy.name) requires a uuid.")
        }
        let network = (proxy.network ?? "tcp").lowercased()
        guard network == "tcp" else {
            throw SwiftCoreError.invalidConfig("vless proxy \(proxy.name) network '\(network)' is not supported (tcp only).")
        }
        self.name = proxy.name
        self.server = server
        self.port = port
        self.uuid = try SwiftCoreProxyEncoding.parseUUID(uuidString)

        if let realityPublicKey = proxy.realityPublicKey {
            guard SwiftCoreRealityCrypto.base64URLDecode(realityPublicKey)?.count == 32 else {
                throw SwiftCoreError.invalidConfig("vless proxy \(proxy.name) reality public-key must decode to 32 bytes.")
            }
            self.security = .reality(
                publicKey: realityPublicKey,
                shortId: proxy.realityShortId ?? "",
                serverName: proxy.servername ?? server,
                alpn: proxy.alpn ?? []
            )
        } else if proxy.tls {
            self.security = .standardTLS(try SwiftCoreTLSTransport(options: SwiftCoreTLSOptions(
                serverName: proxy.servername ?? server,
                alpn: proxy.alpn ?? [],
                skipCertVerify: proxy.skipCertVerify
            )))
        } else {
            self.security = .none
        }

        self.flow = proxy.flow
        let vision = (proxy.flow?.lowercased() == "xtls-rprx-vision")
        if vision, case .none = self.security {
            throw SwiftCoreError.invalidConfig("vless proxy \(proxy.name) flow \(proxy.flow ?? "") requires TLS or REALITY.")
        }
        self.visionEnabled = vision
    }

    func connect(
        request: SwiftCoreOutboundRequest,
        group: EventLoopGroup,
        makeTailHandler: @escaping @Sendable () -> ChannelHandler
    ) -> EventLoopFuture<Channel> {
        let uuid = self.uuid
        let security = self.security
        let flow = self.flow
        let visionEnabled = self.visionEnabled
        return ClientBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                do {
                    let directState = visionEnabled ? SwiftCoreVisionDirectState() : nil
                    switch security {
                    case .none:
                        break
                    case .standardTLS(let transport):
                        try channel.pipeline.syncOperations.addHandler(transport.makeHandler())
                    case .reality(let publicKey, let shortId, let serverName, let alpn):
                        let reality = try SwiftCoreRealityHandshake(publicKeyBase64: publicKey, shortIdHex: shortId)
                        let protocols = alpn.isEmpty ? ["h2", "http/1.1"] : alpn
                        try channel.pipeline.syncOperations.addHandler(
                            SwiftCoreTLS13ClientHandler(serverName: serverName, alpn: protocols, reality: reality, directState: directState)
                        )
                    }
                    try channel.pipeline.syncOperations.addHandler(
                        SwiftCoreVLESSClientHandler(uuid: uuid, request: request, flow: flow)
                    )
                    if visionEnabled, let directState {
                        try channel.pipeline.syncOperations.addHandler(
                            SwiftCoreVisionHandler(userUUID: uuid, directState: directState)
                        )
                    }
                    try channel.pipeline.syncOperations.addHandler(makeTailHandler())
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: server, port: port)
    }
}

/// VLESS wire format helpers, factored out for unit testing.
enum SwiftCoreVLESSProtocol {
    /// Builds the VLESS request header:
    /// version(0) | uuid(16) | addonLen | addons | command(TCP=1) | port(2) | atyp(1) | address.
    /// When `flow` is set, the addons carry the protobuf-encoded flow (field 1, string).
    static func requestHeader(uuid: [UInt8], request: SwiftCoreOutboundRequest, flow: String? = nil) -> [UInt8] {
        var header: [UInt8] = []
        header.append(0x00)               // protocol version
        header.append(contentsOf: uuid)   // 16-byte user id
        if let flow, !flow.isEmpty {
            let flowBytes = Array(flow.utf8)
            let addons: [UInt8] = [0x0a, UInt8(flowBytes.count)] + flowBytes // protobuf: field 1 (string)
            header.append(UInt8(addons.count))
            header.append(contentsOf: addons)
        } else {
            header.append(0x00)           // addon length 0
        }
        header.append(0x01)               // command: TCP
        SwiftCoreProxyEncoding.appendTargetAddress(request, to: &header)
        return header
    }
}

/// Sends the VLESS request header on connect and strips the VLESS response header from the first
/// inbound bytes; everything else is raw, so this is a plain inbound handler.
final class SwiftCoreVLESSClientHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private let uuid: [UInt8]
    private let request: SwiftCoreOutboundRequest
    private let flow: String?
    private var awaitingResponseHeader = true
    private var responseBuffer: ByteBuffer?

    init(uuid: [UInt8], request: SwiftCoreOutboundRequest, flow: String? = nil) {
        self.uuid = uuid
        self.request = request
        self.flow = flow
    }

    func channelActive(context: ChannelHandlerContext) {
        let header = SwiftCoreVLESSProtocol.requestHeader(uuid: uuid, request: request, flow: flow)
        var buffer = context.channel.allocator.buffer(capacity: header.count)
        buffer.writeBytes(header)
        context.writeAndFlush(NIOAny(buffer), promise: nil)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard awaitingResponseHeader else {
            context.fireChannelRead(data)
            return
        }

        var incoming = Self.unwrapInboundIn(data)
        if responseBuffer == nil {
            responseBuffer = incoming
        } else {
            responseBuffer!.writeBuffer(&incoming)
        }

        // Response header: version(1) | addonLen(1) | addons(addonLen).
        guard let addonLength = responseBuffer!.getInteger(at: responseBuffer!.readerIndex + 1, as: UInt8.self) else {
            return
        }
        let headerLength = 2 + Int(addonLength)
        guard responseBuffer!.readableBytes >= headerLength else {
            return
        }
        responseBuffer!.moveReaderIndex(forwardBy: headerLength)
        awaitingResponseHeader = false
        if let remaining = responseBuffer, remaining.readableBytes > 0 {
            context.fireChannelRead(Self.wrapInboundOut(remaining))
        }
        responseBuffer = nil
    }
}
