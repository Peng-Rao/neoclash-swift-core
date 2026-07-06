import NIOCore

/// The stream transport a proxy uses beneath its protocol layer: raw TCP, or WebSocket. The
/// transport handler (if any) sits between the security layer (TLS) and the VLESS/VMess handler,
/// so the protocol sees a plaintext byte stream regardless of how it is carried on the wire.
enum SwiftCoreStreamTransport: Sendable {
    case tcp
    case websocket(SwiftCoreWebSocketTransport)
    case grpc(SwiftCoreGRPCTransport)

    /// Builds the transport from a proxy entry, validating the `network` field.
    static func make(proxy: SwiftCoreProxy) throws -> SwiftCoreStreamTransport {
        switch (proxy.network ?? "tcp").lowercased() {
        case "tcp":
            return .tcp
        case "ws", "websocket":
            return .websocket(try SwiftCoreWebSocketTransport(proxy: proxy))
        case "grpc", "gun":
            return .grpc(try SwiftCoreGRPCTransport(proxy: proxy))
        case let other:
            throw SwiftCoreError.invalidConfig("proxy \(proxy.name) network '\(other)' is not supported.")
        }
    }

    /// ALPN a transport requires regardless of the proxy's `alpn` setting (gRPC needs HTTP/2).
    var forcedALPN: [String]? {
        if case .grpc = self { return ["h2"] }
        return nil
    }

    /// gRPC establishes its own HTTP/2 stream rather than adding an inline handler.
    var isChildStream: Bool {
        if case .grpc = self { return true }
        return false
    }

    /// Installs the inline transport handler (if any) at the current tail of the pipeline. Call
    /// after the security handler and before the protocol handler. gRPC is handled separately via
    /// `SwiftCoreGRPCTransport.connect` and must not reach here.
    func addHandler(to channel: Channel) throws {
        switch self {
        case .tcp, .grpc:
            break
        case .websocket(let ws):
            try channel.pipeline.syncOperations.addHandler(ws.makeHandler())
        }
    }
}
