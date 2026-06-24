import NIOCore
import NIOSSL

/// TLS options parsed from a proxy entry.
struct SwiftCoreTLSOptions: Sendable {
    var serverName: String?
    var alpn: [String]
    var skipCertVerify: Bool
}

/// Wraps a reusable `NIOSSLContext` and produces a client TLS handler per connection.
final class SwiftCoreTLSTransport: @unchecked Sendable {
    private let context: NIOSSLContext
    private let serverName: String?

    init(options: SwiftCoreTLSOptions) throws {
        var configuration = TLSConfiguration.makeClientConfiguration()
        if options.skipCertVerify {
            configuration.certificateVerification = .none
        }
        if !options.alpn.isEmpty {
            configuration.applicationProtocols = options.alpn
        }
        self.context = try NIOSSLContext(configuration: configuration)
        self.serverName = SwiftCoreTLSTransport.validSNI(options.serverName)
    }

    func makeHandler() throws -> NIOSSLClientHandler {
        try NIOSSLClientHandler(context: context, serverHostname: serverName)
    }

    /// NIOSSL rejects IP-literal SNI; only forward domain names as the server hostname.
    private static func validSNI(_ name: String?) -> String? {
        guard let name, !name.isEmpty else { return nil }
        if case .domain = SwiftCoreAddress.detect(host: name) {
            return name
        }
        return nil
    }
}
