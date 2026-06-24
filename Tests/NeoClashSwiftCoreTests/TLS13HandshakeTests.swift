import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import XCTest
@testable import NeoClashSwiftCoreLib

/// Hermetic interop test: the from-scratch `SwiftCoreTLS13ClientHandler` performs a real TLS 1.3
/// handshake against a BoringSSL (NIOSSL) server and exchanges application data. This is the key
/// de-risking step — once our client talks to BoringSSL, REALITY becomes an additive layer.
final class TLS13HandshakeTests: XCTestCase {
    func testClientHandshakesWithBoringSSLServerAndEchoesData() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        defer { try? group.syncShutdownGracefully() }

        let certificate = try NIOSSLCertificate(bytes: Array(Self.certPEM.utf8), format: .pem)
        let privateKey = try NIOSSLPrivateKey(bytes: Array(Self.keyPEM.utf8), format: .pem)
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
        serverConfig.minimumTLSVersion = .tlsv13
        let serverContext = try NIOSSLContext(configuration: serverConfig)

        let serverChannel = try ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                do {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: serverContext))
                    try channel.pipeline.syncOperations.addHandler(EchoServerHandler())
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? serverChannel.close().wait() }
        let port = try XCTUnwrap(serverChannel.localAddress?.port)

        let promise = group.next().makePromise(of: String.self)
        group.next().scheduleTask(in: .seconds(5)) {
            promise.fail(SwiftCoreTLSError.handshakeFailed("timeout"))
        }
        let collector = CollectingClientHandler(expected: "ping-from-swift-tls13", promise: promise)

        let clientChannel = try ClientBootstrap(group: group)
            .channelInitializer { channel in
                do {
                    try channel.pipeline.syncOperations.addHandler(SwiftCoreTLS13ClientHandler(serverName: "localhost"))
                    try channel.pipeline.syncOperations.addHandler(collector)
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: "127.0.0.1", port: port)
            .wait()
        defer { try? clientChannel.close().wait() }

        let echoed = try promise.futureResult.wait()
        XCTAssertEqual(echoed, "ping-from-swift-tls13")
    }

    // Self-signed P-256 certificate for CN=localhost (test only).
    private static let certPEM = """
    -----BEGIN CERTIFICATE-----
    MIIBfTCCASOgAwIBAgIUO7jHrES/1fCQthrAuDvC4hxeZeMwCgYIKoZIzj0EAwIw
    FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYyMjIyMzM1OFoXDTM2MDYxOTIy
    MzM1OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
    AQcDQgAEzrUvhBP1VtxWpITwftn+4iURBlEK3K+fKWblrT+4iIokvDa8K3JXc8wK
    d0Ev7M8HLRL4Zm06NSq7y1apUO3CK6NTMFEwHQYDVR0OBBYEFKnwV4pGukaK9zIQ
    5MrGxl7XcphxMB8GA1UdIwQYMBaAFKnwV4pGukaK9zIQ5MrGxl7XcphxMA8GA1Ud
    EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgU+Htcp++UDHxYjEW/oWN5dqw
    PPT+3hgWZwBehCvTONQCIQCghNh/9f7RAEVSqZH5k2qeOgpbUXrOlIghWBHIekHi
    Cw==
    -----END CERTIFICATE-----
    """

    private static let keyPEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcJQh6NSSjJMC0qY0
    to6FSmWhmMlOpzlLebm+ucingcqhRANCAATOtS+EE/VW3FakhPB+2f7iJREGUQrc
    r58pZuWtP7iIiiS8NrwrcldzzAp3QS/szwctEvhmbTo1KrvLVqlQ7cIr
    -----END PRIVATE KEY-----
    """
}

private final class EchoServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}

private final class CollectingClientHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let expected: String
    private let promise: EventLoopPromise<String>
    private var accumulated = ""

    init(expected: String, promise: EventLoopPromise<String>) {
        self.expected = expected
        self.promise = promise
    }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: expected.utf8.count)
        buffer.writeString(expected)
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = Self.unwrapInboundIn(data)
        if let text = buffer.readString(length: buffer.readableBytes) {
            accumulated += text
            if accumulated.contains(expected) {
                promise.succeed(accumulated)
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
        context.close(promise: nil)
    }
}
