import Foundation
import NIOCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A resolved target the proxy needs to reach. The host is passed through verbatim to the
/// upstream proxy server (the proxy performs its own DNS), matching clash/mihomo behavior.
public struct SwiftCoreOutboundRequest: Sendable {
    public let host: String
    public let port: Int
    public let address: SwiftCoreAddress

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
        self.address = SwiftCoreAddress.detect(host: host)
    }
}

/// The address family of a target, with the bytes needed to encode it in a SOCKS-style header.
public enum SwiftCoreAddress: Sendable, Equatable {
    case ipv4([UInt8])     // 4 bytes, network order
    case ipv6([UInt8])     // 16 bytes, network order
    case domain(String)

    /// VLESS/VMess/SOCKS address-type byte: 1 = IPv4, 2 = domain, 3 = IPv6.
    var atyp: UInt8 {
        switch self {
        case .ipv4: return 0x01
        case .domain: return 0x02
        case .ipv6: return 0x03
        }
    }

    /// Classifies a host string as an IPv4 literal, IPv6 literal, or a domain name.
    public static func detect(host: String) -> SwiftCoreAddress {
        let trimmed = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var v4 = in_addr()
        if trimmed.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            var raw = v4.s_addr
            return withUnsafeBytes(of: &raw) { .ipv4(Array($0)) }
        }
        var v6 = in6_addr()
        if trimmed.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return withUnsafeBytes(of: &v6) { .ipv6(Array($0)) }
        }
        return .domain(host)
    }
}

/// An outbound adapter knows how to reach a target. `connect` returns a channel whose pipeline
/// surfaces plaintext application bytes — all protocol framing and crypto is handled internally.
/// The caller installs its glue handler last via `makeTailHandler` so no inbound data is lost
/// between the channel becoming active and the glue being attached.
public protocol SwiftCoreOutbound: Sendable {
    var name: String { get }
    func connect(
        request: SwiftCoreOutboundRequest,
        group: EventLoopGroup,
        makeTailHandler: @escaping @Sendable () -> ChannelHandler
    ) -> EventLoopFuture<Channel>
}

/// Builds an outbound adapter from a parsed proxy entry. Returns nil for proxy types the Swift
/// core does not implement yet (the caller treats those as unsupported routes). Throws for
/// malformed configuration of a supported type.
enum SwiftCoreOutboundFactory {
    static func make(proxy: SwiftCoreProxy) throws -> SwiftCoreOutbound? {
        switch proxy.type.lowercased() {
        case "direct":
            return SwiftCoreDirectOutbound(name: proxy.name)
        case "vless":
            return try SwiftCoreVLESSOutbound(proxy: proxy)
        case "vmess":
            return try SwiftCoreVMessOutbound(proxy: proxy)
        default:
            return nil
        }
    }
}

/// Shared encoding helpers used by VLESS and VMess request headers.
enum SwiftCoreProxyEncoding {
    /// Appends port (2 bytes, big-endian) + atyp (1 byte) + address, the layout both VLESS and
    /// VMess use for the target address inside their request headers.
    static func appendTargetAddress(_ request: SwiftCoreOutboundRequest, to bytes: inout [UInt8]) {
        bytes.append(UInt8((request.port >> 8) & 0xff))
        bytes.append(UInt8(request.port & 0xff))
        bytes.append(request.address.atyp)
        switch request.address {
        case .ipv4(let octets), .ipv6(let octets):
            bytes.append(contentsOf: octets)
        case .domain(let name):
            let host = Array(name.utf8)
            bytes.append(UInt8(host.count))
            bytes.append(contentsOf: host)
        }
    }

    /// Parses a standard UUID string into 16 bytes.
    static func parseUUID(_ string: String) throws -> [UInt8] {
        guard let uuid = UUID(uuidString: string) else {
            throw SwiftCoreError.invalidConfig("uuid '\(string)' is not a valid UUID.")
        }
        let u = uuid.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}
