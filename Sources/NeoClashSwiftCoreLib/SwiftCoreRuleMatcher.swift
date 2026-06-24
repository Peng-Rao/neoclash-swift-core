import Foundation

/// The information a rule is evaluated against. `address` classifies the target as an IPv4/IPv6
/// literal or a domain (so IP rules only match literal IPs — domain→IP resolution for non
/// `no-resolve` rules arrives with the DNS subsystem).
public struct SwiftCoreRouteContext: Sendable {
    public let host: String
    public let address: SwiftCoreAddress
    public let destinationPort: Int
    public let sourcePort: Int?

    public init(host: String, destinationPort: Int, sourcePort: Int? = nil) {
        self.host = host
        self.address = SwiftCoreAddress.detect(host: host)
        self.destinationPort = destinationPort
        self.sourcePort = sourcePort
    }
}

/// Evaluates a single routing rule against a `SwiftCoreRouteContext`.
///
/// Supported: MATCH, DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, IP-CIDR6,
/// DST-PORT, SRC-PORT. GEOIP/GEOSITE (need geo databases), PROCESS-NAME (platform syscalls), and
/// RULE-SET (rule providers) are not evaluated yet and never match.
enum SwiftCoreRuleMatcher {
    static let supportedTypes: Set<String> = [
        "MATCH", "FINAL", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
        "IP-CIDR", "IP-CIDR6", "DST-PORT", "SRC-PORT", "GEOIP", "GEOSITE"
    ]

    static func matches(rule: SwiftCoreRule, context: SwiftCoreRouteContext, geo: SwiftCoreGeoDatabase? = nil) -> Bool {
        let host = context.host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        switch rule.type.uppercased() {
        case "GEOIP":
            return geo?.geoip?.matches(country: rule.payload, address: context.address) ?? false
        case "GEOSITE":
            return geo?.geosite?.matches(country: rule.payload, host: host) ?? false
        case "MATCH", "FINAL":
            return true
        case "DOMAIN":
            return host == rule.payload.lowercased()
        case "DOMAIN-SUFFIX":
            let payload = rule.payload.lowercased()
            return host == payload || host.hasSuffix("." + payload)
        case "DOMAIN-KEYWORD":
            return host.contains(rule.payload.lowercased())
        case "DOMAIN-REGEX":
            guard let regex = try? NSRegularExpression(pattern: rule.payload, options: [.caseInsensitive]) else {
                return false
            }
            return regex.firstMatch(in: host, options: [], range: NSRange(host.startIndex..., in: host)) != nil
        case "IP-CIDR", "IP-CIDR6":
            return cidrContains(cidr: rule.payload, address: context.address)
        case "DST-PORT":
            return portMatches(spec: rule.payload, port: context.destinationPort)
        case "SRC-PORT":
            return portMatches(spec: rule.payload, port: context.sourcePort)
        default:
            return false
        }
    }

    /// True if `address` (an IP literal) falls within the CIDR block `a.b.c.d/n` (v4 or v6).
    static func cidrContains(cidr: String, address: SwiftCoreAddress) -> Bool {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0 else { return false }
        switch (SwiftCoreAddress.detect(host: String(parts[0])), address) {
        case (.ipv4(let network), .ipv4(let ip)) where prefix <= 32:
            return prefixMatches(network, ip, bits: prefix)
        case (.ipv6(let network), .ipv6(let ip)) where prefix <= 128:
            return prefixMatches(network, ip, bits: prefix)
        default:
            return false
        }
    }

    private static func prefixMatches(_ lhs: [UInt8], _ rhs: [UInt8], bits: Int) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var remaining = bits
        var index = 0
        while remaining >= 8 {
            if lhs[index] != rhs[index] { return false }
            index += 1
            remaining -= 8
        }
        if remaining > 0, index < lhs.count {
            let mask = UInt8(truncatingIfNeeded: 0xff << (8 - remaining))
            if (lhs[index] & mask) != (rhs[index] & mask) { return false }
        }
        return true
    }

    /// Matches a port against a spec of comma/slash-separated single ports and `lo-hi` ranges.
    static func portMatches(spec: String, port: Int?) -> Bool {
        guard let port else { return false }
        for token in spec.split(whereSeparator: { $0 == "," || $0 == "/" }) {
            let trimmed = token.trimmingCharacters(in: .whitespaces)
            if let dash = trimmed.firstIndex(of: "-") {
                if let low = Int(trimmed[..<dash]), let high = Int(trimmed[trimmed.index(after: dash)...]),
                   (min(low, high)...max(low, high)).contains(port) {
                    return true
                }
            } else if Int(trimmed) == port {
                return true
            }
        }
        return false
    }
}
