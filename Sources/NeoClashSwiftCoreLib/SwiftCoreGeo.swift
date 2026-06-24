import Foundation

/// Minimal protobuf wire-format reader (varint + length-delimited; other wire types are skipped).
/// Enough to decode v2ray/mihomo `geoip.dat` and `geosite.dat`.
struct SwiftCoreProtobufReader {
    private let bytes: [UInt8]
    private var offset: Int = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var isAtEnd: Bool { offset >= bytes.count }

    mutating func readVarint() -> UInt64? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while offset < bytes.count {
            let byte = bytes[offset]
            offset += 1
            result |= UInt64(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
            if shift >= 64 { return nil }
        }
        return nil
    }

    /// Returns (fieldNumber, wireType).
    mutating func readTag() -> (field: Int, wire: Int)? {
        guard let tag = readVarint() else { return nil }
        return (Int(tag >> 3), Int(tag & 0x7))
    }

    mutating func readLengthDelimited() -> [UInt8]? {
        guard let length = readVarint() else { return nil }
        let count = Int(length)
        guard count >= 0, offset + count <= bytes.count else { return nil }
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    mutating func skip(wireType: Int) {
        switch wireType {
        case 0: _ = readVarint()
        case 1: offset = min(offset + 8, bytes.count)
        case 2: if let length = readVarint() { offset = min(offset + Int(length), bytes.count) }
        case 5: offset = min(offset + 4, bytes.count)
        default: offset = bytes.count
        }
    }
}

/// GeoIP database (v2ray `GeoIPList`): country code → CIDR list. Used by `GEOIP` rules.
struct SwiftCoreGeoIP {
    private let networks: [String: [(ip: [UInt8], prefix: Int)]]

    init(data: [UInt8]) {
        var networks: [String: [(ip: [UInt8], prefix: Int)]] = [:]
        var reader = SwiftCoreProtobufReader(data)
        while let (field, wire) = reader.readTag() {
            guard field == 1, wire == 2, let entry = reader.readLengthDelimited() else {
                reader.skip(wireType: wire)
                continue
            }
            var entryReader = SwiftCoreProtobufReader(entry)
            var code = ""
            var cidrs: [(ip: [UInt8], prefix: Int)] = []
            while let (innerField, innerWire) = entryReader.readTag() {
                if innerField == 1, innerWire == 2, let bytes = entryReader.readLengthDelimited() {
                    code = String(decoding: bytes, as: UTF8.self)
                } else if innerField == 2, innerWire == 2, let cidrBytes = entryReader.readLengthDelimited() {
                    var cidrReader = SwiftCoreProtobufReader(cidrBytes)
                    var ip: [UInt8] = []
                    var prefix = 0
                    while let (cidrField, cidrWire) = cidrReader.readTag() {
                        if cidrField == 1, cidrWire == 2, let ipBytes = cidrReader.readLengthDelimited() {
                            ip = ipBytes
                        } else if cidrField == 2, cidrWire == 0, let value = cidrReader.readVarint() {
                            prefix = Int(value)
                        } else {
                            cidrReader.skip(wireType: cidrWire)
                        }
                    }
                    if !ip.isEmpty { cidrs.append((ip, prefix)) }
                } else {
                    entryReader.skip(wireType: innerWire)
                }
            }
            if !code.isEmpty { networks[code.uppercased()] = cidrs }
        }
        self.networks = networks
    }

    var countryCount: Int { networks.count }

    func matches(country: String, address: SwiftCoreAddress) -> Bool {
        guard let cidrs = networks[country.uppercased()] else { return false }
        let ip: [UInt8]
        switch address {
        case .ipv4(let bytes), .ipv6(let bytes): ip = bytes
        case .domain: return false
        }
        for cidr in cidrs where cidr.ip.count == ip.count && Self.prefixMatches(cidr.ip, ip, bits: cidr.prefix) {
            return true
        }
        return false
    }

    private static func prefixMatches(_ network: [UInt8], _ ip: [UInt8], bits: Int) -> Bool {
        var remaining = bits
        var index = 0
        while remaining >= 8 {
            if network[index] != ip[index] { return false }
            index += 1
            remaining -= 8
        }
        if remaining > 0, index < network.count {
            let mask = UInt8(truncatingIfNeeded: 0xff << (8 - remaining))
            if (network[index] & mask) != (ip[index] & mask) { return false }
        }
        return true
    }
}

/// GeoSite database (v2ray `GeoSiteList`): country code → domain matcher. Used by `GEOSITE` rules.
struct SwiftCoreGeoSite {
    private struct Matcher {
        var full: Set<String> = []        // Domain.Type Full (exact)
        var domain: Set<String> = []      // Domain.Type Domain (suffix)
        var keywords: [String] = []       // Domain.Type Plain (substring)
        var regexes: [NSRegularExpression] = [] // Domain.Type Regex
    }

    private let sites: [String: Matcher]

    init(data: [UInt8]) {
        var sites: [String: Matcher] = [:]
        var reader = SwiftCoreProtobufReader(data)
        while let (field, wire) = reader.readTag() {
            guard field == 1, wire == 2, let entry = reader.readLengthDelimited() else {
                reader.skip(wireType: wire)
                continue
            }
            var entryReader = SwiftCoreProtobufReader(entry)
            var code = ""
            var matcher = Matcher()
            while let (innerField, innerWire) = entryReader.readTag() {
                if innerField == 1, innerWire == 2, let bytes = entryReader.readLengthDelimited() {
                    code = String(decoding: bytes, as: UTF8.self)
                } else if innerField == 2, innerWire == 2, let domainBytes = entryReader.readLengthDelimited() {
                    var domainReader = SwiftCoreProtobufReader(domainBytes)
                    var type = 0
                    var value = ""
                    while let (domainField, domainWire) = domainReader.readTag() {
                        if domainField == 1, domainWire == 0, let raw = domainReader.readVarint() {
                            type = Int(raw)
                        } else if domainField == 2, domainWire == 2, let bytes = domainReader.readLengthDelimited() {
                            value = String(decoding: bytes, as: UTF8.self).lowercased()
                        } else {
                            domainReader.skip(wireType: domainWire)
                        }
                    }
                    guard !value.isEmpty else { continue }
                    switch type {
                    case 3: matcher.full.insert(value)          // Full
                    case 2: matcher.domain.insert(value)        // Domain (suffix)
                    case 1:                                     // Regex
                        if let regex = try? NSRegularExpression(pattern: value, options: [.caseInsensitive]) {
                            matcher.regexes.append(regex)
                        }
                    default: matcher.keywords.append(value)     // Plain (substring)
                    }
                } else {
                    entryReader.skip(wireType: innerWire)
                }
            }
            if !code.isEmpty { sites[code.uppercased()] = matcher }
        }
        self.sites = sites
    }

    var countryCount: Int { sites.count }

    func matches(country: String, host: String) -> Bool {
        guard let matcher = sites[country.uppercased()] else { return false }
        let host = host.lowercased()
        if matcher.full.contains(host) { return true }
        if matcher.domain.contains(host) { return true }
        var rest = host
        while let dot = rest.firstIndex(of: ".") {
            rest = String(rest[rest.index(after: dot)...])
            if matcher.domain.contains(rest) { return true }
        }
        for keyword in matcher.keywords where host.contains(keyword) { return true }
        let range = NSRange(host.startIndex..., in: host)
        for regex in matcher.regexes where regex.firstMatch(in: host, options: [], range: range) != nil { return true }
        return false
    }
}

/// Loaded geo databases shared with the rule matcher; nil components mean "not loaded yet".
public final class SwiftCoreGeoDatabase: @unchecked Sendable {
    let geoip: SwiftCoreGeoIP?
    let geosite: SwiftCoreGeoSite?

    init(geoip: SwiftCoreGeoIP?, geosite: SwiftCoreGeoSite?) {
        self.geoip = geoip
        self.geosite = geosite
    }
}
