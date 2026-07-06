import Foundation

/// Minimal protobuf wire-format reader (varint + length-delimited; other wire types are skipped).
/// Enough to decode v2ray/mihomo `geoip.dat` and `geosite.dat`. It operates on `Data` and
/// returns length-delimited fields as slices sharing the same backing store, so a memory-mapped
/// multi-MB geo file is walked without copying blocks — the file pages stay clean and evictable
/// instead of becoming dirty RSS.
struct SwiftCoreProtobufReader {
    private let bytes: Data
    private var offset: Int

    init(_ bytes: [UInt8]) {
        self.init(Data(bytes))
    }

    init(_ bytes: Data) {
        self.bytes = bytes
        self.offset = bytes.startIndex
    }

    var isAtEnd: Bool { offset >= bytes.endIndex }

    mutating func readVarint() -> UInt64? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while offset < bytes.endIndex {
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

    mutating func readLengthDelimitedSlice() -> Data? {
        guard let length = readVarint(), length <= UInt64(bytes.endIndex - offset) else { return nil }
        let count = Int(length)
        defer { offset += count }
        return bytes[offset..<offset + count]
    }

    mutating func readLengthDelimited() -> [UInt8]? {
        readLengthDelimitedSlice().map { Array($0) }
    }

    mutating func skip(wireType: Int) {
        switch wireType {
        case 0: _ = readVarint()
        case 1: offset = min(offset + 8, bytes.endIndex)
        case 2: if let length = readVarint() { offset = min(offset + Int(min(length, UInt64(Int.max / 2))), bytes.endIndex) }
        case 5: offset = min(offset + 4, bytes.endIndex)
        default: offset = bytes.endIndex
        }
    }

    /// Reads only the country-code field of a GeoIP/GeoSite entry block, skipping everything
    /// else — used to decide whether a block is worth materializing at all.
    static func entryCode(in block: Data) -> String {
        var reader = SwiftCoreProtobufReader(block)
        while let (field, wire) = reader.readTag() {
            if field == 1, wire == 2, let bytes = reader.readLengthDelimitedSlice() {
                return String(decoding: bytes, as: UTF8.self).uppercased()
            }
            reader.skip(wireType: wire)
        }
        return ""
    }
}

/// GeoIP database (v2ray `GeoIPList`): country code → address intervals. Used by `GEOIP` rules.
///
/// CIDRs are stored as merged, sorted, disjoint intervals in parallel flat arrays — zero
/// per-entry heap allocations and a binary-search lookup. The naive representation (one tuple
/// with a heap-allocated byte array per CIDR, linear scan to match) costs two orders of
/// magnitude more memory for the full ~1M-entry database and made every `GEOIP` rule an O(n)
/// walk per connection.
struct SwiftCoreGeoIP {
    private struct CompactRanges {
        var v4Starts: [UInt32] = []
        var v4Ends: [UInt32] = []
        var v6Starts: [UInt128] = []
        var v6Ends: [UInt128] = []
    }

    private let networks: [String: CompactRanges]

    init(data: [UInt8], codes: Set<String> = []) {
        self.init(data: Data(data), codes: codes)
    }

    /// `codes` restricts parsing to the given uppercase country codes; empty loads every code
    /// (needed when classical rule providers may reference arbitrary codes).
    init(data: Data, codes: Set<String> = []) {
        var networks: [String: CompactRanges] = [:]
        var reader = SwiftCoreProtobufReader(data)
        while let (field, wire) = reader.readTag() {
            guard field == 1, wire == 2, let entry = reader.readLengthDelimitedSlice() else {
                reader.skip(wireType: wire)
                continue
            }
            let code = SwiftCoreProtobufReader.entryCode(in: entry)
            guard !code.isEmpty, codes.isEmpty || codes.contains(code) else { continue }

            var v4: [(UInt32, UInt32)] = []
            var v6: [(UInt128, UInt128)] = []
            var entryReader = SwiftCoreProtobufReader(entry)
            while let (innerField, innerWire) = entryReader.readTag() {
                guard innerField == 2, innerWire == 2, let cidrBytes = entryReader.readLengthDelimitedSlice() else {
                    entryReader.skip(wireType: innerWire)
                    continue
                }
                var cidrReader = SwiftCoreProtobufReader(cidrBytes)
                var ip = Data()
                var prefix = 0
                while let (cidrField, cidrWire) = cidrReader.readTag() {
                    if cidrField == 1, cidrWire == 2, let ipBytes = cidrReader.readLengthDelimitedSlice() {
                        ip = ipBytes
                    } else if cidrField == 2, cidrWire == 0, let value = cidrReader.readVarint() {
                        prefix = Int(value)
                    } else {
                        cidrReader.skip(wireType: cidrWire)
                    }
                }
                if ip.count == 4 {
                    v4.append(Self.range(of: Self.value(UInt32.self, from: ip), prefix: prefix))
                } else if ip.count == 16 {
                    v6.append(Self.range(of: Self.value(UInt128.self, from: ip), prefix: prefix))
                }
            }

            var ranges = CompactRanges()
            (ranges.v4Starts, ranges.v4Ends) = Self.merged(v4)
            (ranges.v6Starts, ranges.v6Ends) = Self.merged(v6)
            networks[code] = ranges
        }
        self.networks = networks
    }

    var countryCount: Int { networks.count }

    func matches(country: String, address: SwiftCoreAddress) -> Bool {
        guard let ranges = networks[country.uppercased()] else { return false }
        switch address {
        case .ipv4(let bytes) where bytes.count == 4:
            return Self.contains(Self.value(UInt32.self, from: bytes), starts: ranges.v4Starts, ends: ranges.v4Ends)
        case .ipv6(let bytes) where bytes.count == 16:
            return Self.contains(Self.value(UInt128.self, from: bytes), starts: ranges.v6Starts, ends: ranges.v6Ends)
        default:
            return false
        }
    }

    private static func value<T: FixedWidthInteger>(_ type: T.Type, from bytes: some Sequence<UInt8>) -> T {
        bytes.reduce(T.zero) { $0 << 8 | T($1) }
    }

    private static func range<T: FixedWidthInteger & UnsignedInteger>(of ip: T, prefix: Int) -> (T, T) {
        let width = min(max(prefix, 0), T.bitWidth)
        // Swift's smart shift returns 0 on overshift, so prefix 0 yields mask 0 (the whole space).
        let mask: T = ~T.zero << (T.bitWidth - width)
        let start = ip & mask
        return (start, start | ~mask)
    }

    /// Sorts and merges overlapping/adjacent intervals so lookups can binary-search a
    /// disjoint list.
    private static func merged<T: FixedWidthInteger>(_ ranges: [(T, T)]) -> ([T], [T]) {
        guard !ranges.isEmpty else { return ([], []) }
        let sorted = ranges.sorted { $0.0 < $1.0 }
        var starts: [T] = []
        var ends: [T] = []
        starts.reserveCapacity(sorted.count)
        ends.reserveCapacity(sorted.count)
        for (start, end) in sorted {
            if let last = ends.last, last == T.max || start <= last + 1 {
                if end > last { ends[ends.count - 1] = end }
            } else {
                starts.append(start)
                ends.append(end)
            }
        }
        return (starts, ends)
    }

    private static func contains<T: FixedWidthInteger>(_ value: T, starts: [T], ends: [T]) -> Bool {
        var low = 0
        var high = starts.count
        while low < high {
            let mid = (low + high) / 2
            if starts[mid] <= value {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low > 0 && value <= ends[low - 1]
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

    init(data: [UInt8], codes: Set<String> = []) {
        self.init(data: Data(data), codes: codes)
    }

    /// `codes` restricts parsing to the given uppercase category codes; empty loads every code.
    init(data: Data, codes: Set<String> = []) {
        var sites: [String: Matcher] = [:]
        var reader = SwiftCoreProtobufReader(data)
        while let (field, wire) = reader.readTag() {
            guard field == 1, wire == 2, let entry = reader.readLengthDelimitedSlice() else {
                reader.skip(wireType: wire)
                continue
            }
            let code = SwiftCoreProtobufReader.entryCode(in: entry)
            guard !code.isEmpty, codes.isEmpty || codes.contains(code) else { continue }

            var matcher = Matcher()
            var entryReader = SwiftCoreProtobufReader(entry)
            while let (innerField, innerWire) = entryReader.readTag() {
                guard innerField == 2, innerWire == 2, let domainBytes = entryReader.readLengthDelimitedSlice() else {
                    entryReader.skip(wireType: innerWire)
                    continue
                }
                var domainReader = SwiftCoreProtobufReader(domainBytes)
                var type = 0
                var value = ""
                while let (domainField, domainWire) = domainReader.readTag() {
                    if domainField == 1, domainWire == 0, let raw = domainReader.readVarint() {
                        type = Int(raw)
                    } else if domainField == 2, domainWire == 2, let bytes = domainReader.readLengthDelimitedSlice() {
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
            }
            sites[code] = matcher
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
