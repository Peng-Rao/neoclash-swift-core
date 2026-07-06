import Foundation

/// A fake-ip pool: hands out synthetic IPv4 addresses from a CIDR range and keeps a bidirectional
/// domain↔ip mapping so a connection targeting a fake ip can be routed back to its domain. When the
/// range is exhausted it wraps around, evicting the oldest mapping for the reused address.
public final class SwiftCoreFakeIPPool: @unchecked Sendable {
    private let lock = NSLock()
    private let base: UInt32          // network address, host byte order
    private let size: UInt32          // number of addresses in the range
    private let firstOffset: UInt32   // skip network + a few reserved addresses
    private var nextOffset: UInt32
    private var domainToIP: [String: UInt32] = [:]
    private var ipToDomain: [UInt32: String] = [:]

    /// Fails if `cidr` is not an IPv4 CIDR.
    public init?(cidr: String) {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              case .ipv4(let bytes) = SwiftCoreAddress.detect(host: String(parts[0])) else {
            return nil
        }
        let raw = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
        self.base = raw & mask
        self.size = prefix >= 32 ? 1 : (UInt32(1) << (32 - prefix))
        self.firstOffset = min(4, size > 4 ? 4 : 0)
        self.nextOffset = self.firstOffset
    }

    /// Returns the fake IPv4 (4 bytes, network order) for `domain`, allocating one if needed.
    public func allocate(domain: String) -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        let key = domain.lowercased()
        if let existing = domainToIP[key] {
            return Self.bytes(base + existing)
        }
        let offset = nextOffset
        if let evicted = ipToDomain[offset] {
            domainToIP.removeValue(forKey: evicted)
        }
        domainToIP[key] = offset
        ipToDomain[offset] = key
        nextOffset += 1
        if nextOffset >= size { nextOffset = firstOffset }
        return Self.bytes(base + offset)
    }

    /// The domain a fake ip maps back to, or nil if it isn't a live fake ip.
    public func domain(forIPv4 bytes: [UInt8]) -> String? {
        guard bytes.count == 4 else { return nil }
        let raw = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        guard raw >= base, raw < base &+ size else { return nil }
        lock.lock(); defer { lock.unlock() }
        return ipToDomain[raw - base]
    }

    /// Whether `bytes` falls inside the fake-ip range.
    public func contains(ipv4 bytes: [UInt8]) -> Bool {
        guard bytes.count == 4 else { return false }
        let raw = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        return raw >= base && raw < base &+ size
    }

    private static func bytes(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24 & 0xff), UInt8(value >> 16 & 0xff), UInt8(value >> 8 & 0xff), UInt8(value & 0xff)]
    }
}
