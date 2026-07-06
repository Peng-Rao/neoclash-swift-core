/// UDP datagram parsing and IPv4+UDP packet construction for the TUN datapath. Pure byte
/// manipulation (no NIO) so it can be exercised directly in tests.
struct SwiftCoreUDPDatagram {
    let sourcePort: Int
    let destinationPort: Int
    let length: Int
    let payload: [UInt8]

    init?(_ segment: ArraySlice<UInt8>) {
        guard segment.count >= 8 else { return nil }
        let base = segment.startIndex
        self.sourcePort = Int(segment[base]) << 8 | Int(segment[base + 1])
        self.destinationPort = Int(segment[base + 2]) << 8 | Int(segment[base + 3])
        let declared = Int(segment[base + 4]) << 8 | Int(segment[base + 5])
        self.length = declared
        let end = (declared >= 8 && base + declared <= segment.endIndex) ? base + declared : segment.endIndex
        self.payload = Array(segment[(base + 8)..<end])
    }

    /// Builds a complete IPv4+UDP packet with correct IP-header and UDP checksums.
    static func build(source: [UInt8], destination: [UInt8], sourcePort: Int, destinationPort: Int, payload: [UInt8]) -> [UInt8] {
        var udp = [UInt8](repeating: 0, count: 8)
        udp[0] = UInt8(sourcePort >> 8); udp[1] = UInt8(sourcePort & 0xff)
        udp[2] = UInt8(destinationPort >> 8); udp[3] = UInt8(destinationPort & 0xff)
        let udpLength = 8 + payload.count
        udp[4] = UInt8(udpLength >> 8); udp[5] = UInt8(udpLength & 0xff)

        var checksumInput = source + destination + [0, 17, UInt8(udpLength >> 8), UInt8(udpLength & 0xff)]
        checksumInput += udp
        checksumInput += payload
        var checksum = swiftCoreInternetChecksum(checksumInput[...])
        if checksum == 0 { checksum = 0xFFFF }   // a computed 0 is transmitted as all-ones
        udp[6] = UInt8(checksum >> 8); udp[7] = UInt8(checksum & 0xff)

        var ip = [UInt8](repeating: 0, count: 20)
        ip[0] = 0x45
        let total = 20 + udpLength
        ip[2] = UInt8(total >> 8); ip[3] = UInt8(total & 0xff)
        ip[8] = 64                        // TTL
        ip[9] = SwiftCoreIPProtocol.udp
        for index in 0..<4 { ip[12 + index] = source[index]; ip[16 + index] = destination[index] }
        let ipChecksum = swiftCoreInternetChecksum(ip[0..<20])
        ip[10] = UInt8(ipChecksum >> 8); ip[11] = UInt8(ipChecksum & 0xff)

        return ip + udp + payload
    }
}

/// A `dns-hijack` target (e.g. `any:53`, `198.18.0.2:53`). A matching UDP datagram is answered
/// locally by the fake-ip/DNS responder rather than forwarded.
struct SwiftCoreDNSHijackTarget: Sendable {
    let address: [UInt8]?   // nil = any destination
    let port: Int

    func matches(destination: [UInt8], port: Int) -> Bool {
        self.port == port && (address == nil || address == destination)
    }

    static func parse(_ entries: [String]) -> [SwiftCoreDNSHijackTarget] {
        entries.compactMap { entry in
            var value = entry
            if let scheme = value.range(of: "://") { value = String(value[scheme.upperBound...]) }
            guard let separator = value.lastIndex(of: ":"), let port = Int(value[value.index(after: separator)...]) else {
                return nil
            }
            let host = String(value[..<separator]).lowercased()
            if host == "any" || host == "*" || host.isEmpty {
                return SwiftCoreDNSHijackTarget(address: nil, port: port)
            }
            if case .ipv4(let bytes) = SwiftCoreAddress.detect(host: host) {
                return SwiftCoreDNSHijackTarget(address: bytes, port: port)
            }
            return nil
        }
    }
}
