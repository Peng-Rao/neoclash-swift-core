/// Minimal IPv4 / TCP / UDP / ICMP packet parsing for the TUN datapath. Pure byte manipulation —
/// no NIO — so it can be exercised directly in tests. Only what the TUN layer needs is parsed.

/// IPv4 next-protocol numbers the TUN layer distinguishes.
enum SwiftCoreIPProtocol {
    static let icmp: UInt8 = 1
    static let tcp: UInt8 = 6
    static let udp: UInt8 = 17
}

/// A parsed IPv4 header plus the ranges of its header and payload within the packet bytes.
struct SwiftCoreIPv4Packet {
    let bytes: [UInt8]
    let headerLength: Int      // IHL in bytes
    let totalLength: Int       // clamped to the available bytes
    let proto: UInt8
    let source: [UInt8]        // 4 bytes, network order
    let destination: [UInt8]   // 4 bytes, network order

    init?(_ bytes: [UInt8]) {
        guard bytes.count >= 20, bytes[0] >> 4 == 4 else { return nil }
        let headerLength = Int(bytes[0] & 0x0f) * 4
        guard headerLength >= 20, bytes.count >= headerLength else { return nil }
        let declared = Int(bytes[2]) << 8 | Int(bytes[3])
        self.bytes = bytes
        self.headerLength = headerLength
        self.totalLength = (declared == 0 || declared > bytes.count) ? bytes.count : declared
        self.proto = bytes[9]
        self.source = Array(bytes[12..<16])
        self.destination = Array(bytes[16..<20])
    }

    /// The transport-layer bytes (TCP/UDP/ICMP header + data).
    var payload: ArraySlice<UInt8> { bytes[headerLength..<totalLength] }
}

/// Dotted-quad rendering of a 4-byte address (for logging).
func swiftCoreIPv4String(_ address: [UInt8]) -> String {
    address.map(String.init).joined(separator: ".")
}

/// TCP header fields the TUN layer reads (ports + flags).
struct SwiftCoreTCPHeader {
    let sourcePort: Int
    let destinationPort: Int
    let flags: UInt8

    init?(_ payload: ArraySlice<UInt8>) {
        guard payload.count >= 14 else { return nil }
        let base = payload.startIndex
        self.sourcePort = Int(payload[base]) << 8 | Int(payload[base + 1])
        self.destinationPort = Int(payload[base + 2]) << 8 | Int(payload[base + 3])
        self.flags = payload[base + 13]
    }

    var isSYN: Bool { flags & 0x02 != 0 }
    var isACK: Bool { flags & 0x10 != 0 }
    var isFIN: Bool { flags & 0x01 != 0 }
    var isRST: Bool { flags & 0x04 != 0 }
}

/// ICMP header fields (type + code).
struct SwiftCoreICMPHeader {
    static let echoReply: UInt8 = 0
    static let echoRequest: UInt8 = 8

    let type: UInt8
    let code: UInt8

    init?(_ payload: ArraySlice<UInt8>) {
        guard payload.count >= 4 else { return nil }
        let base = payload.startIndex
        self.type = payload[base]
        self.code = payload[base + 1]
    }
}

/// The RFC 1071 one's-complement internet checksum over `bytes`.
func swiftCoreInternetChecksum(_ bytes: ArraySlice<UInt8>) -> UInt16 {
    var sum: UInt32 = 0
    var index = bytes.startIndex
    while index < bytes.endIndex {
        let high = UInt32(bytes[index])
        let low = (index + 1) < bytes.endIndex ? UInt32(bytes[index + 1]) : 0
        sum &+= (high << 8) | low
        index += 2
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) &+ (sum >> 16)
    }
    return UInt16(~sum & 0xffff)
}

func swiftCoreInternetChecksum(_ bytes: [UInt8]) -> UInt16 {
    swiftCoreInternetChecksum(bytes[...])
}

enum SwiftCoreICMP {
    /// Turns an ICMP echo-request packet into its echo reply: swap the IP source/destination, set the
    /// ICMP type to echo-reply, and recompute both the IP header and ICMP checksums. Returns nil if
    /// `request` is not a well-formed ICMP echo request.
    static func makeEchoReply(from request: [UInt8]) -> [UInt8]? {
        guard let ip = SwiftCoreIPv4Packet(request), ip.proto == SwiftCoreIPProtocol.icmp else { return nil }
        let icmpStart = ip.headerLength
        let icmpEnd = ip.totalLength
        guard icmpEnd - icmpStart >= 8, request[icmpStart] == SwiftCoreICMPHeader.echoRequest else { return nil }

        var reply = request
        for offset in 0..<4 {
            reply.swapAt(12 + offset, 16 + offset)
        }
        reply[icmpStart] = SwiftCoreICMPHeader.echoReply

        reply[icmpStart + 2] = 0
        reply[icmpStart + 3] = 0
        let icmpChecksum = swiftCoreInternetChecksum(reply[icmpStart..<icmpEnd])
        reply[icmpStart + 2] = UInt8(icmpChecksum >> 8)
        reply[icmpStart + 3] = UInt8(icmpChecksum & 0xff)

        reply[10] = 0
        reply[11] = 0
        let ipChecksum = swiftCoreInternetChecksum(reply[0..<ip.headerLength])
        reply[10] = UInt8(ipChecksum >> 8)
        reply[11] = UInt8(ipChecksum & 0xff)
        return reply
    }
}
