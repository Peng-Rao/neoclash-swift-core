/// TCP segment parsing and IPv4+TCP packet construction for the userspace TCP stack. Pure byte
/// manipulation (no NIO) so it can be exercised directly in tests.

enum SwiftCoreTCPFlag {
    static let fin: UInt8 = 0x01
    static let syn: UInt8 = 0x02
    static let rst: UInt8 = 0x04
    static let psh: UInt8 = 0x08
    static let ack: UInt8 = 0x10
}

/// A parsed TCP segment (header fields + payload).
struct SwiftCoreTCPSegment {
    let sourcePort: Int
    let destinationPort: Int
    let sequenceNumber: UInt32
    let acknowledgmentNumber: UInt32
    let flags: UInt8
    let window: UInt16
    let payload: [UInt8]

    init?(_ segment: ArraySlice<UInt8>) {
        guard segment.count >= 20 else { return nil }
        let base = segment.startIndex
        let dataOffset = Int(segment[base + 12] >> 4) * 4
        guard dataOffset >= 20, segment.count >= dataOffset else { return nil }
        self.sourcePort = Int(segment[base]) << 8 | Int(segment[base + 1])
        self.destinationPort = Int(segment[base + 2]) << 8 | Int(segment[base + 3])
        self.sequenceNumber = SwiftCoreTCPSegment.readUInt32(segment, base + 4)
        self.acknowledgmentNumber = SwiftCoreTCPSegment.readUInt32(segment, base + 8)
        self.flags = segment[base + 13]
        self.window = UInt16(segment[base + 14]) << 8 | UInt16(segment[base + 15])
        self.payload = Array(segment[(base + dataOffset)...])
    }

    var isSYN: Bool { flags & SwiftCoreTCPFlag.syn != 0 }
    var isACK: Bool { flags & SwiftCoreTCPFlag.ack != 0 }
    var isFIN: Bool { flags & SwiftCoreTCPFlag.fin != 0 }
    var isRST: Bool { flags & SwiftCoreTCPFlag.rst != 0 }

    /// Builds a complete IPv4+TCP packet (no options) with correct IP header and TCP checksums.
    static func build(
        source: [UInt8],
        destination: [UInt8],
        sourcePort: Int,
        destinationPort: Int,
        sequenceNumber: UInt32,
        acknowledgmentNumber: UInt32,
        flags: UInt8,
        window: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        var tcp = [UInt8](repeating: 0, count: 20)
        tcp[0] = UInt8(sourcePort >> 8); tcp[1] = UInt8(sourcePort & 0xff)
        tcp[2] = UInt8(destinationPort >> 8); tcp[3] = UInt8(destinationPort & 0xff)
        writeUInt32(&tcp, 4, sequenceNumber)
        writeUInt32(&tcp, 8, acknowledgmentNumber)
        tcp[12] = 5 << 4                  // data offset: 5 words, no options
        tcp[13] = flags
        tcp[14] = UInt8(window >> 8); tcp[15] = UInt8(window & 0xff)

        let tcpLength = tcp.count + payload.count
        // TCP checksum covers a pseudo-header (src, dst, zero, protocol, length) + the segment.
        var checksumInput = source + destination + [0, 6, UInt8(tcpLength >> 8), UInt8(tcpLength & 0xff)]
        checksumInput += tcp
        checksumInput += payload
        let tcpChecksum = swiftCoreInternetChecksum(checksumInput[...])
        tcp[16] = UInt8(tcpChecksum >> 8); tcp[17] = UInt8(tcpChecksum & 0xff)

        var ip = [UInt8](repeating: 0, count: 20)
        ip[0] = 0x45
        let total = 20 + tcpLength
        ip[2] = UInt8(total >> 8); ip[3] = UInt8(total & 0xff)
        ip[8] = 64                        // TTL
        ip[9] = SwiftCoreIPProtocol.tcp
        for index in 0..<4 { ip[12 + index] = source[index]; ip[16 + index] = destination[index] }
        let ipChecksum = swiftCoreInternetChecksum(ip[0..<20])
        ip[10] = UInt8(ipChecksum >> 8); ip[11] = UInt8(ipChecksum & 0xff)

        return ip + tcp + payload
    }

    private static func readUInt32(_ bytes: ArraySlice<UInt8>, _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }

    private static func writeUInt32(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt32) {
        bytes[offset] = UInt8((value >> 24) & 0xff)
        bytes[offset + 1] = UInt8((value >> 16) & 0xff)
        bytes[offset + 2] = UInt8((value >> 8) & 0xff)
        bytes[offset + 3] = UInt8(value & 0xff)
    }
}
