import Foundation

/// Minimal DNS message codec (RFC 1035): encodes A/AAAA queries and decodes the address answers
/// from a response, following name-compression pointers. Enough for a stub resolver over
/// UDP / DoH / DoT.
enum SwiftCoreDNSRecordType: UInt16 {
    case a = 1      // IPv4
    case aaaa = 28  // IPv6
}

struct SwiftCoreDNSAnswer: Equatable {
    let address: SwiftCoreAddress // .ipv4 or .ipv6
    let ttl: UInt32
}

enum SwiftCoreDNSMessage {
    /// Builds a standard recursive query for `name` and `type` with the given transaction id.
    static func encodeQuery(id: UInt16, name: String, type: SwiftCoreDNSRecordType) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(UInt8(id >> 8)); bytes.append(UInt8(id & 0xff))
        bytes.append(0x01); bytes.append(0x00) // flags: RD=1
        bytes.append(0x00); bytes.append(0x01) // QDCOUNT = 1
        bytes.append(contentsOf: [0, 0, 0, 0, 0, 0]) // AN/NS/AR counts = 0
        bytes.append(contentsOf: encodeName(name))
        bytes.append(UInt8(type.rawValue >> 8)); bytes.append(UInt8(type.rawValue & 0xff))
        bytes.append(0x00); bytes.append(0x01) // QCLASS = IN
        return bytes
    }

    static func encodeName(_ name: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for label in name.split(separator: ".") {
            let labelBytes = Array(label.utf8)
            guard labelBytes.count <= 63 else { continue }
            bytes.append(UInt8(labelBytes.count))
            bytes.append(contentsOf: labelBytes)
        }
        bytes.append(0x00) // root
        return bytes
    }

    /// Extracts A/AAAA answers from a response. Returns [] on a malformed or empty response.
    static func decodeAnswers(_ message: [UInt8]) -> [SwiftCoreDNSAnswer] {
        guard message.count >= 12 else { return [] }
        let questionCount = Int(message[4]) << 8 | Int(message[5])
        let answerCount = Int(message[6]) << 8 | Int(message[7])
        guard answerCount > 0 else { return [] }

        var offset = 12
        for _ in 0..<questionCount {
            guard let next = skipName(message, offset) else { return [] }
            offset = next + 4 // QTYPE + QCLASS
        }

        var answers: [SwiftCoreDNSAnswer] = []
        for _ in 0..<answerCount {
            guard let afterName = skipName(message, offset), afterName + 10 <= message.count else { break }
            var cursor = afterName
            let type = UInt16(message[cursor]) << 8 | UInt16(message[cursor + 1])
            cursor += 4 // type + class
            let ttl = UInt32(message[cursor]) << 24 | UInt32(message[cursor + 1]) << 16
                | UInt32(message[cursor + 2]) << 8 | UInt32(message[cursor + 3])
            cursor += 4
            let rdLength = Int(message[cursor]) << 8 | Int(message[cursor + 1])
            cursor += 2
            guard cursor + rdLength <= message.count else { break }
            let rdata = Array(message[cursor..<cursor + rdLength])
            if type == SwiftCoreDNSRecordType.a.rawValue, rdata.count == 4 {
                answers.append(SwiftCoreDNSAnswer(address: .ipv4(rdata), ttl: ttl))
            } else if type == SwiftCoreDNSRecordType.aaaa.rawValue, rdata.count == 16 {
                answers.append(SwiftCoreDNSAnswer(address: .ipv6(rdata), ttl: ttl))
            }
            offset = cursor + rdLength
        }
        return answers
    }

    /// Advances past a (possibly compressed) name and returns the offset just after it.
    private static func skipName(_ message: [UInt8], _ start: Int) -> Int? {
        var offset = start
        while offset < message.count {
            let length = Int(message[offset])
            if length == 0 {
                return offset + 1
            }
            if length & 0xC0 == 0xC0 {
                // Compression pointer: name ends here (two bytes consumed).
                return offset + 2
            }
            offset += 1 + length
        }
        return nil
    }
}
