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

    /// Reads the first question's name and QTYPE (used by the DNS server).
    static func decodeQuestion(_ message: [UInt8]) -> (name: String, type: UInt16)? {
        guard message.count >= 12, (Int(message[4]) << 8 | Int(message[5])) >= 1 else { return nil }
        var offset = 12
        var labels: [String] = []
        while offset < message.count {
            let length = Int(message[offset])
            if length == 0 { offset += 1; break }
            if length & 0xC0 == 0xC0 { offset += 2; break }
            offset += 1
            guard offset + length <= message.count else { return nil }
            labels.append(String(decoding: message[offset..<offset + length], as: UTF8.self))
            offset += length
        }
        guard offset + 2 <= message.count else { return nil }
        return (labels.joined(separator: "."), UInt16(message[offset]) << 8 | UInt16(message[offset + 1]))
    }

    /// Builds a response to `query` echoing the question and appending A/AAAA answers.
    static func encodeResponse(query: [UInt8], answers: [SwiftCoreDNSAnswer]) -> [UInt8] {
        guard let questionEnd = questionEnd(query) else { return query }
        var message = Array(query[0..<questionEnd])
        message[2] |= 0x80 // QR (response)
        message[3] = (message[3] & 0x0f) | 0x80 // RA=1, RCODE=0
        message[6] = UInt8((answers.count >> 8) & 0xff)
        message[7] = UInt8(answers.count & 0xff)
        message[8] = 0; message[9] = 0   // NSCOUNT
        message[10] = 0; message[11] = 0 // ARCOUNT
        for answer in answers {
            let type: UInt16
            let rdata: [UInt8]
            switch answer.address {
            case .ipv4(let bytes): type = SwiftCoreDNSRecordType.a.rawValue; rdata = bytes
            case .ipv6(let bytes): type = SwiftCoreDNSRecordType.aaaa.rawValue; rdata = bytes
            case .domain: continue
            }
            message.append(contentsOf: [0xC0, 0x0C]) // name -> question at offset 12
            message.append(UInt8(type >> 8)); message.append(UInt8(type & 0xff))
            message.append(0x00); message.append(0x01) // class IN
            message.append(UInt8((answer.ttl >> 24) & 0xff)); message.append(UInt8((answer.ttl >> 16) & 0xff))
            message.append(UInt8((answer.ttl >> 8) & 0xff)); message.append(UInt8(answer.ttl & 0xff))
            message.append(UInt8((rdata.count >> 8) & 0xff)); message.append(UInt8(rdata.count & 0xff))
            message.append(contentsOf: rdata)
        }
        return message
    }

    /// Offset just past the header + all questions (so the response can drop any OPT/additional).
    private static func questionEnd(_ message: [UInt8]) -> Int? {
        guard message.count >= 12 else { return nil }
        var offset = 12
        for _ in 0..<(Int(message[4]) << 8 | Int(message[5])) {
            guard let next = skipName(message, offset) else { return nil }
            offset = next + 4
            guard offset <= message.count else { return nil }
        }
        return offset
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
