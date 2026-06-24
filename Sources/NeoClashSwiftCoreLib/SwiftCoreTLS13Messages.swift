import Crypto
import Foundation

/// TLS 1.3 record and handshake message framing, plus the ClientHello builder and ServerHello
/// parser needed by the from-scratch client. Extension ordering is browser-ish but not a byte-exact
/// Chrome JA3 — sufficient for the handshake to complete (REALITY auth lives in the SessionId, added
/// in a later increment); exact fingerprint mimicry can be tightened later.

enum SwiftCoreTLSRecordType: UInt8 {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23
}

enum SwiftCoreTLSHandshakeType: UInt8 {
    case clientHello = 1
    case serverHello = 2
    case newSessionTicket = 4
    case encryptedExtensions = 8
    case certificate = 11
    case certificateVerify = 15
    case finished = 20
}

/// Forward, append-only cursor over a byte array for parsing.
struct SwiftCoreByteReader {
    private let bytes: [UInt8]
    private(set) var offset: Int

    init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    var remaining: Int { bytes.count - offset }

    mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw SwiftCoreTLSError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readUInt16() throws -> Int {
        guard remaining >= 2 else { throw SwiftCoreTLSError.truncated }
        defer { offset += 2 }
        return Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }

    mutating func readUInt24() throws -> Int {
        guard remaining >= 3 else { throw SwiftCoreTLSError.truncated }
        defer { offset += 3 }
        return Int(bytes[offset]) << 16 | Int(bytes[offset + 1]) << 8 | Int(bytes[offset + 2])
    }

    mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard remaining >= count else { throw SwiftCoreTLSError.truncated }
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    mutating func skip(_ count: Int) throws {
        guard remaining >= count else { throw SwiftCoreTLSError.truncated }
        offset += count
    }
}

enum SwiftCoreTLSError: Error, Equatable {
    case truncated
    case unsupported(String)
    case handshakeFailed(String)
}

enum SwiftCoreTLSMessage {
    /// Wraps a payload in a TLS record header (`type | 0x0303 | length`).
    static func record(type: SwiftCoreTLSRecordType, payload: [UInt8]) -> [UInt8] {
        var record: [UInt8] = [type.rawValue, 0x03, 0x03, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)]
        record.append(contentsOf: payload)
        return record
    }

    /// Wraps a body in a handshake message header (`type | 24-bit length`).
    static func handshake(type: SwiftCoreTLSHandshakeType, body: [UInt8]) -> [UInt8] {
        var message: [UInt8] = [type.rawValue]
        message.append(UInt8((body.count >> 16) & 0xff))
        message.append(UInt8((body.count >> 8) & 0xff))
        message.append(UInt8(body.count & 0xff))
        message.append(contentsOf: body)
        return message
    }
}

struct SwiftCoreClientHello {
    let handshakeMessage: [UInt8] // type + length + body (for transcript and record payload)
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let random: [UInt8]
    let sessionId: [UInt8]
    /// Byte offset of the SessionId within `handshakeMessage` (4-byte handshake header + 2 version +
    /// 32 random + 1 session-id-length = 39). REALITY splices its auth tag here.
    let sessionIdOffset: Int

    /// Builds a TLS 1.3 ClientHello. Supply `random`/`sessionId` for REALITY (which needs a known
    /// random as HKDF salt and a crafted SessionId); otherwise random values are generated.
    init(
        serverName: String?,
        alpn: [String] = [],
        random: [UInt8]? = nil,
        sessionId: [UInt8]? = nil,
        privateKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()
    ) {
        let helloRandom = random ?? swiftCoreRandomBytes(32)
        let helloSessionId = sessionId ?? swiftCoreRandomBytes(32)
        let publicKey = Array(privateKey.publicKey.rawRepresentation)

        var body: [UInt8] = []
        body.append(contentsOf: [0x03, 0x03])          // legacy_version
        body.append(contentsOf: helloRandom)           // random (32)
        body.append(UInt8(helloSessionId.count))       // session id length
        body.append(contentsOf: helloSessionId)        // session id (32)

        // cipher_suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
        body.append(contentsOf: [0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03])
        // legacy_compression_methods: null
        body.append(contentsOf: [0x01, 0x00])

        var extensions: [UInt8] = []
        // server_name (0)
        if let serverName, !serverName.isEmpty {
            let host = Array(serverName.utf8)
            var nameEntry: [UInt8] = [0x00] // host_name
            nameEntry.append(UInt8(host.count >> 8)); nameEntry.append(UInt8(host.count & 0xff))
            nameEntry.append(contentsOf: host)
            let list: [UInt8] = [UInt8(nameEntry.count >> 8), UInt8(nameEntry.count & 0xff)] + nameEntry
            extensions.append(contentsOf: Self.extension(0x0000, list))
        }
        // ec_point_formats (11): uncompressed
        extensions.append(contentsOf: Self.extension(0x000b, [0x01, 0x00]))
        // supported_groups (10): x25519
        extensions.append(contentsOf: Self.extension(0x000a, [0x00, 0x02, 0x00, 0x1d]))
        // application_layer_protocol_negotiation (16)
        if !alpn.isEmpty {
            var protocols: [UInt8] = []
            for proto in alpn {
                let bytes = Array(proto.utf8)
                protocols.append(UInt8(bytes.count))
                protocols.append(contentsOf: bytes)
            }
            let list: [UInt8] = [UInt8(protocols.count >> 8), UInt8(protocols.count & 0xff)] + protocols
            extensions.append(contentsOf: Self.extension(0x0010, list))
        }
        // signature_algorithms (13)
        let sigAlgs: [UInt8] = [
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x05, 0x01, // rsa_pkcs1_sha384
            0x08, 0x06, // rsa_pss_rsae_sha512
            0x06, 0x01  // rsa_pkcs1_sha512
        ]
        extensions.append(contentsOf: Self.extension(0x000d, [UInt8(sigAlgs.count >> 8), UInt8(sigAlgs.count & 0xff)] + sigAlgs))
        // supported_versions (43): TLS 1.3
        extensions.append(contentsOf: Self.extension(0x002b, [0x02, 0x03, 0x04]))
        // psk_key_exchange_modes (45): psk_dhe_ke
        extensions.append(contentsOf: Self.extension(0x002d, [0x01, 0x01]))
        // key_share (51): x25519
        var keyShareEntry: [UInt8] = [0x00, 0x1d, 0x00, 0x20]
        keyShareEntry.append(contentsOf: publicKey)
        extensions.append(contentsOf: Self.extension(0x0033, [UInt8(keyShareEntry.count >> 8), UInt8(keyShareEntry.count & 0xff)] + keyShareEntry))

        body.append(UInt8(extensions.count >> 8)); body.append(UInt8(extensions.count & 0xff))
        body.append(contentsOf: extensions)

        self.handshakeMessage = SwiftCoreTLSMessage.handshake(type: .clientHello, body: body)
        self.privateKey = privateKey
        self.random = helloRandom
        self.sessionId = helloSessionId
        self.sessionIdOffset = 4 + 2 + 32 + 1
    }

    private static func `extension`(_ type: UInt16, _ data: [UInt8]) -> [UInt8] {
        [UInt8(type >> 8), UInt8(type & 0xff), UInt8(data.count >> 8), UInt8(data.count & 0xff)] + data
    }
}

struct SwiftCoreServerHello {
    let cipherSuite: SwiftCoreTLS13CipherSuite
    let serverPublicKey: [UInt8] // x25519, 32 bytes
    let sessionIdEcho: [UInt8]

    /// Parses a ServerHello handshake-message body (the bytes after the 4-byte handshake header).
    init(body: [UInt8]) throws {
        var reader = SwiftCoreByteReader(body)
        _ = try reader.readBytes(2) // legacy_version
        let random = try reader.readBytes(32)
        // HelloRetryRequest sentinel random.
        let hrr: [UInt8] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        ]
        if random == hrr {
            throw SwiftCoreTLSError.unsupported("HelloRetryRequest is not supported.")
        }
        let sessionIdLength = Int(try reader.readUInt8())
        let sessionId = try reader.readBytes(sessionIdLength)
        let suiteValue = try reader.readUInt16()
        guard let suite = SwiftCoreTLS13CipherSuite(rawValue: UInt16(suiteValue)) else {
            throw SwiftCoreTLSError.unsupported("Unsupported cipher suite 0x\(String(suiteValue, radix: 16)).")
        }
        _ = try reader.readUInt8() // legacy_compression_method

        var serverKey: [UInt8]?
        let extensionsLength = try reader.readUInt16()
        var extensionsReader = SwiftCoreByteReader(try reader.readBytes(extensionsLength))
        while extensionsReader.remaining >= 4 {
            let type = try extensionsReader.readUInt16()
            let length = try extensionsReader.readUInt16()
            let data = try extensionsReader.readBytes(length)
            if type == 0x0033 { // key_share
                var keyShareReader = SwiftCoreByteReader(data)
                _ = try keyShareReader.readUInt16() // group
                let keyLength = try keyShareReader.readUInt16()
                serverKey = try keyShareReader.readBytes(keyLength)
            }
        }
        guard let serverPublicKey = serverKey, serverPublicKey.count == 32 else {
            throw SwiftCoreTLSError.handshakeFailed("ServerHello missing an x25519 key_share.")
        }
        self.cipherSuite = suite
        self.serverPublicKey = serverPublicKey
        self.sessionIdEcho = sessionId
    }
}
