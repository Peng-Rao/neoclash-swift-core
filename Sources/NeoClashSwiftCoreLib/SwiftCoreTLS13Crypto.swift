import Crypto
import Foundation

/// The hash a TLS 1.3 cipher suite uses for its key schedule (RFC 8446). REALITY's own auth KDF is
/// always SHA-256 regardless of the negotiated suite, so SHA-256 is the default everywhere.
enum SwiftCoreTLS13Hash: Sendable {
    case sha256
    case sha384

    var length: Int { self == .sha256 ? 32 : 48 }

    func hash(_ data: [UInt8]) -> [UInt8] {
        switch self {
        case .sha256: return Array(SHA256.hash(data: Data(data)))
        case .sha384: return Array(SHA384.hash(data: Data(data)))
        }
    }

    func hmac(key: [UInt8], message: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: Data(key))
        switch self {
        case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: Data(message), using: symmetricKey))
        case .sha384: return Array(HMAC<SHA384>.authenticationCode(for: Data(message), using: symmetricKey))
        }
    }
}

/// TLS 1.3 (RFC 8446) cryptographic core: HKDF, the key-schedule secret derivation, traffic-key
/// derivation, and the record-layer AEAD nonce construction. The foundation of the from-scratch
/// TLS 1.3 client required by REALITY (which needs control over the ClientHello that
/// swift-nio-ssl / BoringSSL does not expose).
enum SwiftCoreTLS13 {
    static func transcriptHash(_ data: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        hash.hash(data)
    }

    static func hmac(key: [UInt8], message: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        hash.hmac(key: key, message: message)
    }

    // MARK: HKDF (RFC 5869)

    static func hkdfExtract(salt: [UInt8], ikm: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        let effectiveSalt = salt.isEmpty ? [UInt8](repeating: 0, count: hash.length) : salt
        return hash.hmac(key: effectiveSalt, message: ikm)
    }

    static func hkdfExpand(prk: [UInt8], info: [UInt8], length: Int, hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        var output: [UInt8] = []
        var block: [UInt8] = []
        var counter: UInt8 = 1
        while output.count < length {
            block = hash.hmac(key: prk, message: block + info + [counter])
            output.append(contentsOf: block)
            counter &+= 1
        }
        return Array(output.prefix(length))
    }

    // MARK: TLS 1.3 key schedule (RFC 8446 §7.1)

    static func hkdfExpandLabel(secret: [UInt8], label: String, context: [UInt8], length: Int, hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        let fullLabel = Array("tls13 ".utf8) + Array(label.utf8)
        var info: [UInt8] = []
        info.append(UInt8((length >> 8) & 0xff))
        info.append(UInt8(length & 0xff))
        info.append(UInt8(fullLabel.count))
        info.append(contentsOf: fullLabel)
        info.append(UInt8(context.count))
        info.append(contentsOf: context)
        return hkdfExpand(prk: secret, info: info, length: length, hash: hash)
    }

    static func deriveSecret(secret: [UInt8], label: String, transcriptHash: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        hkdfExpandLabel(secret: secret, label: label, context: transcriptHash, length: hash.length, hash: hash)
    }

    static func finishedKey(baseKey: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        hkdfExpandLabel(secret: baseKey, label: "finished", context: [], length: hash.length, hash: hash)
    }

    /// The verify_data for a Finished message: HMAC(finished_key, transcript_hash).
    static func finishedVerifyData(baseKey: [UInt8], transcriptHash: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) -> [UInt8] {
        hash.hmac(key: finishedKey(baseKey: baseKey, hash: hash), message: transcriptHash)
    }
}

/// Derives the early/handshake/master secrets and the handshake/application traffic secrets from an
/// ECDHE shared secret and the running transcript hashes (RFC 8446 §7.1).
struct SwiftCoreTLS13KeySchedule {
    let hash: SwiftCoreTLS13Hash
    let earlySecret: [UInt8]
    let handshakeSecret: [UInt8]
    let masterSecret: [UInt8]

    init(ecdheSharedSecret: [UInt8], hash: SwiftCoreTLS13Hash = .sha256) {
        self.hash = hash
        let emptyHash = SwiftCoreTLS13.transcriptHash([], hash: hash)
        let zeros = [UInt8](repeating: 0, count: hash.length)

        let early = SwiftCoreTLS13.hkdfExtract(salt: [], ikm: zeros, hash: hash)
        let derived1 = SwiftCoreTLS13.deriveSecret(secret: early, label: "derived", transcriptHash: emptyHash, hash: hash)
        let handshake = SwiftCoreTLS13.hkdfExtract(salt: derived1, ikm: ecdheSharedSecret, hash: hash)
        let derived2 = SwiftCoreTLS13.deriveSecret(secret: handshake, label: "derived", transcriptHash: emptyHash, hash: hash)
        let master = SwiftCoreTLS13.hkdfExtract(salt: derived2, ikm: zeros, hash: hash)

        self.earlySecret = early
        self.handshakeSecret = handshake
        self.masterSecret = master
    }

    func clientHandshakeTrafficSecret(transcriptHash: [UInt8]) -> [UInt8] {
        SwiftCoreTLS13.deriveSecret(secret: handshakeSecret, label: "c hs traffic", transcriptHash: transcriptHash, hash: hash)
    }

    func serverHandshakeTrafficSecret(transcriptHash: [UInt8]) -> [UInt8] {
        SwiftCoreTLS13.deriveSecret(secret: handshakeSecret, label: "s hs traffic", transcriptHash: transcriptHash, hash: hash)
    }

    func clientApplicationTrafficSecret(transcriptHash: [UInt8]) -> [UInt8] {
        SwiftCoreTLS13.deriveSecret(secret: masterSecret, label: "c ap traffic", transcriptHash: transcriptHash, hash: hash)
    }

    func serverApplicationTrafficSecret(transcriptHash: [UInt8]) -> [UInt8] {
        SwiftCoreTLS13.deriveSecret(secret: masterSecret, label: "s ap traffic", transcriptHash: transcriptHash, hash: hash)
    }
}

/// The AEAD cipher suites a TLS 1.3 client may negotiate.
enum SwiftCoreTLS13CipherSuite: UInt16, Sendable {
    case aes128GCMSHA256 = 0x1301
    case aes256GCMSHA384 = 0x1302
    case chacha20Poly1305SHA256 = 0x1303

    var keyLength: Int {
        switch self {
        case .aes128GCMSHA256: return 16
        case .aes256GCMSHA384: return 32
        case .chacha20Poly1305SHA256: return 32
        }
    }

    var hash: SwiftCoreTLS13Hash {
        self == .aes256GCMSHA384 ? .sha384 : .sha256
    }

    var usesChaCha: Bool { self == .chacha20Poly1305SHA256 }
}

/// Per-direction record-protection keys and the RFC 8446 §5.3 nonce construction (the static IV
/// XORed with the big-endian record sequence number).
struct SwiftCoreTLS13RecordKeys {
    let suite: SwiftCoreTLS13CipherSuite
    let key: [UInt8]
    let iv: [UInt8] // 12 bytes

    init(suite: SwiftCoreTLS13CipherSuite, trafficSecret: [UInt8]) {
        self.suite = suite
        self.key = SwiftCoreTLS13.hkdfExpandLabel(secret: trafficSecret, label: "key", context: [], length: suite.keyLength, hash: suite.hash)
        self.iv = SwiftCoreTLS13.hkdfExpandLabel(secret: trafficSecret, label: "iv", context: [], length: 12, hash: suite.hash)
    }

    func nonce(sequenceNumber: UInt64) -> [UInt8] {
        var nonce = iv
        let sequence = withUnsafeBytes(of: sequenceNumber.bigEndian) { Array($0) } // 8 bytes
        for index in 0..<8 {
            nonce[4 + index] ^= sequence[index]
        }
        return nonce
    }

    func seal(plaintext: [UInt8], sequenceNumber: UInt64, additionalData: [UInt8]) throws -> [UInt8] {
        let nonceBytes = nonce(sequenceNumber: sequenceNumber)
        if suite.usesChaCha {
            let box = try ChaChaPoly.seal(
                Data(plaintext),
                using: SymmetricKey(data: Data(key)),
                nonce: ChaChaPoly.Nonce(data: Data(nonceBytes)),
                authenticating: Data(additionalData)
            )
            return Array(box.ciphertext) + Array(box.tag)
        }
        let box = try AES.GCM.seal(
            Data(plaintext),
            using: SymmetricKey(data: Data(key)),
            nonce: AES.GCM.Nonce(data: Data(nonceBytes)),
            authenticating: Data(additionalData)
        )
        return Array(box.ciphertext) + Array(box.tag)
    }

    func open(ciphertextAndTag: [UInt8], sequenceNumber: UInt64, additionalData: [UInt8]) throws -> [UInt8] {
        guard ciphertextAndTag.count >= 16 else {
            throw SwiftCoreError.invalidConfig("TLS 1.3 record too small to contain an AEAD tag.")
        }
        let split = ciphertextAndTag.count - 16
        let ciphertext = Data(ciphertextAndTag[0..<split])
        let tag = Data(ciphertextAndTag[split...])
        let nonceBytes = nonce(sequenceNumber: sequenceNumber)
        if suite.usesChaCha {
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: Data(nonceBytes)), ciphertext: ciphertext, tag: tag)
            return Array(try ChaChaPoly.open(box, using: SymmetricKey(data: Data(key)), authenticating: Data(additionalData)))
        }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(nonceBytes)), ciphertext: ciphertext, tag: tag)
        return Array(try AES.GCM.open(box, using: SymmetricKey(data: Data(key)), authenticating: Data(additionalData)))
    }
}
