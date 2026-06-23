import Crypto
import Foundation

/// Cryptographic primitives required by VMessAEAD that are not provided by swift-crypto's `Crypto`
/// module — notably a single-block AES-128 cipher (for the encrypted auth id) and the recursive
/// HMAC-SHA256 KDF. AEAD sealing/opening reuses `Crypto`'s `AES.GCM` and `ChaChaPoly`.

func swiftCoreRandomBytes(_ count: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    for index in bytes.indices {
        bytes[index] = UInt8.random(in: 0...255)
    }
    return bytes
}

// MARK: - AES-128 single block

/// Minimal AES-128 block cipher. Only single-block encryption is needed (VMess auth id),
/// which `Crypto` does not expose. Validated against the FIPS-197 test vector in the test suite.
struct SwiftCoreAES128Block {
    private static let sbox: [UInt8] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    private static let rcon: [UInt8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    private let roundKeys: [[UInt8]] // 11 round keys of 16 bytes

    init(key: [UInt8]) {
        precondition(key.count == 16, "AES-128 requires a 16-byte key")
        var words: [[UInt8]] = []
        for index in 0..<4 {
            words.append(Array(key[(index * 4)..<(index * 4 + 4)]))
        }
        for index in 4..<44 {
            var temp = words[index - 1]
            if index % 4 == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]].map { Self.sbox[Int($0)] }
                temp[0] ^= Self.rcon[index / 4 - 1]
            }
            let previous = words[index - 4]
            words.append([
                previous[0] ^ temp[0],
                previous[1] ^ temp[1],
                previous[2] ^ temp[2],
                previous[3] ^ temp[3]
            ])
        }
        var keys: [[UInt8]] = []
        for round in 0..<11 {
            var roundKey: [UInt8] = []
            for column in 0..<4 {
                roundKey.append(contentsOf: words[round * 4 + column])
            }
            keys.append(roundKey)
        }
        roundKeys = keys
    }

    func encrypt(_ block: [UInt8]) -> [UInt8] {
        precondition(block.count == 16, "AES block must be 16 bytes")
        var state = block
        addRoundKey(&state, roundKeys[0])
        for round in 1..<10 {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, roundKeys[round])
        }
        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, roundKeys[10])
        return state
    }

    private func addRoundKey(_ state: inout [UInt8], _ key: [UInt8]) {
        for index in 0..<16 { state[index] ^= key[index] }
    }

    private func subBytes(_ state: inout [UInt8]) {
        for index in 0..<16 { state[index] = Self.sbox[Int(state[index])] }
    }

    private func shiftRows(_ state: inout [UInt8]) {
        var temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp
        temp = state[2]; state[2] = state[10]; state[10] = temp
        temp = state[6]; state[6] = state[14]; state[14] = temp
        temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp
    }

    private func mixColumns(_ state: inout [UInt8]) {
        func xtime(_ value: UInt8) -> UInt8 {
            ((value << 1) ^ ((value & 0x80) != 0 ? 0x1b : 0x00)) & 0xff
        }
        for column in 0..<4 {
            let base = column * 4
            let a0 = state[base], a1 = state[base + 1], a2 = state[base + 2], a3 = state[base + 3]
            state[base]     = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
            state[base + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
            state[base + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
            state[base + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
        }
    }
}

// MARK: - Recursive HMAC-SHA256 KDF (VMess AEAD)

/// A "hash function" that is either SHA-256 or a keyed HMAC whose underlying hash is itself one of
/// these — exactly the nested construction v2ray's VMess AEAD KDF uses. All levels are SHA-256
/// based, so the block size is always 64.
private final class SwiftCoreVMessHash {
    enum Kind {
        case sha256
        case hmac(key: [UInt8], parent: SwiftCoreVMessHash)
    }

    private let kind: Kind
    let blockSize = 64

    init(_ kind: Kind) {
        self.kind = kind
    }

    func hash(_ message: [UInt8]) -> [UInt8] {
        switch kind {
        case .sha256:
            return Array(SHA256.hash(data: Data(message)))
        case .hmac(let key, let parent):
            var paddedKey = key
            if paddedKey.count > parent.blockSize {
                paddedKey = parent.hash(paddedKey)
            }
            if paddedKey.count < parent.blockSize {
                paddedKey += [UInt8](repeating: 0, count: parent.blockSize - paddedKey.count)
            }
            let inner = parent.hash(paddedKey.map { $0 ^ 0x36 } + message)
            return parent.hash(paddedKey.map { $0 ^ 0x5c } + inner)
        }
    }
}

func swiftCoreVMessKDF(key: [UInt8], path: [[UInt8]]) -> [UInt8] {
    var hash = SwiftCoreVMessHash(.hmac(key: Array("VMess AEAD KDF".utf8), parent: SwiftCoreVMessHash(.sha256)))
    for element in path {
        hash = SwiftCoreVMessHash(.hmac(key: element, parent: hash))
    }
    return hash.hash(key)
}

func swiftCoreVMessKDF16(key: [UInt8], path: [[UInt8]]) -> [UInt8] {
    Array(swiftCoreVMessKDF(key: key, path: path).prefix(16))
}

// MARK: - Hashing helpers

func swiftCoreVMessCmdKey(uuid: [UInt8]) -> [UInt8] {
    var data = uuid
    data.append(contentsOf: Array("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8))
    return Array(Insecure.MD5.hash(data: Data(data)))
}

/// ChaCha20-Poly1305 key derivation used by VMess: md5(key) || md5(md5(key)).
func swiftCoreVMessChaChaKey(_ key: [UInt8]) -> [UInt8] {
    let first = Array(Insecure.MD5.hash(data: Data(key)))
    let second = Array(Insecure.MD5.hash(data: Data(first)))
    return first + second
}

func swiftCoreFNV1a(_ data: [UInt8]) -> UInt32 {
    var hash: UInt32 = 2_166_136_261
    for byte in data {
        hash ^= UInt32(byte)
        hash = hash &* 16_777_619
    }
    return hash
}

func swiftCoreCRC32(_ data: [UInt8]) -> UInt32 {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in data {
        crc ^= UInt32(byte)
        for _ in 0..<8 {
            crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : (crc >> 1)
        }
    }
    return ~crc
}

// MARK: - AEAD body ciphers

enum SwiftCoreVMessSecurity: Sendable {
    case aesGCM
    case chacha20Poly1305

    var securityByte: UInt8 {
        switch self {
        case .aesGCM: return 0x03
        case .chacha20Poly1305: return 0x04
        }
    }
}

/// A length-prefixed AEAD chunk cipher. `seal`/`open` operate on a single chunk; the 12-byte
/// nonce is `count`(2, big-endian) || iv[2:12], matching v2ray's VMess body framing.
struct SwiftCoreVMessBodyCipher {
    private let security: SwiftCoreVMessSecurity
    private let key: SymmetricKey
    private let nonceBase: [UInt8] // 12 bytes (iv[0:12]); bytes 0..1 overwritten by the counter

    init(security: SwiftCoreVMessSecurity, key: [UInt8], iv: [UInt8]) {
        self.security = security
        switch security {
        case .aesGCM:
            self.key = SymmetricKey(data: Data(key))
        case .chacha20Poly1305:
            self.key = SymmetricKey(data: Data(swiftCoreVMessChaChaKey(key)))
        }
        self.nonceBase = Array(iv.prefix(12))
    }

    private func nonce(count: UInt16) -> [UInt8] {
        var bytes = nonceBase
        bytes[0] = UInt8(count >> 8)
        bytes[1] = UInt8(count & 0xff)
        return bytes
    }

    /// Returns ciphertext || tag for the chunk.
    func seal(_ plaintext: [UInt8], count: UInt16) throws -> [UInt8] {
        let nonceBytes = nonce(count: count)
        switch security {
        case .aesGCM:
            let box = try AES.GCM.seal(Data(plaintext), using: key, nonce: AES.GCM.Nonce(data: Data(nonceBytes)))
            return Array(box.ciphertext) + Array(box.tag)
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(Data(plaintext), using: key, nonce: ChaChaPoly.Nonce(data: Data(nonceBytes)))
            return Array(box.ciphertext) + Array(box.tag)
        }
    }

    func open(_ ciphertextAndTag: [UInt8], count: UInt16) throws -> [UInt8] {
        guard ciphertextAndTag.count >= 16 else {
            throw SwiftCoreError.invalidConfig("VMess chunk too small to contain an AEAD tag.")
        }
        let split = ciphertextAndTag.count - 16
        let ciphertext = Data(ciphertextAndTag[0..<split])
        let tag = Data(ciphertextAndTag[split...])
        let nonceBytes = nonce(count: count)
        switch security {
        case .aesGCM:
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(nonceBytes)), ciphertext: ciphertext, tag: tag)
            return Array(try AES.GCM.open(box, using: key))
        case .chacha20Poly1305:
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: Data(nonceBytes)), ciphertext: ciphertext, tag: tag)
            return Array(try ChaChaPoly.open(box, using: key))
        }
    }
}

// MARK: - AES-128-GCM helpers for the VMess header

enum SwiftCoreAESGCM {
    static func seal(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        let box = try AES.GCM.seal(
            Data(plaintext),
            using: SymmetricKey(data: Data(key)),
            nonce: AES.GCM.Nonce(data: Data(nonce)),
            authenticating: Data(aad)
        )
        return Array(box.ciphertext) + Array(box.tag)
    }

    static func open(key: [UInt8], nonce: [UInt8], ciphertextAndTag: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        guard ciphertextAndTag.count >= 16 else {
            throw SwiftCoreError.invalidConfig("VMess header block too small to contain an AEAD tag.")
        }
        let split = ciphertextAndTag.count - 16
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Data(nonce)),
            ciphertext: Data(ciphertextAndTag[0..<split]),
            tag: Data(ciphertextAndTag[split...])
        )
        return Array(try AES.GCM.open(box, using: SymmetricKey(data: Data(key)), authenticating: Data(aad)))
    }
}
