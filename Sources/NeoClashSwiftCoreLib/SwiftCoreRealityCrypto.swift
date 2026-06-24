import Crypto
import Foundation

/// Helpers for REALITY: base64url/hex decoding, HMAC-SHA512, and the minimal X.509 DER parsing
/// needed to pull the Ed25519 public key and signature out of the server's temporary certificate.
enum SwiftCoreRealityCrypto {
    static func base64URLDecode(_ string: String) -> [UInt8]? {
        var normalized = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while normalized.count % 4 != 0 {
            normalized.append("=")
        }
        guard let data = Data(base64Encoded: normalized) else { return nil }
        return Array(data)
    }

    static func hexDecode(_ string: String) -> [UInt8]? {
        let characters = Array(string)
        guard characters.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(characters.count / 2)
        var index = 0
        while index < characters.count {
            guard let byte = UInt8(String(characters[index...index + 1]), radix: 16) else { return nil }
            bytes.append(byte)
            index += 2
        }
        return bytes
    }

    static func hmacSHA512(key: [UInt8], message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA512>.authenticationCode(for: Data(message), using: SymmetricKey(data: Data(key))))
    }

    // MARK: Certificate parsing

    /// Extracts the first certificate (DER) from a TLS 1.3 Certificate handshake-message body:
    /// `context_len(1) | cert_list_len(3) | [ cert_len(3) cert extensions_len(2) extensions ]...`.
    static func firstCertificate(fromCertificateMessage body: [UInt8]) throws -> [UInt8] {
        var reader = SwiftCoreByteReader(body)
        let contextLength = Int(try reader.readUInt8())
        _ = try reader.readBytes(contextLength)
        let listLength = try reader.readUInt24()
        guard listLength > 0 else {
            throw SwiftCoreError.invalidConfig("REALITY: empty certificate list.")
        }
        let certificateLength = try reader.readUInt24()
        return try reader.readBytes(certificateLength)
    }

    /// Finds the Ed25519 public key inside a certificate DER by matching the fixed Ed25519
    /// SubjectPublicKeyInfo prefix (`SEQ{ SEQ{ OID 1.3.101.112 } BITSTRING(32) }`).
    static func ed25519PublicKey(fromCertificateDER der: [UInt8]) -> [UInt8]? {
        let prefix: [UInt8] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
        guard der.count >= prefix.count + 32 else { return nil }
        for start in 0...(der.count - prefix.count - 32) where Array(der[start..<start + prefix.count]) == prefix {
            let keyStart = start + prefix.count
            return Array(der[keyStart..<keyStart + 32])
        }
        return nil
    }

    /// Returns the certificate's signatureValue: the third element (a BIT STRING) of the outer
    /// Certificate SEQUENCE, with the leading unused-bits byte removed.
    static func signatureValue(fromCertificateDER der: [UInt8]) throws -> [UInt8] {
        var outer = SwiftCoreDERReader(der)
        let certificate = try outer.readElement(expectedTag: 0x30)
        var contents = SwiftCoreDERReader(certificate.content)
        _ = try contents.readElement()                      // tbsCertificate
        _ = try contents.readElement()                      // signatureAlgorithm
        let signature = try contents.readElement(expectedTag: 0x03) // signatureValue BIT STRING
        guard let first = signature.content.first, first == 0x00 else {
            throw SwiftCoreError.invalidConfig("REALITY: malformed certificate signature.")
        }
        return Array(signature.content.dropFirst())
    }
}

/// A minimal DER reader for tag-length-value elements (definite-length only).
struct SwiftCoreDERReader {
    private let bytes: [UInt8]
    private var offset: Int

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.offset = 0
    }

    struct Element {
        let tag: UInt8
        let content: [UInt8]
    }

    mutating func readElement(expectedTag: UInt8? = nil) throws -> Element {
        guard offset < bytes.count else { throw SwiftCoreError.invalidConfig("REALITY: truncated DER.") }
        let tag = bytes[offset]
        offset += 1
        if let expectedTag, tag != expectedTag {
            throw SwiftCoreError.invalidConfig("REALITY: unexpected DER tag 0x\(String(tag, radix: 16)).")
        }
        guard offset < bytes.count else { throw SwiftCoreError.invalidConfig("REALITY: truncated DER length.") }
        var length = Int(bytes[offset])
        offset += 1
        if length & 0x80 != 0 {
            let lengthBytes = length & 0x7f
            guard lengthBytes > 0, lengthBytes <= 4, offset + lengthBytes <= bytes.count else {
                throw SwiftCoreError.invalidConfig("REALITY: invalid DER length.")
            }
            length = 0
            for _ in 0..<lengthBytes {
                length = (length << 8) | Int(bytes[offset])
                offset += 1
            }
        }
        guard offset + length <= bytes.count else { throw SwiftCoreError.invalidConfig("REALITY: DER element overruns buffer.") }
        let content = Array(bytes[offset..<offset + length])
        offset += length
        return Element(tag: tag, content: content)
    }
}
