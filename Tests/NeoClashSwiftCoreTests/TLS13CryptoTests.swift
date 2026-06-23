import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Validates the TLS 1.3 crypto core against published vectors: RFC 5869 (HKDF) and the well-known
/// TLS 1.3 key-schedule constants (early/derived secrets). The full handshake will be validated
/// against a live TLS 1.3 server in a later increment.
final class TLS13CryptoTests: XCTestCase {
    private func hex(_ string: String) -> [UInt8] {
        let chars = Array(string.replacingOccurrences(of: " ", with: ""))
        var bytes: [UInt8] = []
        var index = 0
        while index < chars.count {
            bytes.append(UInt8(String(chars[index...index + 1]), radix: 16)!)
            index += 2
        }
        return bytes
    }

    // RFC 5869 Test Case 1 (HKDF-SHA256).
    func testHKDFRFC5869TestCase1() {
        let ikm = [UInt8](repeating: 0x0b, count: 22)
        let salt = hex("000102030405060708090a0b0c")
        let info = hex("f0f1f2f3f4f5f6f7f8f9")

        let prk = SwiftCoreTLS13.hkdfExtract(salt: salt, ikm: ikm)
        XCTAssertEqual(prk, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))

        let okm = SwiftCoreTLS13.hkdfExpand(prk: prk, info: info, length: 42)
        XCTAssertEqual(okm, hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    }

    // TLS 1.3 Early Secret = HKDF-Extract(0, 0) and the "derived" secret over an empty transcript.
    func testTLS13EarlyAndDerivedSecrets() {
        let zeros = [UInt8](repeating: 0, count: 32)
        let early = SwiftCoreTLS13.hkdfExtract(salt: [], ikm: zeros)
        XCTAssertEqual(early, hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"))

        let derived = SwiftCoreTLS13.deriveSecret(secret: early, label: "derived", transcriptHash: SwiftCoreTLS13.transcriptHash([]))
        XCTAssertEqual(derived, hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"))
    }

    // The key schedule wires Early -> Handshake -> Master; the early secret must match the constant.
    func testKeyScheduleEarlySecretMatchesConstant() {
        let schedule = SwiftCoreTLS13KeySchedule(ecdheSharedSecret: [UInt8](repeating: 0x2a, count: 32))
        XCTAssertEqual(schedule.earlySecret, hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"))
        XCTAssertEqual(schedule.handshakeSecret.count, 32)
        XCTAssertEqual(schedule.masterSecret.count, 32)
    }

    // Record nonce: sequence 0 yields the static IV; the sequence number XORs the low 8 bytes.
    func testRecordNonceConstruction() {
        let keys = SwiftCoreTLS13RecordKeys(suite: .aes128GCMSHA256, trafficSecret: [UInt8](repeating: 0x01, count: 32))
        XCTAssertEqual(keys.iv.count, 12)
        XCTAssertEqual(keys.key.count, 16)
        XCTAssertEqual(keys.nonce(sequenceNumber: 0), keys.iv)

        var expected = keys.iv
        expected[11] ^= 0x05
        XCTAssertEqual(keys.nonce(sequenceNumber: 5), expected)
    }

    // Record AEAD round trip with the TLS 1.3 record additional data, for both suites.
    func testRecordAEADRoundTrip() throws {
        for suite in [SwiftCoreTLS13CipherSuite.aes128GCMSHA256, .chacha20Poly1305SHA256] {
            let keys = SwiftCoreTLS13RecordKeys(suite: suite, trafficSecret: [UInt8](repeating: 0x42, count: 32))
            let plaintext = Array("application data record contents".utf8)
            let recordLength = plaintext.count + 16
            let additionalData: [UInt8] = [0x17, 0x03, 0x03, UInt8(recordLength >> 8), UInt8(recordLength & 0xff)]

            let sealed = try keys.seal(plaintext: plaintext, sequenceNumber: 7, additionalData: additionalData)
            XCTAssertEqual(sealed.count, recordLength)
            let opened = try keys.open(ciphertextAndTag: sealed, sequenceNumber: 7, additionalData: additionalData)
            XCTAssertEqual(opened, plaintext, "suite \(suite)")

            // A wrong sequence number must fail authentication.
            XCTAssertThrowsError(try keys.open(ciphertextAndTag: sealed, sequenceNumber: 8, additionalData: additionalData))
        }
    }

    func testFinishedVerifyDataIsDeterministic() {
        let secret = [UInt8](repeating: 0x33, count: 32)
        let transcript = SwiftCoreTLS13.transcriptHash(Array("transcript".utf8))
        let a = SwiftCoreTLS13.finishedVerifyData(baseKey: secret, transcriptHash: transcript)
        let b = SwiftCoreTLS13.finishedVerifyData(baseKey: secret, transcriptHash: transcript)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, 32)
    }
}
