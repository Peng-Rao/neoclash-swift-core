import Crypto
import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Hermetic REALITY tests: they reproduce the server-side `Open` and certificate-signing logic
/// (from XTLS/REALITY) to verify our client's ClientHello auth tag authenticates and that our
/// certificate verification accepts a genuine REALITY cert while rejecting a forged one.
final class RealityTests: XCTestCase {
    private func base64URL(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func u24(_ value: Int) -> [UInt8] {
        [UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
    }

    private func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        precondition(content.count < 0x80, "test DER helper only supports short-form lengths")
        return [tag, UInt8(content.count)] + content
    }

    /// Builds a minimal Ed25519 certificate DER whose signature field is `signature`.
    private func ed25519Certificate(publicKey: [UInt8], signature: [UInt8]) -> [UInt8] {
        let spki: [UInt8] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00] + publicKey
        let tbs = der(0x30, spki)
        let signatureAlgorithm: [UInt8] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
        let signatureValue = der(0x03, [0x00] + signature)
        return der(0x30, tbs + signatureAlgorithm + signatureValue)
    }

    private func certificateMessage(_ certificateDER: [UInt8]) -> [UInt8] {
        let entry = u24(certificateDER.count) + certificateDER + [0x00, 0x00]
        return [0x00] + u24(entry.count) + entry
    }

    func testClientHelloAuthenticatesAndCertificateVerifies() throws {
        // Server static REALITY keypair.
        let serverPrivate = Curve25519.KeyAgreement.PrivateKey()
        let serverPublic = Array(serverPrivate.publicKey.rawRepresentation)
        let shortIdHex = "1688"

        let reality = try SwiftCoreRealityHandshake(publicKeyBase64: base64URL(serverPublic), shortIdHex: shortIdHex)

        // Build and finalize the ClientHello exactly as the TLS 1.3 client would.
        let hello = SwiftCoreClientHello(
            serverName: "www.microsoft.com",
            alpn: ["h2", "http/1.1"],
            random: reality.helloRandom,
            sessionId: reality.helloSessionId,
            privateKey: reality.privateKey
        )
        var message = hello.handshakeMessage
        try reality.finalizeClientHello(&message, sessionIdOffset: hello.sessionIdOffset)

        // --- Server side: reproduce the REALITY Open ---
        let clientRandom = reality.helloRandom
        let clientPublic = Array(reality.privateKey.publicKey.rawRepresentation)
        let sealedSessionId = Array(message[hello.sessionIdOffset..<hello.sessionIdOffset + 32])

        let serverShared = try serverPrivate.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(clientPublic))
        ).withUnsafeBytes { Array($0) }
        let prk = SwiftCoreTLS13.hkdfExtract(salt: Array(clientRandom[0..<20]), ikm: serverShared)
        let authKey = SwiftCoreTLS13.hkdfExpand(prk: prk, info: Array("REALITY".utf8), length: 32)

        var aad = message
        for index in hello.sessionIdOffset..<hello.sessionIdOffset + 32 {
            aad[index] = 0
        }
        let plaintext = try SwiftCoreAESGCM.open(
            key: authKey,
            nonce: Array(clientRandom[20..<32]),
            ciphertextAndTag: sealedSessionId,
            aad: aad
        )

        XCTAssertEqual(plaintext.count, 16)
        XCTAssertEqual(Array(plaintext[0..<3]), [1, 8, 22]) // client version
        XCTAssertEqual(Array(plaintext[8..<10]), [0x16, 0x88]) // shortId

        // --- Server side: sign the temp certificate, client must verify it ---
        let edPublicKey = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let signature = SwiftCoreRealityCrypto.hmacSHA512(key: authKey, message: edPublicKey)
        let certificate = ed25519Certificate(publicKey: edPublicKey, signature: signature)
        XCTAssertNoThrow(try reality.verifyServerCertificate(messageBody: certificateMessage(certificate)))

        // A certificate signed with the wrong key must be rejected (decoy fallback).
        let badSignature = SwiftCoreRealityCrypto.hmacSHA512(key: [UInt8](repeating: 0, count: 32), message: edPublicKey)
        let badCertificate = ed25519Certificate(publicKey: edPublicKey, signature: badSignature)
        XCTAssertThrowsError(try reality.verifyServerCertificate(messageBody: certificateMessage(badCertificate)))
    }

    func testRealityRejectsInvalidPublicKey() {
        XCTAssertThrowsError(try SwiftCoreRealityHandshake(publicKeyBase64: "not-valid", shortIdHex: "1688"))
    }

    func testDERHelpersExtractKeyAndSignature() throws {
        let publicKey = swiftCoreRandomBytes(32)
        let signature = swiftCoreRandomBytes(64)
        let certificate = ed25519Certificate(publicKey: publicKey, signature: signature)
        XCTAssertEqual(SwiftCoreRealityCrypto.ed25519PublicKey(fromCertificateDER: certificate), publicKey)
        XCTAssertEqual(try SwiftCoreRealityCrypto.signatureValue(fromCertificateDER: certificate), signature)
    }
}
