import Crypto
import Foundation

/// Per-connection REALITY client state, plugged into `SwiftCoreTLS13ClientHandler`.
///
/// On the ClientHello it splices an auth tag into the SessionId (offset 39): the TLS x25519
/// ephemeral key is reused for an ECDH with the server's static REALITY public key; that shared
/// secret is run through HKDF-SHA256 (salt = ClientHello.random[:20], info = "REALITY") to form an
/// AES-256-GCM key, which seals a 16-byte payload (version, timestamp, shortId) with nonce =
/// random[20:32] and AAD = the ClientHello with a zeroed SessionId. After the handshake it verifies
/// the server's Ed25519 certificate by checking HMAC-SHA512(authKey, ed25519PublicKey) equals the
/// certificate signature — the signal that the peer is a genuine REALITY server, not the decoy.
final class SwiftCoreRealityHandshake: SwiftCoreRealityHandshaking, @unchecked Sendable {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let helloRandom: [UInt8]
    let helloSessionId: [UInt8] // 32 zeros; the auth tag is written in finalizeClientHello

    private let serverPublicKey: [UInt8]
    private let authPayload: [UInt8] // 16 bytes: version(3) | 0 | timestamp(4) | shortId(8)
    private var authKey: [UInt8] = []

    init(publicKeyBase64: String, shortIdHex: String) throws {
        guard let serverPublicKey = SwiftCoreRealityCrypto.base64URLDecode(publicKeyBase64), serverPublicKey.count == 32 else {
            throw SwiftCoreError.invalidConfig("reality public-key must decode to 32 bytes.")
        }
        let shortId = shortIdHex.isEmpty ? [] : (SwiftCoreRealityCrypto.hexDecode(shortIdHex) ?? [])
        guard shortId.count <= 8 else {
            throw SwiftCoreError.invalidConfig("reality short-id must be at most 8 bytes.")
        }

        self.serverPublicKey = serverPublicKey
        self.privateKey = Curve25519.KeyAgreement.PrivateKey()
        self.helloRandom = swiftCoreRandomBytes(32)
        self.helloSessionId = [UInt8](repeating: 0, count: 32)

        var payload = [UInt8](repeating: 0, count: 16)
        payload[0] = 1            // client version major (only checked if the server sets min/max)
        payload[1] = 8            // client version minor
        payload[2] = 22           // client version patch
        payload[3] = 0            // reserved
        let timestamp = UInt32(Date().timeIntervalSince1970)
        payload[4] = UInt8((timestamp >> 24) & 0xff)
        payload[5] = UInt8((timestamp >> 16) & 0xff)
        payload[6] = UInt8((timestamp >> 8) & 0xff)
        payload[7] = UInt8(timestamp & 0xff)
        for index in 0..<shortId.count {
            payload[8 + index] = shortId[index]
        }
        self.authPayload = payload
    }

    func finalizeClientHello(_ message: inout [UInt8], sessionIdOffset: Int) throws {
        let serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(serverPublicKey))
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: serverKey)
        let sharedBytes = shared.withUnsafeBytes { Array($0) }

        let prk = SwiftCoreTLS13.hkdfExtract(salt: Array(helloRandom[0..<20]), ikm: sharedBytes)
        let derivedKey = SwiftCoreTLS13.hkdfExpand(prk: prk, info: Array("REALITY".utf8), length: 32)
        self.authKey = derivedKey

        // AAD is the ClientHello with a zeroed SessionId; `message` already has zeros there.
        let nonce = Array(helloRandom[20..<32])
        let sealed = try SwiftCoreAESGCM.seal(key: derivedKey, nonce: nonce, plaintext: authPayload, aad: message)
        guard sealed.count == 32 else {
            throw SwiftCoreError.invalidConfig("REALITY: unexpected sealed SessionId length.")
        }
        for index in 0..<32 {
            message[sessionIdOffset + index] = sealed[index]
        }
    }

    func verifyServerCertificate(messageBody: [UInt8]) throws {
        let certificate = try SwiftCoreRealityCrypto.firstCertificate(fromCertificateMessage: messageBody)
        guard let publicKey = SwiftCoreRealityCrypto.ed25519PublicKey(fromCertificateDER: certificate) else {
            throw SwiftCoreError.invalidConfig("REALITY: server certificate is not Ed25519 (decoy fallback).")
        }
        let signature = try SwiftCoreRealityCrypto.signatureValue(fromCertificateDER: certificate)
        let expected = SwiftCoreRealityCrypto.hmacSHA512(key: authKey, message: publicKey)
        guard expected == signature else {
            throw SwiftCoreError.invalidConfig("REALITY: certificate verification failed (not a genuine REALITY server).")
        }
    }
}
