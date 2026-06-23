import Crypto
import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Unit tests for the outbound adapter primitives: crypto building blocks and the VLESS/VMess wire
/// formats. The VMess tests verify self-consistency (this client's encoder against a decoder built
/// from the same primitives); true interop is covered by manual verification against a real server.
final class OutboundCryptoTests: XCTestCase {
    // MARK: Crypto primitives

    func testAES128MatchesFIPS197Vector() {
        let key: [UInt8] = (0...15).map { UInt8($0) }
        let plaintext: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        let expected: [UInt8] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
        ]
        XCTAssertEqual(SwiftCoreAES128Block(key: key).encrypt(plaintext), expected)
    }

    func testCRC32KnownVector() {
        XCTAssertEqual(swiftCoreCRC32(Array("123456789".utf8)), 0xCBF4_3926)
    }

    func testFNV1aOffsetBasis() {
        XCTAssertEqual(swiftCoreFNV1a([]), 2_166_136_261)
    }

    func testAddressDetection() {
        if case .ipv4(let bytes) = SwiftCoreAddress.detect(host: "127.0.0.1") {
            XCTAssertEqual(bytes, [127, 0, 0, 1])
        } else {
            XCTFail("Expected IPv4")
        }
        if case .ipv6 = SwiftCoreAddress.detect(host: "::1") {} else {
            XCTFail("Expected IPv6")
        }
        if case .domain(let name) = SwiftCoreAddress.detect(host: "example.com") {
            XCTAssertEqual(name, "example.com")
        } else {
            XCTFail("Expected domain")
        }
    }

    // MARK: VLESS

    func testVLESSRequestHeaderEncoding() {
        let uuid = [UInt8](repeating: 0xAB, count: 16)
        let request = SwiftCoreOutboundRequest(host: "example.com", port: 443)
        let header = SwiftCoreVLESSProtocol.requestHeader(uuid: uuid, request: request)

        XCTAssertEqual(header[0], 0x00)                       // version
        XCTAssertEqual(Array(header[1..<17]), uuid)          // uuid
        XCTAssertEqual(header[17], 0x00)                      // addon length
        XCTAssertEqual(header[18], 0x01)                      // command: TCP
        XCTAssertEqual(header[19], UInt8(443 >> 8))           // port high
        XCTAssertEqual(header[20], UInt8(443 & 0xff))         // port low
        XCTAssertEqual(header[21], 0x02)                      // atyp: domain
        let domainLength = Int(header[22])
        XCTAssertEqual(domainLength, "example.com".utf8.count)
        XCTAssertEqual(Array(header[23..<(23 + domainLength)]), Array("example.com".utf8))
    }

    // MARK: Configuration

    func testConfigurationParsesVlessAndVmessProxies() throws {
        let yaml = """
        mixed-port: 7890
        external-controller: 127.0.0.1:9090
        secret: s
        proxies:
          - { name: v, type: vless, server: a.example, port: 443, uuid: 11111111-1111-1111-1111-111111111111, tls: true, servername: a.example }
          - { name: m, type: vmess, server: b.example, port: 8443, uuid: 22222222-2222-2222-2222-222222222222, alterId: 0, cipher: auto }
        proxy-groups:
          - { name: G, type: select, proxies: [v, m, DIRECT] }
        rules:
          - MATCH,G
        """
        let config = try SwiftCoreConfiguration.parse(yaml: yaml)

        let vless = try XCTUnwrap(config.proxies.first { $0.name == "v" })
        XCTAssertEqual(vless.type, "vless")
        XCTAssertEqual(vless.server, "a.example")
        XCTAssertEqual(vless.port, 443)
        XCTAssertTrue(vless.tls)
        XCTAssertEqual(vless.servername, "a.example")

        let vmess = try XCTUnwrap(config.proxies.first { $0.name == "m" })
        XCTAssertEqual(vmess.cipher, "auto")
        XCTAssertEqual(vmess.alterId, 0)

        // Both adapters build without throwing.
        XCTAssertNotNil(try SwiftCoreOutboundFactory.make(proxy: vless))
        XCTAssertNotNil(try SwiftCoreOutboundFactory.make(proxy: vmess))

        // Unsupported proxy types build to nil rather than throwing.
        XCTAssertNil(try SwiftCoreOutboundFactory.make(proxy: SwiftCoreProxy(name: "x", type: "hysteria2")))
    }

    func testVMessRejectsUnsupportedConfig() {
        XCTAssertThrowsError(try SwiftCoreOutboundFactory.make(
            proxy: SwiftCoreProxy(name: "m", type: "vmess", server: "a", port: 443, uuid: "not-a-uuid")
        ))
        XCTAssertThrowsError(try SwiftCoreOutboundFactory.make(
            proxy: SwiftCoreProxy(name: "m", type: "vmess", server: "a", port: 443,
                                  uuid: "22222222-2222-2222-2222-222222222222", alterId: 64)
        ))
    }

    // MARK: VMess wire format (self-consistent round trips)

    private func makeSession(security: SwiftCoreVMessSecurity = .aesGCM) -> (SwiftCoreVMessSession, [UInt8], [UInt8], [UInt8], UInt8) {
        let cmdKey = swiftCoreVMessCmdKey(uuid: (try? SwiftCoreProxyEncoding.parseUUID("11111111-1111-1111-1111-111111111111")) ?? [])
        let requestKey = [UInt8](repeating: 0xA1, count: 16)
        let requestIV = [UInt8](repeating: 0xB2, count: 16)
        let responseV: UInt8 = 0x7E
        let session = SwiftCoreVMessSession(
            cmdKey: cmdKey,
            security: security,
            request: SwiftCoreOutboundRequest(host: "example.com", port: 443),
            requestKey: requestKey,
            requestIV: requestIV,
            responseHeaderByte: responseV
        )
        return (session, cmdKey, requestKey, requestIV, responseV)
    }

    func testVMessRequestHeaderRoundTrip() throws {
        let (session, cmdKey, requestKey, requestIV, responseV) = makeSession()
        let wire = try session.encodeRequestHeader()

        let authID = Array(wire[0..<16])
        let lengthBlock = Array(wire[16..<34])
        let connectionNonce = Array(wire[34..<42])
        let payloadBlock = Array(wire[42...])

        let lengthKey = swiftCoreVMessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
        let lengthNonce = Array(swiftCoreVMessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
        let lengthPlain = try SwiftCoreAESGCM.open(key: lengthKey, nonce: lengthNonce, ciphertextAndTag: lengthBlock, aad: authID)
        let headerLength = Int(lengthPlain[0]) << 8 | Int(lengthPlain[1])
        XCTAssertEqual(payloadBlock.count, headerLength + 16)

        let payloadKey = swiftCoreVMessKDF16(key: cmdKey, path: [Array("VMess Header AEAD Key".utf8), authID, connectionNonce])
        let payloadNonce = Array(swiftCoreVMessKDF(key: cmdKey, path: [Array("VMess Header AEAD Nonce".utf8), authID, connectionNonce]).prefix(12))
        let header = try SwiftCoreAESGCM.open(key: payloadKey, nonce: payloadNonce, ciphertextAndTag: payloadBlock, aad: authID)

        XCTAssertEqual(header[0], 0x01)                          // version
        XCTAssertEqual(Array(header[1..<17]), requestIV)         // body IV
        XCTAssertEqual(Array(header[17..<33]), requestKey)       // body key
        XCTAssertEqual(header[33], responseV)                    // V
        XCTAssertEqual(header[34], 0x01)                         // option: chunk stream
        XCTAssertEqual(header[35] & 0x0f, 0x03)                  // security: aes-128-gcm
        XCTAssertEqual(header[36], 0x00)                         // reserved
        XCTAssertEqual(header[37], 0x01)                         // command: TCP
        XCTAssertEqual(Int(header[38]) << 8 | Int(header[39]), 443)
        XCTAssertEqual(header[40], 0x02)                         // atyp: domain
        let domainLength = Int(header[41])
        XCTAssertEqual(domainLength, "example.com".utf8.count)
        XCTAssertEqual(Array(header[42..<(42 + domainLength)]), Array("example.com".utf8))

        let checksumStart = header.count - 4
        let checksumBody = Array(header[0..<checksumStart])
        let expected = swiftCoreFNV1a(checksumBody)
        let actual = UInt32(header[checksumStart]) << 24
            | UInt32(header[checksumStart + 1]) << 16
            | UInt32(header[checksumStart + 2]) << 8
            | UInt32(header[checksumStart + 3])
        XCTAssertEqual(actual, expected)
    }

    func testVMessBodyRoundTrip() throws {
        for security in [SwiftCoreVMessSecurity.aesGCM, .chacha20Poly1305] {
            let (session, _, requestKey, requestIV, _) = makeSession(security: security)
            let plaintext = Array("hello vmess body, this is a chunk".utf8)
            let framed = try session.encodeBody(plaintext)

            let cipher = SwiftCoreVMessBodyCipher(security: security, key: requestKey, iv: requestIV)
            var buffer = framed
            var recovered: [UInt8] = []
            var count: UInt16 = 0
            while buffer.count >= 2 {
                let size = Int(buffer[0]) << 8 | Int(buffer[1])
                let sealed = Array(buffer[2..<(2 + size)])
                buffer.removeFirst(2 + size)
                recovered.append(contentsOf: try cipher.open(sealed, count: count))
                count = count &+ 1
            }
            XCTAssertEqual(recovered, plaintext, "security \(security)")
        }
    }

    func testVMessResponseRoundTrip() throws {
        let (session, _, requestKey, requestIV, responseV) = makeSession()
        let responseKey = Array(SHA256.hash(data: Data(requestKey)).prefix(16))
        let responseIV = Array(SHA256.hash(data: Data(requestIV)).prefix(16))

        // Server side: AEAD response header [V, 0, 0, 0].
        let headerBytes: [UInt8] = [responseV, 0x00, 0x00, 0x00]
        let lengthKey = swiftCoreVMessKDF16(key: responseKey, path: [Array("AEAD Resp Header Len Key".utf8)])
        let lengthNonce = Array(swiftCoreVMessKDF(key: responseIV, path: [Array("AEAD Resp Header Len IV".utf8)]).prefix(12))
        let lengthSealed = try SwiftCoreAESGCM.seal(key: lengthKey, nonce: lengthNonce, plaintext: [0x00, UInt8(headerBytes.count)], aad: [])
        let payloadKey = swiftCoreVMessKDF16(key: responseKey, path: [Array("AEAD Resp Header Key".utf8)])
        let payloadNonce = Array(swiftCoreVMessKDF(key: responseIV, path: [Array("AEAD Resp Header IV".utf8)]).prefix(12))
        let payloadSealed = try SwiftCoreAESGCM.seal(key: payloadKey, nonce: payloadNonce, plaintext: headerBytes, aad: [])

        var wire = lengthSealed + payloadSealed

        // Server side: one AEAD body chunk.
        let responseCipher = SwiftCoreVMessBodyCipher(security: .aesGCM, key: responseKey, iv: responseIV)
        let payload = Array("response payload over vmess".utf8)
        let sealedBody = try responseCipher.seal(payload, count: 0)
        wire.append(UInt8(sealedBody.count >> 8))
        wire.append(UInt8(sealedBody.count & 0xff))
        wire.append(contentsOf: sealedBody)

        // Client side decode.
        var buffer = wire
        XCTAssertTrue(try session.decodeResponseHeader(&buffer))
        let recovered = try session.decodeBody(&buffer)
        XCTAssertEqual(recovered, payload)
    }
}
