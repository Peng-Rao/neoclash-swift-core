import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

final class TUNTests: XCTestCase {
    // MARK: Packet parsing

    func testParseTCPSyn() {
        var tcp = [UInt8](repeating: 0, count: 20)
        tcp[0] = 0xC7; tcp[1] = 0x38   // source port 51000
        tcp[2] = 0x01; tcp[3] = 0xBB   // destination port 443
        tcp[12] = 0x50                 // data offset (5 words)
        tcp[13] = 0x02                 // SYN
        let packet = Self.ipv4(proto: SwiftCoreIPProtocol.tcp, source: [10, 0, 0, 2], destination: [93, 184, 216, 34], payload: tcp)

        let ip = SwiftCoreIPv4Packet(packet)
        XCTAssertEqual(ip?.proto, SwiftCoreIPProtocol.tcp)
        XCTAssertEqual(ip?.source, [10, 0, 0, 2])
        XCTAssertEqual(ip?.destination, [93, 184, 216, 34])
        let header = SwiftCoreTCPHeader(try! XCTUnwrap(ip).payload)
        XCTAssertEqual(header?.sourcePort, 51000)
        XCTAssertEqual(header?.destinationPort, 443)
        XCTAssertEqual(header?.isSYN, true)
        XCTAssertEqual(header?.isACK, false)
    }

    func testParseUDP() {
        var udp = [UInt8](repeating: 0, count: 12)
        udp[0] = 0xCF; udp[1] = 0x2E   // source port 53038
        udp[2] = 0x00; udp[3] = 0x35   // destination port 53
        udp[4] = 0x00; udp[5] = 0x0C   // length 12
        let packet = Self.ipv4(proto: SwiftCoreIPProtocol.udp, source: [10, 0, 0, 2], destination: [1, 1, 1, 1], payload: udp)

        let ip = try! XCTUnwrap(SwiftCoreIPv4Packet(packet))
        XCTAssertEqual(ip.proto, SwiftCoreIPProtocol.udp)
        let datagram = SwiftCoreUDPDatagram(ip.payload)
        XCTAssertEqual(datagram?.sourcePort, 53038)
        XCTAssertEqual(datagram?.destinationPort, 53)
        XCTAssertEqual(datagram?.length, 12)
        XCTAssertEqual(datagram?.payload.count, 4)
    }

    func testRejectsNonIPv4() {
        XCTAssertNil(SwiftCoreIPv4Packet([0x60, 0, 0, 0]))          // IPv6 version nibble
        XCTAssertNil(SwiftCoreIPv4Packet([0x45, 0, 0]))            // too short
    }

    // MARK: Checksum

    func testInternetChecksumOfValidHeaderIsZero() {
        // ipv4() fills in a correct header checksum, so the header (incl. checksum) must sum to zero.
        let packet = Self.ipv4(proto: SwiftCoreIPProtocol.tcp, source: [10, 0, 0, 2], destination: [8, 8, 8, 8], payload: [])
        XCTAssertEqual(swiftCoreInternetChecksum(packet[0..<20]), 0)
    }

    func testChecksumHandlesOddLength() {
        // An odd-length buffer pads a trailing zero byte, so it must checksum the same as that buffer
        // with an explicit trailing zero appended.
        let odd: [UInt8] = [0x11, 0x22, 0x33]
        XCTAssertEqual(swiftCoreInternetChecksum(odd[...]), swiftCoreInternetChecksum((odd + [0x00])[...]))
    }

    // MARK: ICMP echo reply

    func testMakeEchoReply() {
        var icmp: [UInt8] = [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01] + [1, 2, 3, 4, 5, 6, 7, 8]
        let icmpChecksum = swiftCoreInternetChecksum(icmp[...])
        icmp[2] = UInt8(icmpChecksum >> 8)
        icmp[3] = UInt8(icmpChecksum & 0xff)
        let request = Self.ipv4(proto: SwiftCoreIPProtocol.icmp, source: [10, 0, 0, 2], destination: [10, 0, 0, 1], payload: icmp)

        let reply = try! XCTUnwrap(SwiftCoreICMP.makeEchoReply(from: request))
        let replyIP = try! XCTUnwrap(SwiftCoreIPv4Packet(reply))
        XCTAssertEqual(replyIP.source, [10, 0, 0, 1])          // src/dst swapped
        XCTAssertEqual(replyIP.destination, [10, 0, 0, 2])
        XCTAssertEqual(reply[replyIP.headerLength], SwiftCoreICMPHeader.echoReply)  // type 0
        // Both checksums are valid (sum to zero over their covered ranges).
        XCTAssertEqual(swiftCoreInternetChecksum(reply[0..<replyIP.headerLength]), 0)
        XCTAssertEqual(swiftCoreInternetChecksum(reply[replyIP.headerLength..<reply.count]), 0)
    }

    func testMakeEchoReplyRejectsNonEcho() {
        let tcp = Self.ipv4(proto: SwiftCoreIPProtocol.tcp, source: [10, 0, 0, 2], destination: [10, 0, 0, 1], payload: [UInt8](repeating: 0, count: 20))
        XCTAssertNil(SwiftCoreICMP.makeEchoReply(from: tcp))
    }

    // MARK: Config

    func testParseTUNConfig() throws {
        let config = try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        tun:
          enable: true
          device: utun9
          mtu: 1500
          stack: system
          auto-route: false
          inet4-address: [198.18.0.1/30]
          dns-hijack: [any:53]
        proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]
        rules: [MATCH,DIRECT]
        """)
        XCTAssertTrue(config.tun.enable)
        XCTAssertEqual(config.tun.device, "utun9")
        XCTAssertEqual(config.tun.mtu, 1500)
        XCTAssertEqual(config.tun.stack, "system")
        XCTAssertFalse(config.tun.autoRoute)
        XCTAssertEqual(config.tun.address, ["198.18.0.1/30"])
        XCTAssertEqual(config.tun.dnsHijack, ["any:53"])
    }

    func testTUNDefaultsWhenAbsent() throws {
        let config = try SwiftCoreConfiguration.parse(yaml: """
        mixed-port: 7890
        secret: s
        proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]
        rules: [MATCH,DIRECT]
        """)
        XCTAssertFalse(config.tun.enable)
        XCTAssertEqual(config.tun.mtu, 9000)
    }

    // MARK: Device open (privileged, gated)

    func testDeviceOpenRoundTrip() throws {
        guard ProcessInfo.processInfo.environment["NEOCLASH_TUN"] == "1" else {
            throw XCTSkip("set NEOCLASH_TUN=1 and run as root to exercise the real TUN device")
        }
        let device = SwiftCoreTunDevice(mtu: 1500)
        try device.open(requestedName: "")
        XCTAssertFalse(device.name.isEmpty)
        device.close()
    }

    // MARK: Helpers

    /// Builds an IPv4 packet with a valid header checksum around `payload`.
    private static func ipv4(proto: UInt8, source: [UInt8], destination: [UInt8], payload: [UInt8]) -> [UInt8] {
        var header = [UInt8](repeating: 0, count: 20)
        header[0] = 0x45                                    // version 4, IHL 5
        let total = 20 + payload.count
        header[2] = UInt8(total >> 8); header[3] = UInt8(total & 0xff)
        header[8] = 64                                      // TTL
        header[9] = proto
        for index in 0..<4 { header[12 + index] = source[index] }
        for index in 0..<4 { header[16 + index] = destination[index] }
        let checksum = swiftCoreInternetChecksum(header[0..<20])
        header[10] = UInt8(checksum >> 8); header[11] = UInt8(checksum & 0xff)
        return header + payload
    }
}
