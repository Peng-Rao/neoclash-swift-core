import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for the Phase 4 DNS foundation: the DNS wire codec, the fake-ip pool, and `dns:` parsing.
final class DNSTests: XCTestCase {
    func testEncodeQuery() {
        let query = SwiftCoreDNSMessage.encodeQuery(id: 0x1234, name: "example.com", type: .a)
        XCTAssertEqual(Array(query[0..<2]), [0x12, 0x34])          // id
        XCTAssertEqual(Array(query[2..<4]), [0x01, 0x00])          // flags RD
        XCTAssertEqual(Array(query[4..<6]), [0x00, 0x01])          // QDCOUNT
        // QNAME: 7 "example" 3 "com" 0
        let expectedName: [UInt8] = [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]
        XCTAssertEqual(Array(query[12..<(12 + expectedName.count)]), expectedName)
        XCTAssertEqual(Array(query.suffix(4)), [0x00, 0x01, 0x00, 0x01]) // QTYPE=A, QCLASS=IN
    }

    func testDecodeAnswersWithCompressionPointer() {
        var msg: [UInt8] = []
        msg += [0x12, 0x34, 0x81, 0x80]          // id, flags (response)
        msg += [0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00] // QD=1, AN=2
        msg += [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0] // question name
        msg += [0x00, 0x01, 0x00, 0x01]          // QTYPE=A, QCLASS=IN
        // Answer 1: A record, name = compression pointer to offset 12
        msg += [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C] // ptr, A, IN, TTL=300
        msg += [0x00, 0x04, 93, 184, 216, 34]    // RDLENGTH=4, IPv4
        // Answer 2: AAAA record
        msg += [0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C] // ptr, AAAA, IN, TTL=60
        let v6: [UInt8] = [0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        msg += [0x00, 0x10] + v6                  // RDLENGTH=16, IPv6

        let answers = SwiftCoreDNSMessage.decodeAnswers(msg)
        XCTAssertEqual(answers.count, 2)
        XCTAssertEqual(answers[0].address, .ipv4([93, 184, 216, 34]))
        XCTAssertEqual(answers[0].ttl, 300)
        XCTAssertEqual(answers[1].address, .ipv6(v6))
        XCTAssertEqual(answers[1].ttl, 60)
    }

    func testDecodeAnswersRejectsTruncated() {
        XCTAssertEqual(SwiftCoreDNSMessage.decodeAnswers([0x00, 0x01]), [])
        XCTAssertEqual(SwiftCoreDNSMessage.decodeAnswers([]), [])
    }

    func testFakeIPPoolAllocationAndReverse() throws {
        let pool = try XCTUnwrap(SwiftCoreFakeIPPool(cidr: "198.18.0.1/16"))
        let ip1 = pool.allocate(domain: "a.com")
        let ip2 = pool.allocate(domain: "b.com")
        XCTAssertEqual(ip1, [198, 18, 0, 4])                 // firstOffset skips .0..3
        XCTAssertEqual(ip2, [198, 18, 0, 5])
        XCTAssertEqual(pool.allocate(domain: "A.com"), ip1)  // stable + case-insensitive
        XCTAssertEqual(pool.domain(forIPv4: ip1), "a.com")
        XCTAssertTrue(pool.contains(ipv4: ip1))
        XCTAssertFalse(pool.contains(ipv4: [8, 8, 8, 8]))
        XCTAssertNil(pool.domain(forIPv4: [8, 8, 8, 8]))
    }

    func testFakeIPPoolWrapsAndEvicts() throws {
        let pool = try XCTUnwrap(SwiftCoreFakeIPPool(cidr: "10.0.0.0/30")) // 4 addresses, firstOffset 0
        let first = pool.allocate(domain: "d1")
        _ = pool.allocate(domain: "d2")
        _ = pool.allocate(domain: "d3")
        _ = pool.allocate(domain: "d4")
        let fifth = pool.allocate(domain: "d5")   // wraps, reuses d1's address
        XCTAssertEqual(fifth, first)
        XCTAssertEqual(pool.domain(forIPv4: first), "d5") // d1 evicted
    }

    func testDNSConfigParsing() throws {
        let yaml = """
        mixed-port: 7890
        secret: s
        hosts:
          router.local: 192.168.1.1
        dns:
          enable: true
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          fake-ip-filter:
            - "*.lan"
            - "+.local"
          default-nameserver:
            - 223.5.5.5
          nameserver:
            - 223.5.5.5
            - 8.8.8.8
        proxy-groups:
          - { name: G, type: select, proxies: [DIRECT] }
        rules:
          - MATCH,DIRECT
        """
        let dns = try SwiftCoreConfiguration.parse(yaml: yaml).dns
        XCTAssertTrue(dns.enable)
        XCTAssertEqual(dns.enhancedMode, "fake-ip")
        XCTAssertEqual(dns.fakeIPRange, "198.18.0.1/16")
        XCTAssertEqual(dns.fakeIPFilter, ["*.lan", "+.local"])
        XCTAssertEqual(dns.nameservers, ["223.5.5.5", "8.8.8.8"])
        XCTAssertEqual(dns.defaultNameservers, ["223.5.5.5"])
        XCTAssertEqual(dns.hosts["router.local"], "192.168.1.1")
        // Defaults when fallback-filter / nameserver-policy are absent.
        XCTAssertEqual(dns.fallbackFilter, SwiftCoreDNSFallbackFilter())
        XCTAssertTrue(dns.fallbackFilter.geoIP)
        XCTAssertEqual(dns.fallbackFilter.geoIPCode, "CN")
        XCTAssertEqual(dns.nameserverPolicy, [])
    }

    func testDNSFallbackFilterAndPolicyParsing() throws {
        let yaml = """
        mixed-port: 7890
        dns:
          enable: true
          nameserver:
            - 223.5.5.5
          fallback:
            - tls://8.8.4.4
            - https://1.0.0.1/dns-query
          fallback-filter:
            geoip: false
            geoip-code: US
            ipcidr:
              - 240.0.0.0/4
            domain:
              - "+.google.com"
          nameserver-policy:
            "+.internal.corp": 10.0.0.53
            "www.example.com,api.example.com":
              - tls://1.1.1.1
              - 9.9.9.9
        proxy-groups:
          - { name: G, type: select, proxies: [DIRECT] }
        rules:
          - MATCH,DIRECT
        """
        let dns = try SwiftCoreConfiguration.parse(yaml: yaml).dns
        XCTAssertEqual(dns.fallback, ["tls://8.8.4.4", "https://1.0.0.1/dns-query"])
        XCTAssertFalse(dns.fallbackFilter.geoIP)
        XCTAssertEqual(dns.fallbackFilter.geoIPCode, "US")
        XCTAssertEqual(dns.fallbackFilter.ipcidr, ["240.0.0.0/4"])
        XCTAssertEqual(dns.fallbackFilter.domain, ["+.google.com"])
        // Comma-separated keys expand to one rule per pattern; entries are sorted by key.
        XCTAssertEqual(dns.nameserverPolicy.count, 3)
        let byPattern = Dictionary(uniqueKeysWithValues: dns.nameserverPolicy.map { ($0.pattern, $0.servers) })
        XCTAssertEqual(byPattern["+.internal.corp"], ["10.0.0.53"])
        XCTAssertEqual(byPattern["www.example.com"], ["tls://1.1.1.1", "9.9.9.9"])
        XCTAssertEqual(byPattern["api.example.com"], ["tls://1.1.1.1", "9.9.9.9"])
    }
}
