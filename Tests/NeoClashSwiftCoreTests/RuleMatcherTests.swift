import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Unit tests for the routing rule matcher and an end-to-end routing test through `SwiftCoreState`.
final class RuleMatcherTests: XCTestCase {
    private func matches(_ type: String, _ payload: String, host: String, dstPort: Int = 0, srcPort: Int? = nil) -> Bool {
        let context = SwiftCoreRouteContext(host: host, destinationPort: dstPort, sourcePort: srcPort)
        return SwiftCoreRuleMatcher.matches(rule: SwiftCoreRule(type: type, payload: payload, proxy: "X"), context: context)
    }

    func testDomainRules() {
        XCTAssertTrue(matches("DOMAIN", "example.com", host: "example.com"))
        XCTAssertFalse(matches("DOMAIN", "example.com", host: "www.example.com"))
        XCTAssertTrue(matches("DOMAIN-SUFFIX", "example.com", host: "www.example.com"))
        XCTAssertTrue(matches("DOMAIN-SUFFIX", "example.com", host: "example.com"))
        XCTAssertFalse(matches("DOMAIN-SUFFIX", "example.com", host: "notexample.com"))
        XCTAssertTrue(matches("DOMAIN-KEYWORD", "goog", host: "www.google.com"))
        XCTAssertTrue(matches("DOMAIN-REGEX", #"^.*\.cn$"#, host: "site.cn"))
        XCTAssertFalse(matches("DOMAIN-REGEX", #"^.*\.cn$"#, host: "site.com"))
    }

    func testIPv4CIDR() {
        XCTAssertTrue(matches("IP-CIDR", "10.0.0.0/8", host: "10.1.2.3"))
        XCTAssertTrue(matches("IP-CIDR", "192.168.0.0/16", host: "192.168.7.7"))
        XCTAssertFalse(matches("IP-CIDR", "192.168.0.0/16", host: "192.169.0.1"))
        XCTAssertFalse(matches("IP-CIDR", "10.0.0.0/8", host: "11.0.0.1"))
        XCTAssertTrue(matches("IP-CIDR", "1.2.3.4/32", host: "1.2.3.4"))
        // a domain target never matches an IP rule (no resolution yet)
        XCTAssertFalse(matches("IP-CIDR", "10.0.0.0/8", host: "example.com"))
    }

    func testIPv6CIDR() {
        XCTAssertTrue(matches("IP-CIDR6", "2001:db8::/32", host: "2001:db8::1"))
        XCTAssertFalse(matches("IP-CIDR6", "2001:db8::/32", host: "2001:db9::1"))
        XCTAssertTrue(matches("IP-CIDR6", "::1/128", host: "::1"))
        // v4 target does not match a v6 rule
        XCTAssertFalse(matches("IP-CIDR6", "2001:db8::/32", host: "10.0.0.1"))
    }

    func testPortRules() {
        XCTAssertTrue(matches("DST-PORT", "443", host: "x", dstPort: 443))
        XCTAssertFalse(matches("DST-PORT", "443", host: "x", dstPort: 80))
        XCTAssertTrue(matches("DST-PORT", "80,443,8080", host: "x", dstPort: 8080))
        XCTAssertTrue(matches("DST-PORT", "1000-2000", host: "x", dstPort: 1500))
        XCTAssertFalse(matches("DST-PORT", "1000-2000", host: "x", dstPort: 2500))
        XCTAssertTrue(matches("SRC-PORT", "55000-56000", host: "x", srcPort: 55500))
        XCTAssertFalse(matches("SRC-PORT", "55000", host: "x", srcPort: nil))
    }

    func testUnsupportedRulesNeverMatch() {
        XCTAssertFalse(matches("GEOIP", "CN", host: "1.2.3.4"))
        XCTAssertFalse(matches("GEOSITE", "cn", host: "example.cn"))
        XCTAssertFalse(matches("PROCESS-NAME", "curl", host: "example.com"))
        XCTAssertTrue(matches("MATCH", "", host: "anything.com"))
    }

    func testRoutingThroughStateUsesRuleContext() throws {
        let yaml = """
        mixed-port: 7890
        secret: s
        proxies:
          - { name: P, type: direct }
        proxy-groups:
          - { name: G, type: select, proxies: [P, DIRECT] }
        rules:
          - IP-CIDR,10.0.0.0/8,DIRECT
          - DST-PORT,443,DIRECT
          - DOMAIN-SUFFIX,example.com,DIRECT
          - MATCH,P
        """
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))

        func chosen(host: String, dstPort: Int) -> String? {
            let context = SwiftCoreRouteContext(host: host, destinationPort: dstPort)
            guard case .outbound(let chain, _) = state.route(context: context) else { return nil }
            return chain.last
        }

        XCTAssertEqual(chosen(host: "10.1.2.3", dstPort: 80), "DIRECT")       // IP-CIDR
        XCTAssertEqual(chosen(host: "8.8.8.8", dstPort: 443), "DIRECT")       // DST-PORT
        XCTAssertEqual(chosen(host: "www.example.com", dstPort: 80), "DIRECT")// DOMAIN-SUFFIX
        XCTAssertEqual(chosen(host: "other.org", dstPort: 80), "P")          // MATCH fallthrough
    }
}
