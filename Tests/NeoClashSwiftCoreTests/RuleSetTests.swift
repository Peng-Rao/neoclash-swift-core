import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for `rule-providers` / `RULE-SET`: payload parsing (domain/ipcidr/classical, yaml + text),
/// matching, config parsing, the file-provider loader, and end-to-end routing through the state.
final class RuleSetTests: XCTestCase {
    private func ruleSet(_ behavior: String, _ format: String, _ content: String, name: String = "p") -> SwiftCoreRuleSet {
        let provider = SwiftCoreRuleSetParser.parse(behavior: behavior, format: format, content: Array(content.utf8))!
        return SwiftCoreRuleSet(providers: [name: provider])
    }

    private func matches(_ set: SwiftCoreRuleSet, _ host: String, dstPort: Int = 0, name: String = "p") -> Bool {
        set.matches(provider: name, context: SwiftCoreRouteContext(host: host, destinationPort: dstPort), geo: nil)
    }

    func testDomainProvider() {
        let set = ruleSet("domain", "yaml", """
        payload:
          - "+.example.com"
          - "exact.org"
          - "*.wild.net"
          - ".dotted.io"
        """)
        XCTAssertTrue(matches(set, "example.com"))      // +. matches self
        XCTAssertTrue(matches(set, "www.example.com"))  // +. matches subdomain
        XCTAssertTrue(matches(set, "exact.org"))        // exact
        XCTAssertFalse(matches(set, "notexact.org"))
        XCTAssertTrue(matches(set, "a.wild.net"))       // *.
        XCTAssertTrue(matches(set, "x.dotted.io"))      // leading dot
        XCTAssertFalse(matches(set, "other.com"))
        XCTAssertFalse(set.matches(provider: "missing", context: SwiftCoreRouteContext(host: "example.com", destinationPort: 0), geo: nil))
    }

    func testIPCIDRProviderTextFormat() {
        let set = ruleSet("ipcidr", "text", """
        # comment
        10.0.0.0/8
        192.168.0.0/16
        2001:db8::/32
        """)
        XCTAssertTrue(matches(set, "10.1.2.3"))
        XCTAssertTrue(matches(set, "192.168.5.5"))
        XCTAssertTrue(matches(set, "2001:db8::1"))
        XCTAssertFalse(matches(set, "8.8.8.8"))
        XCTAssertFalse(matches(set, "example.com")) // domain never matches an ipcidr provider
    }

    func testClassicalProvider() {
        let set = ruleSet("classical", "yaml", """
        payload:
          - "DOMAIN-SUFFIX,example.com"
          - "IP-CIDR,1.2.3.0/24"
          - "DST-PORT,443"
        """)
        XCTAssertTrue(matches(set, "www.example.com"))
        XCTAssertTrue(matches(set, "1.2.3.4"))
        XCTAssertTrue(matches(set, "anything.net", dstPort: 443))
        XCTAssertFalse(matches(set, "anything.net", dstPort: 80))
    }

    func testConfigurationParsesRuleProviders() throws {
        let yaml = """
        mixed-port: 7890
        secret: s
        rule-providers:
          ads:
            type: http
            behavior: domain
            url: https://example.com/ads.yaml
            path: ./rules/ads.yaml
            format: yaml
        proxy-groups:
          - { name: G, type: select, proxies: [DIRECT] }
        rules:
          - RULE-SET,ads,REJECT
          - MATCH,DIRECT
        """
        let config = try SwiftCoreConfiguration.parse(yaml: yaml)
        let provider = try XCTUnwrap(config.ruleProviders.first { $0.name == "ads" })
        XCTAssertEqual(provider.type, "http")
        XCTAssertEqual(provider.behavior, "domain")
        XCTAssertEqual(provider.url, "https://example.com/ads.yaml")
        XCTAssertEqual(provider.path, "./rules/ads.yaml")
    }

    func testRoutingThroughRuleSet() throws {
        let yaml = """
        mixed-port: 7890
        secret: s
        proxies:
          - { name: P, type: direct }
        proxy-groups:
          - { name: G, type: select, proxies: [P, DIRECT] }
        rules:
          - RULE-SET,cn,DIRECT
          - MATCH,P
        """
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))

        func chosen(_ host: String) -> String? {
            guard case .outbound(let chain, _) = state.route(context: SwiftCoreRouteContext(host: host, destinationPort: 0)) else { return nil }
            return chain.last
        }
        // No rule set loaded yet -> RULE-SET never matches.
        XCTAssertEqual(chosen("www.taobao.com"), "P")

        state.setRuleSet(ruleSet("domain", "yaml", "payload:\n  - \"+.taobao.com\"", name: "cn"))
        XCTAssertEqual(chosen("www.taobao.com"), "DIRECT") // RULE-SET,cn matches
        XCTAssertEqual(chosen("example.org"), "P")
    }

    func testFileProviderLoaderRoutes() async throws {
        let directory = NSTemporaryDirectory() + "neoclash-ruleset-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory + "/rules", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try "payload:\n  - \"+.blocked.example\"\n".write(toFile: directory + "/rules/ads.yaml", atomically: true, encoding: .utf8)

        let yaml = """
        mixed-port: 7890
        secret: s
        proxies:
          - { name: P, type: direct }
        proxy-groups:
          - { name: G, type: select, proxies: [P, DIRECT] }
        rule-providers:
          ads:
            type: file
            behavior: domain
            path: rules/ads.yaml
        rules:
          - RULE-SET,ads,REJECT
          - MATCH,P
        """
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))
        let loader = SwiftCoreRuleProviderLoader(state: state, directory: directory, providers: state.ruleProviders())
        await loader.load()

        let decision = state.route(context: SwiftCoreRouteContext(host: "x.blocked.example", destinationPort: 0))
        if case .reject = decision {} else { XCTFail("expected REJECT via RULE-SET, got \(decision)") }
    }
}
