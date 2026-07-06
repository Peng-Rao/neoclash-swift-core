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

    // MARK: Loader edge cases

    private func makeLoaderState() throws -> SwiftCoreState {
        let yaml = """
        mixed-port: 7890
        secret: s
        proxies:
          - { name: P, type: direct }
        proxy-groups:
          - { name: G, type: select, proxies: [P, DIRECT] }
        rules:
          - RULE-SET,ads,REJECT
          - MATCH,P
        """
        return SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))
    }

    private func makeLoaderDirectory() throws -> String {
        let directory = NSTemporaryDirectory() + "neoclash-ruleset-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        return directory
    }

    func testLoaderSkipsMissingProviderFile() async throws {
        let directory = try makeLoaderDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }

        let state = try makeLoaderState()
        let loader = SwiftCoreRuleProviderLoader(
            state: state,
            directory: directory,
            providers: [SwiftCoreRuleProvider(name: "ads", type: "file", behavior: "domain", path: "missing.yaml")]
        )
        await loader.load()

        // Nothing installed: the RULE-SET rule falls through to MATCH,P.
        guard case .outbound(let chain, _) = state.route(context: SwiftCoreRouteContext(host: "x.blocked.example", destinationPort: 0)) else {
            return XCTFail("expected fallthrough to MATCH,P")
        }
        XCTAssertEqual(chain.last, "P")
        let logs = state.drainLogObjects().map { $0["payload"] ?? "" }
        XCTAssertTrue(logs.contains { $0.contains("file not found") }, "\(logs)")
    }

    func testLoaderPrefersCachedHTTPDownload() async throws {
        // A text-format http provider without an explicit path caches at ruleset-<name>.txt;
        // when the cache exists the loader must serve it without touching the network.
        let directory = try makeLoaderDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try "# ads\n+.blocked.example\n".write(toFile: directory + "/ruleset-ads.txt", atomically: true, encoding: .utf8)

        let state = try makeLoaderState()
        let loader = SwiftCoreRuleProviderLoader(
            state: state,
            directory: directory,
            providers: [SwiftCoreRuleProvider(name: "ads", type: "http", behavior: "domain", url: "http://invalid.invalid/ads.txt", format: "text")]
        )
        await loader.load()

        let decision = state.route(context: SwiftCoreRouteContext(host: "x.blocked.example", destinationPort: 0))
        if case .reject = decision {} else { XCTFail("expected REJECT via cached provider, got \(decision)") }
    }

    func testLoaderWarnsForMissingURLAndUnsupportedBehavior() async throws {
        let directory = try makeLoaderDirectory()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let absolutePath = directory + "/abs.yaml"
        try "payload:\n  - \"+.blocked.example\"\n".write(toFile: absolutePath, atomically: true, encoding: .utf8)

        let state = try makeLoaderState()
        let loader = SwiftCoreRuleProviderLoader(state: state, directory: directory, providers: [
            SwiftCoreRuleProvider(name: "nourl", type: "http", behavior: "domain"),
            SwiftCoreRuleProvider(name: "ads", type: "file", behavior: "bogus", path: absolutePath)
        ])
        await loader.load()

        let logs = state.drainLogObjects().map { $0["payload"] ?? "" }
        XCTAssertTrue(logs.contains { $0.contains("missing or invalid url") }, "\(logs)")
        XCTAssertTrue(logs.contains { $0.contains("unsupported behavior 'bogus'") }, "\(logs)")
    }
}
