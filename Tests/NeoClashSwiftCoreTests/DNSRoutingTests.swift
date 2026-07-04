import Foundation
import NIOPosix
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for wiring the resolver into routing: IP-CIDR/GEOIP rules applied to domain targets via a
/// resolved IP, `no-resolve` behavior, and `SwiftCoreState.resolvedRoute` (using the hosts table so
/// it stays hermetic).
final class DNSRoutingTests: XCTestCase {
    func testIPRulesUseResolvedIPForDomains() {
        let resolved = SwiftCoreRouteContext(host: "example.com", destinationPort: 443, resolvedIP: .ipv4([10, 0, 0, 5]))
        let unresolved = SwiftCoreRouteContext(host: "example.com", destinationPort: 443)
        let literal = SwiftCoreRouteContext(host: "10.1.2.3", destinationPort: 443)

        func ipcidr(_ noResolve: Bool) -> SwiftCoreRule { SwiftCoreRule(type: "IP-CIDR", payload: "10.0.0.0/8", proxy: "X", noResolve: noResolve) }

        XCTAssertTrue(SwiftCoreRuleMatcher.matches(rule: ipcidr(false), context: resolved))   // uses resolved IP
        XCTAssertFalse(SwiftCoreRuleMatcher.matches(rule: ipcidr(true), context: resolved))   // no-resolve ignores it
        XCTAssertFalse(SwiftCoreRuleMatcher.matches(rule: ipcidr(false), context: unresolved))// nothing resolved
        XCTAssertTrue(SwiftCoreRuleMatcher.matches(rule: ipcidr(false), context: literal))    // literal IP target
    }

    func testRuleParsingNoResolve() throws {
        let yaml = """
        mixed-port: 7890
        secret: s
        proxy-groups:
          - { name: G, type: select, proxies: [DIRECT] }
        rules:
          - IP-CIDR,1.2.3.0/24,DIRECT,no-resolve
          - GEOIP,CN,DIRECT
          - MATCH,DIRECT
        """
        let rules = try SwiftCoreConfiguration.parse(yaml: yaml).rules
        XCTAssertTrue(rules[0].noResolve)
        XCTAssertFalse(rules[1].noResolve)
    }

    func testResolvedRouteUsesHostsAndRespectsNoResolve() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        func makeState(noResolve: Bool) throws -> SwiftCoreState {
            let yaml = """
            mixed-port: 7890
            secret: s
            hosts:
              test.corp: 10.20.0.5
            dns:
              enable: true
            proxies:
              - { name: P, type: direct }
            proxy-groups:
              - { name: G, type: select, proxies: [P, DIRECT] }
            rules:
              - IP-CIDR,10.20.0.0/16,DIRECT\(noResolve ? ",no-resolve" : "")
              - MATCH,P
            """
            let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))
            state.setResolver(SwiftCoreDNSResolver(config: state.dnsConfig(), group: group))
            return state
        }
        func last(_ decision: SwiftCoreRouteDecision) -> String? {
            if case .outbound(let chain, _) = decision { return chain.last }
            return nil
        }

        let resolving = try makeState(noResolve: false)
        XCTAssertTrue(resolving.shouldResolveForRouting(host: "test.corp"))
        XCTAssertFalse(resolving.shouldResolveForRouting(host: "10.1.2.3")) // literal IP, no resolution
        let hit = await resolving.resolvedRoute(host: "test.corp", destinationPort: 443, sourcePort: nil)
        XCTAssertEqual(last(hit), "DIRECT")                                 // resolved 10.20.0.5 -> IP-CIDR
        let miss = await resolving.resolvedRoute(host: "unknown.corp", destinationPort: 443, sourcePort: nil)
        XCTAssertEqual(last(miss), "P")                                     // not in hosts, unresolved -> MATCH

        let notResolving = try makeState(noResolve: true)
        XCTAssertFalse(notResolving.shouldResolveForRouting(host: "test.corp")) // only no-resolve IP rule
        let noResolveHit = await notResolving.resolvedRoute(host: "test.corp", destinationPort: 443, sourcePort: nil)
        XCTAssertEqual(last(noResolveHit), "P")                             // no-resolve ignores the resolved IP

        try? await group.shutdownGracefully()
    }
}
