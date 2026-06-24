import Foundation
import NeoClashSwiftCoreLib
import XCTest

/// Tests for proxy-group strategies (select / url-test / fallback / load-balance) and the relaxed
/// config parsing (optional `external-controller` / `secret`).
final class GroupTests: XCTestCase {
    private func state(groupType: String, members: [String] = ["A", "B", "C"]) throws -> SwiftCoreState {
        let yaml = """
        mixed-port: 7890
        secret: s
        proxies:
          - { name: A, type: direct }
          - { name: B, type: direct }
          - { name: C, type: direct }
        proxy-groups:
          - { name: G, type: \(groupType), proxies: [\(members.joined(separator: ", "))] }
        rules:
          - MATCH,G
        """
        return SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))
    }

    private func chosen(_ state: SwiftCoreState, host: String = "example.com") -> String? {
        guard case .outbound(let chain, _) = state.route(host: host) else { return nil }
        return chain.last
    }

    private func now(_ state: SwiftCoreState) -> String? {
        let object = state.proxiesObject()
        let proxies = object["proxies"] as? [String: Any]
        let group = proxies?["G"] as? [String: Any]
        return group?["now"] as? String
    }

    func testUrlTestPicksLowestDelay() throws {
        let state = try state(groupType: "url-test")
        state.recordDelay(name: "A", delay: 100)
        state.recordDelay(name: "B", delay: 40)
        state.recordDelay(name: "C", delay: 250)
        XCTAssertEqual(chosen(state), "B")
        XCTAssertEqual(now(state), "B")

        state.recordDelay(name: "C", delay: 10)
        XCTAssertEqual(chosen(state), "C")
    }

    func testFallbackPicksFirstAliveInOrder() throws {
        let state = try state(groupType: "fallback")
        // A has no recorded delay -> not alive; B is alive.
        state.recordDelay(name: "B", delay: 80)
        state.recordDelay(name: "C", delay: 20)
        XCTAssertEqual(chosen(state), "B")

        state.recordDelay(name: "A", delay: 300)
        XCTAssertEqual(chosen(state), "A") // first in order, now alive
    }

    func testLoadBalanceIsStickyPerHost() throws {
        let state = try state(groupType: "load-balance", members: ["A", "B"])
        state.recordDelay(name: "A", delay: 50)
        state.recordDelay(name: "B", delay: 50)
        let first = chosen(state, host: "stable.example")
        let second = chosen(state, host: "stable.example")
        XCTAssertNotNil(first)
        XCTAssertEqual(first, second)            // same host -> same member
        XCTAssertTrue(["A", "B"].contains(first!))
    }

    func testSelectHonorsManualSelection() throws {
        let state = try state(groupType: "select")
        XCTAssertEqual(now(state), "A")          // defaults to first
        XCTAssertTrue(state.selectProxy(group: "G", proxy: "C"))
        XCTAssertEqual(now(state), "C")
        XCTAssertEqual(chosen(state), "C")
        XCTAssertFalse(state.selectProxy(group: "G", proxy: "Nope"))
    }

    func testConfigDefaultsWhenControllerAndSecretAbsent() throws {
        let yaml = """
        mixed-port: 7890
        proxies: []
        proxy-groups:
          - { name: G, type: select, proxies: [DIRECT] }
        rules:
          - MATCH,DIRECT
        """
        let config = try SwiftCoreConfiguration.parse(yaml: yaml)
        XCTAssertEqual(config.controllerHost, "127.0.0.1")
        XCTAssertEqual(config.controllerPort, 9090)
        XCTAssertEqual(config.secret, "")

        let state = SwiftCoreState(configuration: config)
        XCTAssertTrue(state.isAuthorized(headers: [:]))                       // empty secret disables auth
        XCTAssertTrue(state.isAuthorized(headers: ["Authorization": "Bearer anything"]))
    }
}
