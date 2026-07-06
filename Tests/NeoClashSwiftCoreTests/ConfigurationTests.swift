import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Failure-path tests for the CLI and YAML configuration surface: every rejection a user can hit
/// from the command line, plus the `SwiftCoreMain` exit codes around them.
final class ConfigurationTests: XCTestCase {
    func testCommandParseRejectsBadArguments() {
        func parseError(_ arguments: [String]) -> SwiftCoreError? {
            do {
                _ = try SwiftCoreCommand.parse(arguments: ["neoclash-swift-core"] + arguments)
                return nil
            } catch {
                return error as? SwiftCoreError
            }
        }
        XCTAssertEqual(parseError(["-f"]), .invalidArguments("Missing value for -f"))
        XCTAssertEqual(parseError(["-f", "c.yaml", "-d"]), .invalidArguments("Missing value for -d"))
        XCTAssertEqual(parseError(["-h"]), .invalidArguments(SwiftCoreCommand.usage))
        XCTAssertEqual(parseError(["--bogus"]), .invalidArguments("Unknown argument: --bogus\n\(SwiftCoreCommand.usage)"))
        XCTAssertEqual(parseError(["-d", "/tmp"]), .invalidArguments("Missing required -f <config.yaml>\n\(SwiftCoreCommand.usage)"))
        XCTAssertEqual(parseError(["-f", "c.yaml"]), .invalidArguments("Missing required -d <runtimeDir>\n\(SwiftCoreCommand.usage)"))
    }

    func testLoadRejectsMissingFile() {
        XCTAssertThrowsError(try SwiftCoreConfiguration.load(from: "/nonexistent/config.yaml")) { error in
            XCTAssertEqual(error as? SwiftCoreError, .missingConfig("/nonexistent/config.yaml"))
        }
    }

    func testParseRejectsMalformedDocuments() {
        func invalidConfigMessage(_ yaml: String) -> String? {
            do {
                _ = try SwiftCoreConfiguration.parse(yaml: yaml)
            } catch let SwiftCoreError.invalidConfig(message) {
                return message
            } catch {
                return nil
            }
            return nil
        }
        XCTAssertEqual(invalidConfigMessage("- a\n- b"), "YAML root must be a mapping.")
        XCTAssertEqual(invalidConfigMessage("mixed-port: 99999"), "mixed-port must be a valid port.")
        XCTAssertEqual(invalidConfigMessage("mixed-port: 7890\nexternal-controller: nonsense"), "external-controller must be host:port.")
        XCTAssertEqual(invalidConfigMessage("mixed-port: 7890\nexternal-controller: 127.0.0.1:bad"), "external-controller port must be valid.")
    }

    func testErrorDescriptions() {
        XCTAssertEqual(SwiftCoreError.invalidArguments("x").errorDescription, "x")
        XCTAssertEqual(SwiftCoreError.missingConfig("/p").errorDescription, "Configuration file is missing: /p")
        XCTAssertEqual(SwiftCoreError.invalidConfig("y").errorDescription, "Invalid Swift core configuration: y")
    }

    func testMainExitCodes() throws {
        XCTAssertEqual(SwiftCoreMain.run(arguments: ["neoclash-swift-core", "--bogus"]), 1)
        XCTAssertEqual(SwiftCoreMain.run(arguments: ["neoclash-swift-core", "-f", "/nonexistent/c.yaml", "-d", NSTemporaryDirectory()]), 1)

        // `-t` validates the configuration and exits without starting servers.
        let directory = NSTemporaryDirectory() + "neoclash-main-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let configPath = directory + "/config.yaml"
        try """
        mixed-port: 7890
        secret: s
        proxy-groups:
          - { name: G, type: select, proxies: [DIRECT] }
        rules:
          - MATCH,DIRECT
        """.write(toFile: configPath, atomically: true, encoding: .utf8)
        XCTAssertEqual(SwiftCoreMain.run(arguments: ["neoclash-swift-core", "-t", "-f", configPath, "-d", directory]), 0)
    }
}
