import Foundation
import NIOCore
import NeoClashSwiftCoreLib
import XCTest

final class LoggingTests: XCTestCase {
    func testDrainReturnsPendingLogsInOrderAndEmptiesQueue() throws {
        let state = SwiftCoreState(configuration: try Self.configuration(logLevel: "debug"))
        _ = state.drainLogObjects() // discard init-time logs

        state.appendLog(level: "info", message: "first")
        state.appendLog(level: "warning", message: "second")

        let drained = state.drainLogObjects()
        XCTAssertEqual(drained.map { $0["payload"] }, ["first", "second"])
        XCTAssertEqual(drained.map { $0["type"] }, ["info", "warning"])

        // An idle queue stays empty: no fabricated heartbeat entries.
        XCTAssertTrue(state.drainLogObjects().isEmpty)
    }

    func testAppendLogHonorsConfiguredLevel() throws {
        let state = SwiftCoreState(configuration: try Self.configuration(logLevel: "warning"))
        _ = state.drainLogObjects()

        state.appendLog(level: "debug", message: "dropped")
        state.appendLog(level: "info", message: "dropped")
        state.appendLog(level: "warning", message: "kept")
        state.appendLog(level: "error", message: "kept too")

        XCTAssertEqual(state.drainLogObjects().map { $0["payload"] }, ["kept", "kept too"])
    }

    func testSilentLevelDropsEverything() throws {
        let state = SwiftCoreState(configuration: try Self.configuration(logLevel: "silent"))
        XCTAssertTrue(state.drainLogObjects().isEmpty)

        state.appendLog(level: "error", message: "dropped")
        XCTAssertTrue(state.drainLogObjects().isEmpty)
    }

    func testErrorDescriptionExposesErrnoInsteadOfNSErrorBridge() {
        let error = IOError(errnoCode: ECONNRESET, reason: "read")
        let text = SwiftCoreErrorText.describe(error)
        XCTAssertFalse(text.contains("NIOCore.IOError error 1"), "NSError bridging leaked: \(text)")
        XCTAssertTrue(text.localizedCaseInsensitiveContains("reset"), "expected errno text, got: \(text)")
    }

    func testRoutineDisconnectClassification() {
        XCTAssertTrue(SwiftCoreErrorText.isRoutineDisconnect(IOError(errnoCode: ECONNRESET, reason: "read")))
        XCTAssertTrue(SwiftCoreErrorText.isRoutineDisconnect(IOError(errnoCode: EPIPE, reason: "write")))
        XCTAssertTrue(SwiftCoreErrorText.isRoutineDisconnect(ChannelError.eof))
        XCTAssertTrue(SwiftCoreErrorText.isRoutineDisconnect(ChannelError.ioOnClosedChannel))

        XCTAssertFalse(SwiftCoreErrorText.isRoutineDisconnect(IOError(errnoCode: EADDRNOTAVAIL, reason: "connect")))
        XCTAssertFalse(SwiftCoreErrorText.isRoutineDisconnect(ChannelError.connectTimeout(.seconds(1))))
        XCTAssertFalse(SwiftCoreErrorText.isRoutineDisconnect(SwiftCoreError.invalidConfig("x")))
    }

    private static func configuration(logLevel: String) throws -> SwiftCoreConfiguration {
        try SwiftCoreConfiguration.parse(yaml: """
            mixed-port: 17897
            external-controller: 127.0.0.1:19097
            secret: test-secret
            mode: rule
            log-level: \(logLevel)
            proxies: []
            proxy-groups:
              - name: Default
                type: select
                proxies:
                  - DIRECT
            rules:
              - MATCH,Default
            """)
    }
}
