// These integration tests use raw BSD sockets (sockaddr_in.sin_len, SOCK_STREAM as Int32, etc.)
// and URLSession, so they are macOS-only. The crypto, TLS 1.3, REALITY, Vision, GEO, group, and
// rule-matcher suites are cross-platform and run on Linux too.
#if canImport(Darwin)
import Darwin
import Foundation
import NeoClashSwiftCoreLib
import XCTest

final class SwiftCoreTests: XCTestCase {
    func testCLIParsesMihomoCompatibleArguments() throws {
        let command = try SwiftCoreCommand.parse(arguments: [
            "neoclash-swift-core",
            "-t",
            "-f", "/tmp/config.yaml",
            "-d", "/tmp/runtime"
        ])

        XCTAssertTrue(command.validateOnly)
        XCTAssertEqual(command.configPath, "/tmp/config.yaml")
        XCTAssertEqual(command.runtimeDirectoryPath, "/tmp/runtime")
    }

    func testConfigurationParsesRuntimeYAML() throws {
        let config = try SwiftCoreConfiguration.parse(yaml: Self.sampleYAML(mixedPort: 17897, controllerPort: 19097))

        XCTAssertEqual(config.mixedPort, 17897)
        XCTAssertEqual(config.controllerHost, "127.0.0.1")
        XCTAssertEqual(config.controllerPort, 19097)
        XCTAssertEqual(config.secret, "test-secret")
        XCTAssertEqual(config.proxyGroups.first?.name, "Default")
        XCTAssertEqual(config.rules.first, SwiftCoreRule(type: "MATCH", payload: "", proxy: "DIRECT"))
    }

    func testStateAuthorizesBearerSecretAndExposesControllerShapes() throws {
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: Self.sampleYAML()))

        XCTAssertTrue(state.isAuthorized(headers: ["Authorization": "Bearer test-secret"]))
        XCTAssertFalse(state.isAuthorized(headers: ["Authorization": "Bearer wrong"]))

        let proxies = state.proxiesObject()
        let proxiesData = try SwiftCoreJSON.data(proxies)
        let proxiesObject = try XCTUnwrap(JSONSerialization.jsonObject(with: proxiesData) as? [String: Any])
        let proxyMap = try XCTUnwrap(proxiesObject["proxies"] as? [String: Any])
        let defaultGroup = try XCTUnwrap(proxyMap["Default"] as? [String: Any])
        XCTAssertEqual(defaultGroup["now"] as? String, "DIRECT")
        XCTAssertEqual(defaultGroup["all"] as? [String], ["DIRECT"])

        let rulesData = try SwiftCoreJSON.data(state.rulesObject())
        let rulesObject = try XCTUnwrap(JSONSerialization.jsonObject(with: rulesData) as? [String: Any])
        let rules = try XCTUnwrap(rulesObject["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.first?["type"] as? String, "MATCH")
        XCTAssertEqual(rules.first?["proxy"] as? String, "DIRECT")

        let connectionsData = try SwiftCoreJSON.data(state.connectionsObject())
        let connectionsObject = try XCTUnwrap(JSONSerialization.jsonObject(with: connectionsData) as? [String: Any])
        XCTAssertEqual((connectionsObject["connections"] as? [Any])?.count, 0)
    }

    func testRuntimeServesControllerAndDirectProxy() async throws {
        let mixedPort = try Self.unusedTCPPort()
        let controllerPort = try Self.unusedTCPPort(excluding: [mixedPort])
        let originPort = try Self.unusedTCPPort(excluding: [mixedPort, controllerPort])

        let origin = TinyHTTPServer(port: originPort)
        try origin.start()
        defer { origin.stop() }

        let configuration = try SwiftCoreConfiguration.parse(yaml: Self.sampleYAML(mixedPort: mixedPort, controllerPort: controllerPort))
        let runtime = SwiftCoreRuntimeSession(configuration: configuration)
        try runtime.start()
        defer { runtime.stop() }

        let version = try await controllerJSON(path: "/version", port: controllerPort)
        XCTAssertEqual(version["version"] as? String, "neoclash-swift-core 0.1.0")

        let configs = try await controllerJSON(path: "/configs", port: controllerPort)
        XCTAssertEqual(configs["mixed-port"] as? Int, mixedPort)
        XCTAssertEqual(configs["mode"] as? String, "rule")

        _ = try await controllerJSON(
            path: "/configs",
            method: "PATCH",
            port: controllerPort,
            body: Data(#"{"mode":"direct"}"#.utf8),
            expectedStatus: 204
        )
        let updatedConfigs = try await controllerJSON(path: "/configs", port: controllerPort)
        XCTAssertEqual(updatedConfigs["mode"] as? String, "direct")

        let proxies = try await controllerJSON(path: "/proxies", port: controllerPort)
        let proxyMap = try XCTUnwrap(proxies["proxies"] as? [String: Any])
        XCTAssertNotNil(proxyMap["Default"])

        let rules = try await controllerJSON(path: "/rules", port: controllerPort)
        XCTAssertEqual((rules["rules"] as? [Any])?.count, 1)

        try await assertReceivesTrafficWebSocket(controllerPort: controllerPort)

        let httpResponse = try TCPSocket.roundTrip(
            port: mixedPort,
            request: "GET http://127.0.0.1:\(originPort)/http HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n"
        )
        XCTAssertTrue(httpResponse.contains("swift-core-ok /http"), httpResponse)

        let connectSocket = try TCPSocket(port: mixedPort)
        try connectSocket.write("CONNECT 127.0.0.1:\(originPort) HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\n\r\n")
        XCTAssertTrue(try connectSocket.readString().contains("200 Connection Established"))
        try connectSocket.write("GET /connect HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n")
        XCTAssertTrue(try connectSocket.readString().contains("swift-core-ok /connect"))
        connectSocket.close()

        let socksSocket = try TCPSocket(port: mixedPort)
        try socksSocket.writeBytes([0x05, 0x01, 0x00])
        XCTAssertEqual(try socksSocket.readBytes(max: 2), [0x05, 0x00])
        try socksSocket.writeBytes([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, UInt8(originPort >> 8), UInt8(originPort & 0xff)])
        XCTAssertEqual(try socksSocket.readBytes(max: 10).prefix(2), [0x05, 0x00])
        try socksSocket.write("GET /socks HTTP/1.1\r\nHost: 127.0.0.1:\(originPort)\r\nConnection: close\r\n\r\n")
        XCTAssertTrue(try socksSocket.readString().contains("swift-core-ok /socks"))
        socksSocket.close()
    }

    func testRuntimeRoutesThroughVLESSOutbound() throws {
        let mixedPort = try Self.unusedTCPPort()
        let controllerPort = try Self.unusedTCPPort(excluding: [mixedPort])
        let vlessPort = try Self.unusedTCPPort(excluding: [mixedPort, controllerPort])

        let uuidString = "11111111-1111-1111-1111-111111111111"
        let server = FakeVLESSServer(port: vlessPort, expectedUUID: [UInt8](repeating: 0x11, count: 16))
        try server.start()
        defer { server.stop() }

        let yaml = """
        mixed-port: \(mixedPort)
        external-controller: 127.0.0.1:\(controllerPort)
        secret: test-secret
        mode: rule
        log-level: info
        allow-lan: false
        proxies:
          - name: vless-test
            type: vless
            server: 127.0.0.1
            port: \(vlessPort)
            uuid: \(uuidString)
        proxy-groups:
          - name: Default
            type: select
            proxies:
              - vless-test
        rules:
          - MATCH,vless-test
        """
        let configuration = try SwiftCoreConfiguration.parse(yaml: yaml)
        let runtime = SwiftCoreRuntimeSession(configuration: configuration)
        try runtime.start()
        defer { runtime.stop() }

        let response = try TCPSocket.roundTrip(
            port: mixedPort,
            request: "GET http://127.0.0.1:\(vlessPort)/vless HTTP/1.1\r\nHost: 127.0.0.1:\(vlessPort)\r\nConnection: close\r\n\r\n"
        )
        XCTAssertTrue(response.contains("swift-core-ok /vless"), response)
    }

    func testDelayEndpointMeasuresDirect() async throws {
        let mixedPort = try Self.unusedTCPPort()
        let controllerPort = try Self.unusedTCPPort(excluding: [mixedPort])
        let originPort = try Self.unusedTCPPort(excluding: [mixedPort, controllerPort])

        let origin = TinyHTTPServer(port: originPort)
        try origin.start()
        defer { origin.stop() }

        let configuration = try SwiftCoreConfiguration.parse(yaml: Self.sampleYAML(mixedPort: mixedPort, controllerPort: controllerPort))
        let runtime = SwiftCoreRuntimeSession(configuration: configuration)
        try runtime.start()
        defer { runtime.stop() }

        let response = try await controllerJSON(
            path: "/proxies/DIRECT/delay?url=http://127.0.0.1:\(originPort)/generate_204&timeout=3000",
            port: controllerPort
        )
        let delay = try XCTUnwrap(response["delay"] as? Int)
        XCTAssertGreaterThanOrEqual(delay, 0)
        XCTAssertLessThan(delay, 3000)
    }

    private static func sampleYAML(mixedPort: Int = 17897, controllerPort: Int = 19097) -> String {
        """
        mixed-port: \(mixedPort)
        external-controller: 127.0.0.1:\(controllerPort)
        secret: test-secret
        mode: rule
        log-level: info
        allow-lan: false
        proxies: []
        proxy-groups:
          - name: Default
            type: select
            proxies:
              - DIRECT
        rules:
          - MATCH,DIRECT
        """
    }

    private static func unusedTCPPort(excluding excluded: Set<Int> = []) throws -> Int {
        for _ in 0..<20 {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else {
                throw POSIXError(.init(rawValue: errno) ?? .EIO)
            }
            defer { Darwin.close(fd) }

            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = 0
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
            let bindResult = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bindResult == 0 else {
                continue
            }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let nameResult = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &length)
                }
            }
            guard nameResult == 0 else {
                continue
            }
            let port = Int(UInt16(bigEndian: address.sin_port))
            if !excluded.contains(port) {
                return port
            }
        }
        throw POSIXError(.EADDRINUSE)
    }

    private func controllerJSON(
        path: String,
        method: String = "GET",
        port: Int,
        body: Data? = nil,
        expectedStatus: Int = 200
    ) async throws -> [String: Any] {
        var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)\(path)")!)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer test-secret", forHTTPHeaderField: "Authorization")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        let httpResponse = try XCTUnwrap(response as? HTTPURLResponse)
        XCTAssertEqual(httpResponse.statusCode, expectedStatus)
        guard !data.isEmpty else {
            return [:]
        }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func assertReceivesTrafficWebSocket(controllerPort: Int) async throws {
        var request = URLRequest(url: URL(string: "ws://127.0.0.1:\(controllerPort)/traffic")!)
        request.setValue("Bearer test-secret", forHTTPHeaderField: "Authorization")
        let task = URLSession.shared.webSocketTask(with: request)
        task.resume()
        defer { task.cancel(with: .normalClosure, reason: nil) }

        let message = try await task.receive()
        switch message {
        case .string(let text):
            let data = Data(text.utf8)
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertNotNil(object["up"])
            XCTAssertNotNil(object["down"])
        case .data(let data):
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertNotNil(object["up"])
            XCTAssertNotNil(object["down"])
        @unknown default:
            XCTFail("Unexpected WebSocket message.")
        }
    }
}

private final class TinyHTTPServer: @unchecked Sendable {
    private let port: Int
    private var listenFD: Int32 = -1
    private var thread: Thread?
    private var isRunning = false

    init(port: Int) {
        self.port = port
    }

    func start() throws {
        listenFD = socket(AF_INET, SOCK_STREAM, 0)
        guard listenFD >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        var reuse: Int32 = 1
        setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0, listen(listenFD, 16) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }

        isRunning = true
        let thread = Thread { [weak self] in
            self?.acceptLoop()
        }
        self.thread = thread
        thread.start()
    }

    func stop() {
        isRunning = false
        if listenFD >= 0 {
            Darwin.shutdown(listenFD, SHUT_RDWR)
            Darwin.close(listenFD)
            listenFD = -1
        }
    }

    private func acceptLoop() {
        while isRunning {
            let fd = accept(listenFD, nil, nil)
            guard fd >= 0 else {
                continue
            }
            Thread {
                self.handle(fd: fd)
            }.start()
        }
    }

    private func handle(fd: Int32) {
        defer { Darwin.close(fd) }
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(fd, &buffer, buffer.count)
        guard count > 0,
              let request = String(bytes: buffer.prefix(count), encoding: .utf8) else {
            return
        }
        let path = request.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
        let body = "swift-core-ok \(path)"
        let response = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        _ = response.withCString { pointer in
            Darwin.write(fd, pointer, strlen(pointer))
        }
    }
}

/// A minimal raw-socket VLESS server for integration testing: it reads and verifies the VLESS
/// request header, strips it, then replies with the VLESS response header followed by an HTTP 200
/// echoing the request path — mirroring `TinyHTTPServer` so the same client assertions apply.
private final class FakeVLESSServer: @unchecked Sendable {
    private let port: Int
    private let expectedUUID: [UInt8]
    private var listenFD: Int32 = -1
    private var thread: Thread?
    private var isRunning = false

    init(port: Int, expectedUUID: [UInt8]) {
        self.port = port
        self.expectedUUID = expectedUUID
    }

    func start() throws {
        listenFD = socket(AF_INET, SOCK_STREAM, 0)
        guard listenFD >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        var reuse: Int32 = 1
        setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0, listen(listenFD, 16) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }

        isRunning = true
        let thread = Thread { [weak self] in
            self?.acceptLoop()
        }
        self.thread = thread
        thread.start()
    }

    func stop() {
        isRunning = false
        if listenFD >= 0 {
            Darwin.shutdown(listenFD, SHUT_RDWR)
            Darwin.close(listenFD)
            listenFD = -1
        }
    }

    private func acceptLoop() {
        while isRunning {
            let fd = accept(listenFD, nil, nil)
            guard fd >= 0 else {
                continue
            }
            Thread {
                self.handle(fd: fd)
            }.start()
        }
    }

    private func handle(fd: Int32) {
        defer { Darwin.close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var buffer: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(fd, &chunk, chunk.count)
            guard count > 0 else { return }
            buffer.append(contentsOf: chunk.prefix(count))
            guard let headerLength = Self.headerLength(buffer), buffer.count >= headerLength else {
                continue
            }
            let httpBytes = Array(buffer[headerLength...])
            guard httpBytes.containsSequence([13, 10, 13, 10]) else {
                continue
            }
            respond(fd: fd, header: Array(buffer[0..<headerLength]), httpBytes: httpBytes)
            return
        }
    }

    /// Length of a VLESS request header given the bytes seen so far, or nil if not yet determinable.
    private static func headerLength(_ buffer: [UInt8]) -> Int? {
        guard buffer.count >= 22 else { return nil }
        switch buffer[21] {
        case 0x01: return 26              // IPv4
        case 0x03: return 38              // IPv6
        case 0x02: return 23 + Int(buffer[22]) // domain (1 length byte + name)
        default: return nil
        }
    }

    private func respond(fd: Int32, header: [UInt8], httpBytes: [UInt8]) {
        let version = header[0]
        let command = header[18]
        let uuid = Array(header[1..<17])
        let request = String(decoding: httpBytes, as: UTF8.self)
        let path = request.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
        let accepted = version == 0x00 && command == 0x01 && uuid == expectedUUID
        let body = accepted ? "swift-core-ok \(path)" : "swift-core-bad"
        let httpResponse = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"

        var out: [UInt8] = [0x00, 0x00] // VLESS response header: version + addon length
        out.append(contentsOf: Array(httpResponse.utf8))
        _ = out.withUnsafeBytes { pointer in
            Darwin.write(fd, pointer.baseAddress, out.count)
        }
    }
}

private final class TCPSocket {
    private var fd: Int32

    init(host: String = "127.0.0.1", port: Int) throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        inet_pton(AF_INET, host, &address.sin_addr)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            let error = POSIXError(.init(rawValue: errno) ?? .EIO)
            close()
            throw error
        }
    }

    deinit {
        close()
    }

    static func roundTrip(port: Int, request: String) throws -> String {
        let socket = try TCPSocket(port: port)
        try socket.write(request)
        defer { socket.close() }
        return try socket.readString()
    }

    func write(_ string: String) throws {
        try writeBytes(Array(string.utf8))
    }

    func writeBytes(_ bytes: [UInt8]) throws {
        var sent = 0
        while sent < bytes.count {
            let written = bytes.withUnsafeBytes {
                Darwin.write(fd, $0.baseAddress!.advanced(by: sent), bytes.count - sent)
            }
            guard written > 0 else {
                throw POSIXError(.init(rawValue: errno) ?? .EIO)
            }
            sent += written
        }
    }

    func readBytes(max: Int = 8192) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: max)
        let count = Darwin.read(fd, &buffer, max)
        if count < 0 {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        return Array(buffer.prefix(count))
    }

    func readString() throws -> String {
        var bytes: [UInt8] = []
        while true {
            var chunk = [UInt8](repeating: 0, count: 4096)
            let count = Darwin.read(fd, &chunk, chunk.count)
            if count > 0 {
                bytes.append(contentsOf: chunk.prefix(count))
                if bytes.containsSequence([13, 10, 13, 10]), bytes.containsSequence(Array("swift-core-ok".utf8)) {
                    break
                }
            } else {
                break
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    func close() {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }
}

private extension Array where Element == UInt8 {
    func containsSequence(_ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, count >= needle.count else { return false }
        for index in 0...(count - needle.count) where Array(self[index..<index + needle.count]) == needle {
            return true
        }
        return false
    }
}

#endif
