import Foundation

public enum SwiftCoreRouteDecision: Sendable {
    case outbound(chain: [String], outbound: SwiftCoreOutbound)
    case reject(chain: [String])
    case unsupported(chain: [String], proxy: String)
}

public struct SwiftCoreConnectionSnapshot: Equatable, Sendable {
    public var id: String
    public var host: String
    public var rule: String
    public var chain: [String]
    public var upload: Int
    public var download: Int

    public init(id: String, host: String, rule: String, chain: [String], upload: Int = 0, download: Int = 0) {
        self.id = id
        self.host = host
        self.rule = rule
        self.chain = chain
        self.upload = upload
        self.download = download
    }
}

public final class SwiftCoreState: @unchecked Sendable {
    private let lock = NSLock()
    private var configuration: SwiftCoreConfiguration
    private var selections: [String: String]
    private var connections: [String: SwiftCoreConnectionSnapshot] = [:]
    private var pendingUploadBytes = 0
    private var pendingDownloadBytes = 0
    private var logs: [[String: String]] = []
    private let directOutbound: SwiftCoreOutbound = SwiftCoreDirectOutbound()
    private var outbounds: [String: SwiftCoreOutbound]

    public init(configuration: SwiftCoreConfiguration) {
        self.configuration = configuration
        self.selections = Dictionary(uniqueKeysWithValues: configuration.proxyGroups.map { group in
            (group.name, group.proxies.first ?? "DIRECT")
        })
        let (built, warnings) = Self.makeOutbounds(configuration)
        self.outbounds = built
        appendLog(level: "info", message: "NeoClash Swift core initialized")
        for warning in warnings {
            appendLog(level: "warning", message: warning)
        }
    }

    private static func makeOutbounds(_ configuration: SwiftCoreConfiguration) -> ([String: SwiftCoreOutbound], [String]) {
        var result: [String: SwiftCoreOutbound] = [:]
        var warnings: [String] = []
        for proxy in configuration.proxies {
            do {
                if let outbound = try SwiftCoreOutboundFactory.make(proxy: proxy) {
                    result[proxy.name] = outbound
                } else {
                    warnings.append("Proxy \(proxy.name) of type \(proxy.type) is not supported yet; routes using it will be rejected.")
                }
            } catch {
                warnings.append("Proxy \(proxy.name) is invalid: \(error.localizedDescription)")
            }
        }
        return (result, warnings)
    }

    public var secret: String {
        withLock { configuration.secret }
    }

    public var controllerHost: String {
        withLock { configuration.controllerHost }
    }

    public var controllerPort: Int {
        withLock { configuration.controllerPort }
    }

    public var mixedBindHost: String {
        withLock { configuration.allowLAN ? "0.0.0.0" : "127.0.0.1" }
    }

    public var mixedPort: Int {
        withLock { configuration.mixedPort }
    }

    public func replaceConfiguration(_ configuration: SwiftCoreConfiguration) {
        let (built, warnings) = Self.makeOutbounds(configuration)
        withLock {
            self.configuration = configuration
            var nextSelections: [String: String] = [:]
            for group in configuration.proxyGroups {
                if let existing = selections[group.name], group.proxies.contains(existing) {
                    nextSelections[group.name] = existing
                } else {
                    nextSelections[group.name] = group.proxies.first ?? "DIRECT"
                }
            }
            selections = nextSelections
            outbounds = built
        }
        appendLog(level: "info", message: "Reloaded Swift core configuration")
        for warning in warnings {
            appendLog(level: "warning", message: warning)
        }
    }

    public func isAuthorized(headers: [String: String]) -> Bool {
        let auth = headers.first { $0.key.caseInsensitiveCompare("authorization") == .orderedSame }?.value
        return auth == "Bearer \(secret)"
    }

    public func configsObject() -> [String: Any] {
        withLock {
            [
                "mixed-port": configuration.mixedPort,
                "mode": configuration.mode,
                "log-level": configuration.logLevel
            ]
        }
    }

    public func updateMode(_ mode: String) {
        withLock {
            configuration.mode = mode
        }
        appendLog(level: "info", message: "Switched outbound mode to \(mode)")
    }

    public func proxiesObject() -> [String: Any] {
        withLock {
            var proxies: [String: [String: Any]] = [
                "DIRECT": ["type": "Direct", "delay": 0],
                "REJECT": ["type": "Reject", "delay": 0]
            ]

            for proxy in configuration.proxies {
                proxies[proxy.name] = [
                    "type": proxy.type,
                    "delay": NSNull()
                ]
            }

            for group in configuration.proxyGroups {
                proxies[group.name] = [
                    "type": group.type,
                    "all": group.proxies,
                    "now": selections[group.name] ?? group.proxies.first ?? "DIRECT"
                ]
            }

            return ["proxies": proxies]
        }
    }

    public func selectProxy(group: String, proxy: String) -> Bool {
        let updated = withLock { () -> Bool in
            guard let proxyGroup = configuration.proxyGroups.first(where: { $0.name == group }),
                  proxyGroup.proxies.contains(proxy) else {
                return false
            }
            selections[group] = proxy
            return true
        }
        if updated {
            appendLog(level: "info", message: "Selected \(proxy) for \(group)")
        }
        return updated
    }

    public func rulesObject() -> [String: Any] {
        withLock {
            [
                "rules": configuration.rules.map { rule in
                    [
                        "type": rule.type,
                        "payload": rule.payload,
                        "proxy": rule.proxy
                    ]
                }
            ]
        }
    }

    public func connectionsObject() -> [String: Any] {
        withLock {
            [
                "connections": connections.values
                    .sorted { $0.id < $1.id }
                    .map(Self.connectionObject)
            ]
        }
    }

    public func clearConnections() {
        withLock {
            connections.removeAll()
        }
        appendLog(level: "info", message: "Cleared Swift core connection table")
    }

    public func addConnection(host: String, rule: String, chain: [String]) -> String {
        let id = UUID().uuidString
        withLock {
            connections[id] = SwiftCoreConnectionSnapshot(id: id, host: host, rule: rule, chain: chain)
        }
        return id
    }

    public func removeConnection(id: String?) {
        guard let id else { return }
        _ = withLock {
            connections.removeValue(forKey: id)
        }
    }

    public func recordUpload(id: String?, bytes: Int) {
        recordTraffic(id: id, upload: bytes, download: 0)
    }

    public func recordDownload(id: String?, bytes: Int) {
        recordTraffic(id: id, upload: 0, download: bytes)
    }

    public func trafficObjectAndReset() -> [String: Any] {
        withLock {
            let object = ["up": pendingUploadBytes, "down": pendingDownloadBytes]
            pendingUploadBytes = 0
            pendingDownloadBytes = 0
            return object
        }
    }

    public func nextLogObject() -> [String: String] {
        withLock {
            if logs.isEmpty {
                return ["type": "info", "payload": "Swift core heartbeat"]
            }
            return logs.removeFirst()
        }
    }

    public func appendLog(level: String, message: String) {
        withLock {
            logs.append(["type": level, "payload": message])
            if logs.count > 256 {
                logs.removeFirst(logs.count - 256)
            }
        }
    }

    public func route(host: String) -> SwiftCoreRouteDecision {
        withLock {
            switch configuration.mode.lowercased() {
            case "direct":
                return .outbound(chain: ["DIRECT"], outbound: directOutbound)
            case "global":
                let proxy = configuration.proxyGroups.first.flatMap { selections[$0.name] } ?? "DIRECT"
                return resolve(proxy: proxy, chain: [proxy])
            default:
                for rule in configuration.rules where matches(rule: rule, host: host) {
                    return resolve(proxy: rule.proxy, chain: [rule.proxy])
                }
                return .outbound(chain: ["DIRECT"], outbound: directOutbound)
            }
        }
    }

    private func recordTraffic(id: String?, upload: Int, download: Int) {
        withLock {
            pendingUploadBytes += upload
            pendingDownloadBytes += download
            if let id, var connection = connections[id] {
                connection.upload += upload
                connection.download += download
                connections[id] = connection
            }
        }
    }

    private func resolve(proxy: String, chain: [String]) -> SwiftCoreRouteDecision {
        let normalized = proxy.uppercased()
        if normalized == "DIRECT" {
            return .outbound(chain: chain.isEmpty ? ["DIRECT"] : chain, outbound: directOutbound)
        }
        if normalized == "REJECT" {
            return .reject(chain: chain.isEmpty ? ["REJECT"] : chain)
        }
        if let group = configuration.proxyGroups.first(where: { $0.name == proxy }) {
            let selected = selections[group.name] ?? group.proxies.first ?? "DIRECT"
            if selected == proxy {
                return .unsupported(chain: chain, proxy: proxy)
            }
            return resolve(proxy: selected, chain: chain + [selected])
        }
        if let outbound = outbounds[proxy] {
            return .outbound(chain: chain.isEmpty ? [proxy] : chain, outbound: outbound)
        }
        return .unsupported(chain: chain, proxy: proxy)
    }

    private func matches(rule: SwiftCoreRule, host: String) -> Bool {
        let normalizedHost = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        switch rule.type.uppercased() {
        case "MATCH":
            return true
        case "DOMAIN":
            return normalizedHost == rule.payload.lowercased()
        case "DOMAIN-SUFFIX":
            let payload = rule.payload.lowercased()
            return normalizedHost == payload || normalizedHost.hasSuffix("." + payload)
        default:
            return false
        }
    }

    private static func connectionObject(_ connection: SwiftCoreConnectionSnapshot) -> [String: Any] {
        [
            "id": connection.id,
            "metadata": [
                "host": connection.host
            ],
            "rule": connection.rule,
            "chains": connection.chain,
            "upload": connection.upload,
            "download": connection.download
        ]
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

public enum SwiftCoreJSON {
    public static func data(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    public static func string(_ object: Any) -> String {
        guard let data = try? data(object), let text = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return text
    }
}
