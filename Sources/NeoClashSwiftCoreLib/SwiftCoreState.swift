import Foundation
import NIOCore

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
    private var delays: [String: Int] = [:]            // proxy name -> last successful delay (ms)
    private var loadBalanceCounters: [String: Int] = [:]

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
        let secret = self.secret
        if secret.isEmpty {
            return true // no secret configured → authentication disabled (mihomo behavior)
        }
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
            func history(_ name: String) -> [[String: Int]] {
                guard let delay = delays[name] else { return [] }
                return [["delay": delay]]
            }

            var proxies: [String: [String: Any]] = [
                "DIRECT": ["type": "Direct", "name": "DIRECT", "history": [["delay": 0]]],
                "REJECT": ["type": "Reject", "name": "REJECT", "history": []]
            ]

            for proxy in configuration.proxies {
                proxies[proxy.name] = [
                    "type": proxy.type,
                    "name": proxy.name,
                    "history": history(proxy.name)
                ]
            }

            for group in configuration.proxyGroups {
                proxies[group.name] = [
                    "type": group.type,
                    "name": group.name,
                    "all": group.proxies,
                    "now": chooseMember(group: group, host: ""),
                    "history": []
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
                let proxy = configuration.proxyGroups.first?.name ?? "DIRECT"
                return resolve(proxy: proxy, host: host, chain: [proxy])
            default:
                for rule in configuration.rules where matches(rule: rule, host: host) {
                    return resolve(proxy: rule.proxy, host: host, chain: [rule.proxy])
                }
                return .outbound(chain: ["DIRECT"], outbound: directOutbound)
            }
        }
    }

    // MARK: Health checks / delays (lock-free public API uses withLock internally)

    public func recordDelay(name: String, delay: Int) {
        withLock { delays[name] = delay }
        appendLog(level: "info", message: "\(name) delay \(delay)ms")
    }

    public func recordFailure(name: String) {
        withLock { delays[name] = nil }
    }

    public func delay(for name: String) -> Int? {
        withLock { delays[name] }
    }

    /// Proxies (not groups, not DIRECT/REJECT) that the periodic monitor should test.
    public func outboundsToHealthCheck() -> [(name: String, outbound: SwiftCoreOutbound)] {
        withLock { configuration.proxies.compactMap { proxy in
            outbounds[proxy.name].map { (proxy.name, $0) }
        } }
    }

    /// Resolves a proxy/group name to the concrete adapter to dial (for on-demand delay testing).
    public func outbound(named name: String) -> SwiftCoreOutbound? {
        withLock { memberOutbound(name: name, host: "", depth: 0) }
    }

    /// Tests one proxy/group's latency, recording the result so groups and `/proxies` reflect it.
    public func measureDelay(name: String, url: String, timeoutMilliseconds: Int, on eventLoop: EventLoop) -> EventLoopFuture<Int> {
        let upper = name.uppercased()
        guard upper != "REJECT" else {
            return eventLoop.makeFailedFuture(SwiftCoreError.invalidConfig("REJECT has no delay"))
        }
        guard let outbound = outbound(named: name) else {
            return eventLoop.makeFailedFuture(SwiftCoreError.invalidConfig("proxy \(name) not found"))
        }
        return SwiftCoreHealthProbe.measure(outbound: outbound, on: eventLoop, url: url, timeoutMilliseconds: timeoutMilliseconds)
            .always { [weak self] result in
                switch result {
                case .success(let milliseconds):
                    self?.recordDelay(name: name, delay: milliseconds)
                case .failure:
                    self?.recordFailure(name: name)
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

    private func resolve(proxy: String, host: String, chain: [String]) -> SwiftCoreRouteDecision {
        let normalized = proxy.uppercased()
        if normalized == "DIRECT" {
            return .outbound(chain: chain.isEmpty ? ["DIRECT"] : chain, outbound: directOutbound)
        }
        if normalized == "REJECT" {
            return .reject(chain: chain.isEmpty ? ["REJECT"] : chain)
        }
        if let group = configuration.proxyGroups.first(where: { $0.name == proxy }) {
            let selected = chooseMember(group: group, host: host)
            if selected == proxy {
                return .unsupported(chain: chain, proxy: proxy)
            }
            return resolve(proxy: selected, host: host, chain: chain + [selected])
        }
        if let outbound = outbounds[proxy] {
            return .outbound(chain: chain.isEmpty ? [proxy] : chain, outbound: outbound)
        }
        return .unsupported(chain: chain, proxy: proxy)
    }

    /// Chooses a group member according to its type. Must be called while holding `lock`.
    private func chooseMember(group: SwiftCoreProxyGroup, host: String) -> String {
        let members = group.proxies.isEmpty ? ["DIRECT"] : group.proxies
        switch group.type.lowercased() {
        case "url-test", "urltest":
            let alive = members.filter { isAlive($0) }
            return alive.min { (delays[$0] ?? Int.max) < (delays[$1] ?? Int.max) } ?? members[0]
        case "fallback":
            return members.first { isAlive($0) } ?? members[0]
        case "load-balance", "loadbalance":
            let alive = members.filter { isAlive($0) }
            let pool = alive.isEmpty ? members : alive
            let index = Self.stableHash(host) % UInt64(pool.count)
            return pool[Int(index)]
        default: // select
            if let selected = selections[group.name], members.contains(selected) {
                return selected
            }
            return members[0]
        }
    }

    /// A member is considered alive if it can carry traffic: DIRECT always, a proxy with a recorded
    /// delay, or a nested group (assumed resolvable). REJECT is never alive.
    private func isAlive(_ name: String) -> Bool {
        let upper = name.uppercased()
        if upper == "DIRECT" { return true }
        if upper == "REJECT" { return false }
        if configuration.proxyGroups.contains(where: { $0.name == name }) { return true }
        return delays[name] != nil
    }

    /// Resolves a name to a concrete adapter (DIRECT or a proxy), following groups. Holds `lock`.
    private func memberOutbound(name: String, host: String, depth: Int) -> SwiftCoreOutbound? {
        guard depth < 16 else { return nil }
        let upper = name.uppercased()
        if upper == "DIRECT" { return directOutbound }
        if upper == "REJECT" { return nil }
        if let group = configuration.proxyGroups.first(where: { $0.name == name }) {
            let member = chooseMember(group: group, host: host)
            if member == name { return nil }
            return memberOutbound(name: member, host: host, depth: depth + 1)
        }
        return outbounds[name]
    }

    /// A deterministic FNV-1a hash so load-balance keeps a host pinned to one member within a run.
    private static func stableHash(_ value: String) -> UInt64 {
        var hash: UInt64 = 1_469_598_103_934_665_603
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 1_099_511_628_211
        }
        return hash
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
