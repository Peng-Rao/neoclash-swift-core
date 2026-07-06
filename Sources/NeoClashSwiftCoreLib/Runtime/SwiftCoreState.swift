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
    private var geoDatabase: SwiftCoreGeoDatabase?
    private var ruleSet: SwiftCoreRuleSet?
    private var resolver: SwiftCoreDNSResolver?
    private var fakeIPPool: SwiftCoreFakeIPPool?

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
        let unsupportedRules = Set(configuration.rules.map { $0.type.uppercased() })
            .subtracting(SwiftCoreRuleMatcher.supportedTypes)
        for type in unsupportedRules.sorted() {
            appendLog(level: "warning", message: "Rule type \(type) is not evaluated yet; such rules are skipped.")
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
                warnings.append("Proxy \(proxy.name) is invalid: \(SwiftCoreErrorText.describe(error))")
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

    /// Returns every pending log entry (oldest first) and clears the queue. Returns an empty
    /// array when idle — the log stream must stay silent rather than fabricate entries, or
    /// clients render a junk line for every tick.
    public func drainLogObjects() -> [[String: String]] {
        withLock {
            let drained = logs
            logs.removeAll(keepingCapacity: true)
            return drained
        }
    }

    public func appendLog(level: String, message: String) {
        withLock {
            guard Self.logRank(level) >= Self.logRank(configuration.logLevel) else {
                return
            }
            logs.append(["type": level, "payload": message])
            if logs.count > 256 {
                logs.removeFirst(logs.count - 256)
            }
        }
    }

    /// mihomo's log-level ordering: everything at or above the configured level is kept.
    /// Unknown levels rank as info so misspelled configs stay chatty rather than silent.
    static func logRank(_ level: String) -> Int {
        switch level.lowercased() {
        case "debug": 0
        case "info": 1
        case "warning": 2
        case "error": 3
        case "silent": Int.max
        default: 1
        }
    }

    public func route(host: String) -> SwiftCoreRouteDecision {
        route(context: SwiftCoreRouteContext(host: host, destinationPort: 0, sourcePort: nil))
    }

    public func route(context routeContext: SwiftCoreRouteContext) -> SwiftCoreRouteDecision {
        withLock {
            switch configuration.mode.lowercased() {
            case "direct":
                return .outbound(chain: ["DIRECT"], outbound: directOutbound)
            case "global":
                let proxy = configuration.proxyGroups.first?.name ?? "DIRECT"
                return resolve(proxy: proxy, host: routeContext.host, chain: [proxy])
            default:
                for rule in configuration.rules where SwiftCoreRuleMatcher.matches(rule: rule, context: routeContext, geo: geoDatabase, ruleSet: ruleSet) {
                    return resolve(proxy: rule.proxy, host: routeContext.host, chain: [rule.proxy])
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

    // MARK: Geo databases

    public func setGeoDatabase(_ database: SwiftCoreGeoDatabase) {
        withLock { geoDatabase = database }
    }

    /// The loaded GeoIP database, if any (used by the DNS resolver's fallback geoip filter).
    func currentGeoIP() -> SwiftCoreGeoIP? {
        withLock { geoDatabase?.geoip }
    }

    public func setRuleSet(_ newRuleSet: SwiftCoreRuleSet) {
        withLock { ruleSet = newRuleSet }
    }

    public func ruleProviders() -> [SwiftCoreRuleProvider] {
        withLock { configuration.ruleProviders }
    }

    // MARK: DNS-assisted routing

    public var dnsEnabled: Bool { withLock { configuration.dns.enable } }
    public func dnsConfig() -> SwiftCoreDNSConfig { withLock { configuration.dns } }

    public var tunEnabled: Bool { withLock { configuration.tun.enable } }
    public func tunConfig() -> SwiftCoreTUNConfig { withLock { configuration.tun } }

    public func setResolver(_ newResolver: SwiftCoreDNSResolver) {
        withLock { resolver = newResolver }
    }

    public func setFakeIPPool(_ pool: SwiftCoreFakeIPPool) {
        withLock { fakeIPPool = pool }
    }

    /// If `host` is a live fake ip, the domain it maps back to (for connecting/routing by domain).
    public func fakeIPDomain(forHost host: String) -> String? {
        guard case .ipv4(let bytes) = SwiftCoreAddress.detect(host: host) else { return nil }
        return withLock { fakeIPPool?.domain(forIPv4: bytes) }
    }

    /// Whether a domain target should be resolved before routing so IP-based rules can apply:
    /// a resolver is available and at least one IP-CIDR/GEOIP rule is not `no-resolve`.
    public func shouldResolveForRouting(host: String) -> Bool {
        withLock {
            guard resolver != nil, case .domain = SwiftCoreAddress.detect(host: host) else { return false }
            return configuration.rules.contains { rule in
                !rule.noResolve && ["IP-CIDR", "IP-CIDR6", "GEOIP"].contains(rule.type.uppercased())
            }
        }
    }

    /// Resolves `host` (if a resolver is set) and routes with the resolved IP available to IP rules.
    /// The resolution happens off the lock; `route(context:)` re-takes it.
    public func resolvedRoute(host: String, destinationPort: Int, sourcePort: Int?) async -> SwiftCoreRouteDecision {
        var resolvedIP: SwiftCoreAddress?
        if let resolver = withLock({ self.resolver }) {
            resolvedIP = await resolver.resolveFirst(host)
        }
        return route(context: SwiftCoreRouteContext(
            host: host,
            destinationPort: destinationPort,
            sourcePort: sourcePort,
            resolvedIP: resolvedIP
        ))
    }

    public var geoipURL: String { withLock { configuration.geoipURL } }
    public var geositeURL: String { withLock { configuration.geositeURL } }

    /// Whether the loaded rules reference GEOIP / GEOSITE, so the runtime can decide to fetch
    /// them. The DNS fallback geoip filter also needs geoip data.
    public func requiresGeoData() -> (geoip: Bool, geosite: Bool) {
        withLock {
            var geoip = false
            var geosite = false
            for rule in configuration.rules {
                switch rule.type.uppercased() {
                case "GEOIP": geoip = true
                case "GEOSITE": geosite = true
                default: break
                }
            }
            let dns = configuration.dns
            if dns.enable, !dns.fallback.isEmpty, dns.fallbackFilter.geoIP {
                geoip = true
            }
            return (geoip, geosite)
        }
    }

    /// Country/category codes referenced by GEOIP/GEOSITE rules, so the loader can skip
    /// materializing the rest of the databases. Empty sets mean "load everything": classical
    /// rule providers can carry geo rules whose codes are only known after download.
    public func requiredGeoCodes() -> (geoip: Set<String>, geosite: Set<String>) {
        withLock {
            let hasClassicalProviders = configuration.ruleProviders.contains {
                $0.behavior.lowercased() == "classical"
            }
            if hasClassicalProviders {
                return ([], [])
            }
            var geoip: Set<String> = []
            var geosite: Set<String> = []
            for rule in configuration.rules {
                switch rule.type.uppercased() {
                case "GEOIP": geoip.insert(rule.payload.uppercased())
                case "GEOSITE": geosite.insert(rule.payload.uppercased())
                default: break
                }
            }
            let dns = configuration.dns
            if dns.enable, !dns.fallback.isEmpty, dns.fallbackFilter.geoIP {
                geoip.insert(dns.fallbackFilter.geoIPCode.uppercased())
            }
            return (geoip, geosite)
        }
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
