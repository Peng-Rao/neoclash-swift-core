import Foundation
import NIOCore
import NIOPosix

public final class SwiftCoreRuntime {
    private let command: SwiftCoreCommand

    public init(command: SwiftCoreCommand) {
        self.command = command
    }

    public func run() throws {
        let configuration = try SwiftCoreConfiguration.load(from: command.configPath)
        if command.validateOnly {
            print("configuration is valid")
            return
        }

        let session = SwiftCoreRuntimeSession(configuration: configuration, runtimeDirectory: command.runtimeDirectoryPath)
        try session.start()
        defer { session.stop() }

        print("neoclash-swift-core 0.1.0")
        print("controller=\(configuration.controllerHost):\(configuration.controllerPort)")
        print("mixed=\(session.state.mixedBindHost):\(configuration.mixedPort)")

        try session.wait()
    }
}

public final class SwiftCoreRuntimeSession: @unchecked Sendable {
    public let state: SwiftCoreState
    private let group: MultiThreadedEventLoopGroup
    private let runtimeDirectory: String?
    private var controller: Channel?
    private var mixed: Channel?
    private var healthMonitor: SwiftCoreHealthMonitor?
    private var geoLoader: SwiftCoreGeoLoader?
    private var ruleProviderLoader: SwiftCoreRuleProviderLoader?
    private var dnsServer: SwiftCoreDNSServer?
    private var stopped = false

    /// A loopback proxy saturates long before it needs an event loop per core, and each extra
    /// NIO thread carries its own stack and allocator caches — cap the default at four.
    public init(configuration: SwiftCoreConfiguration, runtimeDirectory: String? = nil, numberOfThreads: Int = max(2, min(4, System.coreCount))) {
        self.state = SwiftCoreState(configuration: configuration)
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: numberOfThreads)
        self.runtimeDirectory = runtimeDirectory
    }

    deinit {
        stop()
    }

    public func start() throws {
        do {
            controller = try SwiftCoreControllerServer(state: state, group: group).start()
            mixed = try SwiftCoreMixedProxyServer(state: state, group: group).start()
            let monitor = SwiftCoreHealthMonitor(state: state, group: group)
            monitor.start()
            healthMonitor = monitor
            startGeoLoaderIfNeeded()
            startRuleProviderLoaderIfNeeded()
            if state.dnsEnabled {
                let dns = state.dnsConfig()
                let resolver = SwiftCoreDNSResolver(config: dns, group: group)
                state.setResolver(resolver)
                startDNSServerIfNeeded(dns: dns, resolver: resolver)
            }
        } catch {
            stop()
            throw error
        }
    }

    private func startGeoLoaderIfNeeded() {
        guard let runtimeDirectory else { return }
        let required = state.requiresGeoData()
        guard required.geoip || required.geosite else { return }
        let codes = state.requiredGeoCodes()
        let loader = SwiftCoreGeoLoader(
            state: state,
            directory: runtimeDirectory,
            geoipURL: state.geoipURL,
            geositeURL: state.geositeURL,
            needsGeoIP: required.geoip,
            needsGeoSite: required.geosite,
            geoipCodes: codes.geoip,
            geositeCodes: codes.geosite
        )
        loader.start()
        geoLoader = loader
    }

    /// In fake-ip mode, build the shared pool and (if `dns.listen` is set) start the DNS server.
    private func startDNSServerIfNeeded(dns: SwiftCoreDNSConfig, resolver: SwiftCoreDNSResolver) {
        guard dns.isFakeIP, let pool = SwiftCoreFakeIPPool(cidr: dns.fakeIPRange) else { return }
        state.setFakeIPPool(pool)
        let listen = dns.listen.trimmingCharacters(in: .whitespaces)
        guard !listen.isEmpty else { return }
        let host: String
        let port: Int
        if let separator = listen.lastIndex(of: ":"), let parsed = Int(listen[listen.index(after: separator)...]) {
            host = String(listen[..<separator])
            port = parsed
        } else {
            host = listen
            port = 53
        }
        let filter = SwiftCoreFakeIPFilter(patterns: dns.fakeIPFilter)
        let server = SwiftCoreDNSServer(state: state, pool: pool, resolver: resolver, filter: filter, group: group)
        do {
            try server.start(host: host.isEmpty ? "0.0.0.0" : host, port: port)
            dnsServer = server
        } catch {
            state.appendLog(level: "warning", message: "DNS server failed to start on \(listen): \(SwiftCoreErrorText.describe(error))")
        }
    }

    private func startRuleProviderLoaderIfNeeded() {
        guard let runtimeDirectory else { return }
        let providers = state.ruleProviders()
        guard !providers.isEmpty else { return }
        let loader = SwiftCoreRuleProviderLoader(state: state, directory: runtimeDirectory, providers: providers)
        loader.start()
        ruleProviderLoader = loader
    }

    public func wait() throws {
        guard let controller, let mixed else {
            return
        }
        _ = try controller.closeFuture.and(mixed.closeFuture).wait()
    }

    public func stop() {
        guard !stopped else {
            return
        }
        stopped = true
        healthMonitor?.stop()
        healthMonitor = nil
        dnsServer?.stop()
        dnsServer = nil
        try? controller?.close().wait()
        try? mixed?.close().wait()
        try? group.syncShutdownGracefully()
        controller = nil
        mixed = nil
    }
}

public enum SwiftCoreMain {
    public static func run(arguments: [String]) -> Int32 {
        do {
            let command = try SwiftCoreCommand.parse(arguments: arguments)
            try SwiftCoreRuntime(command: command).run()
            return 0
        } catch {
            // Avoid the global C `stderr` (flagged as non-concurrency-safe on Linux/Glibc).
            FileHandle.standardError.write(Data("\(SwiftCoreErrorText.describe(error))\n".utf8))
            return 1
        }
    }
}
