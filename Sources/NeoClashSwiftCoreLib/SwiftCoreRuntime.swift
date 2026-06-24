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
    private var stopped = false

    public init(configuration: SwiftCoreConfiguration, runtimeDirectory: String? = nil, numberOfThreads: Int = max(2, System.coreCount)) {
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
        } catch {
            stop()
            throw error
        }
    }

    private func startGeoLoaderIfNeeded() {
        guard let runtimeDirectory else { return }
        let required = state.requiresGeoData()
        guard required.geoip || required.geosite else { return }
        let loader = SwiftCoreGeoLoader(
            state: state,
            directory: runtimeDirectory,
            geoipURL: state.geoipURL,
            geositeURL: state.geositeURL,
            needsGeoIP: required.geoip,
            needsGeoSite: required.geosite
        )
        loader.start()
        geoLoader = loader
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
            FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
            return 1
        }
    }
}
