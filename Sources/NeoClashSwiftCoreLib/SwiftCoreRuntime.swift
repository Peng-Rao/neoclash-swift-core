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

        let session = SwiftCoreRuntimeSession(configuration: configuration)
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
    private var controller: Channel?
    private var mixed: Channel?
    private var stopped = false

    public init(configuration: SwiftCoreConfiguration, numberOfThreads: Int = max(2, System.coreCount)) {
        self.state = SwiftCoreState(configuration: configuration)
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: numberOfThreads)
    }

    deinit {
        stop()
    }

    public func start() throws {
        do {
            controller = try SwiftCoreControllerServer(state: state, group: group).start()
            mixed = try SwiftCoreMixedProxyServer(state: state, group: group).start()
        } catch {
            stop()
            throw error
        }
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
            fputs("\(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}
