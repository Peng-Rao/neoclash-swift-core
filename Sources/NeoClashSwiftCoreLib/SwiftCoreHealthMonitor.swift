import NIOCore

/// Periodically probes configured proxies so `url-test`/`fallback` groups can pick the best/first
/// alive member, and `/proxies` reflects current delays. Manual `/proxies/{name}/delay` calls and
/// `select` groups don't depend on it.
final class SwiftCoreHealthMonitor: @unchecked Sendable {
    private let state: SwiftCoreState
    private let group: EventLoopGroup
    private let url: String
    private let timeoutMilliseconds: Int
    private var task: RepeatedTask?

    init(
        state: SwiftCoreState,
        group: EventLoopGroup,
        url: String = SwiftCoreHealthProbe.defaultTestURL,
        timeoutMilliseconds: Int = 5000
    ) {
        self.state = state
        self.group = group
        self.url = url
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    /// `initialDelay` is intentionally non-trivial so short-lived runs (e.g. tests) finish before any
    /// outbound probe fires.
    func start(initialDelay: TimeAmount = .seconds(10), interval: TimeAmount = .seconds(300)) {
        let loop = group.next()
        task = loop.scheduleRepeatedTask(initialDelay: initialDelay, delay: interval) { [weak self] _ in
            self?.runChecks()
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    private func runChecks() {
        for entry in state.outboundsToHealthCheck() {
            _ = state.measureDelay(name: entry.name, url: url, timeoutMilliseconds: timeoutMilliseconds, on: group.next())
        }
    }
}
