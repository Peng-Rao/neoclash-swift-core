import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking // URLSession lives here on Linux
#endif

/// Loads configured `rule-providers` (file or http) into a `SwiftCoreRuleSet` and installs it on the
/// state. Runs asynchronously; `RULE-SET` rules don't match until loading completes. HTTP providers
/// are cached in the runtime directory.
final class SwiftCoreRuleProviderLoader: @unchecked Sendable {
    private let state: SwiftCoreState
    private let directory: String
    private let providers: [SwiftCoreRuleProvider]

    init(state: SwiftCoreState, directory: String, providers: [SwiftCoreRuleProvider]) {
        self.state = state
        self.directory = directory
        self.providers = providers
    }

    func start() {
        Task.detached { [self] in
            await load()
        }
    }

    func load() async {
        var built: [String: SwiftCoreRuleSet.Provider] = [:]
        for provider in providers {
            guard let content = await fetch(provider) else { continue }
            if let parsed = SwiftCoreRuleSetParser.parse(behavior: provider.behavior, format: provider.format, content: content) {
                built[provider.name] = parsed
                state.appendLog(level: "info", message: "Loaded rule-provider \(provider.name) (\(provider.behavior))")
            } else {
                state.appendLog(level: "warning", message: "rule-provider \(provider.name): unsupported behavior '\(provider.behavior)'")
            }
        }
        if !built.isEmpty {
            state.setRuleSet(SwiftCoreRuleSet(providers: built))
        }
    }

    private func fetch(_ provider: SwiftCoreRuleProvider) async -> [UInt8]? {
        let path = resolvedPath(provider)
        if provider.type.lowercased() == "file" {
            guard let data = FileManager.default.contents(atPath: path) else {
                state.appendLog(level: "warning", message: "rule-provider \(provider.name): file not found at \(path)")
                return nil
            }
            return Array(data)
        }
        // http: prefer a cached copy, otherwise download.
        if let data = FileManager.default.contents(atPath: path), !data.isEmpty {
            return Array(data)
        }
        guard let urlString = provider.url, let endpoint = URL(string: urlString) else {
            state.appendLog(level: "warning", message: "rule-provider \(provider.name): missing or invalid url")
            return nil
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: endpoint)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                state.appendLog(level: "warning", message: "rule-provider \(provider.name): HTTP \(http.statusCode)")
                return nil
            }
            try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try? data.write(to: URL(fileURLWithPath: path))
            return Array(data)
        } catch {
            state.appendLog(level: "warning", message: "rule-provider \(provider.name) download failed: \(SwiftCoreErrorText.describe(error))")
            return nil
        }
    }

    private func resolvedPath(_ provider: SwiftCoreRuleProvider) -> String {
        if let path = provider.path {
            return path.hasPrefix("/") ? path : directory + "/" + path
        }
        let ext = provider.format.lowercased() == "text" ? "txt" : "yaml"
        return directory + "/ruleset-\(provider.name).\(ext)"
    }
}
