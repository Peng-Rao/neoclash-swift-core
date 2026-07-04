import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking // URLSession lives here on Linux
#endif

/// Downloads the v2ray-format `geoip.dat` / `geosite.dat` from `geox-url` (caching them in the
/// runtime directory), parses them, and installs the result on `SwiftCoreState`. Runs asynchronously
/// so startup is never blocked; until it completes, `GEOIP`/`GEOSITE` rules simply don't match.
final class SwiftCoreGeoLoader: @unchecked Sendable {
    private let state: SwiftCoreState
    private let directory: String
    private let geoipURL: String
    private let geositeURL: String
    private let needsGeoIP: Bool
    private let needsGeoSite: Bool

    init(state: SwiftCoreState, directory: String, geoipURL: String, geositeURL: String, needsGeoIP: Bool, needsGeoSite: Bool) {
        self.state = state
        self.directory = directory
        self.geoipURL = geoipURL
        self.geositeURL = geositeURL
        self.needsGeoIP = needsGeoIP
        self.needsGeoSite = needsGeoSite
    }

    func start() {
        Task.detached { [self] in
            await load()
        }
    }

    func load() async {
        var geoip: SwiftCoreGeoIP?
        if needsGeoIP, let data = await fetch(url: geoipURL, filename: "geoip.dat") {
            let parsed = SwiftCoreGeoIP(data: data)
            geoip = parsed
            state.appendLog(level: "info", message: "Loaded geoip.dat (\(parsed.countryCount) countries)")
        }
        var geosite: SwiftCoreGeoSite?
        if needsGeoSite, let data = await fetch(url: geositeURL, filename: "geosite.dat") {
            let parsed = SwiftCoreGeoSite(data: data)
            geosite = parsed
            state.appendLog(level: "info", message: "Loaded geosite.dat (\(parsed.countryCount) categories)")
        }
        if geoip != nil || geosite != nil {
            state.setGeoDatabase(SwiftCoreGeoDatabase(geoip: geoip, geosite: geosite))
        }
    }

    /// Returns the file bytes, preferring a cached copy in the runtime directory before downloading.
    private func fetch(url: String, filename: String) async -> [UInt8]? {
        let path = directory + "/" + filename
        if let data = FileManager.default.contents(atPath: path), !data.isEmpty {
            return Array(data)
        }
        guard let endpoint = URL(string: url) else {
            state.appendLog(level: "warning", message: "invalid geo url: \(url)")
            return nil
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: endpoint)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                state.appendLog(level: "warning", message: "geo download \(url) returned HTTP \(http.statusCode)")
                return nil
            }
            try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            try? data.write(to: URL(fileURLWithPath: path))
            state.appendLog(level: "info", message: "Downloaded \(filename) (\(data.count) bytes)")
            return Array(data)
        } catch {
            state.appendLog(level: "warning", message: "geo download failed \(url): \(SwiftCoreErrorText.describe(error))")
            return nil
        }
    }
}
