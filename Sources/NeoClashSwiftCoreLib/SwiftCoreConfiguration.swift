import Foundation
import Yams

public enum SwiftCoreError: Error, Equatable, LocalizedError {
    case invalidArguments(String)
    case missingConfig(String)
    case invalidConfig(String)

    public var errorDescription: String? {
        switch self {
        case .invalidArguments(let message):
            message
        case .missingConfig(let path):
            "Configuration file is missing: \(path)"
        case .invalidConfig(let message):
            "Invalid Swift core configuration: \(message)"
        }
    }
}

public struct SwiftCoreCommand: Equatable, Sendable {
    public var validateOnly: Bool
    public var configPath: String
    public var runtimeDirectoryPath: String

    public init(validateOnly: Bool, configPath: String, runtimeDirectoryPath: String) {
        self.validateOnly = validateOnly
        self.configPath = configPath
        self.runtimeDirectoryPath = runtimeDirectoryPath
    }

    public static func parse(arguments: [String]) throws -> SwiftCoreCommand {
        var validateOnly = false
        var configPath: String?
        var runtimeDirectoryPath: String?
        var iterator = Array(arguments.dropFirst()).makeIterator()

        while let argument = iterator.next() {
            switch argument {
            case "-t", "--test":
                validateOnly = true
            case "-f", "--config":
                guard let value = iterator.next() else {
                    throw SwiftCoreError.invalidArguments("Missing value for \(argument)")
                }
                configPath = value
            case "-d", "--directory":
                guard let value = iterator.next() else {
                    throw SwiftCoreError.invalidArguments("Missing value for \(argument)")
                }
                runtimeDirectoryPath = value
            case "-h", "--help":
                throw SwiftCoreError.invalidArguments(Self.usage)
            default:
                throw SwiftCoreError.invalidArguments("Unknown argument: \(argument)\n\(Self.usage)")
            }
        }

        guard let configPath else {
            throw SwiftCoreError.invalidArguments("Missing required -f <config.yaml>\n\(Self.usage)")
        }
        guard let runtimeDirectoryPath else {
            throw SwiftCoreError.invalidArguments("Missing required -d <runtimeDir>\n\(Self.usage)")
        }

        return SwiftCoreCommand(
            validateOnly: validateOnly,
            configPath: configPath,
            runtimeDirectoryPath: runtimeDirectoryPath
        )
    }

    public static let usage = "Usage: neoclash-swift-core [-t] -f <config.yaml> -d <runtimeDir>"
}

public struct SwiftCoreProxy: Equatable, Sendable {
    public var name: String
    public var type: String
    public var server: String?
    public var port: Int?
    public var uuid: String?
    public var cipher: String?
    public var alterId: Int?
    public var network: String?
    public var tls: Bool
    public var servername: String?
    public var alpn: [String]?
    public var skipCertVerify: Bool
    public var flow: String?
    public var clientFingerprint: String?
    public var realityPublicKey: String?
    public var realityShortId: String?

    public init(
        name: String,
        type: String,
        server: String? = nil,
        port: Int? = nil,
        uuid: String? = nil,
        cipher: String? = nil,
        alterId: Int? = nil,
        network: String? = nil,
        tls: Bool = false,
        servername: String? = nil,
        alpn: [String]? = nil,
        skipCertVerify: Bool = false,
        flow: String? = nil,
        clientFingerprint: String? = nil,
        realityPublicKey: String? = nil,
        realityShortId: String? = nil
    ) {
        self.name = name
        self.type = type
        self.server = server
        self.port = port
        self.uuid = uuid
        self.cipher = cipher
        self.alterId = alterId
        self.network = network
        self.tls = tls
        self.servername = servername
        self.alpn = alpn
        self.skipCertVerify = skipCertVerify
        self.flow = flow
        self.clientFingerprint = clientFingerprint
        self.realityPublicKey = realityPublicKey
        self.realityShortId = realityShortId
    }
}

public struct SwiftCoreProxyGroup: Equatable, Sendable {
    public var name: String
    public var type: String
    public var proxies: [String]

    public init(name: String, type: String, proxies: [String]) {
        self.name = name
        self.type = type
        self.proxies = proxies
    }
}

public struct SwiftCoreRule: Equatable, Sendable {
    public var type: String
    public var payload: String
    public var proxy: String

    public init(type: String, payload: String, proxy: String) {
        self.type = type
        self.payload = payload
        self.proxy = proxy
    }
}

public struct SwiftCoreConfiguration: Equatable, Sendable {
    public var mixedPort: Int
    public var controllerHost: String
    public var controllerPort: Int
    public var secret: String
    public var mode: String
    public var logLevel: String
    public var allowLAN: Bool
    public var proxies: [SwiftCoreProxy]
    public var proxyGroups: [SwiftCoreProxyGroup]
    public var rules: [SwiftCoreRule]

    public init(
        mixedPort: Int,
        controllerHost: String,
        controllerPort: Int,
        secret: String,
        mode: String,
        logLevel: String,
        allowLAN: Bool,
        proxies: [SwiftCoreProxy],
        proxyGroups: [SwiftCoreProxyGroup],
        rules: [SwiftCoreRule]
    ) {
        self.mixedPort = mixedPort
        self.controllerHost = controllerHost
        self.controllerPort = controllerPort
        self.secret = secret
        self.mode = mode
        self.logLevel = logLevel
        self.allowLAN = allowLAN
        self.proxies = proxies
        self.proxyGroups = proxyGroups
        self.rules = rules
    }

    public static func load(from path: String) throws -> SwiftCoreConfiguration {
        guard FileManager.default.fileExists(atPath: path) else {
            throw SwiftCoreError.missingConfig(path)
        }
        let yaml = try String(contentsOfFile: path, encoding: .utf8)
        return try parse(yaml: yaml)
    }

    public static func parse(yaml: String) throws -> SwiftCoreConfiguration {
        guard let root = try Yams.load(yaml: yaml) as? [String: Any] else {
            throw SwiftCoreError.invalidConfig("YAML root must be a mapping.")
        }

        let mixedPort = try intValue(root["mixed-port"], key: "mixed-port")
        let (controllerHost, controllerPort) = try parseController(root["external-controller"])
        guard let secret = root["secret"] as? String,
              !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SwiftCoreError.invalidConfig("secret must be present.")
        }

        let proxies = parseProxies(root["proxies"])
        var groups = parseProxyGroups(root["proxy-groups"])
        if groups.isEmpty {
            groups = [SwiftCoreProxyGroup(name: "Default", type: "select", proxies: ["DIRECT"])]
        }
        let rules = parseRules(root["rules"])

        return SwiftCoreConfiguration(
            mixedPort: mixedPort,
            controllerHost: controllerHost,
            controllerPort: controllerPort,
            secret: secret,
            mode: (root["mode"] as? String) ?? "rule",
            logLevel: (root["log-level"] as? String) ?? "info",
            allowLAN: (root["allow-lan"] as? Bool) ?? false,
            proxies: proxies,
            proxyGroups: groups,
            rules: rules.isEmpty ? [SwiftCoreRule(type: "MATCH", payload: "", proxy: groups[0].name)] : rules
        )
    }

    private static func intValue(_ value: Any?, key: String) throws -> Int {
        guard let intValue = value as? Int, (1...65_535).contains(intValue) else {
            throw SwiftCoreError.invalidConfig("\(key) must be a valid port.")
        }
        return intValue
    }

    private static func parseController(_ value: Any?) throws -> (String, Int) {
        guard let controller = value as? String,
              let separator = controller.lastIndex(of: ":") else {
            throw SwiftCoreError.invalidConfig("external-controller must be host:port.")
        }
        let host = String(controller[..<separator])
        let portText = String(controller[controller.index(after: separator)...])
        guard let port = Int(portText), (1...65_535).contains(port) else {
            throw SwiftCoreError.invalidConfig("external-controller port must be valid.")
        }
        return (host.isEmpty ? "127.0.0.1" : host, port)
    }

    private static func parseProxies(_ value: Any?) -> [SwiftCoreProxy] {
        guard let entries = value as? [[String: Any]] else {
            return []
        }
        return entries.compactMap { entry in
            guard let name = entry["name"] as? String, !name.isEmpty else {
                return nil
            }
            let reality = entry["reality-opts"] as? [String: Any]
            let shortId: String?
            switch reality?["short-id"] {
            case let value as String: shortId = value
            case let value as Int: shortId = String(value)
            default: shortId = nil
            }
            return SwiftCoreProxy(
                name: name,
                type: (entry["type"] as? String) ?? "unknown",
                server: entry["server"] as? String,
                port: entry["port"] as? Int,
                uuid: entry["uuid"] as? String,
                cipher: (entry["cipher"] as? String) ?? (entry["security"] as? String),
                alterId: (entry["alterId"] as? Int) ?? (entry["alterid"] as? Int),
                network: entry["network"] as? String,
                tls: (entry["tls"] as? Bool) ?? false,
                servername: (entry["servername"] as? String) ?? (entry["sni"] as? String),
                alpn: entry["alpn"] as? [String],
                skipCertVerify: (entry["skip-cert-verify"] as? Bool) ?? false,
                flow: entry["flow"] as? String,
                clientFingerprint: entry["client-fingerprint"] as? String,
                realityPublicKey: reality?["public-key"] as? String,
                realityShortId: shortId
            )
        }
    }

    private static func parseProxyGroups(_ value: Any?) -> [SwiftCoreProxyGroup] {
        guard let entries = value as? [[String: Any]] else {
            return []
        }
        return entries.compactMap { entry in
            guard let name = entry["name"] as? String, !name.isEmpty else {
                return nil
            }
            let proxies = entry["proxies"] as? [String] ?? ["DIRECT"]
            return SwiftCoreProxyGroup(
                name: name,
                type: (entry["type"] as? String) ?? "select",
                proxies: proxies.isEmpty ? ["DIRECT"] : proxies
            )
        }
    }

    private static func parseRules(_ value: Any?) -> [SwiftCoreRule] {
        guard let entries = value as? [String] else {
            return []
        }
        return entries.compactMap { raw in
            let parts = raw.split(separator: ",", omittingEmptySubsequences: false).map {
                String($0).trimmingCharacters(in: .whitespacesAndNewlines)
            }
            guard parts.count >= 2 else {
                return nil
            }
            if parts[0].uppercased() == "MATCH" {
                return SwiftCoreRule(type: "MATCH", payload: "", proxy: parts[1])
            }
            guard parts.count >= 3 else {
                return nil
            }
            return SwiftCoreRule(type: parts[0].uppercased(), payload: parts[1], proxy: parts[2])
        }
    }
}
