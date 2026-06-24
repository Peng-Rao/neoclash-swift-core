import Foundation
import Yams

/// A loaded set of rule providers (clash `rule-providers`), queried by `RULE-SET` rules.
/// Providers come in three behaviors: `domain` (domain list), `ipcidr` (CIDR list), and
/// `classical` (a list of ordinary rules without a policy).
public final class SwiftCoreRuleSet: @unchecked Sendable {
    enum Provider {
        case domain(full: Set<String>, suffix: Set<String>)
        case ipcidr([String])          // CIDR strings, matched via SwiftCoreRuleMatcher.cidrContains
        case classical([SwiftCoreRule]) // rules without a policy
    }

    private let providers: [String: Provider]

    init(providers: [String: Provider]) {
        self.providers = providers
    }

    var providerNames: [String] { Array(providers.keys) }

    func matches(provider name: String, context: SwiftCoreRouteContext, geo: SwiftCoreGeoDatabase?) -> Bool {
        guard let provider = providers[name] else { return false }
        switch provider {
        case .domain(let full, let suffix):
            let host = context.host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
            if full.contains(host) { return true }
            if suffix.contains(host) { return true }
            var rest = host
            while let dot = rest.firstIndex(of: ".") {
                rest = String(rest[rest.index(after: dot)...])
                if suffix.contains(rest) { return true }
            }
            return false
        case .ipcidr(let cidrs):
            return cidrs.contains { SwiftCoreRuleMatcher.cidrContains(cidr: $0, address: context.address) }
        case .classical(let rules):
            // Classical rules may reference GEOIP/GEOSITE; nested RULE-SET is not resolved here.
            return rules.contains { SwiftCoreRuleMatcher.matches(rule: $0, context: context, geo: geo) }
        }
    }
}

/// Parses rule-provider payloads (yaml or text) into a `SwiftCoreRuleSet.Provider` for a behavior.
enum SwiftCoreRuleSetParser {
    /// Extracts the list of entries from `yaml` (a `payload:` array) or `text` (one per line).
    static func entries(format: String, content: [UInt8]) -> [String] {
        switch format.lowercased() {
        case "text":
            let text = String(decoding: content, as: UTF8.self)
            return text.split(whereSeparator: { $0 == "\n" || $0 == "\r" })
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix("//") }
        default: // yaml (and "mrs" is unsupported; treated as empty)
            guard let root = try? Yams.load(yaml: String(decoding: content, as: UTF8.self)) as? [String: Any],
                  let payload = root["payload"] as? [String] else {
                return []
            }
            return payload.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
    }

    static func parse(behavior: String, format: String, content: [UInt8]) -> SwiftCoreRuleSet.Provider? {
        let items = entries(format: format, content: content)
        switch behavior.lowercased() {
        case "domain":
            var full: Set<String> = []
            var suffix: Set<String> = []
            for entry in items {
                let lower = entry.lowercased()
                if lower.hasPrefix("+.") {
                    suffix.insert(String(lower.dropFirst(2)))
                } else if lower.hasPrefix("*.") {
                    suffix.insert(String(lower.dropFirst(2)))
                } else if lower.hasPrefix(".") {
                    suffix.insert(String(lower.dropFirst()))
                } else {
                    full.insert(lower)
                }
            }
            return .domain(full: full, suffix: suffix)
        case "ipcidr":
            return .ipcidr(items)
        case "classical":
            let rules: [SwiftCoreRule] = items.compactMap { line in
                let parts = line.split(separator: ",", maxSplits: 2).map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count >= 2 else { return nil }
                return SwiftCoreRule(type: parts[0].uppercased(), payload: parts[1], proxy: "")
            }
            return .classical(rules)
        default:
            return nil
        }
    }
}
