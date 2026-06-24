import Foundation
import XCTest
@testable import NeoClashSwiftCoreLib

/// Tests for the GEOIP/GEOSITE subsystem: the protobuf decoder, the `.dat` parsers, matcher
/// integration, and the loader's cache path. `.dat` fixtures are hand-encoded so everything is
/// hermetic (no network). Live URL downloading is exercised in manual end-to-end runs.
final class GeoTests: XCTestCase {
    // MARK: Minimal protobuf encoder (test fixtures)

    private func varint(_ value: UInt64) -> [UInt8] {
        var value = value
        var bytes: [UInt8] = []
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            bytes.append(byte)
        } while value != 0
        return bytes
    }

    private func tag(_ field: Int, _ wire: Int) -> [UInt8] { varint(UInt64(field << 3 | wire)) }
    private func lengthField(_ field: Int, _ bytes: [UInt8]) -> [UInt8] { tag(field, 2) + varint(UInt64(bytes.count)) + bytes }
    private func varintField(_ field: Int, _ value: UInt64) -> [UInt8] { tag(field, 0) + varint(value) }

    /// GeoIPList { GeoIP { country_code=1, CIDR{ ip=1, prefix=2 }=2 } }
    private func geoIPList(_ entries: [(code: String, cidrs: [(ip: [UInt8], prefix: Int)])]) -> [UInt8] {
        var output: [UInt8] = []
        for entry in entries {
            var geoIP = lengthField(1, Array(entry.code.utf8))
            for cidr in entry.cidrs {
                let body = lengthField(1, cidr.ip) + varintField(2, UInt64(cidr.prefix))
                geoIP += lengthField(2, body)
            }
            output += lengthField(1, geoIP)
        }
        return output
    }

    /// GeoSiteList { GeoSite { country_code=1, Domain{ type=1, value=2 }=2 } }
    private func geoSiteList(_ entries: [(code: String, domains: [(type: Int, value: String)])]) -> [UInt8] {
        var output: [UInt8] = []
        for entry in entries {
            var geoSite = lengthField(1, Array(entry.code.utf8))
            for domain in entry.domains {
                let body = varintField(1, UInt64(domain.type)) + lengthField(2, Array(domain.value.utf8))
                geoSite += lengthField(2, body)
            }
            output += lengthField(1, geoSite)
        }
        return output
    }

    // MARK: Tests

    func testGeoIPParseAndMatch() {
        let data = geoIPList([
            ("CN", [([1, 2, 3, 0], 24), ([10, 0, 0, 0], 8)]),
            ("US", [([8, 8, 8, 0], 24)])
        ])
        let geoip = SwiftCoreGeoIP(data: data)
        XCTAssertEqual(geoip.countryCount, 2)
        XCTAssertTrue(geoip.matches(country: "CN", address: .ipv4([1, 2, 3, 4])))
        XCTAssertTrue(geoip.matches(country: "cn", address: .ipv4([10, 9, 8, 7])))
        XCTAssertFalse(geoip.matches(country: "CN", address: .ipv4([8, 8, 8, 8])))
        XCTAssertTrue(geoip.matches(country: "US", address: .ipv4([8, 8, 8, 8])))
        XCTAssertFalse(geoip.matches(country: "JP", address: .ipv4([1, 2, 3, 4])))
        XCTAssertFalse(geoip.matches(country: "CN", address: .domain("example.com")))
    }

    func testGeoSiteParseAndMatch() {
        let data = geoSiteList([
            ("CN", [
                (3, "example.cn"),     // Full (exact)
                (2, "google.cn"),      // Domain (suffix)
                (0, "baidu"),          // Plain (keyword)
                (1, "^.*\\.test$")     // Regex
            ])
        ])
        let geosite = SwiftCoreGeoSite(data: data)
        XCTAssertEqual(geosite.countryCount, 1)
        XCTAssertTrue(geosite.matches(country: "CN", host: "example.cn"))     // full
        XCTAssertFalse(geosite.matches(country: "CN", host: "x.example.cn"))  // full is exact
        XCTAssertTrue(geosite.matches(country: "CN", host: "google.cn"))      // domain exact
        XCTAssertTrue(geosite.matches(country: "CN", host: "www.google.cn"))  // domain suffix
        XCTAssertTrue(geosite.matches(country: "CN", host: "mybaidu.com"))    // keyword
        XCTAssertTrue(geosite.matches(country: "CN", host: "foo.test"))       // regex
        XCTAssertFalse(geosite.matches(country: "CN", host: "example.org"))
        XCTAssertFalse(geosite.matches(country: "US", host: "example.cn"))
    }

    func testMatcherUsesGeoDatabase() {
        let geo = SwiftCoreGeoDatabase(
            geoip: SwiftCoreGeoIP(data: geoIPList([("CN", [([1, 2, 3, 0], 24)])])),
            geosite: SwiftCoreGeoSite(data: geoSiteList([("CN", [(2, "weibo.com")])]))
        )
        let ipContext = SwiftCoreRouteContext(host: "1.2.3.4", destinationPort: 443)
        let domainContext = SwiftCoreRouteContext(host: "api.weibo.com", destinationPort: 443)

        XCTAssertTrue(SwiftCoreRuleMatcher.matches(rule: SwiftCoreRule(type: "GEOIP", payload: "CN", proxy: "X"), context: ipContext, geo: geo))
        XCTAssertTrue(SwiftCoreRuleMatcher.matches(rule: SwiftCoreRule(type: "GEOSITE", payload: "CN", proxy: "X"), context: domainContext, geo: geo))
        // Without a geo database, GEOIP/GEOSITE never match.
        XCTAssertFalse(SwiftCoreRuleMatcher.matches(rule: SwiftCoreRule(type: "GEOIP", payload: "CN", proxy: "X"), context: ipContext, geo: nil))
    }

    func testGeoLoaderReadsCachedFileAndRoutes() async throws {
        let directory = NSTemporaryDirectory() + "neoclash-geo-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let cached = Data(geoIPList([("CN", [([1, 2, 3, 0], 24)])]))
        try cached.write(to: URL(fileURLWithPath: directory + "/geoip.dat"))

        let yaml = """
        mixed-port: 7890
        secret: s
        proxies:
          - { name: P, type: direct }
        proxy-groups:
          - { name: G, type: select, proxies: [P, DIRECT] }
        rules:
          - GEOIP,CN,DIRECT,no-resolve
          - MATCH,P
        """
        let state = SwiftCoreState(configuration: try SwiftCoreConfiguration.parse(yaml: yaml))
        let loader = SwiftCoreGeoLoader(
            state: state,
            directory: directory,
            geoipURL: "http://invalid.invalid/geoip.dat",
            geositeURL: "http://invalid.invalid/geosite.dat",
            needsGeoIP: true,
            needsGeoSite: false
        )
        await loader.load() // uses the cached file, no network

        func chosen(host: String) -> String? {
            guard case .outbound(let chain, _) = state.route(context: SwiftCoreRouteContext(host: host, destinationPort: 443)) else { return nil }
            return chain.last
        }
        XCTAssertEqual(chosen(host: "1.2.3.4"), "DIRECT") // GEOIP,CN
        XCTAssertEqual(chosen(host: "8.8.8.8"), "P")      // MATCH fallthrough
    }
}
