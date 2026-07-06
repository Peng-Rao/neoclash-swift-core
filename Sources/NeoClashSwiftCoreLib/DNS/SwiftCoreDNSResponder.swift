/// Answers a DNS query the way fake-ip mode does, independent of any transport: an A query for a
/// non-filtered domain gets a fake ip from the pool (recording the domain↔ip mapping); a filtered
/// domain (or, when there is no pool, any A query) is resolved for real; everything else gets an
/// empty answer. Shared by the UDP DNS server and TUN `dns-hijack`.
final class SwiftCoreDNSResponder: @unchecked Sendable {
    private let pool: SwiftCoreFakeIPPool?
    private let resolver: SwiftCoreDNSResolver
    private let filter: SwiftCoreFakeIPFilter

    init(pool: SwiftCoreFakeIPPool?, resolver: SwiftCoreDNSResolver, filter: SwiftCoreFakeIPFilter) {
        self.pool = pool
        self.resolver = resolver
        self.filter = filter
    }

    /// Produces the DNS response bytes for `query`.
    func answer(query: [UInt8]) async -> [UInt8] {
        guard let question = SwiftCoreDNSMessage.decodeQuestion(query) else {
            return SwiftCoreDNSMessage.encodeResponse(query: query, answers: [])
        }

        // A record for a non-filtered domain -> allocate a fake ip.
        if question.type == SwiftCoreDNSRecordType.a.rawValue, let pool, !filter.matches(question.name) {
            let ip = pool.allocate(domain: question.name)
            return SwiftCoreDNSMessage.encodeResponse(query: query, answers: [SwiftCoreDNSAnswer(address: .ipv4(ip), ttl: 1)])
        }

        // Filtered A record (or no fake-ip pool) -> resolve for real.
        if question.type == SwiftCoreDNSRecordType.a.rawValue {
            let addresses = await resolver.resolve(question.name)
            let answers = addresses.compactMap { address -> SwiftCoreDNSAnswer? in
                if case .ipv4 = address { return SwiftCoreDNSAnswer(address: address, ttl: 30) }
                return nil
            }
            return SwiftCoreDNSMessage.encodeResponse(query: query, answers: answers)
        }

        // AAAA and everything else -> empty answer (IPv6 fake-ip/resolution not supported yet).
        return SwiftCoreDNSMessage.encodeResponse(query: query, answers: [])
    }
}
