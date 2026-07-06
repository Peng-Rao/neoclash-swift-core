/// Demultiplexes TUN IP packets to per-flow `SwiftCoreTCPConnection`s by their 4-tuple. A SYN with
/// no matching connection starts a new one. Runs entirely on a single event loop (the caller's);
/// closed connections are reaped lazily as their next packet arrives.
final class SwiftCoreTCPStack {
    private struct Key: Hashable {
        let source: [UInt8]
        let sourcePort: Int
        let destination: [UInt8]
        let destinationPort: Int
    }

    private let emit: ([UInt8]) -> Void
    private let onAccept: (SwiftCoreTCPConnection) -> Void
    private var connections: [Key: SwiftCoreTCPConnection] = [:]

    /// - Parameters:
    ///   - emit: writes a finished IP packet back to the TUN device.
    ///   - onAccept: called with a new connection so the caller can wire callbacks and dial the proxy,
    ///     *before* the SYN-ACK is sent.
    init(emit: @escaping ([UInt8]) -> Void, onAccept: @escaping (SwiftCoreTCPConnection) -> Void) {
        self.emit = emit
        self.onAccept = onAccept
    }

    var connectionCount: Int { connections.count }

    /// Routes a parsed IPv4 TCP packet to its connection (creating one on a fresh SYN).
    func receive(ip: SwiftCoreIPv4Packet) {
        guard ip.proto == SwiftCoreIPProtocol.tcp, let segment = SwiftCoreTCPSegment(ip.payload) else { return }
        let key = Key(source: ip.source, sourcePort: segment.sourcePort, destination: ip.destination, destinationPort: segment.destinationPort)

        if let connection = connections[key] {
            connection.receive(segment)
            if connection.state == .closed { connections.removeValue(forKey: key) }
            return
        }

        // A new flow must open with a bare SYN; ignore anything else (a stray/late segment).
        guard segment.isSYN, !segment.isACK else { return }
        let connection = SwiftCoreTCPConnection(
            source: ip.source, sourcePort: segment.sourcePort,
            destination: ip.destination, destinationPort: segment.destinationPort,
            emit: emit
        )
        connections[key] = connection
        onAccept(connection)
        connection.start(with: segment)
        if connection.state == .closed { connections.removeValue(forKey: key) }
    }
}
