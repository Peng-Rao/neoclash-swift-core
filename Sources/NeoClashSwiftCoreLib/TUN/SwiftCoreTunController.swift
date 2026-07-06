import Foundation
import NIOCore
import NIOPosix
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Owns the TUN device and drives the userspace TCP stack. Captured packets are handled on a single
/// event loop: ICMP echo requests are answered directly, and TCP flows are terminated by
/// `SwiftCoreTCPConnection` and spliced to a proxy dial via the same routing/outbound path the mixed
/// proxy uses (`state.resolvedRoute` → `outbound.connect`). UDP relay is a later step.
final class SwiftCoreTunController: @unchecked Sendable {
    private let state: SwiftCoreState
    private let group: EventLoopGroup
    /// The single event loop all packet processing, connections, and splice bookkeeping run on.
    private let loop: EventLoop
    /// Writes a finished IP packet back toward the app (the TUN device in production).
    private var emit: ([UInt8]) -> Void
    private let dnsResponder: SwiftCoreDNSResponder?
    private let dnsHijack: [SwiftCoreDNSHijackTarget]
    private var device: SwiftCoreTunDevice?
    private lazy var stack = SwiftCoreTCPStack(
        emit: { [weak self] packet in self?.emit(packet) },
        onAccept: { [weak self] connection in self?.accept(connection) }
    )

    /// Designated init. Tests inject an explicit `loop` + `emit`; production passes neither and the
    /// device is wired in `start`.
    init(
        state: SwiftCoreState,
        group: EventLoopGroup,
        loop: EventLoop? = nil,
        emit: (([UInt8]) -> Void)? = nil,
        dnsResponder: SwiftCoreDNSResponder? = nil,
        dnsHijack: [SwiftCoreDNSHijackTarget] = []
    ) {
        self.state = state
        self.group = group
        self.loop = loop ?? group.next()
        self.emit = emit ?? { _ in }
        self.dnsResponder = dnsResponder
        self.dnsHijack = dnsHijack
    }

    /// Opens the device and starts the read loop. Requires root; unprivileged runs log a warning and
    /// skip so the process still comes up.
    func start(config: SwiftCoreTUNConfig) {
        guard config.enable else { return }
        guard geteuid() == 0 else {
            state.appendLog(level: "warning", message: "TUN mode requires root privileges; skipping (re-run with sudo to enable).")
            return
        }

        let device = SwiftCoreTunDevice(mtu: config.mtu)
        do {
            try device.open(requestedName: config.device)
        } catch {
            state.appendLog(level: "warning", message: "TUN device failed to open: \(SwiftCoreErrorText.describe(error))")
            return
        }
        self.device = device
        emit = { packet in device.write(packet) }
        state.appendLog(level: "info", message: "TUN device \(device.name) up (mtu \(config.mtu), stack \(config.stack)); TCP relay active.")

        let loop = self.loop
        device.startReadLoop { [weak self] packet in
            loop.execute { self?.receive(packet) }
        }
    }

    func stop() {
        device?.close()
        device = nil
    }

    /// Processes one inbound IP packet. Must be called on `loop`.
    func receive(_ packet: [UInt8]) {
        guard let ip = SwiftCoreIPv4Packet(packet) else { return }
        switch ip.proto {
        case SwiftCoreIPProtocol.icmp:
            if let reply = SwiftCoreICMP.makeEchoReply(from: packet) {
                emit(reply)
            }
        case SwiftCoreIPProtocol.tcp:
            stack.receive(ip: ip)
        case SwiftCoreIPProtocol.udp:
            handleUDP(ip)
        default:
            break
        }
    }

    /// Answers a `dns-hijack` UDP query locally (fake-ip / resolver). Non-hijacked UDP is dropped —
    /// general UDP relay needs UDP-capable outbounds, which come in a later step.
    private func handleUDP(_ ip: SwiftCoreIPv4Packet) {
        guard let responder = dnsResponder,
              let datagram = SwiftCoreUDPDatagram(ip.payload),
              dnsHijack.contains(where: { $0.matches(destination: ip.destination, port: datagram.destinationPort) }) else {
            return
        }
        let source = ip.source
        let destination = ip.destination
        let sourcePort = datagram.sourcePort
        let destinationPort = datagram.destinationPort
        let query = datagram.payload
        let loop = self.loop
        Task { [weak self] in
            let response = await responder.answer(query: query)
            loop.execute {
                guard let self else { return }
                // Reply from the address the app queried (destination) back to the app (source).
                let reply = SwiftCoreUDPDatagram.build(
                    source: destination, destination: source,
                    sourcePort: destinationPort, destinationPort: sourcePort,
                    payload: response
                )
                self.emit(reply)
            }
        }
    }

    private func accept(_ connection: SwiftCoreTCPConnection) {
        let flow = SwiftCoreTunFlow(connection: connection)
        connection.onEstablished = { [weak self] _ in self?.dial(flow) }
        connection.onAppData = { [weak self] bytes in self?.forwardToProxy(flow, bytes) }
        connection.onClosed = { [weak self] in self?.closeFlow(flow) }
        connection.onReadPauseChanged = { [weak self] paused in self?.setProxyRead(flow, paused: paused) }
    }

    private func dial(_ flow: SwiftCoreTunFlow) {
        var host = swiftCoreIPv4String(flow.connection.destination)
        if let domain = state.fakeIPDomain(forHost: host) { host = domain }
        let port = flow.connection.destinationPort
        let sourcePort = flow.connection.sourcePort

        Task { [weak self] in
            guard let self else { return }
            let decision = await self.state.resolvedRoute(host: host, destinationPort: port, sourcePort: sourcePort)
            self.loop.execute { self.apply(decision, flow: flow, host: host, port: port) }
        }
    }

    private func apply(_ decision: SwiftCoreRouteDecision, flow: SwiftCoreTunFlow, host: String, port: Int) {
        guard !flow.closed else { return }
        let chain: [String]
        let outbound: SwiftCoreOutbound
        switch decision {
        case .outbound(let routeChain, let adapter):
            chain = routeChain
            outbound = adapter
        case .reject:
            state.appendLog(level: "info", message: "TUN rejected \(host):\(port)")
            flow.connection.reset()
            return
        case .unsupported(_, let proxy):
            state.appendLog(level: "warning", message: "TUN proxy \(proxy) is not implemented by Swift core v1")
            flow.connection.reset()
            return
        }

        let loop = self.loop
        let request = SwiftCoreOutboundRequest(host: host, port: port)
        outbound.connect(request: request, group: group) { [weak self] in
            SwiftCoreTunProxyTailHandler(flow: flow, loop: loop, controller: self)
        }.whenComplete { [weak self] result in
            loop.execute {
                guard let self else { return }
                switch result {
                case .success(let channel):
                    guard !flow.closed else {
                        channel.close(promise: nil)
                        return
                    }
                    flow.channel = channel
                    flow.connectionID = self.state.addConnection(host: "\(host):\(port)", rule: outbound.name, chain: chain)
                    if !flow.pending.isEmpty {
                        let bytes = flow.pending
                        flow.pending.removeAll()
                        self.state.recordUpload(id: flow.connectionID, bytes: bytes.count)
                        var buffer = channel.allocator.buffer(capacity: bytes.count)
                        buffer.writeBytes(bytes)
                        channel.writeAndFlush(NIOAny(buffer), promise: nil)
                    }
                case .failure(let error):
                    self.state.appendLog(level: "warning", message: "TUN dial \(host):\(port) via \(outbound.name) failed: \(SwiftCoreErrorText.describe(error))")
                    flow.connection.reset()
                }
            }
        }
    }

    // MARK: App <-> proxy bridging (all on `stackLoop`)

    private func forwardToProxy(_ flow: SwiftCoreTunFlow, _ bytes: [UInt8]) {
        guard !flow.closed else { return }
        guard let channel = flow.channel else {
            flow.pending.append(contentsOf: bytes)
            return
        }
        state.recordUpload(id: flow.connectionID, bytes: bytes.count)
        var buffer = channel.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        channel.writeAndFlush(NIOAny(buffer), promise: nil)
    }

    fileprivate func proxyData(_ flow: SwiftCoreTunFlow, _ bytes: [UInt8]) {
        guard !flow.closed else { return }
        state.recordDownload(id: flow.connectionID, bytes: bytes.count)
        flow.connection.deliverToApp(bytes)
    }

    fileprivate func proxyClosed(_ flow: SwiftCoreTunFlow) {
        guard !flow.closed else { return }
        flow.connection.proxyDidClose()
    }

    private func closeFlow(_ flow: SwiftCoreTunFlow) {
        guard !flow.closed else { return }
        flow.closed = true
        flow.channel?.close(promise: nil)
        flow.channel = nil
        state.removeConnection(id: flow.connectionID)
    }

    private func setProxyRead(_ flow: SwiftCoreTunFlow, paused: Bool) {
        flow.channel?.setOption(ChannelOptions.autoRead, value: !paused).whenComplete { _ in }
    }
}

/// Per-flow controller-side state: the proxy channel (once dialed), bytes buffered before it is
/// ready, and the connection-tracking id. Only touched on the stack event loop.
final class SwiftCoreTunFlow: @unchecked Sendable {
    let connection: SwiftCoreTCPConnection
    var channel: Channel?
    var pending: [UInt8] = []
    var connectionID: String?
    var closed = false

    init(connection: SwiftCoreTCPConnection) {
        self.connection = connection
    }
}

/// Tail handler on the proxy channel: forwards proxy→app bytes and close events back to the TCP
/// connection, hopping onto the stack event loop.
final class SwiftCoreTunProxyTailHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let flow: SwiftCoreTunFlow
    private let loop: EventLoop
    private weak var controller: SwiftCoreTunController?

    init(flow: SwiftCoreTunFlow, loop: EventLoop, controller: SwiftCoreTunController?) {
        self.flow = flow
        self.loop = loop
        self.controller = controller
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = Self.unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes), !bytes.isEmpty else { return }
        let flow = self.flow
        loop.execute { [weak controller] in controller?.proxyData(flow, bytes) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        let flow = self.flow
        loop.execute { [weak controller] in controller?.proxyClosed(flow) }
        context.fireChannelInactive()
    }
}
