import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Owns the TUN device and the packet read loop. This first step is a stack-agnostic foundation: it
/// answers ICMP echo requests directly (proving read+inject work) and logs a bounded sample of the
/// TCP/UDP flows it sees. A later step replaces the flow handling with a userspace TCP/IP stack that
/// dials each flow through the proxy via the existing outbound path.
final class SwiftCoreTunController: @unchecked Sendable {
    private let state: SwiftCoreState
    private var device: SwiftCoreTunDevice?
    private let flowLock = NSLock()
    private var loggedFlows = 0
    private let maxLoggedFlows = 16

    init(state: SwiftCoreState) {
        self.state = state
    }

    /// Opens the device and starts the read loop. Requires root; if the process is unprivileged it
    /// logs a warning and returns without starting (so a non-root run degrades gracefully).
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
        state.appendLog(level: "info", message: "TUN device \(device.name) up (mtu \(config.mtu), stack \(config.stack)); ICMP-echo responder active.")

        device.startReadLoop { [weak self] packet in
            self?.handle(packet: packet, device: device)
        }
    }

    func stop() {
        device?.close()
        device = nil
    }

    private func handle(packet: [UInt8], device: SwiftCoreTunDevice) {
        guard let ip = SwiftCoreIPv4Packet(packet) else { return }
        switch ip.proto {
        case SwiftCoreIPProtocol.icmp:
            if let reply = SwiftCoreICMP.makeEchoReply(from: packet) {
                device.write(reply)
            }
        case SwiftCoreIPProtocol.tcp:
            if let tcp = SwiftCoreTCPHeader(ip.payload), tcp.isSYN, !tcp.isACK {
                logFlow("TCP SYN → \(swiftCoreIPv4String(ip.destination)):\(tcp.destinationPort)")
            }
        case SwiftCoreIPProtocol.udp:
            if let udp = SwiftCoreUDPHeader(ip.payload) {
                logFlow("UDP → \(swiftCoreIPv4String(ip.destination)):\(udp.destinationPort)")
            }
        default:
            break
        }
    }

    /// Logs the first `maxLoggedFlows` captured flows so capture is observable without flooding.
    private func logFlow(_ description: String) {
        flowLock.lock()
        let shouldLog = loggedFlows < maxLoggedFlows
        if shouldLog { loggedFlows += 1 }
        flowLock.unlock()
        if shouldLog {
            state.appendLog(level: "info", message: "TUN captured \(description)")
        }
    }
}
