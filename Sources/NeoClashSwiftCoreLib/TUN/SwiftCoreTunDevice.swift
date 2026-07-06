import CSwiftCoreTun
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A layer-3 TUN device: opens the platform interface (utun on macOS, /dev/net/tun on Linux via the
/// `CSwiftCoreTun` shim), reads and writes whole IP packets, and normalizes the macOS 4-byte
/// address-family header so callers always see raw IP packets.
final class SwiftCoreTunDevice: @unchecked Sendable {
    /// macOS utun frames are prefixed with a 4-byte address family; Linux (`IFF_NO_PI`) is not.
    #if canImport(Darwin)
    private static let hasFamilyPrefix = true
    #else
    private static let hasFamilyPrefix = false
    #endif

    private let mtu: Int
    private var fd: Int32 = -1
    private var running = false
    private var readThread: Thread?
    private(set) var name = ""

    init(mtu: Int) {
        self.mtu = mtu
    }

    /// Opens the device. `requestedName` may name a specific interface ("utun5"/"tun0") or be empty
    /// to let the kernel assign one. Throws with the underlying errno on failure.
    func open(requestedName: String) throws {
        var nameBuffer = [CChar](repeating: 0, count: 64)
        let result = requestedName.withCString { request in
            swiftcore_tun_open(request, &nameBuffer, nameBuffer.count)
        }
        guard result >= 0 else {
            throw SwiftCoreError.invalidConfig("TUN open failed (errno \(-result)).")
        }
        fd = result
        name = String(cString: nameBuffer)
    }

    /// Reads a single IP packet (blocking). Returns nil once the device is closed or on error.
    func read() -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: mtu + 4)
        var count = 0
        repeat {
            count = buffer.withUnsafeMutableBytes { pointer in
                readBytes(fd, pointer.baseAddress, pointer.count)
            }
        } while count < 0 && errno == EINTR
        guard count > 0 else { return nil }

        var packet = Array(buffer[0..<count])
        if Self.hasFamilyPrefix {
            guard packet.count > 4 else { return nil }
            packet.removeFirst(4)
        }
        return packet
    }

    /// Writes a single IP packet, adding the macOS address-family prefix when required.
    func write(_ packet: [UInt8]) {
        let frame: [UInt8]
        if Self.hasFamilyPrefix {
            // Darwin AF_INET = 2, AF_INET6 = 30; the family is a 4-byte big-endian prefix.
            let isIPv6 = (packet.first ?? 0) >> 4 == 6
            frame = (isIPv6 ? [0, 0, 0, 30] : [0, 0, 0, 2]) + packet
        } else {
            frame = packet
        }
        frame.withUnsafeBytes { pointer in
            _ = writeBytes(fd, pointer.baseAddress, pointer.count)
        }
    }

    /// Starts a dedicated thread that reads packets and hands each to `onPacket` until `close()`.
    func startReadLoop(onPacket: @escaping @Sendable ([UInt8]) -> Void) {
        running = true
        let thread = Thread { [weak self] in
            guard let self else { return }
            while self.running, let packet = self.read() {
                onPacket(packet)
            }
        }
        thread.name = "neoclash-tun-read"
        thread.stackSize = 1 << 20
        readThread = thread
        thread.start()
    }

    /// Stops the read loop and closes the device fd.
    func close() {
        running = false
        if fd >= 0 {
            _ = closeFd(fd)
            fd = -1
        }
    }
}

// Thin, platform-qualified POSIX wrappers so the calls are unambiguous with Foundation imported.
@inline(__always)
private func readBytes(_ fd: Int32, _ buffer: UnsafeMutableRawPointer?, _ count: Int) -> Int {
    #if canImport(Darwin)
    return Darwin.read(fd, buffer, count)
    #else
    return Glibc.read(fd, buffer, count)
    #endif
}

@inline(__always)
private func writeBytes(_ fd: Int32, _ buffer: UnsafeRawPointer?, _ count: Int) -> Int {
    #if canImport(Darwin)
    return Darwin.write(fd, buffer, count)
    #else
    return Glibc.write(fd, buffer, count)
    #endif
}

@inline(__always)
private func closeFd(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
    return Darwin.close(fd)
    #else
    return Glibc.close(fd)
    #endif
}
