#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import NIOCore

/// Renders channel errors with their real cause. `Error.localizedDescription` routes Swift
/// struct errors through NSError bridging, which hides NIO's errno details behind opaque
/// text like "(NIOCore.IOError error 1.)" — so error text must go through
/// `CustomStringConvertible` instead.
public enum SwiftCoreErrorText {
    public static func describe(_ error: Error) -> String {
        String(describing: error)
    }

    /// Whether the error is ordinary connection teardown (peer reset, broken pipe, half-close
    /// races) rather than something worth surfacing: a proxy sees these constantly whenever a
    /// client abandons its keep-alive sockets.
    public static func isRoutineDisconnect(_ error: Error) -> Bool {
        if let ioError = error as? IOError {
            switch ioError.errnoCode {
            case ECONNRESET, ECONNABORTED, EPIPE, ENOTCONN, EBADF:
                return true
            default:
                return false
            }
        }
        if let channelError = error as? ChannelError {
            switch channelError {
            case .ioOnClosedChannel, .alreadyClosed, .outputClosed, .inputClosed, .eof:
                return true
            default:
                return false
            }
        }
        return false
    }
}
