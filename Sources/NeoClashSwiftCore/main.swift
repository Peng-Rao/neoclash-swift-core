#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import NeoClashSwiftCoreLib

let exitStatus = SwiftCoreMain.run(arguments: CommandLine.arguments)
if exitStatus != 0 {
    exit(exitStatus)
}
