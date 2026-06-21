import Darwin
import NeoClashSwiftCoreLib

let status = SwiftCoreMain.run(arguments: CommandLine.arguments)
if status != 0 {
    exit(status)
}
