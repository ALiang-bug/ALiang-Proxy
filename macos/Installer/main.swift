import Foundation
import Darwin

do {
    // No configurable privileged destination or user-supplied command is accepted.
    try HelperInstaller.requireAdministrator()
    guard CommandLine.arguments.count == 1 else { throw InstallFailure.invalidArguments }
    var length: UInt32 = 0
    _NSGetExecutablePath(nil, &length)
    var buffer = [CChar](repeating: 0, count: Int(length))
    guard _NSGetExecutablePath(&buffer, &length) == 0 else { throw InstallFailure.unsafeSource }
    let executable = URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath()
    try HelperInstaller.install(source: executable.deletingLastPathComponent().path, expected: InstallerBuild.expectedSHA256)
    print("Installed protected TUN helper. No daemon started; no network changes made.")
} catch {
    let code = (error as? InstallFailure)?.rawValue ?? "installationFailed"
    FileHandle.standardError.write(Data(("Helper installation refused: " + code + "\n").utf8))
    exit(1)
}
