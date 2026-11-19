import Foundation
import CryptoKit
import Darwin

@main struct NativeInstallerTests {
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func check(_ condition: Bool) { precondition(condition) }
    static func rejects(_ expected: InstallFailure, _ action: () throws -> Void) throws {
        do { try action(); fatalError("Accepted unsafe input: \(expected)") }
        catch let error as InstallFailure { precondition(error == expected, "Wrong rejection: \(error)") }
    }
    static func fixture(_ run: (URL, Int32) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("native-installer-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: url) }
        let fd = try HelperInstaller.openDirectory(url.path)
        defer { close(fd) }
        try run(url, fd)
    }
    static func main() throws {
        precondition(geteuid() != 0, "Run safety tests without root")
        try rejects(.administratorRequired) { try HelperInstaller.requireAdministrator(501) }
        print("PASS non-root rejected")
        let payload = Data("synthetic helper for offline tests".utf8)
        try fixture { path, fd in
            let source = path.appendingPathComponent("proxy-core")
            try payload.write(to: source)
            check(try HelperInstaller.readPayload(fd, expected: digest(payload)) == payload)
            try rejects(.integrityFailed) { _ = try HelperInstaller.readPayload(fd, expected: String(repeating: "0", count: 64)) }
            try FileManager.default.removeItem(at: source)
            try FileManager.default.createSymbolicLink(atPath: source.path, withDestinationPath: "/dev/null")
            try rejects(.unsafeSource) { _ = try HelperInstaller.readPayload(fd, expected: digest(payload)) }
            try FileManager.default.removeItem(at: source)
            precondition(mkfifo(source.path, 0o600) == 0)
            try rejects(.unsafeSource) { _ = try HelperInstaller.readPayload(fd, expected: digest(payload)) }
        }
        print("PASS payload hash, symlink and FIFO boundaries")
        try fixture { path, fd in
            let source = path.appendingPathComponent("proxy-core")
            let file = open(source.path, O_WRONLY | O_CREAT, 0o600)
            precondition(file >= 0)
            precondition(ftruncate(file, off_t(HelperInstaller.maximumBytes + 1)) == 0)
            close(file)
            try rejects(.unsafeSource) { _ = try HelperInstaller.readPayload(fd, expected: digest(payload)) }
        }
        print("PASS oversized source rejected")
        try fixture { path, fd in
            let target = path.appendingPathComponent(HelperInstaller.helperName)
            try HelperInstaller.installPayload(payload, directory: fd, owner: geteuid(), group: getegid())
            check(try Data(contentsOf: target) == payload)
            var info = stat(); precondition(lstat(target.path, &info) == 0)
            precondition(info.st_mode & 0o777 == 0o755 && info.st_uid == geteuid())
            let update = Data("new helper".utf8)
            try HelperInstaller.installPayload(update, directory: fd, owner: geteuid(), group: getegid())
            check(try Data(contentsOf: target) == update)
            check(try FileManager.default.contentsOfDirectory(atPath: path.path).count == 1)
            precondition(chmod(path.path, 0o777) == 0)
            try rejects(.unsafeDirectory) { try HelperInstaller.installPayload(payload, directory: fd, owner: geteuid(), group: getegid()) }
            precondition(chmod(path.path, 0o700) == 0)
            check(try Data(contentsOf: target) == update)
            try FileManager.default.removeItem(at: target)
            let sentinel = path.appendingPathComponent("untouched")
            try payload.write(to: sentinel)
            try FileManager.default.createSymbolicLink(at: target, withDestinationURL: sentinel)
            try rejects(.unsafeExistingHelper) { try HelperInstaller.installPayload(update, directory: fd, owner: geteuid(), group: getegid()) }
            check(try Data(contentsOf: sentinel) == payload)
        }
        print("PASS atomic install/update, permissions, unsafe directory and target symlink; prior helper preserved")
        try fixture { path, _ in
            let lockPath = path.appendingPathComponent("lock").path
            let first = try HelperInstaller.acquireLock(lockPath, owner: geteuid())
            try rejects(.tunRunning) { _ = try HelperInstaller.acquireLock(lockPath, owner: geteuid()) }
            close(first)
            let second = try HelperInstaller.acquireLock(lockPath, owner: geteuid()); close(second)
            precondition(chmod(lockPath, 0o666) == 0)
            try rejects(.unsafeLock) { _ = try HelperInstaller.acquireLock(lockPath, owner: geteuid()) }
            try FileManager.default.removeItem(atPath: lockPath)
            try FileManager.default.createSymbolicLink(atPath: lockPath, withDestinationPath: "/dev/null")
            try rejects(.unsafeLock) { _ = try HelperInstaller.acquireLock(lockPath, owner: geteuid()) }
        }
        print("PASS runtime lock exclusivity, release, permissions and symlink boundaries")
        try fixture { path, _ in
            let real = path.appendingPathComponent("real")
            try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false)
            let link = path.appendingPathComponent("link")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
            try rejects(.unsafeDirectory) { _ = try HelperInstaller.openDirectory(link.path) }
        }
        print("PASS directory symlink rejected; all native installer tests passed (no privileged or network changes)")
    }
}
