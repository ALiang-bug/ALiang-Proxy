import Foundation
import CryptoKit
import Darwin

enum InstallFailure: String, Error {
    case administratorRequired, invalidArguments, unsafeSource, integrityFailed
    case unsafeDirectory, unsafeExistingHelper, unsafeLock, tunRunning, ioFailure
}

enum HelperInstaller {
    static let helperName = "local.privateproxy.tun-core"
    static let maximumBytes = 64 * 1024 * 1024

    static func requireAdministrator(_ uid: uid_t = geteuid()) throws {
        guard uid == 0 else { throw InstallFailure.administratorRequired }
    }
    static func openDirectory(_ path: String) throws -> Int32 {
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw InstallFailure.unsafeDirectory }
        return fd
    }
    static func checkDirectory(_ fd: Int32, owner: uid_t = 0) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == owner, info.st_mode & 0o022 == 0 else { throw InstallFailure.unsafeDirectory }
    }
    static func childDirectory(_ parent: Int32, name: String, create: Bool = false) throws -> Int32 {
        if create && mkdirat(parent, name, 0o755) != 0 && errno != EEXIST { throw InstallFailure.ioFailure }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw InstallFailure.unsafeDirectory }
        do { try checkDirectory(fd); return fd } catch { close(fd); throw error }
    }
    static func readPayload(_ directory: Int32, expected: String) throws -> Data {
        let fd = openat(directory, "proxy-core", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw InstallFailure.unsafeSource }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size > 0, info.st_size <= maximumBytes else { throw InstallFailure.unsafeSource }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw InstallFailure.ioFailure }
            if count == 0 { break }
            guard data.count + count <= maximumBytes else { throw InstallFailure.unsafeSource }
            data.append(contentsOf: buffer.prefix(count))
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard digest == expected else { throw InstallFailure.integrityFailed }
        return data
    }
    static func acquireLock(_ path: String, owner: uid_t = 0) throws -> Int32 {
        let fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw InstallFailure.unsafeLock }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == owner, info.st_mode & 0o077 == 0, info.st_nlink == 1 else { throw InstallFailure.unsafeLock }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw InstallFailure.tunRunning }
            return fd
        } catch { close(fd); throw error }
    }
    // Descriptor-relative operations prevent path replacement between checks and writes.
    // Tests exercise this transaction only in disposable, unprivileged directories.
    static func installPayload(_ data: Data, directory: Int32, owner: uid_t = 0, group: gid_t = 0) throws {
        try checkDirectory(directory, owner: owner)
        var existing = stat()
        if fstatat(directory, helperName, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG, existing.st_uid == owner,
                  existing.st_mode & 0o022 == 0, existing.st_nlink == 1 else { throw InstallFailure.unsafeExistingHelper }
        } else if errno != ENOENT { throw InstallFailure.ioFailure }
        let temporary = helperName + ".install-" + UUID().uuidString
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw InstallFailure.ioFailure }
        defer { close(fd); unlinkat(directory, temporary, 0) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw InstallFailure.ioFailure }
                offset += count
            }
        }
        guard fchown(fd, owner, group) == 0, fchmod(fd, 0o755) == 0,
              fsync(fd) == 0, renameat(directory, temporary, directory, helperName) == 0 else { throw InstallFailure.ioFailure }
    }
    static func install(source: String, expected: String) throws {
        try requireAdministrator()
        let sourceDirectory = try openDirectory(source)
        defer { close(sourceDirectory) }
        let data = try readPayload(sourceDirectory, expected: expected)
        // Same lifetime lock as the TUN core; never unlink it on exit.
        let lock = try acquireLock("/var/run/local.privateproxy.tun.lock")
        defer { close(lock) }
        let root = try openDirectory("/")
        defer { close(root) }
        try checkDirectory(root)
        let library = try childDirectory(root, name: "Library")
        defer { close(library) }
        let target = try childDirectory(library, name: "PrivilegedHelperTools", create: true)
        defer { close(target) }
        try installPayload(data, directory: target)
    }
}
