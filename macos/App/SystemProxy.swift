import Foundation

// Recoverable changes limited to the explicitly selected network service.
// Existing enabled proxies are refused; bypass lists and DNS are never modified.
struct ProxySnapshot: Codable {
    struct Entry: Codable { let kind: String; let server: String; let port: Int }
    let service: String
    let entries: [Entry]
    let managedPort: UInt16
    init(service: String, entries: [Entry], managedPort: UInt16 = 17890) { self.service = service; self.entries = entries; self.managedPort = managedPort }
}
enum SystemProxy {
    static var recoveryURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("PrivateProxyMac/proxy-recovery.json")
    }
    static var needsRecovery: Bool { FileManager.default.fileExists(atPath: recoveryURL.path) }
    static func command(_ arguments: [String]) throws -> String {
        let p = Process(), output = Pipe(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup"); p.arguments = arguments
        p.standardOutput = output; p.standardError = FileHandle.nullDevice
        try p.run(); let data = output.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw ClientError.message("无法读取网络代理设置") }
        return String(decoding: data, as: UTF8.self)
    }
    static func services() throws -> [String] { try command(["-listallnetworkservices"]).components(separatedBy: .newlines).dropFirst().filter { !$0.isEmpty && !$0.hasPrefix("*") } }
    static func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func validate(_ saved: ProxySnapshot) throws {
        let kinds: Set<String> = ["webproxy", "securewebproxy", "socksfirewallproxy"]
        guard !saved.service.isEmpty, saved.service.count <= 256, !saved.service.hasPrefix("-"),
              !saved.service.contains("\n"), !saved.service.contains("\r"),
              saved.managedPort > 1024, saved.entries.count == 3, Set(saved.entries.map(\.kind)) == kinds,
              saved.entries.allSatisfy({ $0.server.count <= 253 && $0.port >= 0 && $0.port <= 65535 && !$0.server.contains("\n") }) else {
            throw ClientError.message("恢复记录无效，已拒绝修改网络设置。")
        }
    }
    static func privileged(_ commands: [[String]]) throws {
        let permitted: Set<String> = ["-setwebproxy", "-setsecurewebproxy", "-setsocksfirewallproxy", "-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"]
        guard commands.allSatisfy({ !$0.isEmpty && permitted.contains($0[0]) && (3...4).contains($0.count) }) else { throw ClientError.message("不允许的网络操作") }
        let shell = "set -e\n" + commands.map { "/usr/sbin/networksetup " + $0.map(shellQuote).joined(separator: " ") }.joined(separator: "\n")
        let literal = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "do shell script \"\(literal)\" with administrator privileges"]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw ClientError.message("代理设置未完成；如果已部分修改，请点击“关闭系统代理”还原开启前设置。") }
    }
    private static let transactionLock = NSLock()
    static func enable(service: String, port: UInt16) throws {
        transactionLock.lock(); defer { transactionLock.unlock() }
        try ProxyTransaction(backend: LiveProxyBackend()).enable(service: service, port: port)
    }
    static func restore() throws {
        transactionLock.lock(); defer { transactionLock.unlock() }
        try ProxyTransaction(backend: LiveProxyBackend()).restore()
    }
}
final class LiveProxyBackend: ProxyBackend {
    func services() throws -> [String] { try SystemProxy.services() }
    func read(kind: String, service: String) throws -> String { try SystemProxy.command(["-get" + kind, service]) }
    func authorize(_ commands: [[String]]) throws { try SystemProxy.privileged(commands) }
    func load() throws -> Data? {
        guard SystemProxy.needsRecovery else { return nil }
        return try LimitedFile.read(SystemProxy.recoveryURL, maxBytes: 8191)
    }
    func save(_ data: Data) throws {
        try FileManager.default.createDirectory(at: SystemProxy.recoveryURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: SystemProxy.recoveryURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: SystemProxy.recoveryURL.path)
    }
    func clear() throws { try FileManager.default.removeItem(at: SystemProxy.recoveryURL) }
}
