import Foundation
import Combine
import Darwin
import CryptoKit

private final class TUNCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func cancel() { lock.lock(); value = true; lock.unlock() }
}

@MainActor final class TUNSession: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var busy = false
    @Published private(set) var installing = false
    @Published private(set) var helperStatus = "辅助程序尚未检查"
    @Published private(set) var status = "TUN 未启动；联网和路由恢复需自行验收"
    private var cancellation: TUNCancellation?
    private var authorization: Process?
    private var generation = UUID()

    static let helper = URL(fileURLWithPath: "/Library/PrivilegedHelperTools/local.privateproxy.tun-core")
    static func verifyHelper(expected: Data) throws {
        var path = helper.path
        while true {
            var info = stat()
            guard lstat(path, &info) == 0, info.st_uid == 0,
                  (info.st_mode & 0o022) == 0, (info.st_mode & S_IFMT) != S_IFLNK else {
                throw ClientError.message("请先点击“安装辅助程序”完成安装。")
            }
            if path == "/" { break }
            path = (path as NSString).deletingLastPathComponent
        }
        let installed = try LimitedFile.read(helper, maxBytes: 64 * 1024 * 1024)
        guard SHA256.hash(data: installed) == SHA256.hash(data: expected) else {
            throw ClientError.message("TUN 辅助程序版本不一致，请重新安装。")
        }
    }
    func refreshHelper(core: URL) {
        guard !installing else { return }
        do {
            try Self.verifyHelper(expected: LimitedFile.read(core, maxBytes: 64 * 1024 * 1024))
            helperStatus = "辅助程序已安装且版本匹配"
        } catch { helperStatus = "辅助程序未安装、版本不匹配或保护检查未通过，请安装或更新" }
    }
    func installHelper(core: URL) {
        guard !busy, !running else { return }
        guard let installer = Bundle.main.url(forResource: "install-tun-helper", withExtension: nil),
              FileManager.default.isExecutableFile(atPath: installer.path),
              let hash = Bundle.main.url(forResource: "install-tun-helper", withExtension: "sha256"),
              let digest = try? LimitedFile.read(hash, maxBytes: 128),
              let expected = String(data: digest, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let bytes = try? LimitedFile.read(installer, maxBytes: 64 * 1024 * 1024),
              SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == expected else {
            helperStatus = "原生安装组件缺失或完整性校验失败，请重新获取完整应用。"; return
        }
        busy = true; installing = true; helperStatus = "等待管理员授权并安装辅助程序…"
        let command = "exec " + SystemProxy.shellQuote(installer.path)
        let literal = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        Task {
            do {
                try await Task.detached {
                    let proc = Process()
                    proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                    proc.arguments = ["-e", "do shell script \"" + literal + "\" with administrator privileges"]
                    proc.standardOutput = FileHandle.nullDevice; proc.standardError = FileHandle.nullDevice
                    try proc.run(); proc.waitUntilExit()
                    guard proc.terminationStatus == 0 else { throw ClientError.message("安装未完成：可能取消了授权、已有 TUN 在运行，或安全校验未通过。可停止 TUN 后重试。") }
                }.value
                try Self.verifyHelper(expected: LimitedFile.read(core, maxBytes: 64 * 1024 * 1024))
                helperStatus = "辅助程序安装成功；尚未启动 TUN，也未修改网络设置"
            } catch { helperStatus = error.localizedDescription }
            installing = false; busy = false
        }
    }
    func start(config: Data, core: URL) {
        guard !busy, !running else { return }
        do {
            try Self.verifyHelper(expected: LimitedFile.read(core, maxBytes: 64 * 1024 * 1024))
            let check = try helperCheck(config, core: core)
            guard check else { throw ClientError.message("TUN 配置未通过安全校验。") }
            let conflicts = try Self.readConflictingInterfaces()
            guard conflicts.isEmpty else {
                throw ClientError.message("仍有接管流量的 TUN 路由：" + conflicts.joined(separator: ", ") + "。请确认其他 VPN/TUN 已停止；仅关闭窗口不一定停止内核。")
            }
            let id = UUID(); generation = id
            let token = TUNCancellation(); cancellation = token
            let directory = "/private/tmp/pp-tun-" + UUID().uuidString.prefix(12)
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let path = directory + "/control.sock"
            let listener = socket(AF_UNIX, SOCK_STREAM, 0)
            guard listener >= 0 else { try? FileManager.default.removeItem(atPath: directory); throw ClientError.message("无法建立本地控制通道。") }
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(path.utf8) + [0]
            withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
            let bound = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            guard bound == 0, listen(listener, 1) == 0 else { close(listener); try? FileManager.default.removeItem(atPath: directory); throw ClientError.message("无法监听本地控制通道。") }
            let capability = UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")
            let proc = Process(); proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            // Only fixed helper, generated path and random capability enter the shell.
            let command = "exec " + Self.helper.path + " run-tun-socket " + path + " " + capability
            proc.arguments = ["-e", "do shell script \"" + command + "\" with administrator privileges"]
            proc.standardOutput = FileHandle.nullDevice; proc.standardError = FileHandle.nullDevice
            proc.terminationHandler = { _ in token.cancel() }
            do { try proc.run() } catch { close(listener); try? FileManager.default.removeItem(atPath: directory); throw error }
            authorization = proc; busy = true; status = "等待管理员授权和 TUN 启动…"
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                var client: Int32 = -1
                defer { if client >= 0 { close(client) }; close(listener); try? FileManager.default.removeItem(atPath: directory) }
                let deadline = Date().addingTimeInterval(60)
                func available(_ fd: Int32) -> Bool { var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0); return poll(&item, 1, 100) > 0 }
                while !token.cancelled && Date() < deadline { if available(listener) { client = accept(listener, nil, nil); break } }
                var authenticated = false; var ready = false
                if client >= 0 {
                    var line = Data()
                    while !token.cancelled && Date() < deadline && line.count <= 64 {
                        if !available(client) { continue }; var byte: UInt8 = 0
                        if read(client, &byte, 1) != 1 { break }; if byte == 10 { authenticated = String(data: line, encoding: .utf8) == capability; break }; line.append(byte)
                    }
                    if authenticated {
                        var timeout = timeval(tv_sec: 2, tv_usec: 0); setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                        var noSignal: Int32 = 1; setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
                        var length = UInt32(config.count).bigEndian; var frame = withUnsafeBytes(of: &length) { Data($0) }; frame.append(config)
                        var offset = 0
                        frame.withUnsafeBytes { buffer in while offset < frame.count && !token.cancelled { let n = send(client, buffer.baseAddress!.advanced(by: offset), frame.count-offset, 0); if n <= 0 { break }; offset += n } }
                        if offset == frame.count {
                            line = Data()
                            while !token.cancelled && Date() < deadline && line.count < 16 {
                                if !available(client) { continue }; var byte: UInt8 = 0
                                if read(client, &byte, 1) != 1 { break }; if byte == 10 { ready = line == Data("ready".utf8); break }; line.append(byte)
                            }
                        }
                    }
                    if ready { DispatchQueue.main.async { [weak self] in guard let self, self.generation == id else { return }; self.running = true; self.busy = false; self.status = "TUN 已启动（远端连通性尚未检测）" } }
                    while ready && !token.cancelled { if available(client) { var byte: UInt8 = 0; if read(client, &byte, 1) <= 0 { break } } }
                }
                // Closing the authenticated channel cancels the root core context.
                if client >= 0 { shutdown(client, SHUT_WR) }
                if !authenticated && proc.isRunning { proc.terminate() }
                let cleanupDeadline = Date().addingTimeInterval(15)
                while proc.isRunning && Date() < cleanupDeadline { Thread.sleep(forTimeInterval: 0.05) }
                let cleanupConfirmed = !proc.isRunning
                DispatchQueue.main.async { [weak self] in
                    guard let self, self.generation == id else { return }
                    self.running = false; self.busy = !cleanupConfirmed; self.cancellation = nil
                    self.status = !cleanupConfirmed ? "TUN 退出未确认，请在本机核查辅助进程与路由；禁止再次启动" : ready ? "TUN 控制通道已关闭；请核查路由恢复" : "TUN 未启动：授权取消、超时或内核启动失败"
                }
            }
        } catch { status = (error as? ClientError)?.localizedDescription ?? "TUN 准备失败，未启动。" }
    }
    func stop() { guard cancellation != nil else { return }; busy = true; status = "正在关闭 TUN 控制通道…"; cancellation?.cancel() }
    private func helperCheck(_ data: Data, core: URL) throws -> Bool {
        let proc = Process(), input = Pipe(); proc.executableURL = core; proc.arguments = ["check-tun"]; proc.standardInput = input; proc.standardOutput = FileHandle.nullDevice; proc.standardError = FileHandle.nullDevice
        try proc.run(); try input.fileHandleForWriting.write(contentsOf: data); try input.fileHandleForWriting.close(); proc.waitUntilExit(); return proc.terminationStatus == 0
    }
    func inspectRoutes() {
        guard !busy, !running else { return }
        do {
            let conflicts = try Self.readConflictingInterfaces()
            status = conflicts.isEmpty ? "未发现其他 TUN 的默认/半默认接管路由（不代表联网已通过）" : "仍有接管流量的 TUN 路由：" + conflicts.joined(separator: ", ")
        } catch { status = error.localizedDescription }
    }
    static func readConflictingInterfaces() throws -> [String] {
        let routes = Process(), output = Pipe()
        routes.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat"); routes.arguments = ["-rn"]
        routes.standardOutput = output; routes.standardError = FileHandle.nullDevice
        do { try routes.run() } catch { throw ClientError.message("无法启动路由读取命令；尚未判断是否存在 TUN 冲突。") }
        let data = output.fileHandleForReading.readDataToEndOfFile(); routes.waitUntilExit()
        guard routes.terminationStatus == 0 else { throw ClientError.message("读取系统路由失败（退出码 \(routes.terminationStatus)）；尚未判断是否存在 TUN 冲突。") }
        let text = String(decoding: data, as: UTF8.self)
        guard text.contains("Destination"), text.contains("Netif") else { throw ClientError.message("无法识别路由表格式；尚未判断是否存在 TUN 冲突。") }
        return conflictingInterfaces(text)
    }
    static func conflictingRoutes(_ text: String) -> Bool { !conflictingInterfaces(text).isEmpty }
    static func conflictingInterfaces(_ text: String) -> [String] {
        let defaults: Set<String> = ["default", "0/1", "128.0/1", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        var interfaces = Set<String>()
        for line in text.split(separator: "\n") {
            let fields = line.split(whereSeparator: { $0.isWhitespace })
            guard fields.count >= 4, defaults.contains(String(fields[0])) else { continue }
            // Uppercase I is RTF_IFSCOPE, not an unscoped system default.
            if fields[0] == "default" && fields[2].contains("I") { continue }
            let name = String(fields[3])
            if name.hasPrefix("utun"), !name.dropFirst(4).isEmpty, name.dropFirst(4).allSatisfy({ $0.isNumber }) { interfaces.insert(name) }
        }
        return interfaces.sorted()
    }
}
