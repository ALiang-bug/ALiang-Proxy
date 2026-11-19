import Foundation
import Combine

struct NodeMeasurement {
    var delayMS: Int?
    var MBps: Double?
    var message = "未测试"
}
private struct ProbeReply: Decodable {
    let ok: Bool
    let error: String?
    let delayMS: Int?
    let MBps: Double?
}
@MainActor final class NodeTests: ObservableObject {
    @Published private(set) var results: [String: NodeMeasurement] = [:]
    @Published private(set) var busy = false
    @Published private(set) var progress = "未执行真实节点测试"
    private var process: Process?
    private var cancelled = false
    func clear() { stop(); results = [:] }
    func stop() { cancelled = true; if process?.isRunning == true { process?.terminate() } }
    func start(nodes: [String], core: URL, speed: Bool, makeInput: @escaping (String) throws -> Data) {
        guard !busy, !nodes.isEmpty else { return }
        busy = true; cancelled = false
        Task {
            defer { self.process = nil; self.busy = false; if self.cancelled { self.progress = "已取消；已完成的结果保留" } }
            for (index, tag) in nodes.enumerated() {
                if cancelled { break }
                progress = "\(speed ? "下载测速" : "连接测试") \(index + 1)/\(nodes.count) · \(tag)"
                var value = results[tag] ?? NodeMeasurement(); value.message = "测试中…"; results[tag] = value
                let child = Process(), input = Pipe(), output = Pipe()
                child.executableURL = core; child.arguments = [speed ? "probe-speed" : "probe"]
                child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
                do {
                    let data = try makeInput(tag)
                    try child.run(); process = child
                    let replyData = try await Task.detached {
                        try input.fileHandleForWriting.write(contentsOf: data)
                        try input.fileHandleForWriting.close()
                        let reply = output.fileHandleForReading.readDataToEndOfFile()
                        child.waitUntilExit()
                        return reply
                    }.value
                    process = nil
                    if cancelled { value.message = "已取消"; results[tag] = value; break }
                    let reply = try JSONDecoder().decode(ProbeReply.self, from: replyData)
                    if reply.ok {
                        value.delayMS = max(1, reply.delayMS ?? 1)
                        if speed { value.MBps = reply.MBps }
                        value.message = "测试目标可达"
                    } else {
                        // Preserve no stale successful metrics after a failed test.
                        value.delayMS = nil; value.MBps = nil
                        value.message = reply.error == "cancelled_or_timeout" ? "超时或已取消" : "测试失败（连接、校验或目标响应异常）"
                    }
                } catch {
                    if child.isRunning { child.terminate(); await Task.detached { child.waitUntilExit() }.value }; process = nil; value.delayMS = nil; value.MBps = nil; value.message = cancelled ? "已取消" : "测试失败"
                }
                results[tag] = value
            }
            if !cancelled { progress = "测试完成；结果仅代表本次测试目标和当前网络" }
        }
    }
}
