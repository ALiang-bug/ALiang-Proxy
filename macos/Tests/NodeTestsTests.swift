import Foundation

@main struct NodeTestsTests {
    @MainActor static func wait(_ tests: NodeTests) async throws {
        let deadline = Date().addingTimeInterval(5)
        while tests.busy && Date() < deadline { try await Task.sleep(nanoseconds: 10_000_000) }
        guard !tests.busy else { fatalError("test process did not finish") }
    }
    @MainActor static func main() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let core = directory.appendingPathComponent("fake-core")
        let script = """
        #!/bin/sh
        payload=$(/bin/cat)
        case "$payload" in
          slow) /bin/sleep 1; printf '%s' '{"ok":true,"delayMS":80}' ;;
          fail) printf '%s' '{"ok":false,"error":"connection_or_tls_failed"}' ;;
          *) printf '%s' '{"ok":true,"delayMS":20,"MBps":2.5}' ;;
        esac
        """
        try script.write(to: core, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: core.path)
        let tests = NodeTests()
        tests.start(nodes: ["ok", "fail"], core: core, speed: false) { Data($0.utf8) }
        try await wait(tests)
        guard tests.results["ok"]?.delayMS == 20, tests.results["fail"]?.delayMS == nil else { fatalError("per-node results mixed") }
        tests.start(nodes: ["ok"], core: core, speed: true) { Data($0.utf8) }
        try await wait(tests)
        guard tests.results["ok"]?.MBps == 2.5 else { fatalError("missing speed") }
        tests.start(nodes: ["ok"], core: core, speed: false) { _ in Data("fail".utf8) }
        try await wait(tests)
        guard tests.results["ok"]?.MBps == nil else { fatalError("stale successful speed retained") }
        tests.start(nodes: ["slow", "never"], core: core, speed: false) { Data($0.utf8) }
        try await Task.sleep(nanoseconds: 100_000_000)
        tests.stop(); try await wait(tests)
        guard tests.results["never"] == nil, tests.progress.contains("取消") else { fatalError("cancel did not stop batch") }
        print("Node measurement UI model: per-node results, speed, failed retest and cancellation passed. Fake local process only; no network.")
    }
}
