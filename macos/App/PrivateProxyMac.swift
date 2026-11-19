import SwiftUI
import AppKit
import Security
import CryptoKit
import UniformTypeIdentifiers

struct Outbound: Identifiable {
    var id: String { tag }
    let tag: String
    let type: String
    let members: [String]
}
struct ImportedProfile {
    let yaml: Data
    let core: [String: Any]
    let report: [String: Any]
    let source: String?
    var outbounds: [Outbound] {
        (core["outbounds"] as? [[String: Any]] ?? []).compactMap {
            guard let tag = $0["tag"] as? String, let type = $0["type"] as? String else { return nil }
            return Outbound(tag: tag, type: type, members: $0["outbounds"] as? [String] ?? [])
        }
    }
}
enum ClientError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}
final class HTTPSOnlyRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(SubscriptionPolicy.allowsRedirect(from: task.originalRequest?.url, to: request.url) ? request : nil)
    }
}
enum Vault {
    static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "local.privateproxy.mac", kSecAttrAccount as String: "active-profile"]
    static func save(_ data: Data) throws {
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query; item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw ClientError.message("无法保存到钥匙串") }; return
        }
        guard status == errSecSuccess else { throw ClientError.message("无法更新钥匙串") }
    }
    static func load() -> Data? {
        var request = query; request[kSecReturnData as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }
    static func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ClientError.message("无法删除钥匙串中的配置，请重试") }
    }
}
func checkedCore() throws -> URL {
    guard let url = Bundle.main.url(forResource: "proxy-core", withExtension: nil),
          let hashURL = Bundle.main.url(forResource: "proxy-core", withExtension: "sha256"),
          let hashData = try? LimitedFile.read(hashURL, maxBytes: 128),
          let expected = String(data: hashData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
          let bytes = try? LimitedFile.read(url, maxBytes: 64 * 1024 * 1024),
          SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == expected else {
        throw ClientError.message("代理内核完整性校验失败，请从本项目重新构建。")
    }
    return url
}
func helper(_ command: String, input: Data) throws -> Data {
    let url = try checkedCore()
    let process = Process(); process.executableURL = url; process.arguments = [command]
    let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
    process.standardInput = stdin; process.standardOutput = stdout; process.standardError = stderr
    try process.run()
    // Read stdout concurrently so a large compiled configuration cannot fill the pipe.
    let group = DispatchGroup(); let output = LockedData()
    group.enter(); DispatchQueue.global().async { output.set(stdout.fileHandleForReading.readDataToEndOfFile()); group.leave() }
    try stdin.fileHandleForWriting.write(contentsOf: input); try stdin.fileHandleForWriting.close()
    process.waitUntilExit(); group.wait()
    guard process.terminationStatus == 0 else { throw ClientError.message("配置校验失败（仅支持 VLESS/Trojan 和手动策略组，请检查配置格式与参数）") }
    return output.get()
}
final class LockedData: @unchecked Sendable {
    private var value = Data(); private let lock = NSLock()
    func set(_ data: Data) { lock.lock(); defer { lock.unlock() }; value = data }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return value }
}
func compile(_ yaml: Data, source: String?) throws -> ImportedProfile {
    let output = try helper("compile", input: yaml)
    guard let root = try JSONSerialization.jsonObject(with: output) as? [String: Any],
          let envelope = root["envelope"] as? [String: Any], let json = envelope["coreJSON"] as? String,
          let data = json.data(using: .utf8), let core = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let report = root["report"] as? [String: Any] else { throw ClientError.message("内核返回了无效配置") }
    return ImportedProfile(yaml: yaml, core: core, report: report, source: source)
}

@MainActor final class Client: ObservableObject {
    @Published var active: ImportedProfile?
    @Published var pending: ImportedProfile?
    @Published var selections: [String: String] = [:]
    @Published var exit = ""
    @Published var link = ""
    @Published var status = "未连接"
    @Published var error: String?
    @Published var busy = false
    @Published var connected = false
    @Published var port = "17890"
    @Published var nodeDNS: NodeDNS = .system
    @Published var services: [String] = []
    @Published var networkService = ""
    @Published var systemProxy = false
    @Published var recovery = SystemProxy.needsRecovery
    private var process: Process?
    private var proxyOperationInFlight = false
    init() {
        services = (try? SystemProxy.services()) ?? []
        networkService = services.first(where: { $0 == "Wi-Fi" }) ?? services.first ?? ""
        busy = true
        Task {
            defer { busy = false }
            guard let data = Vault.load() else { return }
            do {
                let stored = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                guard let text = stored?["yaml"] as? String, let yaml = Data(base64Encoded: text) else { return }
                let source = stored?["source"] as? String
                let profile = try await Task.detached { try compile(yaml, source: source) }.value
                active = profile; resetChoices()
            } catch { self.error = "已保存的配置无法读取，请重新导入。" }
        }
    }
    func resetChoices() {
        selections = [:]
        for node in active?.outbounds ?? [] where node.type == "selector" { selections[node.tag] = node.members.first }
        exit = (active?.core["route"] as? [String: Any])?["final"] as? String ?? active?.outbounds.first?.tag ?? ""
    }
    func importFile() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false
        panel.allowedContentTypes = [.yaml, .plainText, .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await stage { let data = try await Task.detached { try LimitedFile.read(url, maxBytes: SubscriptionPolicy.maxBytes) }.value; return (data, nil) } }
    }
    func subscription(update: Bool = false) {
        let text = update ? active?.source ?? "" : link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = SubscriptionPolicy.validatedURL(text) else { error = "请输入有效的 HTTPS Clash YAML 订阅地址"; return }
        Task {
            await stage {
                var request = URLRequest(url: url); request.timeoutInterval = 30
                let config = URLSessionConfiguration.ephemeral; config.urlCache = nil; config.timeoutIntervalForResource = 45
                let session = URLSession(configuration: config, delegate: HTTPSOnlyRedirects(), delegateQueue: nil); defer { session.invalidateAndCancel() }
                let (bytes, response) = try await session.bytes(for: request)
                guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode), response.url?.scheme == "https" else { throw ClientError.message("订阅服务器返回错误") }
                var data = Data()
                for try await byte in bytes { data.append(byte); if data.count > SubscriptionPolicy.maxBytes { throw ClientError.message("订阅超过 1 MB") } }
                return (data, text)
            }
        }
    }
    func stage(_ obtain: () async throws -> (Data, String?)) async {
        guard !busy, !connected else { return }; busy = true; defer { busy = false }
        do {
            let (data, source) = try await obtain()
            pending = try await Task.detached { try compile(data, source: source) }.value
        } catch { self.error = (error as? ClientError)?.localizedDescription ?? "导入失败；请检查网络或文件，原配置已保留。" }
    }
    func activate() {
        guard let profile = pending else { return }
        do {
            var saved: [String: Any] = ["yaml": profile.yaml.base64EncodedString()]
            saved["source"] = profile.source
            try Vault.save(JSONSerialization.data(withJSONObject: saved))
            active = profile; pending = nil; link = ""; resetChoices()
        } catch { self.error = error.localizedDescription }
    }
    func forget() {
        guard !connected, !busy else { return }
        do { try Vault.delete(); active = nil; selections = [:]; exit = "" }
        catch { self.error = error.localizedDescription }
    }
    func probeInput(node: String) throws -> Data {
        guard let profile = active, !busy, !connected, nodeDNS != .system,
              profile.outbounds.contains(where: { $0.tag == node && $0.type != "selector" }) else {
            throw ClientError.message("请先停止连接，导入配置并选择独立 DoH，再测试具体节点。")
        }
        var core = profile.core
        core["inbounds"] = [["type": "mixed", "listen": "127.0.0.1", "listen_port": 17890, "set_system_proxy": false]]
        core["route"] = ["final": node, "auto_detect_interface": true]
        nodeDNS.apply(to: &core)
        return try JSONSerialization.data(withJSONObject: core)
    }
    func tunInput() throws -> Data {
        guard let profile = active, !connected, !busy, !systemProxy, !recovery, nodeDNS != .system else {
            throw ClientError.message("请先停止本地代理并恢复系统代理，导入配置并选择独立 DoH。")
        }
        var core = profile.core
        core["inbounds"] = [["type": "mixed", "listen": "127.0.0.1", "listen_port": 17890, "set_system_proxy": false]]
        core["route"] = ["final": exit, "auto_detect_interface": true]
        var outbounds = core["outbounds"] as? [[String: Any]] ?? []
        for i in outbounds.indices where outbounds[i]["type"] as? String == "selector" { if let tag = outbounds[i]["tag"] as? String { outbounds[i]["default"] = selections[tag] } }
        core["outbounds"] = outbounds; nodeDNS.apply(to: &core)
        return try JSONSerialization.data(withJSONObject: core)
    }
    func start() {
        guard !busy, !connected, process == nil, let profile = active, let number = UInt16(port), number > 1024 else { error = "请导入配置，并使用 1025–65535 的端口"; return }
        busy = true; status = "正在启动本地代理…"
        do {
            var core = profile.core
            core["inbounds"] = [["type": "mixed", "tag": "desktop", "listen": "127.0.0.1", "listen_port": number, "set_system_proxy": false]]
            core["route"] = ["final": exit, "auto_detect_interface": true]
            var outbounds = core["outbounds"] as? [[String: Any]] ?? []
            for i in outbounds.indices where outbounds[i]["type"] as? String == "selector" { if let tag = outbounds[i]["tag"] as? String { outbounds[i]["default"] = selections[tag] } }
            core["outbounds"] = outbounds
            nodeDNS.apply(to: &core)
            let data = try JSONSerialization.data(withJSONObject: core)
            let url = try checkedCore()
            let proc = Process(), stdin = Pipe(), stdout = Pipe()
            proc.executableURL = url; proc.arguments = ["run"]; proc.standardInput = stdin; proc.standardOutput = stdout; proc.standardError = FileHandle.nullDevice
            proc.terminationHandler = { [weak self] ended in Task { @MainActor in
                guard let self, self.process === ended else { return }
                self.process = nil; self.connected = false; self.busy = self.proxyOperationInFlight; self.status = "未连接"
                if ended.terminationStatus != 0 { self.error = "代理内核退出，请检查配置或端口占用。" }
                if self.systemProxy && !self.proxyOperationInFlight { self.changeProxy(enable: false) }
            } }
            try proc.run(); process = proc
            Task { [weak self, weak proc] in
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                guard let self, let proc, self.process === proc, !self.connected else { return }
                self.error = "内核启动超时，已停止，请重试。"
                self.terminateCore()
            }
            Task.detached { [self] in
                do {
                    try stdin.fileHandleForWriting.write(contentsOf: data); try stdin.fileHandleForWriting.close()
                    let ready = stdout.fileHandleForReading.availableData
                    await MainActor.run {
                        guard self.process === proc, proc.isRunning else { return }
                        self.busy = false
                        if String(data: ready, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) == "ready" { self.connected = true; self.status = "本地代理已启动（远端连通性尚未检测）" }
                        else { self.error = "内核启动失败"; self.stop() }
                    }
                } catch { await MainActor.run {
                    guard self.process === proc else { return }
                    self.busy = false; self.error = "无法启动内核"; self.stop()
                } }
            }
        } catch { busy = false; status = "未连接"; self.error = error.localizedDescription }
    }
    func stop() {
        guard !busy else { return }
        if systemProxy || recovery {
            changeProxy(enable: false, stopAfter: true)
        } else { terminateCore() }
    }
    func changeProxy(enable: Bool, stopAfter: Bool = false) {
        guard !busy else { return }
        let number = UInt16(port) ?? 17890
        if enable && (!connected || number <= 1024) { error = "请先启动有效的本地代理"; return }
        busy = true
        let service = networkService
        proxyOperationInFlight = true
        Task {
            do {
                try await Task.detached {
                    if enable { try SystemProxy.enable(service: service, port: number) }
                    else { try SystemProxy.restore() }
                }.value
                if enable && process == nil {
                    try await Task.detached { try SystemProxy.restore() }.value
                    systemProxy = false
                    error = "内核已退出，刚启用的系统代理已恢复。"
                } else { systemProxy = enable }
                if stopAfter { terminateCore() }
            } catch { self.error = error.localizedDescription; busy = false }
            proxyOperationInFlight = false
            recovery = SystemProxy.needsRecovery
            if !stopAfter || process == nil { busy = false }
        }
    }
    private func terminateCore() {
        guard let process else { busy = false; connected = false; status = "未连接"; return }
        busy = true; status = "正在停止…"; process.terminate()
    }
    func shutdownForQuit() {
        systemProxy = false; recovery = false
        process?.terminate()
    }
    func proxySettings() { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension")!) }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var client: Client?
    weak var tun: TUNSession?
    weak var tests: NodeTests?
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let icon = NSImage(contentsOf: url), icon.isValid {
            NSApplication.shared.applicationIconImage = icon
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if tun?.busy == true || tun?.running == true {
            tun?.stop()
            client?.error = "正在停止 TUN；请等待辅助进程退出确认后再退出应用。"
            return .terminateCancel
        }
        guard client?.busy != true else {
            client?.error = "请等待当前操作结束后再退出，以确保代理设置可以恢复。"
            return .terminateCancel
        }
        if SystemProxy.needsRecovery {
            do { try SystemProxy.restore() }
            catch {
                let alert = NSAlert(); alert.messageText = "系统代理尚未恢复"; alert.informativeText = "请先恢复系统代理再退出，以免网络无法访问。"; alert.runModal()
                return .terminateCancel
            }
        }
        tests?.stop()
        client?.shutdownForQuit()
        return .terminateNow
    }
}
@main struct PrivateProxyMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var client = Client()
    @StateObject private var tun = TUNSession()
    @StateObject private var tests = NodeTests()
    var body: some Scene {
        WindowGroup("ALiang Proxy") {
            ContentView(client: client, tun: tun, tests: tests).frame(minWidth: 880, minHeight: 760)
                .onAppear { appDelegate.client = client; appDelegate.tun = tun; appDelegate.tests = tests }
        }
    }
}
struct ContentView: View {
    @ObservedObject var client: Client
    @ObservedObject var tun: TUNSession
    @ObservedObject var tests: NodeTests
    @State private var speedNode: String?
    @State private var sortBySpeed = false
    @State private var nodeSearch = ""
    private var leaves: [Outbound] {
        (client.active?.outbounds ?? []).filter { $0.type != "selector" && (nodeSearch.isEmpty || $0.tag.localizedCaseInsensitiveContains(nodeSearch)) }.sorted {
            if sortBySpeed {
                return (tests.results[$0.tag]?.MBps ?? -1) > (tests.results[$1.tag]?.MBps ?? -1)
            }
            return (tests.results[$0.tag]?.delayMS ?? Int.max) < (tests.results[$1.tag]?.delayMS ?? Int.max)
        }
    }
    private func test(_ nodes: [String], speed: Bool = false) {
        do {
            let core = try checkedCore()
            guard let first = nodes.first else { return }; _ = try client.probeInput(node: first)
            tests.start(nodes: nodes, core: core, speed: speed) { try client.probeInput(node: $0) }
        } catch { client.error = error.localizedDescription }
    }
    private var locked: Bool { client.busy || client.connected || tun.running || tun.busy || tests.busy }
    private var totalNodes: Int { (client.active?.outbounds ?? []).filter { $0.type != "selector" }.count }
    private var readyCount: Int { tests.results.values.filter { $0.delayMS != nil }.count }
    private var maxDelay: Double { Double(max(1, tests.results.values.compactMap(\.delayMS).max() ?? 1)) }
    private var maxSpeed: Double { max(0.01, tests.results.values.compactMap(\.MBps).max() ?? 0.01) }
    private var effectiveLeaf: String? {
        let nodes = client.active?.outbounds ?? []
        var tag = client.exit; var visited = Set<String>()
        while let node = nodes.first(where: { $0.tag == tag }), visited.insert(tag).inserted {
            if node.type != "selector" { return node.tag }
            guard let next = client.selections[tag] ?? node.members.first else { return nil }; tag = next
        }
        return nil
    }
    private var path: String {
        let nodes = client.active?.outbounds ?? []
        var tag = client.exit; var visited = Set<String>(); var chain: [String] = []
        while let node = nodes.first(where: { $0.tag == tag }), visited.insert(tag).inserted {
            chain.append(tag)
            guard node.type == "selector", let next = client.selections[tag] ?? node.members.first else { break }
            tag = next
        }
        return chain.isEmpty ? "导入订阅后选择节点" : chain.joined(separator: "  →  ")
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                subscriptionCard
                connectionCard
                tunCard
                measurementsCard
                HStack {
                    Image(systemName: "lock.shield")
                    Text("配置保存在本机钥匙串 · 不自动连接 · 测试结果仅代表当时网络")
                    Spacer()
                    Text("ALiang Proxy / macOS").fontDesign(.monospaced)
                }.font(.system(size: 11)).foregroundStyle(.secondary).padding(.horizontal, 4)
            }.padding(30).frame(maxWidth: 1180).frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .buttonStyle(ActionButtonStyle())
        .onDisappear { tests.stop() }
        .onChange(of: client.active?.yaml) { tests.clear() }
        .confirmationDialog("下载测速将通过该节点访问 Cloudflare，最多下载约 5 MiB，并消耗订阅流量。", isPresented: Binding(get: { speedNode != nil }, set: { if !$0 { speedNode = nil } })) {
            Button("开始下载测速") { if let node = speedNode { test([node], speed: true) }; speedNode = nil }
            Button("取消", role: .cancel) { speedNode = nil }
        }
        .alert("提示", isPresented: Binding(get: { client.error != nil }, set: { if !$0 { client.error = nil } })) { Button("好") { client.error = nil } } message: { Text(client.error ?? "") }
        .sheet(isPresented: Binding(get: { client.pending != nil }, set: { if !$0 { client.pending = nil } })) {
            VStack(alignment: .leading, spacing: 16) {
                Text("导入确认").font(.title2.bold())
                if let pending = client.pending {
                    Text("识别到 \(pending.report["nodes"] as? Int ?? 0) 个节点、\(pending.report["groups"] as? Int ?? 0) 个策略组。")
                    Text("\(pending.report["ignoredRules"] as? Int ?? 0) 条非默认规则停用；\(pending.report["disabledGroupChoices"] as? Int ?? 0) 个直接/拒绝策略选项停用。")
                    Text("使用本地代理入口和系统 DNS，替代原配置的 TUN、Fake-IP、自定义 DNS 和控制端口。配置只保存在本机钥匙串。")
                }
                HStack { Button("取消") { client.pending = nil }; Spacer(); Button("确认并激活") { client.activate() }.buttonStyle(.borderedProminent) }
            }.padding(24).frame(width: 480)
        }
    }
    private var header: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(spacing: 14) {
                Image(nsImage: BrandAssets.logo)
                    .resizable().interpolation(.high).scaledToFit()
                    .frame(width: 72, height: 72)
                    .accessibilityLabel("ALiang Proxy 标志")
                VStack(alignment: .leading, spacing: 5) {
                    Text("ALiang Proxy").font(.system(size: 30, weight: .bold, design: .rounded))
                    Text("订阅、连接与节点表现，一处管理").font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer()
                StatusBadge(text: tun.running ? "TUN 运行中" : client.connected ? "本地服务运行中" : tests.busy ? "正在测试" : "待连接", color: (tun.running || client.connected) ? .teal : tests.busy ? .blue : .secondary)
            }
            HStack(spacing: 12) {
                summary("已导入节点", value: String(totalNodes), icon: "server.rack", tint: .blue)
                summary("本次测试可达", value: String(readyCount), icon: "checkmark.seal", tint: .teal)
                summary("当前模式", value: tun.running ? "TUN" : client.connected ? "本地代理" : "待机", icon: "point.3.connected.trianglepath.dotted", tint: .indigo)
            }
        }.padding(.bottom, 4)
    }
    private func summary(_ title: String, value: String, icon: String, tint: Color) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).foregroundStyle(tint).font(.system(size: 18))
            VStack(alignment: .leading, spacing: 4) { Text(title).font(.system(size: 11)).foregroundStyle(.secondary); Text(value).font(.system(size: 20, weight: .semibold, design: .rounded)) }
            Spacer(minLength: 0)
        }.padding(16).frame(maxWidth: .infinity).background(tint.opacity(0.055), in: RoundedRectangle(cornerRadius: 16))
    }
    private var subscriptionCard: some View {
        DashboardCard(step: "01", title: "导入订阅", subtitle: "从订阅链接或本地 YAML 开始", icon: "tray.and.arrow.down", content: {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    Image(systemName: "link").foregroundStyle(.secondary)
                    SecureField("粘贴 HTTPS 订阅链接", text: $client.link).textFieldStyle(.plain)
                    Button { client.subscription() } label: { Label("导入订阅", systemImage: "arrow.down.circle.fill") }.buttonStyle(ActionButtonStyle(prominent: true)).disabled(client.link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    Button { client.importFile() } label: { Label("选择文件", systemImage: "folder") }
                }.padding(10).background(Color.primary.opacity(0.025), in: RoundedRectangle(cornerRadius: 14))
                HStack {
                    StatusBadge(text: client.active == nil ? "尚未导入" : "配置已载入", color: client.active == nil ? .secondary : .teal)
                    if let profile = client.active {
                        Text("\(totalNodes) 个节点 · \(profile.outbounds.filter { $0.type == "selector" }.count) 个策略组").font(.system(size: 12)).foregroundStyle(.secondary)
                        Spacer()
                        Button { client.subscription(update: true) } label: { Label("更新", systemImage: "arrow.clockwise") }.disabled(profile.source == nil)
                        Button("删除配置", role: .destructive) { client.forget() }
                    } else { Text("导入后先核对兼容性报告，再确认激活。").font(.system(size: 12)).foregroundStyle(.secondary) }
                }
            }
        }).disabled(locked)
    }
    private var connectionCard: some View {
        DashboardCard(step: "02", title: "代理连接", subtitle: "先启动本地服务，再按需让系统应用使用它", icon: "personalhotspot", tint: .teal, content: {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Picker("默认出口", selection: $client.exit) { Text("请选择节点或策略组").tag(""); ForEach(client.active?.outbounds ?? []) { Text($0.tag).tag($0.tag) } }.disabled(locked)
                    Picker("节点解析", selection: $client.nodeDNS) { ForEach(NodeDNS.allCases) { Text($0.title).tag($0) } }.frame(maxWidth: 290).disabled(locked)
                }
                Label(path, systemImage: "arrow.triangle.branch").font(.system(size: 12)).foregroundStyle(.secondary).textSelection(.enabled)
                DisclosureGroup("策略组选择 · 当前使用统一默认出口") {
                    VStack(spacing: 10) {
                        ForEach((client.active?.outbounds ?? []).filter { $0.type == "selector" }) { group in
                            Picker(group.tag, selection: Binding(get: { client.selections[group.tag] ?? group.members.first ?? "" }, set: { client.selections[group.tag] = $0 })) { ForEach(group.members, id: \.self) { Text($0).tag($0) } }
                        }
                    }.padding(.top, 12).disabled(locked)
                }.font(.system(size: 12))
                Divider()
                HStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("本地代理服务").font(.system(size: 14, weight: .semibold))
                        Text(client.status).font(.system(size: 12)).foregroundStyle(.secondary)
                        Text("127.0.0.1:\(client.port) · HTTP / HTTPS / SOCKS5").font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    TextField("端口", text: $client.port).textFieldStyle(.roundedBorder).frame(width: 80).disabled(locked)
                    Button { client.connected ? client.stop() : client.start() } label: { Label(client.connected ? "停止本地服务" : "启动本地服务", systemImage: client.connected ? "stop.fill" : "play.fill") }
                        .buttonStyle(ActionButtonStyle(prominent: true, tint: .teal)).disabled(client.busy || client.active == nil || tun.running || tun.busy || tests.busy)
                }
                HStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("系统代理").font(.system(size: 14, weight: .semibold))
                        Text(client.systemProxy ? "系统应用使用本地代理；关闭后恢复开启前的设置" : client.recovery ? "上次连接尚未完成还原，请点击关闭系统代理" : "尚未由本应用接管；其他软件的设置仍可能生效").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Picker("网络", selection: $client.networkService) { ForEach(client.services, id: \.self) { Text($0).tag($0) } }.frame(width: 170).disabled(client.systemProxy || client.recovery || client.busy || tun.running || tun.busy)
                    Button { client.systemProxy || client.recovery ? client.changeProxy(enable: false) : client.changeProxy(enable: true) } label: { Label(client.systemProxy || client.recovery ? "关闭系统代理" : "启用系统代理", systemImage: "desktopcomputer") }
                        .disabled(client.busy || tun.running || tun.busy || tests.busy || (!client.recovery && !client.connected))
                }
                DisclosureGroup("连接说明与系统设置") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("系统代理让支持该设置的应用自动使用本地服务。仅启动本地服务时，应用需单独配置代理地址。启用时保存当前代理地址、端口和关闭状态；关闭时还原这些设置。macOS 会请求授权，已有启用的代理不会被覆盖。异常退出后的还原备份保存在本机，完成还原后自动删除。独立 DoH 只改变本客户端的解析方式，节点域名会发送给所选 DNS 服务商。").font(.system(size: 12)).foregroundStyle(.secondary)
                        Button("打开系统网络设置") { client.proxySettings() }
                    }.padding(.top, 10)
                }.font(.system(size: 12))
            }
        })
    }
    private var tunCard: some View {
        DashboardCard(step: "03", title: "TUN 隧道", subtitle: "通过虚拟网卡接管更广泛的应用流量", icon: "point.topleft.down.to.point.bottomright.curvepath", tint: .indigo, content: {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 8) {
                        StatusBadge(text: tun.running ? "隧道运行中" : "实验功能", color: tun.running ? .teal : .orange)
                        Text(tun.status).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    if tun.busy { ProgressView().controlSize(.small) }
                    Button { if tun.running || tun.busy { tun.stop() } else { do { let input = try client.tunInput(); tun.start(config: input, core: try checkedCore()) } catch { client.error = error.localizedDescription } } } label: {
                        Label(tun.running || tun.busy ? "停止 TUN" : "启动 TUN", systemImage: tun.running || tun.busy ? "stop.fill" : "power")
                    }.buttonStyle(ActionButtonStyle(prominent: true, tint: .indigo)).disabled(client.connected || client.busy || client.active == nil || tests.busy || tun.installing)
                    Button { tun.inspectRoutes() } label: { Label("检查冲突", systemImage: "stethoscope") }.disabled(tun.running || tun.busy)
                }
                HStack(spacing: 14) {
                    Label(tun.helperStatus, systemImage: "lock.shield").font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button {
                        do { tun.installHelper(core: try checkedCore()) } catch { client.error = error.localizedDescription }
                    } label: { Label(tun.installing ? "正在安装…" : "安装／更新辅助程序", systemImage: "arrow.down.circle") }
                        .disabled(tun.running || tun.busy || client.busy || tests.busy)
                }
                Text("首次使用请点击安装按钮，并在 macOS 授权窗口输入管理员密码。安装仅放置受保护的辅助程序，不启动 TUN、不修改路由。启动前请关闭其他客户端 TUN 和系统代理。实机联网、异常退出及路由恢复尚待验收。").font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .onAppear { if let core = try? checkedCore() { tun.refreshHelper(core: core) } }
        })
    }
    private var measurementsCard: some View {
        DashboardCard(step: "04", title: "节点表现", subtitle: "先看可达性，再比较响应与下载速度", icon: "chart.bar.xaxis", tint: .cyan, content: {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 10) {
                    Button { test(leaves.map(\.tag)) } label: { Label(nodeSearch.isEmpty ? "测试全部节点" : "测试筛选节点", systemImage: "bolt.fill") }
                        .buttonStyle(ActionButtonStyle(prominent: true)).disabled(locked || client.active == nil || leaves.isEmpty)
                    if tests.busy { Button { tests.stop() } label: { Label("取消测试", systemImage: "xmark") } }
                    Spacer()
                    Picker("排序", selection: $sortBySpeed) { Text("低延迟优先").tag(false); Text("高下载速度优先").tag(true) }.pickerStyle(.segmented).frame(width: 260)
                }
                HStack {
                    if tests.busy { ProgressView().controlSize(.small) }
                    Text(tests.progress).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                    Spacer()
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("搜索地区或节点", text: $nodeSearch).textFieldStyle(.roundedBorder).frame(width: 190)
                }
                if leaves.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "network").font(.system(size: 30)).foregroundStyle(.tertiary)
                        Text(client.active == nil ? "导入订阅后，在这里比较节点" : "没有匹配的节点").font(.system(size: 13)).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity).padding(.vertical, 30)
                } else {
                    LazyVStack(spacing: 10) { ForEach(leaves) { node in nodeRow(node) } }
                }
                Text("延迟：经节点访问 Apple HTTPS 页面的耗时，越短越好。下载：访问 Cloudflare，单次最多约 5 MiB 加协议开销，需确认且会消耗订阅流量；越高越好。条形长度按本次已有结果相对比较，未测试不会显示虚构数值。请先停止连接并选择独立 DoH。").font(.system(size: 11)).foregroundStyle(.secondary)
            }
        })
    }
    private func nodeRow(_ node: Outbound) -> some View {
        let measurement = tests.results[node.tag]
        let selected = effectiveLeaf == node.tag
        let latencyColor: Color = (measurement?.delayMS ?? 0) > 600 ? .orange : .teal
        return HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 7) {
                Text(node.tag).font(.system(size: 13, weight: .semibold)).lineLimit(2)
                HStack(spacing: 6) {
                    Text(node.type.uppercased()).font(.system(size: 9, weight: .bold, design: .monospaced)).padding(.horizontal, 5).padding(.vertical, 3).background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 4))
                    Text(measurement?.message ?? "未测试").font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            MetricBar(title: "响应延迟", value: measurement?.delayMS.map { "\($0) ms" } ?? "—", fraction: measurement?.delayMS.map { Double($0) / maxDelay }, tint: latencyColor)
            MetricBar(title: "下载速度", value: measurement?.MBps.map { String(format: "%.2f MB/s", $0) } ?? "—", fraction: measurement?.MBps.map { $0 / maxSpeed }, tint: .blue)
            HStack(spacing: 6) {
                Button("测试") { test([node.tag]) }
                Button { speedNode = node.tag } label: { Image(systemName: "speedometer") }.help("下载测速：最多约 5 MiB") .accessibilityLabel("测速 " + node.tag)
                Button { client.exit = node.tag } label: { Image(systemName: selected ? "checkmark.circle.fill" : "arrow.right.circle") }.help("选为默认出口").accessibilityLabel("选用 " + node.tag)
                    .buttonStyle(ActionButtonStyle(prominent: selected, tint: .teal))
            }.disabled(locked)
        }.padding(14).background(selected ? Color.teal.opacity(0.045) : Color.primary.opacity(0.018), in: RoundedRectangle(cornerRadius: 14))
            .overlay { RoundedRectangle(cornerRadius: 14).strokeBorder(selected ? Color.teal.opacity(0.35) : Color.primary.opacity(0.045)) }
    }

}
