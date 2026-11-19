import Foundation

protocol ProxyBackend: AnyObject {
    func services() throws -> [String]
    func read(kind: String, service: String) throws -> String
    func authorize(_ commands: [[String]]) throws
    func load() throws -> Data?
    func save(_ data: Data) throws
    func clear() throws
}
struct ProxyState: Equatable {
    let enabled: Bool
    let server: String
    let port: Int
    let authenticated: Bool
    init(_ text: String) throws {
        var fields: [String: String] = [:]
        for line in text.components(separatedBy: .newlines) where !line.isEmpty {
            let pair = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2, fields[String(pair[0])] == nil else { throw ClientError.message("无法识别网络代理状态，未修改设置") }
            fields[String(pair[0])] = pair[1].trimmingCharacters(in: .whitespaces)
        }
        guard let flag = fields["Enabled"], ["Yes", "No"].contains(flag),
              let host = fields["Server"], let port = Int(fields["Port"] ?? ""), (0...65535).contains(port),
              let auth = fields["Authenticated Proxy Enabled"], ["0", "1"].contains(auth) else { throw ClientError.message("网络代理状态不完整，未修改设置") }
        self.enabled = flag == "Yes"; self.server = host; self.port = port; self.authenticated = auth == "1"
    }
}
// The same transaction is exercised with a fake backend before any real network
// change. Recovery is removed only after reading back a successfully restored state.
struct ProxyTransaction {
    let backend: ProxyBackend
    func enable(service: String, port: UInt16) throws {
        guard try backend.load() == nil else { throw ClientError.message("请先关闭上次的系统代理以还原设置") }
        guard try backend.services().contains(service), port > 1024 else { throw ClientError.message("请选择有效网络服务和端口") }
        let pac = try backend.read(kind: "autoproxyurl", service: service)
        let discovery = try backend.read(kind: "proxyautodiscovery", service: service)
        guard pac.components(separatedBy: .newlines).contains("Enabled: No"),
              discovery.components(separatedBy: .newlines).contains("Auto Proxy Discovery: Off") else {
            throw ClientError.message("该网络服务启用了自动代理（PAC/WPAD）或状态无法确认，请先自行停用；应用不会覆盖它。")
        }
        var entries: [ProxySnapshot.Entry] = []
        for kind in ["webproxy", "securewebproxy", "socksfirewallproxy"] {
            let state = try ProxyState(backend.read(kind: kind, service: service))
            guard !state.enabled, !state.authenticated else { throw ClientError.message("已有启用或认证代理，应用不会覆盖它") }
            entries.append(.init(kind: kind, server: state.server, port: state.port))
        }
        let saved = ProxySnapshot(service: service, entries: entries, managedPort: port)
        try SystemProxy.validate(saved)
        try backend.save(JSONEncoder().encode(saved))
        let commands = entries.flatMap { [["-set" + $0.kind, service, "127.0.0.1", String(port)], ["-set" + $0.kind + "state", service, "on"]] }
        do {
            try backend.authorize(commands)
            for entry in entries {
                let state = try ProxyState(backend.read(kind: entry.kind, service: service))
                guard state.enabled, !state.authenticated, state.server == "127.0.0.1", state.port == Int(port) else { throw ClientError.message("系统代理设置未生效，请点击关闭系统代理以还原设置") }
            }
        } catch {
            // Cancellation before mutation needs no second authorization prompt.
            // Any partial/unverified mutation keeps the recovery record intact.
            if (try? matchesOriginal(saved)) == true { try? backend.clear() }
            throw error
        }
    }
    func matchesOriginal(_ saved: ProxySnapshot) throws -> Bool {
        for entry in saved.entries {
            let state = try ProxyState(backend.read(kind: entry.kind, service: saved.service))
            guard !state.enabled, !state.authenticated else { return false }
            if !entry.server.isEmpty && entry.port > 0 && (state.server != entry.server || state.port != entry.port) { return false }
        }
        return true
    }
    func restore() throws {
        guard let data = try backend.load() else { return }
        guard data.count < 8192 else { throw ClientError.message("恢复记录过大，已拒绝修改设置") }
        let saved = try JSONDecoder().decode(ProxySnapshot.self, from: data)
        try SystemProxy.validate(saved)
        guard try backend.services().contains(saved.service) else { throw ClientError.message("原网络服务不存在，请在系统设置中检查代理") }
        // Check all three before authorizing any change. Never overwrite a new
        // active proxy installed by another application or the user.
        for entry in saved.entries {
            let state = try ProxyState(backend.read(kind: entry.kind, service: saved.service))
            guard !state.authenticated, !state.enabled || (state.server == "127.0.0.1" && state.port == Int(saved.managedPort)) else { throw ClientError.message("系统代理已被其他软件或手动设置更改，无法安全还原。请先在系统设置中关闭其他代理，再点击关闭系统代理；开启前的设置备份仍保留。") }
        }
        if try matchesOriginal(saved) { try backend.clear(); return }
        var commands: [[String]] = []
        for entry in saved.entries {
            // networksetup -set*proxy also enables that proxy. Restore the
            // saved endpoint first, then explicitly leave the proxy disabled.
            if !entry.server.isEmpty && entry.port > 0 { commands.append(["-set" + entry.kind, saved.service, entry.server, String(entry.port)]) }
            commands.append(["-set" + entry.kind + "state", saved.service, "off"])
        }
        try backend.authorize(commands)
        guard try matchesOriginal(saved) else { throw ClientError.message("系统代理恢复未生效，恢复记录已保留") }
        try backend.clear()
    }
}
