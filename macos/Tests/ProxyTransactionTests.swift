import Foundation

final class FakeProxyBackend: ProxyBackend {
    struct State { var enabled = false; var host = "old.proxy"; var port = 8080; var authenticated = false }
    var states = Dictionary(uniqueKeysWithValues: ["webproxy", "securewebproxy", "socksfirewallproxy"].map { ($0, State()) })
    var record: Data?
    var calls = 0
    var failAfter: Int?
    var ignoreCommands = false
    var available = true
    var automaticProxy = false
    func services() throws -> [String] { available ? ["Wi-Fi"] : [] }
    func read(kind: String, service: String) throws -> String {
        if kind == "autoproxyurl" { return "URL: (null)\nEnabled: \(automaticProxy ? "Yes" : "No")" }
        if kind == "proxyautodiscovery" { return "Auto Proxy Discovery: Off" }
        let state = states[kind]!
        return "Enabled: \(state.enabled ? "Yes" : "No")\nServer: \(state.host)\nPort: \(state.port)\nAuthenticated Proxy Enabled: \(state.authenticated ? 1 : 0)"
    }
    func authorize(_ commands: [[String]]) throws {
        calls += 1
        for (index, command) in commands.enumerated() {
            if failAfter == index { throw ClientError.message("synthetic authorization failure") }
            if ignoreCommands { continue }
            let option = String(command[0].dropFirst(4))
            if option.hasSuffix("state") {
                let key = String(option.dropLast(5)); states[key]!.enabled = command[2] == "on"
            } else {
                states[option]!.host = command[2]; states[option]!.port = Int(command[3])!
                // Matches networksetup(8): setting an endpoint turns proxy on.
                states[option]!.enabled = true
            }
        }
    }
    func load() throws -> Data? { record }
    func save(_ data: Data) throws { record = data }
    func clear() throws { record = nil }
}
func runTransactionTests() throws {
    func expectFailure(_ action: () throws -> Void) {
        do { try action(); fatalError("expected transaction failure") } catch { }
    }
    do {
        let backend = FakeProxyBackend()
        for kind in backend.states.keys { backend.states[kind]!.host = "127.0.0.1"; backend.states[kind]!.port = 7897 }
        let transaction = ProxyTransaction(backend: backend)
        try transaction.enable(service: "Wi-Fi", port: 17890)
        try transaction.restore()
        guard backend.record == nil, backend.states.values.allSatisfy({ !$0.enabled && $0.host == "127.0.0.1" && $0.port == 7897 }) else {
            fatalError("restoring a disabled Clash endpoint re-enabled it")
        }
    }
    do {
        let backend = FakeProxyBackend(), transaction: ProxyTransaction
        transaction = ProxyTransaction(backend: backend)
        try transaction.enable(service: "Wi-Fi", port: 17890)
        guard backend.record != nil, backend.states.values.allSatisfy({ $0.enabled && $0.host == "127.0.0.1" && $0.port == 17890 }) else { fatalError("enable failed") }
        try transaction.restore()
        guard backend.record == nil, backend.states.values.allSatisfy({ !$0.enabled && $0.host == "old.proxy" && $0.port == 8080 }) else { fatalError("restore failed") }
    }
    do {
        let backend = FakeProxyBackend(); backend.failAfter = 0
        expectFailure { try ProxyTransaction(backend: backend).enable(service: "Wi-Fi", port: 17890) }
        guard backend.calls == 1, backend.record == nil, backend.states.values.allSatisfy({ !$0.enabled }) else { fatalError("cancel caused mutation or second prompt") }
    }
    do {
        let backend = FakeProxyBackend(); backend.failAfter = 2
        let transaction = ProxyTransaction(backend: backend)
        expectFailure { try transaction.enable(service: "Wi-Fi", port: 17890) }
        guard backend.record != nil, backend.states["webproxy"]!.enabled else { fatalError("partial failure lost recovery") }
        backend.failAfter = nil
        try transaction.restore()
        guard backend.record == nil, backend.states.values.allSatisfy({ !$0.enabled && $0.host == "old.proxy" }) else { fatalError("partial failure not recoverable") }
    }
    do {
        let backend = FakeProxyBackend(), transaction: ProxyTransaction
        transaction = ProxyTransaction(backend: backend)
        try transaction.enable(service: "Wi-Fi", port: 17890)
        backend.failAfter = 0
        expectFailure { try transaction.restore() }
        guard backend.record != nil else { fatalError("recovery lost on authorization denial") }
        backend.failAfter = nil; backend.ignoreCommands = true
        expectFailure { try transaction.restore() }
        guard backend.record != nil else { fatalError("unverified restore deleted recovery") }
    }
    do {
        let backend = FakeProxyBackend(); let transaction = ProxyTransaction(backend: backend)
        try transaction.enable(service: "Wi-Fi", port: 17890)
        backend.states["securewebproxy"]!.host = "new.proxy"
        let before = backend.calls
        expectFailure { try transaction.restore() }
        guard backend.calls == before, backend.record != nil, backend.states["securewebproxy"]!.host == "new.proxy" else { fatalError("overwrote later proxy change") }
    }
    do {
        let backend = FakeProxyBackend(); backend.states["socksfirewallproxy"]!.authenticated = true
        expectFailure { try ProxyTransaction(backend: backend).enable(service: "Wi-Fi", port: 17890) }
        guard backend.calls == 0, backend.record == nil else { fatalError("authenticated proxy overwritten") }
    }
    do {
        let backend = FakeProxyBackend(); backend.available = false
        expectFailure { try ProxyTransaction(backend: backend).enable(service: "Wi-Fi", port: 17890) }
        guard backend.calls == 0, backend.record == nil else { fatalError("missing service mutated") }
        backend.record = Data(repeating: 0x20, count: 8192)
        expectFailure { try ProxyTransaction(backend: backend).restore() }
        guard backend.calls == 0, backend.record != nil else { fatalError("oversized recovery accepted") }
    }
    do {
        let backend = FakeProxyBackend(); backend.automaticProxy = true
        expectFailure { try ProxyTransaction(backend: backend).enable(service: "Wi-Fi", port: 17890) }
        guard backend.calls == 0, backend.record == nil else { fatalError("automatic proxy overwritten") }
    }
    print("Proxy transaction: enable/read-back/restore, authorization cancellation, partial failure recovery, denied/ineffective restoration, later user changes, authenticated proxy and invalid recovery passed with fake backend. No system network changes.")
}
