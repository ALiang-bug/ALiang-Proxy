import Foundation

enum ClientError: Error { case message(String) }
@main struct ProxySafetyTests {
    static func main() throws {
        for mode in NodeDNS.allCases {
            var config: [String: Any] = ["route": ["final": "selected"]]
            mode.apply(to: &config)
            let route = config["route"] as! [String: Any]
            guard route["final"] as? String == "selected" else { fatalError("DNS changed selected exit") }
            if mode == .system { guard config["dns"] == nil else { fatalError("system mode changed DNS") } }
            else { guard route["default_domain_resolver"] as? String == "node-bootstrap", config["dns"] != nil else { fatalError("missing scoped bootstrap") } }
        }
        for route in ["default fe80::1 UGScg utun4", "0/1 198.18.0.1 UGSc utun8", "128.0/1 198.18.0.1 UGSc utun8", "::/1 fe80::1 UGSc utun8"] {
            guard TUNSession.conflictingRoutes(route) else { fatalError("conflicting tunnel missed") }
        }
        guard !TUNSession.conflictingRoutes("default 192.168.1.1 UGScg en0\nfe80::%utun0 link#10 UCI utun0") else { fatalError("inactive utun mistaken for active default tunnel") }
        guard !TUNSession.conflictingRoutes("default fe80::%utun0 UGcIg utun0\ndefault fe80::%utun2 UGcIg utun2") else { fatalError("scoped IPv6 defaults misidentified") }
        guard TUNSession.conflictingInterfaces("default fe80::%utun0 UGcIg utun0\n128.0/1 198.18.0.0 UGSc utun4") == ["utun4"] else { fatalError("real split default hidden by scoped routes") }
        try runLimitedFileTests()
        try runTransactionTests()
        let origin = URL(string: "https://example.com/sub?token=synthetic")!
        guard SubscriptionPolicy.validatedURL(origin.absoluteString) != nil,
              SubscriptionPolicy.allowsRedirect(from: origin, to: URL(string: "https://example.com/new")),
              !SubscriptionPolicy.allowsRedirect(from: origin, to: URL(string: "http://example.com/new")),
              !SubscriptionPolicy.allowsRedirect(from: origin, to: URL(string: "https://other.example/new")),
              !SubscriptionPolicy.allowsRedirect(from: origin, to: URL(string: "https://example.com:8443/new")) else { fatalError("redirect policy failed") }
        for invalid in ["http://example.com", "file:///etc/passwd", "https://user:secret@example.com", "https://example.com#fragment", "https://example.com:0"] {
            guard SubscriptionPolicy.validatedURL(invalid) == nil else { fatalError("unsafe subscription URL accepted") }
        }
        let entries = ["webproxy", "securewebproxy", "socksfirewallproxy"].map { ProxySnapshot.Entry(kind: $0, server: "", port: 0) }
        try SystemProxy.validate(.init(service: "Wi-Fi", entries: entries))
        var rejected = 0
        for invalid in [
            ProxySnapshot(service: "-setdnsservers", entries: entries),
            ProxySnapshot(service: "Wi-Fi\nEthernet", entries: entries),
            ProxySnapshot(service: "Wi-Fi", entries: [.init(kind: "dnsservers", server: "", port: 0)]),
            ProxySnapshot(service: "Wi-Fi", entries: Array(repeating: entries[0], count: 3)),
            ProxySnapshot(service: "Wi-Fi", entries: [.init(kind: "webproxy", server: "localhost", port: -1), entries[1], entries[2]])
        ] {
            do { try SystemProxy.validate(invalid) } catch { rejected += 1 }
        }
        guard rejected == 5 else { fatalError("malformed recovery record accepted") }
        guard SystemProxy.shellQuote("a'b;$(touch /tmp/not-executed)") == "'a'\\''b;$(touch /tmp/not-executed)'" else { fatalError("shell quoting failed") }
        let payload = "a'b;$(exit 9);\nnot-a-command"
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf %s " + SystemProxy.shellQuote(payload)]
        process.standardOutput = pipe
        try process.run()
        let roundtrip = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0, String(decoding: roundtrip, as: UTF8.self) == payload else { fatalError("shell metacharacters executed") }
        var blocked = false
        do { try SystemProxy.privileged([["-setdnsservers", "Wi-Fi", "1.1.1.1"]]) } catch { blocked = true }
        guard blocked else { fatalError("non-proxy privileged operation accepted") }
        print("Proxy safety: valid recovery accepted; 5 malformed records and non-proxy privileged operation rejected; shell quoting, restoration ownership and HTTPS URL/redirect policy passed. No network settings changed.")
    }
}
