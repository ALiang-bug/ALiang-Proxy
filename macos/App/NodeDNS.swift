import Foundation

enum NodeDNS: String, CaseIterable, Identifiable {
    case system, alidns, cloudflare
    var id: String { rawValue }
    var title: String {
        switch self { case .system: return "系统 DNS"; case .alidns: return "阿里 DNS over HTTPS"; case .cloudflare: return "Cloudflare DNS over HTTPS" }
    }
    func apply(to config: inout [String: Any]) {
        guard self != .system else { return }
        let endpoint = self == .alidns ? ("223.5.5.5", "dns.alidns.com") : ("1.1.1.1", "cloudflare-dns.com")
        config["dns"] = ["servers": [["type": "https", "tag": "node-bootstrap", "server": endpoint.0, "server_port": 443, "path": "/dns-query", "tls": ["enabled": true, "server_name": endpoint.1]]], "final": "node-bootstrap", "strategy": "ipv4_only"]
        var route = config["route"] as? [String: Any] ?? [:]
        route["default_domain_resolver"] = "node-bootstrap"
        config["route"] = route
    }
}
