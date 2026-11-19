import Foundation

enum SubscriptionPolicy {
    static let maxBytes = 1_048_576
    static func validatedURL(_ text: String) -> URL? {
        guard let url = URL(string: text), url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
              url.fragment == nil, (1...65535).contains(url.port ?? 443) else { return nil }
        return url
    }
    static func allowsRedirect(from original: URL?, to destination: URL?) -> Bool {
        guard let original, let destination, validatedURL(destination.absoluteString) != nil else { return false }
        return original.host?.lowercased() == destination.host?.lowercased() && (original.port ?? 443) == (destination.port ?? 443)
    }
}
