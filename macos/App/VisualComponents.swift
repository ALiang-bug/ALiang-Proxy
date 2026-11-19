import SwiftUI
import AppKit

enum BrandAssets {
    // Load the bundled PNG explicitly; named SwiftUI images may resolve through
    // an asset catalog instead of standalone resource files on macOS.
    static let logo: NSImage = {
        if let url = Bundle.main.url(forResource: "BrandIcon", withExtension: "png"),
           let image = NSImage(contentsOf: url), image.isValid {
            return image
        }
        return NSImage(systemSymbolName: "network", accessibilityDescription: "ALiang Proxy") ?? NSImage(size: NSSize(width: 72, height: 72))
    }()
}

struct ActionButtonStyle: ButtonStyle {
    var prominent = false
    var tint: Color = .blue
    @Environment(\.isEnabled) private var enabled
    @State private var hovered = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 13, weight: .semibold))
            .padding(.horizontal, 16).padding(.vertical, 11)
            .foregroundStyle(prominent ? Color.white : Color.primary)
            .background {
                RoundedRectangle(cornerRadius: 11)
                    .fill(prominent ? tint.gradient : Color(nsColor: .controlBackgroundColor).gradient)
            }
            .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(prominent ? tint.opacity(0.5) : Color.primary.opacity(hovered ? 0.24 : 0.10), lineWidth: 1) }
            .shadow(color: prominent ? tint.opacity(enabled ? 0.2 : 0) : .black.opacity(hovered ? 0.07 : 0.02), radius: hovered ? 8 : 3, y: hovered ? 4 : 2)
            .scaleEffect(configuration.isPressed && enabled ? 0.97 : 1)
            .opacity(enabled ? 1 : 0.40)
            .animation(.easeOut(duration: 0.13), value: configuration.isPressed)
            .animation(.easeOut(duration: 0.15), value: hovered)
            .onHover { hovered = $0 }
    }
}
struct DashboardCard<Content: View>: View {
    let step: String
    let title: String
    let subtitle: String
    let icon: String
    var tint: Color = .blue
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 12) {
                Image(systemName: icon).font(.system(size: 20, weight: .semibold)).foregroundStyle(tint)
                    .frame(width: 44, height: 44).background(tint.opacity(0.09), in: RoundedRectangle(cornerRadius: 13))
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.system(size: 18, weight: .bold))
                    Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                Text(step).font(.system(size: 14, weight: .bold, design: .monospaced)).foregroundStyle(.tertiary)
            }
            content
        }
        .padding(24).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.8), in: RoundedRectangle(cornerRadius: 22))
        .overlay { RoundedRectangle(cornerRadius: 22).strokeBorder(Color.primary.opacity(0.07)) }
        .shadow(color: .black.opacity(0.025), radius: 14, y: 5)
    }
}
struct StatusBadge: View {
    let text: String
    var color: Color = .secondary
    var body: some View {
        HStack(spacing: 6) { Circle().fill(color).frame(width: 6, height: 6); Text(text).font(.system(size: 11, weight: .medium)) }
            .padding(.horizontal, 10).padding(.vertical, 6).background(color.opacity(0.09), in: Capsule())
    }
}
struct MetricBar: View {
    let title: String
    let value: String
    let fraction: Double?
    var tint: Color = .blue
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack { Text(title).foregroundStyle(.secondary).lineLimit(1); Spacer(minLength: 4); Text(value).fontWeight(.semibold).monospacedDigit() }.font(.system(size: 11))
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.primary.opacity(0.055))
                    if let fraction { Capsule().fill(tint.gradient).frame(width: geometry.size.width * min(1, max(0, fraction))) }
                }
            }.frame(height: 5)
        }.frame(width: 130).accessibilityElement(children: .combine)
    }
}
