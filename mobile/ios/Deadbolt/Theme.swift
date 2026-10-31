// Deadbolt's look on iOS: the Rune desktop app and the Chrome extension.
//
// Every colour, radius, weight and motion value is copied from
// extension/static/theme.css, which copies Rune's rune-theme-opencode by hand.
// Checked against the Rune pin in crates/app/Cargo.toml
// (rev 1b787190b0965faa8fbd6a49fdadb1970374a765): themes/opencode/assets/theme.json
// `v2-*` tokens, and themes/opencode/src/lib.rs `Type`, `Radius`, `Motion`.
// The extension's three contrast fixes are kept (focus #5b7ef9 and
// text-faint #666666 in light, text-faint #a3a3a3 in dark). On a Rune bump,
// re-read those files and update this one.
//
// Fonts are Rune's own files (InterVariable.ttf at the 14pt optical size,
// IBM Plex Mono Regular/Medium), copied from the pinned rune-theme-opencode by
// scripts/build-core.sh into Generated/Fonts.
//
// iOS changes on purpose, nothing else:
// - type is Rune's sizes times `scale` (13pt `ui` becomes 15pt), then
//   follows Dynamic Type;
// - controls are at least 44pt tall (Rune's are 28 to 32) for touch;
// - icons are SF Symbols until the extension's glyph set is ported.

import CoreText
import SwiftUI
import UIKit

enum Rune {
    /// Rune's sizes are for a desktop at arm's length; 15/13 brings `ui` to
    /// iOS's reading size before Dynamic Type.
    static let scale: CGFloat = 15.0 / 13.0

    // MARK: Colour (theme.css :root, then its prefers-color-scheme: dark block)

    static let bgDeep = dynamic(0xFAFAFA, 0x080808)
    static let bg = dynamic(0xFFFFFF, 0x161616)
    static let layer01 = dynamic(0xFAFAFA, 0x242424)
    static let layer02 = dynamic(0xF2F2F2, 0x2E2E2E)
    static let layer03 = dynamic(0xEEEEEE, 0x3A3A3A)
    static let layer04 = dynamic(0xDBDBDB, 0x5C5C5C)
    static let border = dynamic(0x000000, 0xFFFFFF, alpha: 0x1A)
    static let borderMuted = dynamic(0x000000, 0xFFFFFF, alpha: 0x14)
    static let borderStrong = dynamic(0x000000, 0xFFFFFF, alpha: 0x33)
    static let focus = dynamic(0x5B7EF9, 0x7698FD)
    static let hover = dynamic(0x000000, 0xFFFFFF, lightAlpha: 0x0A, darkAlpha: 0x0F)
    static let pressed = dynamic(0x000000, 0xFFFFFF, lightAlpha: 0x14, darkAlpha: 0x1A)
    static let text = dynamic(0x161616, 0xFAFAFA)
    static let muted = dynamic(0x5C5C5C, 0xAEAEAE)
    static let faint = dynamic(0x808080, 0x808080)
    static let textFaint = dynamic(0x666666, 0xA3A3A3)
    static let icon = dynamic(0x3A3A3A, 0xDBDBDB)
    static let iconMuted = dynamic(0x808080, 0x808080)
    static let iconFaint = dynamic(0xAEAEAE, 0x5C5C5C)
    static let accent = dynamic(0x3B5CF6, 0x3B5CF6)
    static let textAccent = dynamic(0x3B5CF6, 0xA2BCFF)
    static let contrast = dynamic(0x242424, 0x5C5C5C)
    static let onContrast = dynamic(0xFFFFFF, 0xFFFFFF)
    static let contrastPressed = dynamic(0xFFFFFF, 0x000000, lightAlpha: 0x3D, darkAlpha: 0x66)
    static let button = dynamic(0xFFFFFF, 0xFFFFFF, lightAlpha: 0xFF, darkAlpha: 0x0F)
    static let knob = dynamic(0xF2F2F2, 0xF2F2F2)
    static let danger = dynamic(0xB82D35, 0xF17471)
    static let dangerBg = dynamic(0xFCECEB, 0x461516)
    static let success = dynamic(0x198B43, 0x6BD586)
    static let textSuccess = dynamic(0x167A3B, 0x6BD586)
    static let warning = dynamic(0xCB9F34, 0xF2CF76)
    static let brand = dynamic(0xF02E29, 0xF02E29)
    /// The app's search fill: layer_02, layer_01 in the dark (vault.css).
    static let searchFill = dynamic(0xF2F2F2, 0x242424)
    /// The neutral button and input's 0.5px ring (`--elevation-button`).
    static let buttonRing = dynamic(0x000000, 0xFFFFFF, lightAlpha: 0x24, darkAlpha: 0x33)
    static let buttonShadow = dynamic(0x000000, 0x000000, lightAlpha: 0x1A, darkAlpha: 0x66)

    // MARK: Radius (xs 2, sm 4, md 6, lg 8, xl 10)

    static let radiusSm: CGFloat = 4
    static let radiusMd: CGFloat = 6
    static let radiusLg: CGFloat = 8
    static let radiusXl: CGFloat = 10

    // MARK: Motion: critically damped springs (control 200, overlay 240, disclosure 300 ms)

    static let control = Animation.spring(duration: 0.2, bounce: 0)
    static let overlay = Animation.spring(duration: 0.24, bounce: 0)
    static let disclosure = Animation.spring(duration: 0.3, bounce: 0)

    // MARK: Type (Rune's `Type`: size, variable weight, line, tracking)

    struct TextStyle: Sendable {
        var size: CGFloat
        var weight: CGFloat
        var line: CGFloat
        var tracking: CGFloat
        var mono = false
        var relativeTo: UIFont.TextStyle = .body
    }

    // MARK: Helpers

    private static func dynamic(_ light: UInt32, _ dark: UInt32, alpha: UInt32 = 0xFF) -> Color {
        dynamic(light, dark, lightAlpha: alpha, darkAlpha: alpha)
    }

    private static func dynamic(_ light: UInt32, _ dark: UInt32, lightAlpha: UInt32, darkAlpha: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark ? rgb(dark, darkAlpha) : rgb(light, lightAlpha)
        })
    }

    private static func rgb(_ hex: UInt32, _ alpha: UInt32) -> UIColor {
        UIColor(
            red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: CGFloat(alpha) / 255
        )
    }
}

extension Rune.TextStyle {
    static let ui = Rune.TextStyle(size: 13, weight: 440, line: 20, tracking: -0.04)
    static let uiMedium = Rune.TextStyle(size: 13, weight: 530, line: 20, tracking: -0.04)
    static let small = Rune.TextStyle(size: 11, weight: 440, line: 12, tracking: 0.05, relativeTo: .caption1)
    static let smallMedium = Rune.TextStyle(size: 11, weight: 530, line: 12, tracking: 0.05, relativeTo: .caption1)
    /// The row detail's 11.5/440 `FACT` (vault.css `.vrow .sub`).
    static let fact = Rune.TextStyle(size: 11.5, weight: 440, line: 14, tracking: 0, relativeTo: .caption1)
    static let textXSmall = Rune.TextStyle(size: 12, weight: 400, line: 18, tracking: 0, relativeTo: .footnote)
    static let hero = Rune.TextStyle(size: 17, weight: 530, line: 22, tracking: 0, relativeTo: .title3)
    static let detailTitle = Rune.TextStyle(size: 20, weight: 600, line: 26, tracking: 0, relativeTo: .title2)
    static let mono = Rune.TextStyle(size: 12, weight: 400, line: 18, tracking: 0, mono: true)
    static let code = Rune.TextStyle(size: 17, weight: 500, line: 23, tracking: 0, mono: true, relativeTo: .title3)
}

// MARK: Fonts

enum RuneFonts {
    private nonisolated(unsafe) static var inter: CTFontDescriptor?
    private nonisolated(unsafe) static var registered = false

    /// Registers the bundled fonts once, at launch.
    static func register() {
        guard !registered else { return }
        registered = true
        for name in ["InterVariable", "IBMPlexMono-Regular", "IBMPlexMono-Medium"] {
            guard let url = Bundle.main.url(forResource: name, withExtension: "ttf") else { continue }
            CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
            if name == "InterVariable",
               let descriptors = CTFontManagerCreateFontDescriptorsFromURL(url as CFURL) as? [CTFontDescriptor] {
                inter = descriptors.first
            }
        }
    }

    static func uiFont(_ style: Rune.TextStyle, size: CGFloat) -> UIFont {
        if style.mono {
            let name = style.weight >= 500 ? "IBMPlexMono-Medium" : "IBMPlexMono"
            return UIFont(name: name, size: size)
                ?? .monospacedSystemFont(ofSize: size, weight: style.weight >= 500 ? .medium : .regular)
        }
        guard let inter else {
            return .systemFont(ofSize: size, weight: style.weight >= 600 ? .semibold : style.weight >= 500 ? .medium : .regular)
        }
        // Rune pins Inter's weight axis to the style's value and its optical
        // size to 14 (the extension's subset does the same).
        let wght = 0x7767_6874 // 'wght'
        let opsz = 0x6F70_737A // 'opsz'
        let variation: [NSNumber: NSNumber] = [
            NSNumber(value: wght): NSNumber(value: Double(style.weight)),
            NSNumber(value: opsz): NSNumber(value: 14),
        ]
        let descriptor = CTFontDescriptorCreateCopyWithAttributes(
            inter,
            [kCTFontVariationAttribute: variation] as CFDictionary
        )
        return CTFontCreateWithFontDescriptor(descriptor, size, nil) as UIFont
    }
}

struct RuneText: ViewModifier {
    let style: Rune.TextStyle
    @Environment(\.dynamicTypeSize) private var typeSize

    func body(content: Content) -> some View {
        let traits = UITraitCollection(preferredContentSizeCategory: UIContentSizeCategory(typeSize))
        let metrics = UIFontMetrics(forTextStyle: style.relativeTo)
        let size = metrics.scaledValue(for: style.size * Rune.scale, compatibleWith: traits)
        let line = metrics.scaledValue(for: style.line * Rune.scale, compatibleWith: traits)
        let font = RuneFonts.uiFont(style, size: size)
        return content
            .font(Font(font as CTFont))
            .tracking(style.tracking * Rune.scale)
            .lineSpacing(max(0, line - font.lineHeight))
    }
}

extension View {
    func rune(_ style: Rune.TextStyle) -> some View {
        modifier(RuneText(style: style))
    }
}

// MARK: Controls

/// rune-kit's push button: Neutral by default, Contrast (with its sheen) as
/// primary, an 8px radius, `ui_medium`; press lays the theme's overlay over
/// the fill and settles at 0.98.
struct RuneButtonStyle: ButtonStyle {
    enum Kind { case neutral, primary }
    var kind: Kind = .neutral
    var wide = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .rune(.uiMedium)
            .foregroundStyle(kind == .primary ? Rune.onContrast : Rune.text)
            .padding(.horizontal, 14)
            .frame(minHeight: 44)
            .frame(maxWidth: wide ? .infinity : nil)
            .background {
                let shape = RoundedRectangle(cornerRadius: Rune.radiusLg, style: .continuous)
                ZStack {
                    shape.fill(kind == .primary ? Rune.contrast : Rune.button)
                    if kind == .primary {
                        shape.fill(LinearGradient(colors: [.white.opacity(0.2), .white.opacity(0)], startPoint: .top, endPoint: .bottom))
                    }
                    if configuration.isPressed {
                        shape.fill(kind == .primary ? Rune.contrastPressed : Rune.pressed)
                    }
                    shape.strokeBorder(kind == .primary ? Color.white.opacity(0.14) : Rune.buttonRing, lineWidth: 0.5)
                }
                .shadow(color: Rune.buttonShadow, radius: 0.75, y: 1)
            }
            .opacity(isEnabled ? 1 : (kind == .primary ? 0.4 : 0.5))
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(Rune.control, value: configuration.isPressed)
            .contentShape(Rectangle())
    }
}

/// rune-kit's ghost IconButton: a muted glyph with the press overlay behind it.
struct RuneIconButtonStyle: ButtonStyle {
    var tint: Color = Rune.iconMuted

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 17, weight: .regular))
            .foregroundStyle(configuration.isPressed ? Rune.icon : tint)
            .frame(width: 44, height: 44)
            .background(
                RoundedRectangle(cornerRadius: Rune.radiusLg, style: .continuous)
                    .fill(configuration.isPressed ? Rune.pressed : .clear)
                    .padding(6)
            )
            .contentShape(Rectangle())
            .animation(Rune.control, value: configuration.isPressed)
    }
}

/// rune-kit's TextInput: bg_base with a faint sheen and the neutral button's
/// ring, a 6px radius; focus is a 1px ring in border_focus.
struct RuneInput: ViewModifier {
    var focused: Bool
    var invalid = false

    func body(content: Content) -> some View {
        content
            .rune(.ui)
            .foregroundStyle(Rune.text)
            .tint(Rune.focus)
            .padding(.horizontal, 12)
            .frame(minHeight: 44)
            .background {
                let shape = RoundedRectangle(cornerRadius: Rune.radiusMd, style: .continuous)
                ZStack {
                    shape.fill(Rune.bg)
                    shape.fill(LinearGradient(colors: [.white.opacity(0.06), .white.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                    if focused || invalid {
                        shape.strokeBorder(invalid ? Rune.danger : Rune.focus, lineWidth: 1)
                    } else {
                        shape.strokeBorder(Rune.buttonRing, lineWidth: 0.5)
                    }
                }
                .shadow(color: focused || invalid ? .clear : Rune.buttonShadow, radius: 0.75, y: 1)
            }
            .animation(Rune.control, value: focused)
    }
}

extension View {
    func runeInput(focused: Bool, invalid: Bool = false) -> some View {
        modifier(RuneInput(focused: focused, invalid: invalid))
    }

    /// A section's name: `small_medium`, muted.
    func runeLabel() -> some View {
        rune(.smallMedium).foregroundStyle(Rune.muted).textCase(nil)
    }

    /// vault.css `.box` / `.code-box`: layer_01 with a 1px border_muted inset.
    func runeBox() -> some View {
        background(
            RoundedRectangle(cornerRadius: Rune.radiusXl, style: .continuous)
                .fill(Rune.layer01)
                .overlay(
                    RoundedRectangle(cornerRadius: Rune.radiusXl, style: .continuous)
                        .strokeBorder(Rune.borderMuted, lineWidth: 1)
                )
        )
    }
}

/// rune-kit's Switch: a capsule in layer_04 off and the accent on, each with
/// its sheen, and a pill knob; sized up for touch.
struct RuneToggleStyle: ToggleStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(spacing: 12) {
                configuration.label
                Spacer(minLength: 8)
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(configuration.isOn ? Rune.accent : Rune.layer04)
                        .overlay(Capsule().fill(LinearGradient(colors: [.white.opacity(0), .white.opacity(configuration.isOn ? 0.1 : 0.2)], startPoint: .top, endPoint: .bottom)))
                        .overlay(Capsule().strokeBorder(Color.black.opacity(0.1), lineWidth: 0.5))
                    Capsule()
                        .fill(Rune.knob)
                        .overlay(Capsule().fill(LinearGradient(colors: [.white, .white.opacity(0)], startPoint: .top, endPoint: .bottom)))
                        .shadow(color: .black.opacity(0.4), radius: 0.25, y: 0.5)
                        .frame(width: 30, height: 20)
                        .padding(2)
                }
                .frame(width: 50, height: 24)
                .animation(Rune.control, value: configuration.isOn)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(isEnabled ? 1 : 0.5)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

/// The app's glyph tile: layer_02 with the item's letter in one tone.
struct LetterTile: View {
    let title: String
    var size: CGFloat = 32
    var radius: CGFloat = Rune.radiusLg

    var body: some View {
        Text(title.first.map { String($0).uppercased() } ?? "•")
            .rune(size > 40 ? .hero : .uiMedium)
            .foregroundStyle(Rune.icon)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(Rune.layer02))
            .accessibilityHidden(true)
    }
}

/// Deadbolt's mark: the red keyhole on its dark tile (crates/app/scripts/icon.swift).
struct KeyholeMark: View {
    var size: CGFloat

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .fill(Color(white: 0.1))
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .strokeBorder(Color.white.opacity(0.1), lineWidth: 1)
            Canvas { context, canvas in
                let s = canvas.width / 1024
                context.fill(Path(ellipseIn: CGRect(x: 352 * s, y: 222 * s, width: 320 * s, height: 320 * s)), with: .color(Rune.brand))
                var stem = Path()
                stem.move(to: CGPoint(x: 451 * s, y: 490 * s))
                stem.addLine(to: CGPoint(x: 573 * s, y: 490 * s))
                stem.addLine(to: CGPoint(x: 632 * s, y: 780 * s))
                stem.addLine(to: CGPoint(x: 392 * s, y: 780 * s))
                stem.closeSubpath()
                context.fill(stem, with: .color(Rune.brand))
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
