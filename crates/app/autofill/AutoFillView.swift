// Native UI for the Deadbolt credential provider: connecting, onboarding
// redirect, biometric + passphrase unlock, and searchable credential picker.
// macOS: AppKit, with offscreen `NSBitmapImageRep` rendering for headless
// verification. iOS: SwiftUI drawn with the app's Rune theme
// (mobile/ios/Deadbolt/Theme.swift: Inter, IBM Plex Mono, Rune colours).

#if os(macOS)
import AppKit
import Foundation

@MainActor
private enum Palette {
    static let keyholeRed = NSColor(srgbRed: 0.94, green: 0.18, blue: 0.16, alpha: 1.0)
    static let markFill = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(calibratedWhite: 0.08, alpha: 1.0)
            : NSColor(calibratedWhite: 0.11, alpha: 1.0)
    }
    static let sheetBackground = NSColor.windowBackgroundColor
    static let cardFill = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(calibratedWhite: 1.0, alpha: 0.045)
            : NSColor(calibratedWhite: 0.0, alpha: 0.035)
    }
    static let selectedRowFill = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0.94, green: 0.18, blue: 0.16, alpha: 0.22)
            : NSColor(srgbRed: 0.88, green: 0.16, blue: 0.14, alpha: 0.14)
    }
    static let selectedRowBorder = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0.94, green: 0.18, blue: 0.16, alpha: 0.55)
            : NSColor(srgbRed: 0.86, green: 0.16, blue: 0.14, alpha: 0.45)
    }
    static let divider = NSColor.separatorColor
    static let warningFill = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0.95, green: 0.68, blue: 0.18, alpha: 0.12)
            : NSColor(srgbRed: 0.85, green: 0.55, blue: 0.06, alpha: 0.10)
    }
    static let warningText = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0.96, green: 0.76, blue: 0.34, alpha: 1.0)
            : NSColor(srgbRed: 0.62, green: 0.38, blue: 0.02, alpha: 1.0)
    }
    static let errorText = NSColor.systemRed
}

/// Draws Deadbolt's signature red keyhole badge (`crates/app/scripts/icon.swift`).
private final class KeyholeBadgeView: NSView {
    override var intrinsicContentSize: NSSize {
        NSSize(width: 28, height: 28)
    }

    override func draw(_ dirtyRect: NSRect) {
        let rect = bounds.insetBy(dx: 0.5, dy: 0.5)
        let bg = NSBezierPath(roundedRect: rect, xRadius: 7, yRadius: 7)
        Palette.markFill.setFill()
        bg.fill()
        NSColor(calibratedWhite: 1.0, alpha: 0.10).setStroke()
        bg.lineWidth = 1
        bg.stroke()

        Palette.keyholeRed.setFill()
        let scaleX = rect.width / 1024.0
        let scaleY = rect.height / 1024.0
        let circle = NSRect(
            x: rect.minX + 352.0 * scaleX,
            y: rect.minY + 482.0 * scaleY,
            width: 320.0 * scaleX,
            height: 320.0 * scaleY
        )
        NSBezierPath(ovalIn: circle).fill()

        let stem = NSBezierPath()
        stem.move(to: NSPoint(x: rect.minX + 451.0 * scaleX, y: rect.minY + 534.0 * scaleY))
        stem.line(to: NSPoint(x: rect.minX + 573.0 * scaleX, y: rect.minY + 534.0 * scaleY))
        stem.line(to: NSPoint(x: rect.minX + 632.0 * scaleX, y: rect.minY + 244.0 * scaleY))
        stem.line(to: NSPoint(x: rect.minX + 392.0 * scaleX, y: rect.minY + 244.0 * scaleY))
        stem.close()
        stem.fill()
    }
}

private final class LoginRowView: NSView {
    var onSingleClick: (() -> Void)?
    var onDoubleClick: (() -> Void)?

    private let isSelectedRow: Bool

    init(login: SiteLogin, showVault: Bool, isSelected: Bool) {
        self.isSelectedRow = isSelected
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false

        let titleField = NSTextField(labelWithString: login.title)
        titleField.font = .systemFont(ofSize: 13, weight: .medium)
        titleField.textColor = .labelColor
        titleField.lineBreakMode = .byTruncatingTail

        let subtitleField = NSTextField(labelWithString: login.subtitle)
        subtitleField.font = .systemFont(ofSize: 11.5, weight: .regular)
        subtitleField.textColor = .secondaryLabelColor
        subtitleField.lineBreakMode = .byTruncatingMiddle

        let textStack = NSStackView(views: [titleField, subtitleField])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 2
        textStack.translatesAutoresizingMaskIntoConstraints = false

        let spacer = NSView()
        spacer.setContentHuggingPriority(.init(1), for: .horizontal)
        spacer.setContentCompressionResistancePriority(.init(1), for: .horizontal)

        let rowStack = NSStackView(views: [textStack, spacer])
        rowStack.orientation = .horizontal
        rowStack.alignment = .centerY
        rowStack.spacing = 8
        rowStack.translatesAutoresizingMaskIntoConstraints = false

        if showVault {
            let badge = NSTextField(labelWithString: login.vault)
            badge.font = .systemFont(ofSize: 10.5, weight: .medium)
            badge.textColor = .secondaryLabelColor
            badge.setContentCompressionResistancePriority(.required, for: .horizontal)
            badge.setContentHuggingPriority(.required, for: .horizontal)
            rowStack.addArrangedSubview(badge)
        }

        if isSelected {
            let returnHint = NSTextField(labelWithString: "⏎")
            returnHint.font = .monospacedSystemFont(ofSize: 11, weight: .medium)
            returnHint.textColor = .secondaryLabelColor
            returnHint.setContentHuggingPriority(.required, for: .horizontal)
            rowStack.addArrangedSubview(returnHint)
        }

        addSubview(rowStack)
        NSLayoutConstraint.activate([
            heightAnchor.constraint(equalToConstant: 48),
            rowStack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            rowStack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            rowStack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func draw(_ dirtyRect: NSRect) {
        let inset = bounds.insetBy(dx: 1, dy: 1)
        let path = NSBezierPath(roundedRect: inset, xRadius: 8, yRadius: 8)
        if isSelectedRow {
            Palette.selectedRowFill.setFill()
            path.fill()
            Palette.selectedRowBorder.setStroke()
            path.lineWidth = 1
            path.stroke()
        } else {
            Palette.cardFill.setFill()
            path.fill()
        }
    }

    override func mouseDown(with event: NSEvent) {
        if event.clickCount >= 2 {
            onDoubleClick?()
        } else {
            onSingleClick?()
        }
    }
}

private final class FlippedDocumentView: NSView {
    override var isFlipped: Bool { true }
}

@MainActor
public final class AutoFillRootView: NSView, NSSearchFieldDelegate, NSTextFieldDelegate {
    private let model: AutoFillControllerModel

    private let contextField = NSTextField(labelWithString: "")
    private let bodyContainer = NSView()
    private let passphraseField = NSSecureTextField()
    private let searchField = NSSearchField()
    private let listScrollView = NSScrollView()
    private let listStack = NSStackView()

    private var lastRenderedScreenTag: String = ""

    public init(model: AutoFillControllerModel) {
        self.model = model
        super.init(frame: NSRect(x: 0, y: 0, width: 420, height: 340))
        wantsLayer = true
        passphraseField.delegate = self
        searchField.delegate = self
        configureShell()
        render(focusIfChanged: false)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    public var preferredSheetSize: NSSize {
        switch model.screen {
        case .picker:
            return NSSize(width: 420, height: 360)
        default:
            return NSSize(width: 420, height: 268)
        }
    }

    override public func draw(_ dirtyRect: NSRect) {
        Palette.sheetBackground.setFill()
        dirtyRect.fill()
    }

    override public func cancelOperation(_ sender: Any?) {
        model.cancelByUser()
    }

    public func clearSecrets() {
        passphraseField.stringValue = ""
    }

    private func configureShell() {
        let badge = KeyholeBadgeView()
        badge.translatesAutoresizingMaskIntoConstraints = false

        let brandField = NSTextField(labelWithString: "Deadbolt")
        brandField.font = .systemFont(ofSize: 13.5, weight: .semibold)
        brandField.textColor = .labelColor

        contextField.font = .systemFont(ofSize: 12, weight: .regular)
        contextField.textColor = .secondaryLabelColor
        contextField.lineBreakMode = .byTruncatingMiddle
        contextField.alignment = .right

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let header = NSStackView(views: [badge, brandField, spacer, contextField])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 9
        header.translatesAutoresizingMaskIntoConstraints = false

        let divider = NSBox()
        divider.boxType = .separator
        divider.translatesAutoresizingMaskIntoConstraints = false

        bodyContainer.translatesAutoresizingMaskIntoConstraints = false

        addSubview(header)
        addSubview(divider)
        addSubview(bodyContainer)

        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: topAnchor, constant: 14),
            header.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 18),
            header.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -18),
            header.heightAnchor.constraint(equalToConstant: 28),

            divider.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 12),
            divider.leadingAnchor.constraint(equalTo: leadingAnchor),
            divider.trailingAnchor.constraint(equalTo: trailingAnchor),

            bodyContainer.topAnchor.constraint(equalTo: divider.bottomAnchor),
            bodyContainer.leadingAnchor.constraint(equalTo: leadingAnchor),
            bodyContainer.trailingAnchor.constraint(equalTo: trailingAnchor),
            bodyContainer.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }

    public func render(focusIfChanged: Bool = true) {
        contextField.stringValue = model.contextLabel
        let tag = screenTag(model.screen)
        let screenChanged = tag != lastRenderedScreenTag
        lastRenderedScreenTag = tag

        for subview in bodyContainer.subviews {
            subview.removeFromSuperview()
        }

        switch model.screen {
        case let .connecting(message):
            buildStatusScreen(title: message, detail: nil, primaryTitle: nil, primaryAction: nil)
        case .syncingConfiguration:
            buildStatusScreen(
                title: "Updating AutoFill suggestions…",
                detail: nil,
                primaryTitle: nil,
                primaryAction: nil
            )
        case .notInitialized:
            buildStatusScreen(
                title: "Deadbolt isn't set up yet",
                detail: "Open Deadbolt to create a vault or join an existing device.",
                primaryTitle: "Open Deadbolt",
                primaryAction: #selector(handleOpenDeadbolt)
            )
        case let .failed(message):
            buildStatusScreen(
                title: "Can't reach Deadbolt",
                detail: message,
                primaryTitle: "Try Again",
                primaryAction: #selector(handleRetry)
            )
        case let .locked(touchIdReady, touchIdReset, unlocking, touchIdInFlight, error):
            buildLockedScreen(
                touchIdReady: touchIdReady,
                touchIdReset: touchIdReset,
                unlocking: unlocking,
                touchIdInFlight: touchIdInFlight,
                error: error,
                shouldFocus: focusIfChanged && screenChanged
            )
        case .picker:
            buildPickerScreen(shouldFocus: focusIfChanged && screenChanged)
        }
    }

    private func screenTag(_ screen: AutoFillControllerModel.Screen) -> String {
        switch screen {
        case .connecting:
            return "connecting"
        case .syncingConfiguration:
            return "syncing"
        case .notInitialized:
            return "notInitialized"
        case .failed:
            return "failed"
        case .locked:
            return "locked"
        case .picker:
            return "picker"
        }
    }

    private func buildStatusScreen(
        title: String,
        detail: String?,
        primaryTitle: String?,
        primaryAction: Selector?
    ) {
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        titleLabel.textColor = .labelColor
        titleLabel.alignment = .center

        let stack = NSStackView(views: [titleLabel])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false

        if let detail, !detail.isEmpty {
            let detailLabel = NSTextField(wrappingLabelWithString: detail)
            detailLabel.font = .systemFont(ofSize: 12, weight: .regular)
            detailLabel.textColor = .secondaryLabelColor
            detailLabel.alignment = .center
            detailLabel.maximumNumberOfLines = 3
            stack.addArrangedSubview(detailLabel)
            detailLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true
        }

        let footer = makeFooter(
            primaryTitle: primaryTitle,
            primaryEnabled: true,
            primaryAction: primaryAction
        )

        bodyContainer.addSubview(stack)
        bodyContainer.addSubview(footer)

        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: bodyContainer.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: bodyContainer.centerYAnchor, constant: -18),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: bodyContainer.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: bodyContainer.trailingAnchor, constant: -24),

            footer.leadingAnchor.constraint(equalTo: bodyContainer.leadingAnchor, constant: 18),
            footer.trailingAnchor.constraint(equalTo: bodyContainer.trailingAnchor, constant: -18),
            footer.bottomAnchor.constraint(equalTo: bodyContainer.bottomAnchor, constant: -14),
        ])
    }

    private func buildLockedScreen(
        touchIdReady: Bool,
        touchIdReset: Bool,
        unlocking: Bool,
        touchIdInFlight: Bool,
        error: String?,
        shouldFocus: Bool
    ) {
        let titleText: String = {
            if touchIdInFlight {
                return "Touch ID to unlock Deadbolt"
            }
            return "Deadbolt is locked"
        }()
        let titleLabel = NSTextField(labelWithString: titleText)
        titleLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        titleLabel.textColor = .labelColor

        let subtitleText: String = {
            if touchIdReset {
                return "Touch ID changed on this Mac. Enter your passphrase to unlock."
            }
            if touchIdInFlight {
                return "Touch the sensor, or enter your passphrase below."
            }
            return "Enter your passphrase to unlock and fill."
        }()
        let subtitleLabel = NSTextField(wrappingLabelWithString: subtitleText)
        subtitleLabel.font = .systemFont(ofSize: 12, weight: .regular)
        subtitleLabel.textColor = .secondaryLabelColor

        passphraseField.placeholderString = "Passphrase"
        passphraseField.font = .systemFont(ofSize: 13)
        passphraseField.isEnabled = !unlocking
        passphraseField.bezelStyle = .roundedBezel
        passphraseField.translatesAutoresizingMaskIntoConstraints = false

        let formStack = NSStackView(views: [titleLabel, subtitleLabel, passphraseField])
        formStack.orientation = .vertical
        formStack.alignment = .leading
        formStack.spacing = 10
        formStack.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            passphraseField.widthAnchor.constraint(equalTo: formStack.widthAnchor),
            passphraseField.heightAnchor.constraint(equalToConstant: 28),
        ])

        if let error, !error.isEmpty {
            let errorLabel = NSTextField(wrappingLabelWithString: error)
            errorLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
            errorLabel.textColor = Palette.errorText
            formStack.addArrangedSubview(errorLabel)
            errorLabel.widthAnchor.constraint(equalTo: formStack.widthAnchor).isActive = true
        }

        let footer = makeLockedFooter(
            touchIdReady: touchIdReady,
            unlocking: unlocking,
            touchIdInFlight: touchIdInFlight
        )

        bodyContainer.addSubview(formStack)
        bodyContainer.addSubview(footer)

        NSLayoutConstraint.activate([
            formStack.topAnchor.constraint(equalTo: bodyContainer.topAnchor, constant: 20),
            formStack.leadingAnchor.constraint(equalTo: bodyContainer.leadingAnchor, constant: 20),
            formStack.trailingAnchor.constraint(equalTo: bodyContainer.trailingAnchor, constant: -20),

            footer.leadingAnchor.constraint(equalTo: bodyContainer.leadingAnchor, constant: 18),
            footer.trailingAnchor.constraint(equalTo: bodyContainer.trailingAnchor, constant: -18),
            footer.bottomAnchor.constraint(equalTo: bodyContainer.bottomAnchor, constant: -14),
        ])

        if shouldFocus, !touchIdInFlight {
            window?.makeFirstResponder(passphraseField)
        }
    }

    private func buildPickerScreen(shouldFocus: Bool) {
        searchField.placeholderString = "Search logins"
        if searchField.stringValue != model.searchQuery {
            searchField.stringValue = model.searchQuery
        }
        searchField.font = .systemFont(ofSize: 13)
        searchField.sendsSearchStringImmediately = true
        searchField.translatesAutoresizingMaskIntoConstraints = false

        let topStack = NSStackView(views: [searchField])
        topStack.orientation = .vertical
        topStack.alignment = .leading
        topStack.spacing = 8
        topStack.translatesAutoresizingMaskIntoConstraints = false
        searchField.widthAnchor.constraint(equalTo: topStack.widthAnchor).isActive = true

        if model.unassociated {
            let banner = makeWarningBanner(
                "Unverified app. Pick a login only if you trust this window."
            )
            topStack.addArrangedSubview(banner)
            banner.widthAnchor.constraint(equalTo: topStack.widthAnchor).isActive = true
        }

        if let pickerError = model.pickerError, !pickerError.isEmpty {
            let errLabel = NSTextField(wrappingLabelWithString: pickerError)
            errLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
            errLabel.textColor = Palette.errorText
            topStack.addArrangedSubview(errLabel)
            errLabel.widthAnchor.constraint(equalTo: topStack.widthAnchor).isActive = true
        }

        let footer = makeFooter(
            primaryTitle: model.filling ? "Filling…" : "Fill Password",
            primaryEnabled: !model.filling && model.selectedLogin != nil,
            primaryAction: #selector(handleFillSelected)
        )

        bodyContainer.addSubview(topStack)
        bodyContainer.addSubview(footer)

        NSLayoutConstraint.activate([
            topStack.topAnchor.constraint(equalTo: bodyContainer.topAnchor, constant: 14),
            topStack.leadingAnchor.constraint(equalTo: bodyContainer.leadingAnchor, constant: 18),
            topStack.trailingAnchor.constraint(equalTo: bodyContainer.trailingAnchor, constant: -18),

            footer.leadingAnchor.constraint(equalTo: bodyContainer.leadingAnchor, constant: 18),
            footer.trailingAnchor.constraint(equalTo: bodyContainer.trailingAnchor, constant: -18),
            footer.bottomAnchor.constraint(equalTo: bodyContainer.bottomAnchor, constant: -14),
        ])

        if model.filteredLogins.isEmpty {
            let emptyText = model.allLogins.isEmpty
                ? "No saved logins match \(model.contextLabel)."
                : "No logins match \"\(model.searchQuery)\"."
            let emptyLabel = NSTextField(wrappingLabelWithString: emptyText)
            emptyLabel.font = .systemFont(ofSize: 12.5, weight: .regular)
            emptyLabel.textColor = .secondaryLabelColor
            emptyLabel.alignment = .center
            emptyLabel.translatesAutoresizingMaskIntoConstraints = false
            bodyContainer.addSubview(emptyLabel)
            NSLayoutConstraint.activate([
                emptyLabel.centerXAnchor.constraint(equalTo: bodyContainer.centerXAnchor),
                emptyLabel.centerYAnchor.constraint(equalTo: bodyContainer.centerYAnchor, constant: 6),
                emptyLabel.leadingAnchor.constraint(greaterThanOrEqualTo: bodyContainer.leadingAnchor, constant: 24),
                emptyLabel.trailingAnchor.constraint(lessThanOrEqualTo: bodyContainer.trailingAnchor, constant: -24),
            ])
        } else {
            configureLoginScrollList()
            bodyContainer.addSubview(listScrollView)
            NSLayoutConstraint.activate([
                listScrollView.topAnchor.constraint(equalTo: topStack.bottomAnchor, constant: 10),
                listScrollView.leadingAnchor.constraint(equalTo: bodyContainer.leadingAnchor, constant: 18),
                listScrollView.trailingAnchor.constraint(equalTo: bodyContainer.trailingAnchor, constant: -18),
                listScrollView.bottomAnchor.constraint(equalTo: footer.topAnchor, constant: -10),
            ])
        }

        if shouldFocus {
            window?.makeFirstResponder(searchField)
        }
    }

    private func configureLoginScrollList() {
        for view in listStack.arrangedSubviews {
            listStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        listStack.orientation = .vertical
        listStack.alignment = .leading
        listStack.spacing = 6
        listStack.translatesAutoresizingMaskIntoConstraints = false

        let showVault = model.hasMultipleVaults
        var selectedRowView: NSView?
        for (idx, login) in model.filteredLogins.enumerated() {
            let isSelected = idx == model.selectedIndex
            let row = LoginRowView(login: login, showVault: showVault, isSelected: isSelected)
            row.onSingleClick = { [weak self] in
                self?.model.selectRow(idx)
            }
            row.onDoubleClick = { [weak self] in
                self?.model.fillRow(idx)
            }
            listStack.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: listStack.widthAnchor).isActive = true
            if isSelected {
                selectedRowView = row
            }
        }

        let docView = FlippedDocumentView()
        docView.translatesAutoresizingMaskIntoConstraints = false
        docView.addSubview(listStack)

        listScrollView.drawsBackground = false
        listScrollView.hasVerticalScroller = true
        listScrollView.autohidesScrollers = true
        listScrollView.borderType = .noBorder
        listScrollView.translatesAutoresizingMaskIntoConstraints = false
        listScrollView.documentView = docView

        if let clipView = listScrollView.contentView as NSClipView? {
            NSLayoutConstraint.activate([
                docView.topAnchor.constraint(equalTo: clipView.topAnchor),
                docView.leadingAnchor.constraint(equalTo: clipView.leadingAnchor),
                docView.trailingAnchor.constraint(equalTo: clipView.trailingAnchor),

                listStack.topAnchor.constraint(equalTo: docView.topAnchor),
                listStack.leadingAnchor.constraint(equalTo: docView.leadingAnchor),
                listStack.trailingAnchor.constraint(equalTo: docView.trailingAnchor),
                listStack.bottomAnchor.constraint(equalTo: docView.bottomAnchor),
            ])
        }

        if let selectedRowView {
            layoutSubtreeIfNeeded()
            selectedRowView.scrollToVisible(selectedRowView.bounds)
        }
    }

    private func makeWarningBanner(_ message: String) -> NSView {
        let box = NSView()
        box.wantsLayer = true
        box.translatesAutoresizingMaskIntoConstraints = false
        let label = NSTextField(wrappingLabelWithString: message)
        label.font = .systemFont(ofSize: 11, weight: .medium)
        label.textColor = Palette.warningText
        label.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(label)
        NSLayoutConstraint.activate([
            label.topAnchor.constraint(equalTo: box.topAnchor, constant: 6),
            label.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -6),
            label.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 10),
            label.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -10),
        ])
        box.layer?.cornerRadius = 6
        box.layer?.backgroundColor = Palette.warningFill.cgColor
        return box
    }

    private func makeLockedFooter(
        touchIdReady: Bool,
        unlocking: Bool,
        touchIdInFlight: Bool
    ) -> NSView {
        let cancelBtn = NSButton(title: "Cancel", target: self, action: #selector(handleCancel))
        cancelBtn.bezelStyle = .rounded
        cancelBtn.keyEquivalent = "\u{1b}"

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        var views: [NSView] = [cancelBtn, spacer]

        if touchIdReady {
            let touchTitle = touchIdInFlight ? "Touch ID…" : "Use Touch ID"
            let touchBtn = NSButton(
                title: touchTitle,
                target: self,
                action: #selector(handleTouchID)
            )
            touchBtn.bezelStyle = .rounded
            touchBtn.isEnabled = !unlocking && !touchIdInFlight
            views.append(touchBtn)
        }

        let unlockTitle = unlocking ? "Unlocking…" : "Unlock"
        let unlockBtn = NSButton(
            title: unlockTitle,
            target: self,
            action: #selector(handleSubmitUnlock)
        )
        unlockBtn.bezelStyle = .rounded
        unlockBtn.keyEquivalent = "\r"
        unlockBtn.isEnabled = !unlocking
        views.append(unlockBtn)

        let row = NSStackView(views: views)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        row.translatesAutoresizingMaskIntoConstraints = false
        return row
    }

    private func makeFooter(
        primaryTitle: String?,
        primaryEnabled: Bool,
        primaryAction: Selector?
    ) -> NSView {
        let cancelBtn = NSButton(title: "Cancel", target: self, action: #selector(handleCancel))
        cancelBtn.bezelStyle = .rounded
        cancelBtn.keyEquivalent = "\u{1b}"

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        var views: [NSView] = [cancelBtn, spacer]
        if let primaryTitle, let primaryAction {
            let primary = NSButton(title: primaryTitle, target: self, action: primaryAction)
            primary.bezelStyle = .rounded
            primary.keyEquivalent = "\r"
            primary.isEnabled = primaryEnabled
            views.append(primary)
        }

        let row = NSStackView(views: views)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        row.translatesAutoresizingMaskIntoConstraints = false
        return row
    }

    // MARK: - Controls & Keyboard

    public func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        if field === passphraseField {
            model.clearUnlockError()
        } else if field === searchField {
            model.updateSearchQuery(searchField.stringValue)
        }
    }

    public func control(
        _ control: NSControl,
        textView: NSTextView,
        doCommandBy commandSelector: Selector
    ) -> Bool {
        if commandSelector == #selector(NSResponder.cancelOperation(_:)) {
            model.cancelByUser()
            return true
        }
        if control === passphraseField {
            if commandSelector == #selector(NSResponder.insertNewline(_:)) {
                handleSubmitUnlock()
                return true
            }
            return false
        }
        if control === searchField {
            if commandSelector == #selector(NSResponder.moveDown(_:)) {
                model.moveSelection(delta: 1)
                return true
            }
            if commandSelector == #selector(NSResponder.moveUp(_:)) {
                model.moveSelection(delta: -1)
                return true
            }
            if commandSelector == #selector(NSResponder.insertNewline(_:)) {
                model.fillSelected()
                return true
            }
        }
        return false
    }

    @objc private func handleCancel() {
        clearSecrets()
        model.cancelByUser()
    }

    @objc private func handleTouchID() {
        model.promptTouchID()
    }

    @objc private func handleSubmitUnlock() {
        let pass = passphraseField.stringValue
        passphraseField.stringValue = ""
        model.submitPassphrase(pass)
    }

    @objc private func handleFillSelected() {
        model.fillSelected()
    }

    @objc private func handleOpenDeadbolt() {
        model.openDeadboltApp()
    }

    @objc private func handleRetry() {
        model.retryConnection()
    }

    // MARK: - Offscreen snapshot rendering (never opens a window)

    public func renderOffscreenPNG(
        appearanceName: NSAppearance.Name = .darkAqua,
        scale: CGFloat = 2.0
    ) -> Data? {
        let size = preferredSheetSize
        frame = NSRect(origin: .zero, size: size)
        appearance = NSAppearance(named: appearanceName)
        render(focusIfChanged: false)
        layoutSubtreeIfNeeded()

        let pixelsWide = Int(size.width * scale)
        let pixelsHigh = Int(size.height * scale)
        guard let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: pixelsWide,
            pixelsHigh: pixelsHigh,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ) else {
            return nil
        }
        rep.size = size
        if let targetAppearance = appearance {
            targetAppearance.performAsCurrentDrawingAppearance {
                cacheDisplay(in: bounds, to: rep)
            }
        } else {
            cacheDisplay(in: bounds, to: rep)
        }
        return rep.representation(using: .png, properties: [:])
    }
}
#endif

#if os(iOS)
import Combine
import SwiftUI

/// Bumped by the model's `onChange` so SwiftUI re-reads the model.
@MainActor
public final class AutoFillObserver: ObservableObject {
    @Published var revision = 0

    public init() {}
}

public struct AutoFillRootView: View {
    let model: AutoFillControllerModel
    @ObservedObject var observer: AutoFillObserver

    public init(model: AutoFillControllerModel, observer: AutoFillObserver) {
        self.model = model
        self.observer = observer
    }

    public var body: some View {
        let _ = observer.revision
        VStack(spacing: 0) {
            ProviderHeader(title: model.contextLabel) { model.cancelByUser() }
            ZStack {
                switch model.screen {
                case let .connecting(message):
                    ProviderStatus(message: message, progress: true)
                case .notInitialized:
                    ProviderMessage(
                        title: "Set up Deadbolt first",
                        detail: "Open Deadbolt on this iPhone and set up or join your vault, then try again."
                    )
                case let .locked(touchIdReady, touchIdReset, unlocking, touchIdInFlight, error):
                    ProviderLockView(
                        model: model,
                        prompt: model.lockedPrompt,
                        biometricReady: touchIdReady,
                        biometricReset: touchIdReset,
                        unlocking: unlocking,
                        biometricInFlight: touchIdInFlight,
                        error: error
                    )
                case .syncingConfiguration:
                    ProviderStatus(message: "Setting up AutoFill…", progress: true)
                case .picker:
                    ProviderPicker(model: model, observer: observer)
                case let .failed(message):
                    // Busy is a wait, not an error: say so quietly.
                    ProviderMessage(
                        title: model.failureIsBusy ? "Deadbolt is busy" : "Deadbolt couldn't fill this",
                        detail: model.failureIsBusy
                            ? "Deadbolt is finishing something else with your vault. Try again in a moment."
                            : message
                    ) {
                        Button("Try again") { model.retryConnection() }
                            .buttonStyle(RuneButtonStyle())
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Rune.bg.ignoresSafeArea())
        .foregroundStyle(Rune.text)
    }
}

private struct ProviderHeader: View {
    let title: String
    let cancel: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            KeyholeMark(size: 28)
            Text(title)
                .rune(.uiMedium)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 8)
            Button("Cancel", action: cancel)
                .buttonStyle(RuneButtonStyle())
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Rune.borderMuted).frame(height: 1)
        }
    }
}

private struct ProviderStatus: View {
    let message: String
    var progress = false

    var body: some View {
        VStack(spacing: 12) {
            if progress {
                ProgressView().tint(Rune.iconMuted)
            }
            Text(message).rune(.ui).foregroundStyle(Rune.muted)
        }
        .padding(28)
    }
}

private struct ProviderMessage<Actions: View>: View {
    let title: String
    let detail: String
    let actions: Actions

    init(title: String, detail: String, @ViewBuilder actions: () -> Actions = { EmptyView() }) {
        self.title = title
        self.detail = detail
        self.actions = actions()
    }

    var body: some View {
        VStack(spacing: 12) {
            Text(title).rune(.hero)
            Text(detail)
                .rune(.ui)
                .foregroundStyle(Rune.muted)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            actions.padding(.top, 4)
        }
        .padding(28)
    }
}

private struct ProviderLockView: View {
    let model: AutoFillControllerModel
    let prompt: String?
    let biometricReady: Bool
    let biometricReset: Bool
    let unlocking: Bool
    let biometricInFlight: Bool
    let error: String?

    @State private var passphraseText = ""
    @FocusState private var focused: Bool

    private var biometryName: String { Enclave.biometryName }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(model.needsBiometricVerification ? "Confirm it's you" : "Deadbolt is locked")
                    .rune(.hero)
                    .padding(.top, 8)
                    .accessibilityAddTraits(.isHeader)
                if let prompt {
                    Text(prompt)
                        .rune(.ui)
                        .foregroundStyle(Rune.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if model.needsBiometricVerification {
                    verification
                } else {
                    passphrase
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
        }
        .scrollDismissesKeyboard(.interactively)
    }

    /// A verified passkey ceremony: only a fresh biometric match counts, so
    /// there is no passphrase field to try.
    @ViewBuilder private var verification: some View {
        let shown = error == AutoFillControllerModel.verificationNeeded ? nil : error
        if biometricReady {
            biometricButton(kind: .primary)
            errorLine(shown)
            quiet("This site asks for \(biometryName). Your passphrase can't confirm a passkey.")
        } else {
            errorLine(shown)
            quiet(Enclave.unavailableReason ?? (biometricReset
                ? "\(biometryName) was reset. Open Deadbolt and unlock it with your passphrase to turn \(biometryName) back on."
                : "Turn on \(biometryName) in Deadbolt's settings to use passkeys."))
            quiet("This site asks for \(biometryName), and your passphrase can't confirm a passkey.")
        }
    }

    @ViewBuilder private var passphrase: some View {
        VStack(alignment: .leading, spacing: 6) {
            SecureField("Passphrase", text: $passphraseText)
                .textContentType(.password)
                .focused($focused)
                .submitLabel(.go)
                .onSubmit(unlock)
                .onChange(of: passphraseText) { model.clearUnlockError() }
                .runeInput(focused: focused, invalid: error != nil)
                .disabled(unlocking)
            errorLine(error)
        }
        Button(action: unlock) {
            HStack(spacing: 8) {
                if unlocking { ProgressView().tint(Rune.onContrast) }
                Text("Unlock")
            }
        }
        .buttonStyle(RuneButtonStyle(kind: .primary, wide: true))
        .disabled(passphraseText.isEmpty || unlocking || biometricInFlight)
        if biometricReady {
            biometricButton(kind: .neutral)
        } else if biometricReset {
            quiet("\(biometryName) was reset. Enter your passphrase.")
        }
    }

    private func biometricButton(kind: RuneButtonStyle.Kind) -> some View {
        Button {
            model.promptTouchID()
        } label: {
            HStack(spacing: 8) {
                if biometricInFlight {
                    ProgressView().tint(kind == .primary ? Rune.onContrast : Rune.iconMuted)
                } else {
                    Image(systemName: biometryName == "Touch ID" ? "touchid" : "faceid")
                        .accessibilityHidden(true)
                }
                Text(kind == .primary ? "Use \(biometryName)" : "Unlock with \(biometryName)")
            }
        }
        .buttonStyle(RuneButtonStyle(kind: kind, wide: true))
        .disabled(unlocking || biometricInFlight)
    }

    @ViewBuilder private func errorLine(_ text: String?) -> some View {
        if let text {
            Text(text)
                .rune(.textXSmall)
                .foregroundStyle(Rune.danger)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func quiet(_ text: String) -> some View {
        Text(text)
            .rune(.textXSmall)
            .foregroundStyle(Rune.muted)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func unlock() {
        guard !passphraseText.isEmpty, !unlocking, !biometricInFlight else { return }
        model.submitPassphrase(passphraseText)
    }
}

private struct ProviderPicker: View {
    let model: AutoFillControllerModel
    /// The model isn't observable itself: without this the list would draw
    /// before `updateSearchQuery` runs and lag one keystroke behind.
    @ObservedObject var observer: AutoFillObserver
    @State private var query: String

    /// Starts from the model's query: after an unlock or a failed pick the
    /// picker is rebuilt, and an empty field over a filtered list would lie.
    init(model: AutoFillControllerModel, observer: AutoFillObserver) {
        self.model = model
        self.observer = observer
        _query = State(initialValue: model.searchQuery)
    }

    var body: some View {
        let _ = observer.revision
        VStack(spacing: 0) {
            ProviderSearchField(text: $query)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .onChange(of: query) { _, next in model.updateSearchQuery(next) }
            if model.unassociated {
                Text("This app has no website Deadbolt can match. Check the login before filling it.")
                    .rune(.textXSmall)
                    .foregroundStyle(Rune.muted)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }
            if let error = model.pickerError {
                Text(error)
                    .rune(.textXSmall)
                    .foregroundStyle(Rune.danger)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }
            if model.filteredLogins.isEmpty && model.filteredPasskeys.isEmpty {
                Spacer()
                Text(query.isEmpty ? "Nothing saved for this site." : "No matches.")
                    .rune(.ui)
                    .foregroundStyle(Rune.muted)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        if !model.filteredPasskeys.isEmpty {
                            ProviderSectionLabel(text: "Passkeys")
                            ForEach(Array(model.filteredPasskeys.enumerated()), id: \.offset) { index, passkey in
                                Button { model.fillPasskeyRow(index) } label: {
                                    ProviderRow(
                                        title: passkey.username ?? "Passkey",
                                        detail: passkey.vault,
                                        tile: passkey.username ?? "P"
                                    )
                                }
                                .buttonStyle(ProviderRowStyle())
                                .disabled(model.filling)
                            }
                            if !model.filteredLogins.isEmpty {
                                ProviderSectionLabel(text: "Passwords")
                            }
                        }
                        ForEach(Array(model.filteredLogins.enumerated()), id: \.offset) { index, login in
                            Button { model.fillRow(index) } label: {
                                ProviderRow(
                                    title: login.title.isEmpty ? "Untitled" : login.title,
                                    detail: model.hasMultipleVaults ? "\(login.subtitle) · \(login.vault)" : login.subtitle,
                                    tile: login.title
                                )
                            }
                            .buttonStyle(ProviderRowStyle())
                            .disabled(model.filling)
                        }
                    }
                    .padding(.horizontal, 6)
                    .padding(.bottom, 12)
                }
            }
        }
    }
}

private struct ProviderSectionLabel: View {
    let text: String

    var body: some View {
        Text(text)
            .runeLabel()
            .padding(.horizontal, 10)
            .padding(.top, 10)
            .padding(.bottom, 4)
    }
}

/// The app's search field (Views.swift `SearchField`).
private struct ProviderSearchField: View {
    @Binding var text: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15))
                .foregroundStyle(Rune.iconMuted)
            TextField("Search", text: $text)
                .rune(.ui)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(Rune.iconFaint)
                }
                .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 40)
        .background(RoundedRectangle(cornerRadius: Rune.radiusLg, style: .continuous).fill(Rune.searchFill))
    }
}

/// The app's item row (Views.swift `ItemRow`).
private struct ProviderRow: View {
    let title: String
    let detail: String
    let tile: String

    var body: some View {
        HStack(spacing: 10) {
            LetterTile(title: tile)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).rune(.ui).foregroundStyle(Rune.text).lineLimit(1)
                if !detail.isEmpty {
                    Text(detail).rune(.fact).foregroundStyle(Rune.textFaint).lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .frame(minHeight: 52)
        .contentShape(Rectangle())
    }
}

private struct ProviderRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(
                RoundedRectangle(cornerRadius: Rune.radiusLg, style: .continuous)
                    .fill(configuration.isPressed ? Rune.pressed : .clear)
            )
            .animation(Rune.control, value: configuration.isPressed)
    }
}
#endif
