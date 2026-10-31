// Native AppKit UI for `DeadboltAutoFill.appex`: connecting, onboarding redirect,
// Touch ID + passphrase unlock, and searchable credential picker.
// Supports offscreen `NSBitmapImageRep` rendering for headless verification.

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
