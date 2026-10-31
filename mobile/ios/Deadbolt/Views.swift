// Screens, drawn with Theme.swift (Rune / the extension's vault page) on top
// of iOS navigation, gestures, Dynamic Type and the system biometric sheet.

import SwiftUI

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            Rune.bg.ignoresSafeArea()
            switch model.phase {
            case .starting:
                // Nothing at launch (it's brief); after pairing, the new vault
                // can take a moment to open, so say so instead of a blank screen.
                if model.status != nil, model.notice == nil {
                    OpeningView()
                } else {
                    Color.clear
                }
            case .failed(let message):
                CenteredMessage(title: "Deadbolt couldn't start", detail: message)
            case .setup:
                SetupView().id(model.generation)
            case .joining(let code):
                JoiningView(code: code)
            case .locked:
                LockView().id(model.generation)
            case .unlocked:
                VaultView()
            }
            // Keep the vault out of the app switcher's snapshot.
            if scenePhase != .active {
                Rune.bg.ignoresSafeArea()
                KeyholeMark(size: 56)
            }
        }
        .foregroundStyle(Rune.text)
        // Locking must remove secrets immediately, never cross-fade them out.
        .animation(model.phase == .unlocked ? Rune.overlay : nil, value: model.phase)
    }
}

struct OpeningView: View {
    var body: some View {
        VStack(spacing: 12) {
            ProgressView().tint(Rune.iconMuted)
            Text("Opening your vault").rune(.ui).foregroundStyle(Rune.muted)
        }
        .accessibilityElement(children: .combine)
    }
}

struct CenteredMessage: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 8) {
            Text(title).rune(.hero).accessibilityAddTraits(.isHeader)
            Text(detail).rune(.ui).foregroundStyle(Rune.muted).multilineTextAlignment(.center)
        }
        .padding(28)
    }
}

/// A quiet line under the control that failed.
struct NoticeLine: View {
    let text: String?

    var body: some View {
        if let text {
            Text(text)
                .rune(.textXSmall)
                .foregroundStyle(Rune.danger)
                .frame(maxWidth: .infinity, alignment: .leading)
                .transition(.opacity)
        }
    }
}

/// vault.css `.hero`: the mark, a 17/530 title and a muted line.
struct Hero: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            KeyholeMark(size: 44)
            Text(title).rune(.hero).padding(.top, 4).accessibilityAddTraits(.isHeader)
            Text(detail).rune(.ui).foregroundStyle(Rune.muted).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: Pairing

struct SetupView: View {
    @EnvironmentObject private var model: AppModel
    @State private var passphrase = ""
    @State private var confirm = ""
    @FocusState private var focus: Field?

    private enum Field { case passphrase, confirm }

    private var mismatch: Bool { !confirm.isEmpty && passphrase != confirm }
    private var canStart: Bool { !model.busy && !passphrase.isEmpty && passphrase == confirm }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Hero(
                    title: "Pair with your other device",
                    detail: "This iPhone joins the vault you already have. Choose a passphrase for this iPhone. It stays here and doesn't need to match your other devices."
                )
                VStack(alignment: .leading, spacing: 6) {
                    Text("Passphrase for this iPhone").runeLabel()
                    SecureField("Passphrase", text: $passphrase)
                        .textContentType(.newPassword)
                        .focused($focus, equals: .passphrase)
                        .submitLabel(.next)
                        .onSubmit { focus = .confirm }
                        .runeInput(focused: focus == .passphrase)
                    SecureField("Confirm passphrase", text: $confirm)
                        .textContentType(.newPassword)
                        .focused($focus, equals: .confirm)
                        .submitLabel(.go)
                        .onSubmit(start)
                        .runeInput(focused: focus == .confirm, invalid: mismatch)
                    NoticeLine(text: mismatch ? "The passphrases don't match." : model.notice)
                }
                Button(action: start) {
                    HStack(spacing: 8) {
                        if model.busy { ProgressView().tint(Rune.onContrast) }
                        Text("Show pairing code")
                    }
                }
                .buttonStyle(RuneButtonStyle(kind: .primary, wide: true))
                .disabled(!canStart)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 32)
        }
        .scrollDismissesKeyboard(.interactively)
        .onAppear { Metrics.firstScreen("setup") }
    }

    private func start() {
        guard canStart else { return }
        let passphrase = self.passphrase
        Task { await model.startJoin(passphrase: passphrase) }
    }
}

struct JoiningView: View {
    @EnvironmentObject private var model: AppModel
    let code: String
    @State private var copied = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Hero(
                    title: "Enter this code on your other device",
                    detail: "On a computer that has your vault, run the command below. The code works once, for 5 minutes."
                )
                // vault.css `.code-box.pair`: the code centred, its copy under it.
                VStack(spacing: 12) {
                    Text(code)
                        .rune(.code)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .textSelection(.enabled)
                        .accessibilityLabel(code.replacingOccurrences(of: "-", with: " "))
                    Button(copied ? "Copied" : "Copy code") {
                        model.copy(code)
                        copied = true
                    }
                    .buttonStyle(RuneButtonStyle())
                }
                .padding(.vertical, 14)
                .padding(.horizontal, 12)
                .runeBox()
                Text("deadbolt pair \(code)")
                    .rune(.mono)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(RoundedRectangle(cornerRadius: Rune.radiusSm).fill(Rune.layer02))
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Waiting for your other device").rune(.textXSmall).foregroundStyle(Rune.muted)
                }
                Button("Cancel") { Task { await model.cancelJoin() } }
                    .buttonStyle(RuneButtonStyle())
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 32)
        }
    }
}

// MARK: Lock

struct LockView: View {
    @EnvironmentObject private var model: AppModel
    @State private var passphrase = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Spacer(minLength: 40)
            KeyholeMark(size: 44)
            Text("Deadbolt is locked").rune(.hero).accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 6) {
                SecureField("Passphrase", text: $passphrase)
                    .textContentType(.password)
                    .focused($focused)
                    .submitLabel(.go)
                    .onSubmit(unlock)
                    .runeInput(focused: focused, invalid: model.notice != nil)
                NoticeLine(text: model.notice)
            }
            Button(action: unlock) {
                HStack(spacing: 8) {
                    if model.busy { ProgressView().tint(Rune.onContrast) }
                    Text("Unlock")
                }
            }
            .buttonStyle(RuneButtonStyle(kind: .primary, wide: true))
            .disabled(passphrase.isEmpty || model.busy)
            if model.biometricReady {
                if let why = model.biometricUnavailableReason {
                    Text(why).rune(.textXSmall).foregroundStyle(Rune.textFaint)
                } else {
                    Button {
                        Task { await model.unlockWithBiometrics() }
                    } label: {
                        Label("Unlock with \(model.biometryName)", systemImage: model.biometryName == "Touch ID" ? "touchid" : "faceid")
                    }
                    .buttonStyle(RuneButtonStyle(wide: true))
                    .disabled(model.busy)
                }
            }
            Spacer(minLength: 40)
            Spacer(minLength: 40)
        }
        .padding(.horizontal, 20)
        .onAppear { Metrics.firstScreen("lock") }
    }

    private func unlock() {
        guard !passphrase.isEmpty, !model.busy else { return }
        let passphrase = self.passphrase
        // Accepted unlocks change generation and replace this view. Keep the
        // input when a pending background lock temporarily rejects the action.
        Task { await model.unlock(passphrase: passphrase) }
    }
}

// MARK: Vault

struct VaultView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingSettings = false
    @State private var path: [ItemSummary] = []

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                SearchField(text: $model.query)
                    .padding(.horizontal, 14)
                    .padding(.top, 6)
                    .padding(.bottom, 10)
                // The app's vault head: the list's name, then how many show.
                HStack {
                    Text("Logins").runeLabel()
                    Spacer(minLength: 8)
                    if model.itemsLoaded {
                        Text(model.items.count.formatted())
                            .rune(.small)
                            .monospacedDigit()
                            .foregroundStyle(Rune.textFaint)
                            .accessibilityLabel("\(model.items.count) logins")
                    }
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 2)
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.items) { item in
                            NavigationLink(value: item) { ItemRow(item: item) }
                                .buttonStyle(RowStyle())
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.bottom, 12)
                    .overlay(alignment: .top) {
                        if model.itemsLoaded, model.items.isEmpty {
                            CenteredMessage(
                                title: model.query.isEmpty ? "No items yet" : "No matches",
                                detail: model.query.isEmpty ? "Items from your other devices appear here once they sync." : "Nothing matches “\(model.query)”."
                            )
                            .padding(.top, 60)
                        }
                    }
                }
                .scrollDismissesKeyboard(.immediately)
                .refreshable { await model.syncNow() }
                if let approval = model.approval {
                    ApprovalView(request: approval)
                        .id(approval.id)
                }
                StatusFooter(showingSettings: $showingSettings)
            }
            .background(Rune.bg)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: ItemSummary.self) { item in
                ItemView(summary: item)
            }
            .sheet(isPresented: $showingSettings) { SettingsView() }
        }
    }
}

/// A read authorizes this exact signed scope, not a computer-wide session.
/// Drawn as the app's floating panel: who asks, for which field of which
/// login, then Deny and Allow.
struct ApprovalView: View {
    @EnvironmentObject private var model: AppModel
    let request: PendingApproval

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("\(request.originName) wants to read").runeLabel()
                    HStack(spacing: 12) {
                        KindTile(size: 32, radius: Rune.radiusLg)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(request.title).rune(.uiMedium).foregroundStyle(Rune.textStrong)
                            Text(request.field).rune(.fact).foregroundStyle(Rune.textFaint)
                        }
                    }
                    .accessibilityElement(children: .combine)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(request.caller).rune(.textXSmall).foregroundStyle(Rune.muted)
                        Text("Deadbolt checked which program is asking. What it says about where it was started isn't checked.")
                            .rune(.about)
                            .foregroundStyle(Rune.textFaint)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Computer ID: \(request.origin)")
                            Text("Vault: \(request.vault)")
                            Text("Item: \(request.item)")
                            Text("Field: \(request.field)")
                            Text("Request: \(request.id)")
                        }
                        .rune(.fact)
                        .foregroundStyle(Rune.textFaint)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                    } label: {
                        Text("Exact request").rune(.textXSmall).foregroundStyle(Rune.muted)
                    }
                    .tint(Rune.iconMuted)
                    if let notice = model.approvalNotice {
                        NoticeLine(text: notice)
                    } else if let why = model.biometricUnavailableReason
                        ?? (model.biometricReady ? nil : "Turn on \(model.biometryName) in Settings to allow reads.") {
                        // Why Allow is off is a state, not an error: say it quietly.
                        Text(why)
                            .rune(.textXSmall)
                            .foregroundStyle(Rune.textFaint)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 240)
            .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Button("Deny") { Task { await model.respondToApproval(request, allow: false) } }
                    .buttonStyle(RuneButtonStyle(kind: .neutral, wide: true))
                    .disabled(model.approvalResponding)
                Button("Allow with \(model.biometryName)") { Task { await model.respondToApproval(request, allow: true) } }
                    .buttonStyle(RuneButtonStyle(kind: .primary, wide: true))
                    .disabled(model.approvalResponding || !model.biometricReady || model.biometricUnavailableReason != nil)
            }
        }
        .padding(14)
        .runeFloating()
        .padding(.horizontal, 8)
        .padding(.bottom, 8)
    }
}

/// The app's search: plain on layer_02 (layer_01 in the dark), an 8px
/// radius, a muted magnifier; no ring.
struct SearchField: View {
    @Binding var text: String
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15))
                .foregroundStyle(Rune.iconMuted)
            TextField("Search", text: $text)
                .rune(.ui)
                .focused($focused)
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

/// The app's `list_row`: the login glyph, the title in `ui` over the
/// username in `FACT`, an 8px radius; pressed fills `--pressed`. Rows are
/// 52pt (the app's are 46) for touch.
struct ItemRow: View {
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 12) {
            LoginGlyph()
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? "Untitled" : item.title)
                    .rune(.ui)
                    .foregroundStyle(Rune.text)
                    .lineLimit(1)
                if let username = item.username, !username.isEmpty {
                    Text(username)
                        .rune(.fact)
                        .foregroundStyle(Rune.textFaint)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        // Only matters at large Dynamic Type sizes, where rows outgrow 52pt.
        .padding(.vertical, 4)
        .frame(minHeight: 52)
        .contentShape(Rectangle())
    }
}

struct RowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(
                RoundedRectangle(cornerRadius: Rune.radiusLg, style: .continuous)
                    .fill(configuration.isPressed ? Rune.pressed : .clear)
            )
            .animation(Rune.control, value: configuration.isPressed)
    }
}

/// vault.css `.bottom`: the sync dot and a short status, then the actions.
struct StatusFooter: View {
    @EnvironmentObject private var model: AppModel
    @Binding var showingSettings: Bool

    var body: some View {
        HStack(spacing: 7) {
            SyncDot(state: model.sync)
            Text(statusText)
                .rune(.small)
                .foregroundStyle(Rune.muted)
                .lineLimit(1)
            Spacer(minLength: 4)
            Button { Task { await model.syncNow() } } label: {
                Image(systemName: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(RuneIconButtonStyle())
            .disabled(model.sync == .syncing)
            .accessibilityLabel("Sync now")
            Button { showingSettings = true } label: {
                Image(systemName: "slider.horizontal.3")
            }
            .buttonStyle(RuneIconButtonStyle())
            .accessibilityLabel("Settings")
            Button { Task { await model.lock() } } label: {
                Image(systemName: "lock")
            }
            .buttonStyle(RuneIconButtonStyle())
            .accessibilityLabel("Lock")
        }
        .padding(.leading, 16)
        .padding(.trailing, 6)
        .padding(.vertical, 2)
        .background(Rune.bg)
        .overlay(alignment: .top) { Rune.borderMuted.frame(height: 1) }
    }

    private var statusText: String {
        if let notice = model.notice { return notice }
        switch model.sync {
        case .idle: return "Saved on this iPhone"
        case .syncing: return "Syncing"
        case .synced(let date): return "Synced \(date.formatted(date: .omitted, time: .shortened))"
        case .offline: return "Offline. Showing saved items."
        case .failed: return "Couldn't sync. Showing saved items."
        }
    }
}

struct SyncDot: View {
    let state: AppModel.SyncState
    @State private var breathe = false

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 6, height: 6)
            .opacity(state == .syncing && breathe ? 0.35 : 1)
            .scaleEffect(state == .syncing && breathe ? 0.8 : 1)
            .onChange(of: state, initial: true) { _, state in
                if state == .syncing {
                    withAnimation(.easeInOut(duration: 0.7).repeatForever(autoreverses: true)) { breathe = true }
                } else {
                    breathe = false
                }
            }
            .accessibilityHidden(true)
    }

    private var color: Color {
        switch state {
        case .syncing: Rune.textAccent
        case .synced: Rune.success
        case .failed: Rune.danger
        default: Rune.iconFaint
        }
    }
}

// MARK: Item

struct ItemView: View {
    @EnvironmentObject private var model: AppModel
    let summary: ItemSummary
    @State private var detail: ItemDetail?
    @State private var revealed: String?
    @State private var code: OneTimeCode?
    @State private var codeFetched = Date()
    @State private var copied: String?
    @State private var failure: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // The app's item head: the kind's 44pt glyph tile by a 22/600
                // title over the kind's name.
                HStack(alignment: .top, spacing: 14) {
                    KindTile().padding(.top, 2)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(summary.title.isEmpty ? "Untitled" : summary.title)
                            .rune(.title)
                            .foregroundStyle(Rune.textStrong)
                            .lineLimit(2)
                        Text("Login")
                            .rune(.textSmall)
                            .foregroundStyle(Rune.muted)
                    }
                }
                .padding(.bottom, 8)
                if let detail {
                    VStack(spacing: 2) {
                        if detail.hasPassword {
                            FieldLine(label: "Password") {
                                if let revealed {
                                    Text(revealed).rune(.mono).textSelection(.disabled)
                                } else {
                                    Text("••••••••••••").rune(.ui).tracking(1.3)
                                }
                            } actions: {
                                Button { toggleReveal() } label: {
                                    Image(systemName: revealed == nil ? "eye" : "eye.slash")
                                }
                                .buttonStyle(RuneIconButtonStyle())
                                .accessibilityLabel(revealed == nil ? "Show password" : "Hide password")
                                copyButton("password") { copyPassword() }
                            }
                        }
                        if let username = detail.username, !username.isEmpty {
                            FieldLine(label: "Username") {
                                Text(username).rune(.ui).lineLimit(1)
                            } actions: {
                                copyButton("username") { model.copy(username) }
                            }
                        }
                        if let url = detail.url, !url.isEmpty {
                            FieldLine(label: "URL") {
                                if let link = URL(string: url), link.scheme == "https" || link.scheme == "http" {
                                    Link(url, destination: link).rune(.ui).foregroundStyle(Rune.textAccent).lineLimit(1)
                                } else {
                                    Text(url).rune(.ui).lineLimit(1)
                                }
                            } actions: {
                                copyButton("URL") { model.copy(url) }
                            }
                        }
                        if detail.hasOtp {
                            FieldLine(label: "One-time code") {
                                TimelineView(.periodic(from: .now, by: 1)) { context in
                                    codeValue(now: context.date)
                                }
                            } actions: {
                                copyButton("one-time code") { if let code { model.copy(code.code) } }
                            }
                        }
                    }
                    .padding(.horizontal, -8)
                }
                NoticeLine(text: failure)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 24)
        }
        .background(Rune.bg)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Rune.bg, for: .navigationBar)
        .tint(Rune.muted)
        .task { await load() }
        .task(id: detail?.hasOtp) { await refreshCodes() }
        .onDisappear {
            revealed = nil
            code = nil
            detail = nil
        }
    }

    private func copyButton(_ label: String, action: @escaping () -> Void) -> some View {
        Button {
            action()
            flash(label)
        } label: {
            Image(systemName: copied == label ? "checkmark" : "square.on.square")
                .contentTransition(.symbolEffect(.replace))
        }
        .buttonStyle(RuneIconButtonStyle(tint: copied == label ? Rune.textSuccess : Rune.iconMuted))
        .accessibilityLabel(copied == label ? "Copied" : "Copy \(label)")
    }

    @ViewBuilder
    private func codeValue(now: Date) -> some View {
        if let code {
            let left = max(0, code.remaining - Int(now.timeIntervalSince(codeFetched)))
            // The app's code row: 3+3 groups beside a 40×3 bar that empties
            // over the period.
            HStack(spacing: 12) {
                Text(Self.grouped(code.code))
                    .rune(.otp)
                    .foregroundStyle(Rune.textStrong)
                Capsule()
                    .fill(Rune.layer03)
                    .frame(width: 40, height: 3)
                    .overlay(alignment: .leading) {
                        Capsule()
                            .fill(Rune.textAccent)
                            .frame(width: 40 * CGFloat(left) / CGFloat(max(1, code.period)), height: 3)
                            .animation(.linear(duration: 1), value: left)
                    }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Code \(code.code), \(left) seconds left")
        } else {
            Text("••• •••").rune(.otp).foregroundStyle(Rune.textFaint)
        }
    }

    private func load() async {
        guard let core = model.core else { return }
        let generation = model.generation
        do {
            let next = try await core.item(id: summary.id)
            guard model.canRead(generation: generation) else { return }
            detail = next
        } catch {
            guard model.canRead(generation: generation) else { return }
            failure = error.localizedDescription
        }
    }

    /// Refreshes the code when it runs out. Passive: never counts as
    /// activity, so an open code can't keep the vault unlocked.
    private func refreshCodes() async {
        guard detail?.hasOtp == true, let core = model.core else { return }
        let generation = model.generation
        while !Task.isCancelled, model.phase == .unlocked {
            do {
                let next = try await core.code(id: summary.id)
                guard model.canRead(generation: generation) else { return }
                code = next
                codeFetched = Date()
                try await Task.sleep(for: .seconds(max(1, next.remaining)))
            } catch is CancellationError {
                return
            } catch {
                code = nil
                return
            }
        }
    }

    private func toggleReveal() {
        if revealed != nil {
            revealed = nil
            return
        }
        guard let core = model.core else { return }
        let generation = model.generation
        Task {
            do {
                let value = try await core.secret(id: summary.id, field: "password")
                guard model.canRead(generation: generation) else { return }
                revealed = value
            } catch {
                guard model.canRead(generation: generation) else { return }
                failure = error.localizedDescription
            }
        }
    }

    private func copyPassword() {
        guard let core = model.core else { return }
        let generation = model.generation
        Task {
            do {
                let value = try await core.secret(id: summary.id, field: "password")
                guard model.canRead(generation: generation) else { return }
                model.copy(value)
            } catch {
                guard model.canRead(generation: generation) else { return }
                failure = error.localizedDescription
            }
        }
    }

    private func flash(_ label: String) {
        withAnimation(Rune.control) { copied = label }
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            if copied == label { withAnimation(Rune.control) { copied = nil } }
        }
    }

    static func grouped(_ code: String) -> String {
        guard code.count == 6 || code.count == 8 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<mid]) \(code[mid...])"
    }
}

/// vault.css `.line` in the item page: a label over its value, actions at
/// the end; pressing fills layer_02 with a 10px radius.
struct FieldLine<Value: View, Actions: View>: View {
    let label: String
    @ViewBuilder var value: Value
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).runeFieldLabel()
                value
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 0) { actions }
        }
        .padding(.leading, 16)
        .padding(.trailing, 2)
        .padding(.vertical, 8)
        .frame(minHeight: 56)
    }
}

// MARK: Settings

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            // The app's Settings page: a 22/600 title, groups named in
            // text_faint, rows with a medium label over a faint line.
            VStack(alignment: .leading, spacing: 24) {
                HStack {
                    Text("Settings")
                        .rune(.title)
                        .foregroundStyle(Rune.textStrong)
                        .accessibilityAddTraits(.isHeader)
                    Spacer()
                    Button("Done") { dismiss() }.buttonStyle(RuneButtonStyle())
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Security").runeFieldLabel()
                    VStack(alignment: .leading, spacing: 2) {
                        Toggle(isOn: Binding(
                            get: { model.biometricReady },
                            set: { on in if on { Task { await model.enableBiometrics() } } }
                        )) {
                            Text("Unlock with \(model.biometryName)")
                                .rune(.uiMedium)
                                .foregroundStyle(Rune.textStrong)
                        }
                        .toggleStyle(RuneToggleStyle())
                        .disabled(model.biometricUnavailableReason != nil || model.biometricReady || model.busy)
                        // Outside the toggle so a disabled switch doesn't fade the reason.
                        Text(model.biometricUnavailableReason
                            ?? "Your passphrase is still needed every 14 days and when \(model.biometryName) changes.")
                            .rune(.about)
                            .foregroundStyle(Rune.textFaint)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, 10)
                    .frame(minHeight: 56)
                    NoticeLine(text: model.notice)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("This iPhone").runeFieldLabel()
                    SettingFact(title: "Locks after", value: "5 minutes idle, or when you leave the app")
                    SettingFact(title: "Copied items", value: "Stay on this iPhone and clear after 30 seconds")
                }
            }
            .padding(20)
        }
        .background(Rune.bg.ignoresSafeArea())
        .presentationDragIndicator(.visible)
    }
}

struct SettingFact: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).rune(.uiMedium).foregroundStyle(Rune.textStrong)
            Text(value).rune(.about).foregroundStyle(Rune.textFaint)
        }
        .padding(.vertical, 10)
        .frame(minHeight: 56, alignment: .leading)
    }
}
