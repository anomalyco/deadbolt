// App state: opening the core, pairing, unlock (passphrase or biometrics),
// search, sync, and the lock rules (background, idle). Secrets are fetched on
// demand and only kept by the views that show them. Errors are quiet: a line
// under the control that failed, or the status footer for sync.

import Foundation
import SwiftUI
import UIKit

@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        case starting
        case failed(String)
        case setup
        case joining(code: String)
        case locked
        case unlocked
    }

    enum SyncState: Equatable {
        case idle
        case syncing
        case synced(Date)
        case offline
        case failed
    }

    static let idleLimit: TimeInterval = 5 * 60
    static let clipboardLifetime: TimeInterval = 30
    static let appGroup = "group.pw.deadbolt"

    @Published private(set) var phase: Phase = .starting
    @Published private(set) var status: CoreStatus?
    @Published private(set) var items: [ItemSummary] = []
    @Published private(set) var itemsLoaded = false
    @Published var query = "" {
        didSet { if query != oldValue { noteActivity(); scheduleSearch() } }
    }
    /// The last failure, shown quietly where it happened. Cleared by the next attempt.
    @Published var notice: String?
    @Published private(set) var busy = false
    @Published private(set) var sync: SyncState = .idle
    @Published private(set) var approval: PendingApproval?
    @Published private(set) var approvalResponding = false
    @Published private(set) var approvalNotice: String?

    private(set) var core: (any CoreAPI)?
    @Published private(set) var generation: UInt64 = 0
    private var scenePhase: ScenePhase = .inactive
    private var opening = false
    private var authenticationPending = false
    private var pendingLocks = 0
    private var statusRequest: UInt64 = 0
    private let openCore: @MainActor () async throws -> any CoreAPI
    private let unseal: @Sendable (Data) async throws -> Data
    private let biometricAvailability: @MainActor () -> String?
    private let publishIdentities: @Sendable (String) async -> Void
    private var lastActivity = Date()
    private var idleTimer: Timer?
    private var searchTask: Task<Void, Never>?
    private var joinTask: Task<Void, Never>?
    private var approvalTask: Task<Void, Never>?
    private var identityTask: Task<Void, Never>?
    private var biometricPromptInFlight = false
    /// One automatic prompt per trip to the foreground; after that the
    /// person taps the button.
    private var autoPrompted = false
    private var autoPromptAfterLock = false
    private var copiedChangeCount: Int?
    private var unlockStarted: Date?
    /// Set once the person turns biometrics on; a preference, never a key.
    /// Passphrase unlocks rotate the slot while it's set.
    private var biometricsWanted: Bool {
        get { UserDefaults.standard.bool(forKey: "biometricsWanted") }
        set { UserDefaults.standard.set(newValue, forKey: "biometricsWanted") }
    }

    var biometricReady: Bool { status?.biometricReady ?? false }
    var biometricUnavailableReason: String? { biometricAvailability() }
    var biometryName: String { Enclave.biometryName }

    init(
        openCore: @escaping @MainActor () async throws -> any CoreAPI,
        unseal: @escaping @Sendable (Data) async throws -> Data = { token in
            try await Task.detached(priority: .userInitiated) {
                try Enclave.unseal(token, reason: "Unlock Deadbolt")
            }.value
        },
        biometricAvailability: @escaping @MainActor () -> String? = { Enclave.unavailableReason },
        publishIdentities: @escaping @Sendable (String) async -> Void = { _ in }
    ) {
        self.openCore = openCore
        self.unseal = unseal
        self.biometricAvailability = biometricAvailability
        self.publishIdentities = publishIdentities
    }

    // MARK: Startup

    func start() async {
        guard core == nil, !opening else { return }
        opening = true
        defer { opening = false }
        let generation = self.generation
        phase = .starting
        do {
            core = try await openCore()
            guard isCurrent(generation) else {
                await lock()
                return
            }
            try await refreshStatus(generation: generation)
            guard isCurrent(generation) else { return }
            await autoPromptIfReady()
        } catch {
            guard isCurrent(generation) else { return }
            phase = .failed(error.localizedDescription)
        }
    }

    /// The store lives in the App Group container so the AutoFill extension
    /// (pw.deadbolt.app.autofill) can open it later.
    static func storePath() throws -> String {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            throw CoreFailure(code: nil, message: "This copy of Deadbolt can't reach its storage. Reinstall it.")
        }
        var dir = container.appendingPathComponent("Deadbolt", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // Reapply on every open, including an already-existing store.
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        return dir.path
    }

    private func refreshStatus(generation: UInt64, allowUnlock: Bool = false) async throws {
        guard let core else { return }
        statusRequest &+= 1
        let request = statusRequest
        var status = try await core.status()
        guard generation == self.generation, request == statusRequest else { return }
        // A join may have crossed the persistence boundary before cancellation.
        // Keep initialized metadata, but never expose an unlocked background UI.
        status.unlocked = status.unlocked && isCurrent(generation) && allowUnlock
        self.status = status
        if !status.initialized {
            if case .joining = phase { return }
            phase = .setup
        } else if status.unlocked {
            if phase != .unlocked { didUnlock() }
        } else {
            let wasUnlocked = phase == .unlocked
            phase = .locked
            if wasUnlocked { clearUnlockedState() }
        }
    }

    // MARK: Pairing

    func startJoin(passphrase: String) async {
        guard let core, phase == .setup, canAuthenticate else { return }
        self.generation &+= 1
        let generation = self.generation
        await perform(generation: generation) {
            let reply = try await core.joinStart(passphrase: passphrase)
            guard await self.acceptAuthentication(generation) else { return }
            self.phase = .joining(code: reply.code)
            self.pollJoin(generation: generation)
        }
    }

    func cancelJoin() async {
        await lock()
    }

    private func pollJoin(generation: UInt64) {
        joinTask?.cancel()
        joinTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, let core = self.core, !Task.isCancelled else { return }
                do {
                    let status = try await core.joinStatus()
                    // This is a read, not join-start: a stale reply cannot
                    // unlock anything and must not cancel a newer pairing.
                    guard self.isCurrent(generation) else { return }
                    switch status.state {
                    case .waiting:
                        continue
                    case .joined:
                        self.joinTask = nil
                        self.phase = .starting
                        try await self.refreshStatus(generation: generation, allowUnlock: true)
                        return
                    case .error:
                        self.joinTask = nil
                        self.notice = status.error ?? "Pairing didn't finish. Try again with a new code."
                        self.phase = .starting
                        try await self.refreshStatus(generation: generation)
                        return
                    }
                } catch {
                    guard self.isCurrent(generation) else { return }
                    self.joinTask = nil
                    self.notice = error.localizedDescription
                    try? await self.refreshStatus(generation: generation)
                    return
                }
            }
        }
    }

    // MARK: Unlock and lock

    func unlock(passphrase: String) async {
        guard let core, phase == .locked, canAuthenticate else { return }
        self.generation &+= 1
        let generation = self.generation
        unlockStarted = Date()
        await perform(generation: generation) {
            try await core.unlock(passphrase: passphrase)
            guard await self.acceptAuthentication(generation) else { return }
            try await self.refreshStatus(generation: generation, allowUnlock: true)
            guard self.isCurrent(generation), self.phase == .unlocked else { return }
            if self.biometricsWanted, self.biometricUnavailableReason == nil {
                // docs/touch-id.md: a passphrase unlock rotates the slot and
                // restarts its 14 days.
                try? await self.enrollBiometrics(generation: generation)
            }
        }
    }

    func unlockWithBiometrics() async {
        guard let core, phase == .locked, canAuthenticate, !biometricPromptInFlight,
              biometricReady, biometricUnavailableReason == nil else { return }
        self.generation &+= 1
        let generation = self.generation
        authenticationPending = true
        biometricPromptInFlight = true
        notice = nil
        busy = true
        defer {
            biometricPromptInFlight = false
            authenticationPending = false
            if generation == self.generation { busy = false }
        }
        do {
            let token = try await core.biometricToken()
            guard await acceptAuthentication(generation) else { return }
            guard !token.isEmpty else { return }
            let key = try await unseal(token)
            guard await acceptAuthentication(generation) else { return }
            unlockStarted = Date()
            try await core.unlockBiometric(key: key)
            guard await acceptAuthentication(generation) else { return }
            try await refreshStatus(generation: generation, allowUnlock: true)
        } catch EnclaveFailure.cancelled {
            // Quietly back to the passphrase field.
        } catch {
            guard await acceptAuthentication(generation) else { return }
            notice = error.localizedDescription
        }
    }

    /// Offers biometrics straight away when the app opens locked.
    func autoPromptIfReady() async {
        guard scenePhase == .active, canAuthenticate, phase == .locked, !autoPrompted,
              biometricReady, biometricUnavailableReason == nil else { return }
        autoPrompted = true
        await unlockWithBiometrics()
    }

    func lock() async {
        let generation = invalidate()
        await finishLock(generation: generation)
    }

    /// Runs synchronously in the scene callback, before any queued completion.
    private func invalidate() -> UInt64 {
        generation &+= 1
        pendingLocks += 1
        joinTask?.cancel()
        joinTask = nil
        if case .failed = phase, core == nil {
            // Keep the startup failure actionable across scene transitions.
        } else {
            phase = status?.initialized == false ? .setup : .locked
        }
        clearUnlockedState()
        busy = false
        notice = nil
        status?.unlocked = false
        return generation
    }

    private func finishLock(generation: UInt64) async {
        defer {
            pendingLocks -= 1
            if pendingLocks == 0 { Task { await resumeAutoPromptAfterLock() } }
        }
        guard let core else { return }
        do {
            try await core.lock()
            try await refreshStatus(generation: generation)
        } catch {
            guard generation == self.generation else { return }
            notice = error.localizedDescription
        }
    }

    private func didUnlock() {
        phase = .unlocked
        notice = nil
        noteActivity()
        startIdleTimer()
        scheduleSearch()
        pollApprovals()
        scheduleIdentityPublication()
        Task { await syncNow() }
    }

    private func clearUnlockedState() {
        idleTimer?.invalidate()
        idleTimer = nil
        searchTask?.cancel()
        approvalTask?.cancel()
        approvalTask = nil
        approval = nil
        approvalNotice = nil
        approvalResponding = false
        identityTask?.cancel()
        identityTask = nil
        unlockStarted = nil
        items = []
        itemsLoaded = false
        query = ""
        sync = .idle
        clearClipboardIfOurs()
    }

    // MARK: Biometrics

    func enableBiometrics() async {
        guard phase == .unlocked, canAuthenticate else { return }
        let generation = self.generation
        await perform(generation: generation) {
            try await self.enrollBiometrics(generation: generation)
            guard self.isCurrent(generation) else { return }
            self.biometricsWanted = true
        }
    }

    private func enrollBiometrics(generation: UInt64) async throws {
        guard let core else { return }
        let key = try Enclave.randomSlotKey()
        let token = try await Task.detached(priority: .userInitiated) { try Enclave.seal(key) }.value
        guard await acceptAuthentication(generation) else { return }
        try await core.biometricEnroll(key: key, token: token)
        guard await acceptAuthentication(generation) else { return }
        try await refreshStatus(generation: generation, allowUnlock: true)
    }

    // MARK: Vault

    /// The app owns the open store. Publish only non-secret lookup metadata,
    /// separately from browsing and from every extension fill request.
    /// Runs after the list it was scheduled behind, so a large vault's
    /// identity snapshot never delays the first rows.
    private func scheduleIdentityPublication() {
        identityTask?.cancel()
        guard let core, phase == .unlocked else { return }
        let generation = self.generation
        let list = searchTask
        identityTask = Task(priority: .utility) { [weak self] in
            await list?.value
            guard !Task.isCancelled, self?.canRead(generation: generation) == true,
                  let json = try? await core.credentialIdentities(), let self,
                  self.canRead(generation: generation) else { return }
            await self.publishIdentities(json)
        }
    }

    // MARK: Computer read approvals

    private func pollApprovals() {
        approvalTask?.cancel()
        guard let core, phase == .unlocked, scenePhase == .active else { return }
        let generation = self.generation
        approvalTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.canRead(generation: generation), self.scenePhase == .active else { return }
                do {
                    let pending = try await core.approvalPending()
                    guard self.canRead(generation: generation), self.scenePhase == .active else { return }
                    let next = pending.flatMap { $0.expired ? nil : $0 }
                    if self.approval?.id != next?.id { self.approvalNotice = nil }
                    self.approval = next
                } catch {
                    guard self.canRead(generation: generation) else { return }
                    self.approval = nil
                }
                // Polling is passive and never resets the idle lock.
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func respondToApproval(_ request: PendingApproval, allow: Bool) async {
        let generation = self.generation
        guard let core, canRead(generation: generation), scenePhase == .active,
              !approvalResponding, !authenticationPending, approval?.id == request.id, !request.expired else { return }
        if allow {
            guard biometricReady, biometricUnavailableReason == nil else {
                approvalNotice = biometricUnavailableReason ?? "Enable biometrics in Settings before allowing a computer read."
                return
            }
        }
        approvalResponding = true
        approvalNotice = nil
        authenticationPending = true
        defer {
            authenticationPending = false
            if generation == self.generation { approvalResponding = false }
        }
        do {
            var key = Data()
            if allow {
                let token = try await core.biometricToken()
                guard await acceptAuthentication(generation), approval?.id == request.id, !request.expired else { return }
                // A fresh cryptographic match for this exact signed request;
                // a prior vault unlock is never authorization for a read.
                key = try await unseal(token)
                guard await acceptAuthentication(generation), approval?.id == request.id, !request.expired else { return }
            }
            try await core.approvalRespond(id: request.id, allow: allow, key: key)
            guard canRead(generation: generation), approval?.id == request.id else { return }
            approval = nil
        } catch EnclaveFailure.cancelled {
            // Keep the request available for Deny or another deliberate Allow.
        } catch {
            guard canRead(generation: generation), approval?.id == request.id else { return }
            approvalNotice = error.localizedDescription
        }
    }

    /// Syncs in the background; the list stays usable throughout.
    func syncNow() async {
        guard let core, phase == .unlocked, sync != .syncing else { return }
        let generation = self.generation
        sync = .syncing
        defer {
            // Pull-to-refresh may cancel its caller while the core finishes.
            // Cancellation must not leave the next manual sync disabled.
            if generation == self.generation, phase == .unlocked, sync == .syncing { sync = .idle }
        }
        do {
            try await core.sync()
            guard canRead(generation: generation) else { return }
            sync = .synced(Date())
            scheduleSearch()
            scheduleIdentityPublication()
        } catch let failure as CoreFailure {
            guard canRead(generation: generation) else { return }
            sync = failure.code == "Network" ? .offline : .failed
        } catch {
            guard canRead(generation: generation) else { return }
            sync = .failed
        }
    }

    private func scheduleSearch() {
        searchTask?.cancel()
        guard phase == .unlocked, let core else { return }
        let query = self.query
        let generation = self.generation
        searchTask = Task { [weak self] in
            guard !Task.isCancelled else { return }
            let started = Date()
            do {
                let items = try await core.items(query: query)
                guard !Task.isCancelled, let self, self.canRead(generation: generation) else { return }
                self.items = items
                let first = !self.itemsLoaded
                self.itemsLoaded = true
                Metrics.record("search_ms", since: started, extra: "items=\(items.count) query_len=\(query.count)")
                if first, let unlockStarted = self.unlockStarted {
                    Metrics.record("unlock_to_list_ms", since: unlockStarted, extra: "items=\(items.count)")
                    self.unlockStarted = nil
                }
            } catch {
                guard !Task.isCancelled, let self, self.canRead(generation: generation) else { return }
                self.itemsLoaded = true
                self.notice = error.localizedDescription
            }
        }
    }

    /// Copies `value` for this device only, expiring after 30 seconds, and
    /// clears it on lock if it's still ours.
    func copy(_ value: String) {
        guard scenePhase != .background else { return }
        if phase != .unlocked {
            guard case .joining = phase else { return }
        }
        noteActivity()
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(Self.clipboardLifetime),
            ]
        )
        copiedChangeCount = UIPasteboard.general.changeCount
    }

    private func clearClipboardIfOurs() {
        if let count = copiedChangeCount, UIPasteboard.general.changeCount == count {
            UIPasteboard.general.items = []
        }
        copiedChangeCount = nil
    }

    // MARK: Activity and idle lock

    /// Called for touches and deliberate actions. Background work (one-time
    /// code refreshes, sync) never calls it, so it can't hold the vault open.
    func noteActivity() {
        lastActivity = Date()
    }

    private func startIdleTimer() {
        idleTimer?.invalidate()
        let timer = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkIdle() }
        }
        RunLoop.main.add(timer, forMode: .common)
        idleTimer = timer
    }

    private func checkIdle() {
        guard phase == .unlocked else { return }
        if Date().timeIntervalSince(lastActivity) >= Self.idleLimit {
            Task { await lock() }
        }
    }

    func scenePhaseChanged(to scenePhase: ScenePhase) {
        self.scenePhase = scenePhase
        switch scenePhase {
        case .background:
            autoPrompted = false
            autoPromptAfterLock = false
            let generation = invalidate()
            Task { await finishLock(generation: generation) }
        case .active:
            if pendingLocks > 0 { autoPromptAfterLock = true }
            let generation = self.generation
            // The core owns iroh rebind/reconnect. Do not make vault browsing
            // or status wait for its network round (also safe while locked).
            if let core {
                Task {
                    guard isCurrent(generation), self.scenePhase == .active else { return }
                    try? await core.foreground()
                    guard canRead(generation: generation) else { return }
                    scheduleSearch()
                    scheduleIdentityPublication()
                }
            }
            Task {
                guard core != nil, !opening, isCurrent(generation), pendingLocks == 0, !authenticationPending else { return }
                if case .joining = phase { return }
                try? await refreshStatus(generation: generation, allowUnlock: phase == .unlocked)
                guard isCurrent(generation), self.scenePhase == .active else { return }
                if phase == .unlocked {
                    checkIdle()
                    pollApprovals()
                } else {
                    await autoPromptIfReady()
                }
            }
        default:
            break
        }
    }

    // MARK: Helpers

    private func resumeAutoPromptAfterLock() async {
        guard autoPromptAfterLock, scenePhase == .active, canAuthenticate else { return }
        autoPromptAfterLock = false
        await autoPromptIfReady()
    }

    private var canAuthenticate: Bool {
        scenePhase == .active && pendingLocks == 0 && !authenticationPending
    }

    private func isCurrent(_ generation: UInt64) -> Bool {
        generation == self.generation && scenePhase != .background && !Task.isCancelled
    }

    func canRead(generation: UInt64) -> Bool {
        isCurrent(generation) && phase == .unlocked
    }

    private func acceptAuthentication(_ generation: UInt64) async -> Bool {
        guard isCurrent(generation) else {
            // Core.lock may have run before this queued operation even started.
            // Re-lock after its completion, even if foregrounded again meanwhile.
            await lock()
            return false
        }
        return true
    }

    private func perform(generation: UInt64, _ body: @escaping @MainActor () async throws -> Void) async {
        authenticationPending = true
        busy = true
        notice = nil
        defer {
            authenticationPending = false
            if generation == self.generation { busy = false }
        }
        do {
            try await body()
        } catch {
            guard await acceptAuthentication(generation) else { return }
            notice = error.localizedDescription
        }
    }
}

/// Timing lines for the launch and search targets, printed to the app's
/// stdout (`xcrun simctl launch --console-pty`). Never includes vault data.
enum Metrics {
    static func record(_ name: String, since start: Date, extra: String = "") {
        let ms = Int(Date().timeIntervalSince(start) * 1000)
        print("deadbolt-metric \(name)=\(ms) \(extra)")
    }

    /// When the process started, from the kernel.
    static var processStart: Date? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
        let start = info.kp_proc.p_un.__p_starttime
        return Date(timeIntervalSince1970: TimeInterval(start.tv_sec) + TimeInterval(start.tv_usec) / 1_000_000)
    }

    @MainActor private static var launchRecorded = false

    /// Records process start to the first usable screen, once.
    @MainActor static func firstScreen(_ name: String) {
        guard !launchRecorded, let start = processStart else { return }
        launchRecorded = true
        record("launch_to_\(name)_ms", since: start)
    }
}
