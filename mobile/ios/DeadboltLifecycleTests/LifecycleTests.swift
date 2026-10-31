import XCTest
import Combine
import AuthenticationServices

/// Protocol.swift reads the wire version the Rust build generates; these
/// hostless tests never speak the wire protocol.
let generatedProtocolVersion: UInt32 = 0

/// These gates deliberately ignore cancellation, just like an already queued
/// synchronous FFI call. A late success must not reopen the UI or the core.
private actor Gate {
    private var entered = false
    private var released = false
    private var entrants: [CheckedContinuation<Void, Never>] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        entered = true
        entrants.forEach { $0.resume() }
        entrants.removeAll()
        if !released { await withCheckedContinuation { waiters.append($0) } }
    }

    func waitUntilEntered() async {
        if !entered { await withCheckedContinuation { entrants.append($0) } }
    }

    func release() {
        released = true
        waiters.forEach { $0.resume() }
        waiters.removeAll()
    }
}

private actor DelayedCore: CoreAPI {
    enum Call: Hashable { case status, unlock, lock, joinStart, joinStatus, joinCommitted, biometricToken, unlockBiometric, foreground, items, approvalPending, sync, identities }
    private var state: CoreStatus
    private var gates: [Call: Gate] = [:]
    private var counts: [Call: Int] = [:]
    private var observers: [Call: [(Int, CheckedContinuation<Void, Never>)]] = [:]
    private var pending: PendingApproval?
    private var responses: [(id: String, allow: Bool, key: Data)] = []
    private var queries: [String] = []

    init(initialized: Bool = true, biometricReady: Bool = false) {
        state = CoreStatus(initialized: initialized, unlocked: false, biometricReady: biometricReady)
    }

    func delay(_ call: Call, with gate: Gate) { gates[call] = gate }
    func count(_ call: Call) -> Int { counts[call, default: 0] }
    func snapshot() -> CoreStatus { state }
    func setApproval(_ approval: PendingApproval?) { pending = approval }
    func approvalResponses() -> [(id: String, allow: Bool, key: Data)] { responses }
    func searched() -> [String] { queries }
    func waitFor(_ call: Call, count: Int = 1) async {
        if counts[call, default: 0] < count {
            await withCheckedContinuation { observers[call, default: []].append((count, $0)) }
        }
    }

    private func record(_ call: Call) async {
        counts[call, default: 0] += 1
        let ready = observers[call, default: []].filter { $0.0 <= counts[call, default: 0] }
        observers[call]?.removeAll { $0.0 <= counts[call, default: 0] }
        ready.forEach { $0.1.resume() }
        if let gate = gates.removeValue(forKey: call) { await gate.wait() }
    }

    func status() async throws -> CoreStatus {
        let snapshot = state
        await record(.status)
        return snapshot
    }
    private var unlockFailure: CoreFailure?
    func failUnlock(with failure: CoreFailure?) { unlockFailure = failure }
    func unlock(passphrase: String) async throws {
        await record(.unlock)
        if let unlockFailure { throw unlockFailure }
        state.unlocked = true
    }
    func lock() async throws {
        state.unlocked = false
        await record(.lock)
    }
    func joinStart(passphrase: String) async throws -> JoinStart {
        await record(.joinStart)
        return JoinStart(code: "test-only-code")
    }
    func joinStatus() async throws -> JoinStatus {
        let locks = counts[.lock, default: 0]
        await record(.joinStatus)
        // Simulates a commit that won the persistence race with cancellation.
        state.initialized = true
        state.unlocked = counts[.lock, default: 0] == locks
        await record(.joinCommitted)
        return JoinStatus(state: .joined)
    }
    func joinCancel() async throws { try await lock() }
    func biometricToken() async throws -> Data {
        await record(.biometricToken)
        return Data([1])
    }
    func unlockBiometric(key: Data) async throws {
        await record(.unlockBiometric)
        state.unlocked = true
    }
    func biometricEnroll(key: Data, token: Data) async throws {}
    func foreground() async throws { await record(.foreground) }
    func sync() async throws { await record(.sync) }
    func items(query: String) async throws -> [ItemSummary] {
        queries.append(query)
        await record(.items)
        return [ItemSummary(id: "test", title: "Test login", kind: "login")]
    }
    func item(id: String) async throws -> ItemDetail { throw CancellationError() }
    func secret(id: String, field: String) async throws -> String { throw CancellationError() }
    func code(id: String) async throws -> OneTimeCode { throw CancellationError() }
    func approvalPending() async throws -> PendingApproval? {
        await record(.approvalPending)
        return pending
    }
    func approvalRespond(id: String, allow: Bool, key: Data) async throws {
        responses.append((id, allow, key))
        pending = nil
    }
    func credentialIdentities() async throws -> String {
        await record(.identities)
        return #"{"passwords":[]}"#
    }
}

/// The reasons the app asked the biometric sheet to show.
private actor Reasons {
    private var reasons: [String] = []
    func add(_ reason: String) { reasons.append(reason) }
    func all() -> [String] { reasons }
}

/// What the app handed to the system identity store.
private actor Published {
    private var snapshots: [String] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func add(_ json: String) {
        snapshots.append(json)
        waiters.forEach { $0.resume() }
        waiters.removeAll()
    }

    func all() -> [String] { snapshots }

    func waitForFirst() async {
        if snapshots.isEmpty { await withCheckedContinuation { waiters.append($0) } }
    }
}

@MainActor
private final class ModelRef {
    weak var model: AppModel?
}

@MainActor
final class LifecycleTests: XCTestCase {
    func testEverySearchReachesTheCoreWithoutDebounce() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        // Let the post-unlock sync and its refresh read settle first.
        for await state in model.$sync.values {
            if case .synced = state { break }
        }
        await core.waitFor(.items, count: 2)
        let before = await core.count(.items)
        let typed = Date()
        model.query = "00999"
        await core.waitFor(.items, count: before + 1)
        // The removed debounce waited 120 ms before any core read.
        XCTAssertLessThan(Date().timeIntervalSince(typed), 0.1)
        let last = await core.searched().last
        XCTAssertEqual(last, "00999")
        await model.lock()
    }

    /// Bounded: a lock that never comes fails instead of hanging the run.
    private func waitForLock(_ model: AppModel) async -> Bool {
        let deadline = Date().addingTimeInterval(2)
        while model.phase != .locked, Date() < deadline {
            try? await Task.sleep(for: .milliseconds(20))
        }
        return model.phase == .locked
    }

    /// Sync, approval polling and list reads are passive: five idle minutes
    /// after the last touch lock the vault however much they ran.
    func testPassiveWorkDoesNotHoldTheIdleLockOpen() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        let unlocked = Date()
        await model.unlock(passphrase: "test")
        for await state in model.$sync.values {
            if case .synced = state { break }
        }
        await core.waitFor(.approvalPending, count: 2)
        await model.syncNow()
        model.checkIdle(now: unlocked.addingTimeInterval(AppModel.idleLimit - 5))
        XCTAssertEqual(model.phase, .unlocked)
        // Measured from the unlock, not from the passive work (over 1 s later).
        model.checkIdle(now: unlocked.addingTimeInterval(AppModel.idleLimit + 0.5))
        let locked = await waitForLock(model)
        XCTAssertTrue(locked)
        XCTAssertTrue(model.items.isEmpty)
        let locks = await core.count(.lock)
        XCTAssertGreaterThanOrEqual(locks, 1)
    }

    /// A touch or a typed query restarts the five minutes.
    func testActivityRestartsTheIdleLock() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        let touched = Date().addingTimeInterval(1)
        try? await Task.sleep(for: .seconds(1))
        model.noteActivity()
        model.checkIdle(now: touched.addingTimeInterval(AppModel.idleLimit - 1))
        XCTAssertEqual(model.phase, .unlocked)
        model.query = "typed"
        model.checkIdle(now: Date().addingTimeInterval(AppModel.idleLimit - 1))
        XCTAssertEqual(model.phase, .unlocked)
        model.checkIdle(now: Date().addingTimeInterval(AppModel.idleLimit + 1))
        let locked = await waitForLock(model)
        XCTAssertTrue(locked)
        XCTAssertEqual(model.query, "")
    }

    /// Busy covers another unlock and AutoFill holding the vault alike.
    func testBusyUnlockSaysSomethingTrueForBothCauses() async {
        let core = DelayedCore()
        await core.failUnlock(with: CoreFailure(code: "Busy", message: "Another setup or unlock is running. Finish or cancel it first."))
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        XCTAssertEqual(model.phase, .locked)
        XCTAssertEqual(model.notice, "Deadbolt is busy with another unlock or AutoFill. Try again in a moment.")
        await core.failUnlock(with: CoreFailure(code: "Authentication", message: "The passphrase or biometric key did not unlock this device."))
        await model.unlock(passphrase: "wrong")
        XCTAssertEqual(model.notice, "The passphrase or biometric key did not unlock this device.")
    }

    func testSearchBurstRunsOneReadThenOnlyTheLatestQuery() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        for await state in model.$sync.values {
            if case .synced = state { break }
        }
        await core.waitFor(.items, count: 2)
        let before = await core.count(.items)
        let read = Gate()
        await core.delay(.items, with: read)
        model.query = "0"
        await read.waitUntilEntered()
        // Keystrokes while the uncancellable read runs only mark a rerun.
        for query in ["00", "009", "0099", "00999"] { model.query = query }
        await read.release()
        await core.waitFor(.items, count: before + 2)
        // Absence check: no further read follows the latest query.
        try? await Task.sleep(for: .milliseconds(150))
        let reads = await core.count(.items)
        XCTAssertEqual(reads, before + 2)
        let searched = await core.searched().suffix(2)
        XCTAssertEqual(Array(searched), ["0", "00999"])
        await model.lock()
    }

    func testIdentityPublicationWaitsForFirstListAndPublishesOnce() async {
        let core = DelayedCore()
        let published = Published()
        let ref = ModelRef()
        let model = AppModel(openCore: { core }, publishIdentities: { json in
            // Rows must be on screen before the snapshot is handed over.
            let loaded = await ref.model?.itemsLoaded ?? false
            await published.add(loaded ? json : "published before the first list")
        })
        ref.model = model
        model.scenePhaseChanged(to: .active)
        await model.start()
        let list = Gate()
        let sync = Gate()
        await core.delay(.items, with: list)
        // Hold the post-unlock sync so its own refresh can't publish first.
        await core.delay(.sync, with: sync)
        await model.unlock(passphrase: "test")
        await list.waitUntilEntered()
        // Rows come first: no identity snapshot while the first list runs,
        // even given time to start one.
        try? await Task.sleep(for: .milliseconds(150))
        let early = await core.count(.identities)
        XCTAssertEqual(early, 0)
        await list.release()
        await published.waitForFirst()
        XCTAssertTrue(model.itemsLoaded)
        let snapshots = await published.all()
        XCTAssertEqual(snapshots, [#"{"passwords":[]}"#])
        await model.lock()
        await sync.release()
    }

    func testIdentitySnapshotFinishingAfterBackgroundIsNotPublished() async {
        let core = DelayedCore()
        let published = Published()
        let model = AppModel(openCore: { core }, publishIdentities: { await published.add($0) })
        model.scenePhaseChanged(to: .active)
        await model.start()
        let snapshot = Gate()
        await core.delay(.identities, with: snapshot)
        await model.unlock(passphrase: "test")
        await snapshot.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        await core.waitFor(.lock)
        await snapshot.release()
        // Absence check: give the stale task time to finish and be dropped.
        try? await Task.sleep(for: .milliseconds(200))
        let snapshots = await published.all()
        XCTAssertTrue(snapshots.isEmpty)
        XCTAssertEqual(model.phase, .locked)
    }

    func testCancelledRefreshDoesNotWedgeManualSync() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        // Wait for the automatic post-unlock round to finish first.
        for await state in model.$sync.values {
            if case .synced = state { break }
        }
        let gate = Gate()
        await core.delay(.sync, with: gate)
        let sync = Task { await model.syncNow() }
        await gate.waitUntilEntered()
        sync.cancel()
        await gate.release()
        await sync.value
        XCTAssertEqual(model.sync, .idle)
        await model.syncNow()
        if case .synced = model.sync {} else { XCTFail("manual sync remained disabled") }
        await model.lock()
    }

    func testBackgroundPreservesStartupFailure() async {
        let model = AppModel(openCore: { throw CoreFailure(code: nil, message: "Storage unavailable") })
        await model.start()
        XCTAssertEqual(model.phase, .failed("Storage unavailable"))
        model.scenePhaseChanged(to: .background)
        XCTAssertEqual(model.phase, .failed("Storage unavailable"))
        await model.lock()
        XCTAssertEqual(model.phase, .failed("Storage unavailable"))
    }

    func testRejectedUnlockDuringLockDoesNotResetInputIdentity() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        let gate = Gate()
        await core.delay(.lock, with: gate)
        model.scenePhaseChanged(to: .background)
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .active)
        let generation = model.generation
        await model.unlock(passphrase: "still typed in the view")
        XCTAssertEqual(model.generation, generation)
        let unlocks = await core.count(.unlock)
        XCTAssertEqual(unlocks, 0)
        await gate.release()
    }

    func testForegroundDuringLockPromptsAfterLockFinishes() async {
        let core = DelayedCore(biometricReady: true)
        let model = AppModel(openCore: { core }, unseal: { _, _ in Data(repeating: 3, count: 32) }, biometricAvailability: { nil })
        await model.start()
        let gate = Gate()
        await core.delay(.lock, with: gate)
        model.scenePhaseChanged(to: .background)
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .active)
        let before = await core.count(.biometricToken)
        XCTAssertEqual(before, 0)
        await gate.release()
        for await phase in model.$phase.values {
            if phase == .unlocked { break }
        }
        let after = await core.count(.biometricToken)
        XCTAssertEqual(after, 1)
        await model.lock()
    }

    private func request(_ id: String = "request-a") -> PendingApproval {
        PendingApproval(id: id, origin: "test-computer-id", expiresAt: UInt64(Date().timeIntervalSince1970) + 120,
                        vault: "test-vault", item: "test-item", field: "password", title: "Test login",
                        originName: "Test computer", caller: "Verified socket peer; ancestry unverified")
    }

    private func waitForApproval(_ model: AppModel, id: String = "request-a") async {
        for await approval in model.$approval.values {
            if approval?.id == id { return }
        }
    }

    func testApprovalUnavailableDoesNotAllowAndDenyUsesNoKey() async {
        let core = DelayedCore(biometricReady: true)
        let pending = request()
        await core.setApproval(pending)
        let model = AppModel(openCore: { core }, biometricAvailability: { "No Secure Enclave in Simulator." })
        await model.start()
        model.scenePhaseChanged(to: .active)
        await model.unlock(passphrase: "test")
        await waitForApproval(model)
        await model.respondToApproval(pending, allow: true)
        XCTAssertEqual(model.approvalNotice, "No Secure Enclave in Simulator.")
        let before = await core.approvalResponses()
        XCTAssertTrue(before.isEmpty)
        await model.respondToApproval(pending, allow: false)
        let responses = await core.approvalResponses()
        XCTAssertEqual(responses.count, 1)
        XCTAssertEqual(responses.first?.id, pending.id)
        XCTAssertEqual(responses.first?.allow, false)
        XCTAssertEqual(responses.first?.key, Data())
        await model.lock()
    }

    func testApprovalAllowRequiresFreshKeyAndExactRequest() async {
        let core = DelayedCore(biometricReady: true)
        let pending = request()
        await core.setApproval(pending)
        let key = Data(repeating: 2, count: 32)
        let match = Gate()
        let reasons = Reasons()
        let model = AppModel(openCore: { core }, unseal: { _, reason in
            await reasons.add(reason)
            await match.wait()
            return key
        }, biometricAvailability: { nil })
        await model.start()
        model.scenePhaseChanged(to: .active)
        await model.unlock(passphrase: "test")
        await waitForApproval(model)
        let response = Task { await model.respondToApproval(pending, allow: true) }
        await match.waitUntilEntered()
        let before = await core.approvalResponses()
        XCTAssertTrue(before.isEmpty)
        await match.release()
        await response.value
        let responses = await core.approvalResponses()
        XCTAssertEqual(responses.count, 1)
        XCTAssertEqual(responses.first?.id, pending.id)
        XCTAssertEqual(responses.first?.allow, true)
        XCTAssertEqual(responses.first?.key, key)
        // The system sheet names this exact read, not a vault unlock.
        let asked = await reasons.all()
        XCTAssertEqual(asked, ["Allow Test computer to read password from Test login"])
        await model.lock()
    }

    func testBiometricUnlockAsksToUnlockDeadbolt() async {
        let core = DelayedCore(biometricReady: true)
        let reasons = Reasons()
        let model = AppModel(openCore: { core }, unseal: { _, reason in
            await reasons.add(reason)
            return Data(repeating: 1, count: 32)
        }, biometricAvailability: { nil })
        model.scenePhaseChanged(to: .active)
        await model.start()
        XCTAssertEqual(model.phase, .unlocked)
        let asked = await reasons.all()
        XCTAssertEqual(asked, ["Unlock Deadbolt"])
        await model.lock()
    }

    func testApprovalBiometricCompletionAfterBackgroundCannotRespond() async {
        let core = DelayedCore(biometricReady: true)
        let pending = request()
        await core.setApproval(pending)
        let match = Gate()
        let model = AppModel(openCore: { core }, unseal: { _, _ in
            await match.wait()
            return Data(repeating: 2, count: 32)
        }, biometricAvailability: { nil })
        await model.start()
        model.scenePhaseChanged(to: .active)
        await model.unlock(passphrase: "test")
        await waitForApproval(model)
        let response = Task { await model.respondToApproval(pending, allow: true) }
        await match.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        XCTAssertNil(model.approval)
        await core.waitFor(.lock)
        await match.release()
        await response.value
        let responses = await core.approvalResponses()
        XCTAssertTrue(responses.isEmpty)
        XCTAssertEqual(model.phase, .locked)
    }

    func testApprovalReplacementWhileMatchingCannotRespondToOldRequest() async {
        let core = DelayedCore(biometricReady: true)
        let pending = request()
        await core.setApproval(pending)
        let match = Gate()
        let model = AppModel(openCore: { core }, unseal: { _, _ in
            await match.wait()
            return Data(repeating: 2, count: 32)
        }, biometricAvailability: { nil })
        await model.start()
        model.scenePhaseChanged(to: .active)
        await model.unlock(passphrase: "test")
        await waitForApproval(model)
        let response = Task { await model.respondToApproval(pending, allow: true) }
        await match.waitUntilEntered()
        await core.setApproval(request("request-b"))
        await waitForApproval(model, id: "request-b")
        await match.release()
        await response.value
        let responses = await core.approvalResponses()
        XCTAssertTrue(responses.isEmpty)
        XCTAssertEqual(model.approval?.id, "request-b")
        await model.lock()
    }

    private func model(_ core: DelayedCore) -> AppModel {
        let model = AppModel(openCore: { core })
        model.scenePhaseChanged(to: .active)
        return model
    }

    func testForegroundUnlockWorksAndBackgroundRejectsNewUnlock() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        XCTAssertEqual(model.phase, .unlocked)
        XCTAssertEqual(model.status?.unlocked, true)
        model.query = "test"
        model.scenePhaseChanged(to: .background)
        XCTAssertEqual(model.phase, .locked)
        XCTAssertEqual(model.query, "")
        XCTAssertTrue(model.items.isEmpty)
        XCTAssertFalse(model.itemsLoaded)
        XCTAssertEqual(model.sync, .idle)
        await model.unlock(passphrase: "test")
        let unlocks = await core.count(.unlock)
        XCTAssertEqual(unlocks, 1)
        await core.waitFor(.lock)
    }

    func testForegroundReconnectDoesNotBlockBrowsingOrLock() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        await model.unlock(passphrase: "test")
        await core.waitFor(.items)
        let gate = Gate()
        await core.delay(.foreground, with: gate)
        model.scenePhaseChanged(to: .active)
        await gate.waitUntilEntered()
        let reads = await core.count(.items)
        model.query = "another search"
        await core.waitFor(.items, count: reads + 1)
        XCTAssertEqual(model.phase, .unlocked)
        await model.lock()
        XCTAssertEqual(model.phase, .locked)
        await gate.release()
    }

    func testUnlockedStatusArrivingAfterBackgroundIsDiscarded() async {
        let core = DelayedCore()
        let model = model(core)
        await model.start()
        let gate = Gate()
        await core.delay(.status, with: gate)
        let unlock = Task { await model.unlock(passphrase: "test") }
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        await core.waitFor(.lock)
        await gate.release()
        await unlock.value
        XCTAssertEqual(model.phase, .locked)
        XCTAssertEqual(model.status?.unlocked, false)
        XCTAssertTrue(model.items.isEmpty)
        let state = await core.snapshot()
        XCTAssertFalse(state.unlocked)
    }

    func testLockBeforeQueuedUnlockStartsRelocksLateSuccess() async {
        let core = DelayedCore()
        let gate = Gate()
        await core.delay(.unlock, with: gate)
        let model = model(core)
        await model.start()
        let unlock = Task { await model.unlock(passphrase: "test") }
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        // These assertions run before the asynchronous core lock gets a turn.
        XCTAssertEqual(model.phase, .locked)
        XCTAssertFalse(model.busy)
        XCTAssertTrue(model.items.isEmpty)
        await core.waitFor(.lock)
        await gate.release()
        await unlock.value
        let state = await core.snapshot()
        let locks = await core.count(.lock)
        XCTAssertFalse(state.unlocked)
        XCTAssertGreaterThanOrEqual(locks, 2)
        XCTAssertEqual(model.phase, .locked)
        XCTAssertFalse(model.status?.unlocked ?? true)
    }

    func testBackgroundCancelsJoinBeforeCodeReturns() async {
        let core = DelayedCore(initialized: false)
        let gate = Gate()
        await core.delay(.joinStart, with: gate)
        let model = model(core)
        await model.start()
        let join = Task { await model.startJoin(passphrase: "test") }
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        XCTAssertEqual(model.phase, .setup)
        XCTAssertFalse(model.busy)
        await core.waitFor(.lock)
        await gate.release()
        await join.value
        let polls = await core.count(.joinStatus)
        let locks = await core.count(.lock)
        XCTAssertEqual(polls, 0)
        XCTAssertGreaterThanOrEqual(locks, 2)
        XCTAssertEqual(model.phase, .setup)
    }

    func testPersistedJoinCompletingAfterBackgroundStaysLocked() async {
        let core = DelayedCore(initialized: false)
        let gate = Gate()
        await core.delay(.joinStatus, with: gate)
        let model = model(core)
        await model.start()
        await model.startJoin(passphrase: "test")
        XCTAssertEqual(model.phase, .joining(code: "test-only-code"))
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        XCTAssertEqual(model.phase, .setup)
        await core.waitFor(.lock)
        await gate.release()
        await core.waitFor(.joinCommitted)
        // A foreground refresh must discover the persisted vault, not setup.
        model.scenePhaseChanged(to: .active)
        await model.lock()
        let state = await core.snapshot()
        XCTAssertTrue(state.initialized)
        XCTAssertFalse(state.unlocked)
        XCTAssertEqual(model.status?.initialized, true)
        XCTAssertEqual(model.phase, .locked)
    }

    func testOpenCompletingInBackgroundLocksAndDoesNotAutoPrompt() async {
        let core = DelayedCore(biometricReady: true)
        let open = Gate()
        let model = AppModel(openCore: { await open.wait(); return core }, biometricAvailability: { nil })
        model.scenePhaseChanged(to: .active)
        let start = Task { await model.start() }
        await open.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        XCTAssertEqual(model.phase, .locked)
        await open.release()
        await start.value
        let tokens = await core.count(.biometricToken)
        let locks = await core.count(.lock)
        XCTAssertEqual(tokens, 0)
        XCTAssertGreaterThanOrEqual(locks, 1)
        XCTAssertEqual(model.phase, .locked)
        XCTAssertEqual(model.status?.initialized, true)
    }

    func testLateStatusCannotReplaceBackgroundStateOrAutoPrompt() async {
        let core = DelayedCore(biometricReady: true)
        let gate = Gate()
        await core.delay(.status, with: gate)
        let model = AppModel(openCore: { core }, biometricAvailability: { nil })
        model.scenePhaseChanged(to: .active)
        let start = Task { await model.start() }
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        await core.waitFor(.lock)
        await gate.release()
        await start.value
        let tokens = await core.count(.biometricToken)
        XCTAssertEqual(tokens, 0)
        XCTAssertEqual(model.phase, .locked)
    }

    func testLateBiometricTokenNeverStartsPrompt() async {
        let core = DelayedCore(biometricReady: true)
        let gate = Gate()
        await core.delay(.biometricToken, with: gate)
        let model = AppModel(openCore: { core }, unseal: { _, _ in
            XCTFail("stale token started a biometric prompt")
            throw CancellationError()
        }, biometricAvailability: { nil })
        model.scenePhaseChanged(to: .active)
        let start = Task { await model.start() }
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        await core.waitFor(.lock)
        await gate.release()
        await start.value
        let unlocks = await core.count(.unlockBiometric)
        XCTAssertEqual(unlocks, 0)
        XCTAssertEqual(model.phase, .locked)
    }

    func testLateBiometricMatchDoesNotSubmitKeyAfterForegroundReturn() async {
        let core = DelayedCore(biometricReady: true)
        let match = Gate()
        let model = AppModel(openCore: { core }, unseal: { _, _ in
            await match.wait()
            return Data(repeating: 1, count: 32)
        }, biometricAvailability: { nil })
        model.scenePhaseChanged(to: .active)
        let start = Task { await model.start() }
        await match.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        await core.waitFor(.lock)
        model.scenePhaseChanged(to: .active)
        await match.release()
        await start.value
        let unlocks = await core.count(.unlockBiometric)
        XCTAssertEqual(unlocks, 0)
        XCTAssertEqual(model.phase, .locked)
    }

    func testLateBiometricCoreUnlockRelocks() async {
        let core = DelayedCore(biometricReady: true)
        let gate = Gate()
        await core.delay(.unlockBiometric, with: gate)
        let model = AppModel(openCore: { core }, unseal: { _, _ in
            Data(repeating: 1, count: 32)
        }, biometricAvailability: { nil })
        model.scenePhaseChanged(to: .active)
        let start = Task { await model.start() }
        await gate.waitUntilEntered()
        model.scenePhaseChanged(to: .background)
        await core.waitFor(.lock)
        await gate.release()
        await start.value
        let state = await core.snapshot()
        XCTAssertFalse(state.unlocked)
        XCTAssertEqual(model.phase, .locked)
    }
}

/// A fake in-process provider client: unlocked, two synthetic logins, and a
/// record of every command each extension request sent.
private final class FakeProviderClient: AutofillAgentClient, @unchecked Sendable {
    private let lock = NSLock()
    private var request = 0
    private var sent: [(request: Int, command: AutofillCommand)] = []

    /// Scripted refusals: the next fill, or the next status, fails with this.
    var fillError: AgentCallError?
    var statusError: AgentCallError?
    /// Runs just before a successful fill reply is returned.
    var beforeFillReply: (@Sendable () async -> Void)?

    var fills: [(request: Int, command: AutofillCommand)] {
        lock.lock(); defer { lock.unlock() }
        return sent.filter { if case .autofillFill = $0.command { return true }; return false }
    }

    var lists: Int {
        lock.lock(); defer { lock.unlock() }
        return sent.filter { if case .autofillList = $0.command { return true }; return false }.count
    }

    func beginRequest(_ request: ProviderRequest) {
        lock.lock(); self.request += 1; lock.unlock()
    }

    func endRequest() {}

    func send(_ command: AutofillCommand, timeout: TimeInterval, handle: AutofillCallHandle?) async throws -> AutofillReply {
        let (fillError, statusError) = lock.withLock { () -> (AgentCallError?, AgentCallError?) in
            sent.append((request, command))
            return (self.fillError, self.statusError)
        }
        switch command {
        case .autofillStatus:
            if let statusError {
                lock.withLock { self.statusError = nil }
                throw statusError
            }
            return .autofillStatus(AutofillStatusReply(initialized: true, unlocked: true, touchIdReady: false))
        case let .autofillList(services, _, _, _):
            let logins = ["one", "two"].map {
                SiteLogin(login: LoginRef(vault: "vault", item: $0), vault: "Synthetic", title: "Synthetic \($0)",
                          username: "synthetic-\($0)@example.test", hasPassword: true, service: services.first)
            }
            return .autofillList(AutofillListReply(logins: logins, identitiesHash: ""))
        case .autofillFill:
            if let fillError {
                lock.withLock { self.fillError = nil }
                throw fillError
            }
            if let hook = lock.withLock({ () -> (@Sendable () async -> Void)? in
                defer { self.beforeFillReply = nil }
                return self.beforeFillReply
            }) {
                await hook()
            }
            return .autofillFill(AutofillFillReply(values: SiteValues(username: "synthetic", password: "synthetic-password"), identitiesHash: ""))
        default:
            return .done
        }
    }
}

@MainActor
private final class RecordingCompleter: ExtensionContextCompleting {
    var passwords: [String] = []
    func completePassword(user: String, password: String, afterDelivery: (@Sendable () async -> Void)?) { passwords.append(password) }
    func completeExtensionConfiguration() {}
    func cancelRequest(code: ASExtensionError.Code) {}
    func completeOneTimeCode(_ code: String) {}
    func completePasskeyAssertion(_ assertion: PasskeyAssertion) {}
    func completePasskeyRegistration(_ registration: PasskeyRegistration) {}
}

private struct NoLauncher: AgentLaunching {
    func startInBackground() async -> Bool { false }
    func openContainingApp() async -> Bool { false }
}

@MainActor
final class ProviderPickerTests: XCTestCase {
    private func waitForPicker(_ model: AutoFillControllerModel) async -> Bool {
        let deadline = Date().addingTimeInterval(2)
        while model.screen != .picker, Date() < deadline {
            try? await Task.sleep(for: .milliseconds(5))
        }
        return model.screen == .picker
    }

    /// A pick lets the list go and pauses briefly before its fill. A new
    /// request arriving in that pause owns the client: the old pick must not
    /// send anything, and nothing may complete with its login.
    func testPickReplacedDuringItsPauseNeverFills() async {
        let client = FakeProviderClient()
        let completer = RecordingCompleter()
        let model = AutoFillControllerModel(client: client, launcher: NoLauncher(), identitySyncer: nil, completer: completer)
        let site = AutofillService(identifier: "site-00042.example.test", kind: .domain)
        model.beginCredentialList(services: [site])
        let shown = await waitForPicker(model)
        XCTAssertTrue(shown)
        model.fillRow(0)
        // The replacement request arrives inside the pick's pause.
        model.beginCredentialList(services: [AutofillService(identifier: "other.example.test", kind: .domain)])
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertTrue(client.fills.isEmpty, "a replaced pick sent a fill")
        XCTAssertTrue(completer.passwords.isEmpty)
        let shownAgain = await waitForPicker(model)
        XCTAssertTrue(shownAgain)
        // The new request's picker is fully usable and fills its own pick.
        XCTAssertFalse(model.filling)
        model.fillRow(0)
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(client.fills.map(\.request), [2])
        XCTAssertEqual(completer.passwords, ["synthetic-password"])
    }

    /// A new request replaces the pick just as its successful reply comes
    /// back: the old login never completes into the new request.
    func testPickReplacedAsItsReplyReturnsNeverCompletes() async {
        let client = FakeProviderClient()
        let completer = RecordingCompleter()
        let model = AutoFillControllerModel(client: client, launcher: NoLauncher(), identitySyncer: nil, completer: completer)
        model.beginCredentialList(services: [AutofillService(identifier: "site-00042.example.test", kind: .domain)])
        let shown = await waitForPicker(model)
        XCTAssertTrue(shown)
        client.beforeFillReply = { @MainActor [weak model] in
            model?.beginCredentialList(services: [AutofillService(identifier: "other.example.test", kind: .domain)])
        }
        model.fillRow(0)
        try? await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(client.fills.count, 1)
        XCTAssertTrue(completer.passwords.isEmpty, "a replaced pick delivered its password into the new request")
        let shownAgain = await waitForPicker(model)
        XCTAssertTrue(shownAgain)
        XCTAssertFalse(model.filling)
    }

    /// Face ID cancelled during a pick's fill (the list already let go): the
    /// sheet says it is locked and neither relists nor prompts again.
    func testCancelledFaceIDDuringPickShowsLockedWithoutRelisting() async {
        let client = FakeProviderClient()
        let completer = RecordingCompleter()
        let model = AutoFillControllerModel(client: client, launcher: NoLauncher(), identitySyncer: nil, completer: completer)
        model.beginCredentialList(services: [AutofillService(identifier: "site-00042.example.test", kind: .domain)])
        let shown = await waitForPicker(model)
        XCTAssertTrue(shown)
        XCTAssertEqual(client.lists, 1)
        client.fillError = .cancelled
        model.fillRow(0)
        try? await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(client.lists, 1, "a cancelled Face ID relisted")
        if case .locked = model.screen {} else { XCTFail("expected the locked screen, got \(model.screen)") }
        XCTAssertTrue(completer.passwords.isEmpty)
    }

    /// The quiet busy presentation belongs to the failure it was set for.
    func testBusyPresentationDoesNotOutliveItsFailure() async {
        let client = FakeProviderClient()
        let completer = RecordingCompleter()
        let model = AutoFillControllerModel(client: client, launcher: NoLauncher(), identitySyncer: nil, completer: completer)
        client.statusError = .agentError(code: .busy, message: "The app still has the vault open.")
        model.beginCredentialList(services: [AutofillService(identifier: "site-00042.example.test", kind: .domain)])
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertTrue(model.failureIsBusy)
        client.statusError = .agentError(code: .failed, message: "Something else went wrong.")
        model.retryConnection()
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(model.screen, .failed("Something else went wrong."))
        XCTAssertFalse(model.failureIsBusy, "a later non-busy failure kept the busy wording")
        model.retryConnection()
        let shown = await waitForPicker(model)
        XCTAssertTrue(shown)
        XCTAssertFalse(model.failureIsBusy)
    }

    /// Without interference the pick fills exactly once.
    func testPickFillsOnce() async {
        let client = FakeProviderClient()
        let completer = RecordingCompleter()
        let model = AutoFillControllerModel(client: client, launcher: NoLauncher(), identitySyncer: nil, completer: completer)
        model.beginCredentialList(services: [AutofillService(identifier: "site-00042.example.test", kind: .domain)])
        let shown = await waitForPicker(model)
        XCTAssertTrue(shown)
        model.fillRow(0)
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(client.fills.count, 1)
        XCTAssertEqual(completer.passwords, ["synthetic-password"])
    }
}
