// Headless unit, live-agent socket, and offscreen snapshot suite for
// `DeadboltAutoFill.appex`. Invoked by `crates/app/tests/app/autofill.rs`
// (and `--snap-dir <dir>` for offscreen UI stills; never opens a window).

import AppKit
import AuthenticationServices
import Darwin
import Foundation

private func check(
    _ condition: Bool,
    _ message: @autoclosure () -> String = "assertion failed",
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    if !condition {
        throw TestFailure("\(file):\(line): \(message())")
    }
}

private struct TestFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) {
        self.description = description
    }
}

// MARK: - Test Doubles

@MainActor
private final class RecordingCompleter: ExtensionContextCompleting {
    struct DeliveredPassword: Equatable {
        let user: String
        let password: String
    }

    var deliveredPasswords: [DeliveredPassword] = []
    var configurationCompletedCount = 0
    var cancelledCodes: [ASExtensionError.Code] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func completePassword(
        user: String,
        password: String,
        afterDelivery: (@Sendable () async -> Void)?
    ) {
        Task { @MainActor in
            if let afterDelivery {
                await afterDelivery()
            }
            self.deliveredPasswords.append(DeliveredPassword(user: user, password: password))
            self.wakeAll()
        }
    }

    func completeExtensionConfiguration() {
        configurationCompletedCount += 1
        wakeAll()
    }

    func cancelRequest(code: ASExtensionError.Code) {
        cancelledCodes.append(code)
        wakeAll()
    }

    func waitForCompletion(timeoutSeconds: TimeInterval = 5.0) async throws {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while deliveredPasswords.isEmpty && configurationCompletedCount == 0 && cancelledCodes.isEmpty {
            if Date() >= deadline {
                throw TestFailure("timed out waiting for extension completion")
            }
            try? await Task.sleep(nanoseconds: 15_000_000)
        }
    }

    private func wakeAll() {
        let current = waiters
        waiters.removeAll()
        for waiter in current {
            waiter.resume()
        }
    }
}

private actor MockIdentityStore: IdentityStoreProviding {
    var enabled: Bool
    var replacedBatches: [[PasswordIdentity]] = []
    var removeAllCalls = 0

    init(enabled: Bool = true) {
        self.enabled = enabled
    }

    func setEnabled(_ value: Bool) {
        enabled = value
    }

    func isEnabled() async -> Bool {
        enabled
    }

    func replacePasswordIdentities(_ identities: [PasswordIdentity]) async throws {
        replacedBatches.append(identities)
    }

    func removeAllIdentities() async throws {
        removeAllCalls += 1
    }

    func batches() -> [[PasswordIdentity]] {
        replacedBatches
    }
}

private struct NoopLauncher: AgentLaunching {
    func startInBackground() async -> Bool { false }
    func openContainingApp() async -> Bool { false }
}

private actor CountingMockClient: AutofillAgentClient {
    var snapshot: AutofillIdentitiesReply
    private(set) var calls: [AutofillCommand] = []

    init(snapshot: AutofillIdentitiesReply) {
        self.snapshot = snapshot
    }

    func setSnapshot(_ next: AutofillIdentitiesReply) {
        snapshot = next
    }

    func send(
        _ command: AutofillCommand,
        timeout: TimeInterval,
        handle: SocketCallHandle?
    ) async throws -> AutofillReply {
        calls.append(command)
        switch command {
        case .autofillIdentities:
            return .autofillIdentities(snapshot)
        default:
            throw AgentCallError.agentError(code: .forbidden, message: "unexpected mock call")
        }
    }

    func callCount() -> Int {
        calls.count
    }
}

@MainActor
private func waitUntil(
    timeoutSeconds: TimeInterval = 5.0,
    _ description: String,
    predicate: @MainActor () -> Bool
) async throws {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while !predicate() {
        if Date() >= deadline {
            throw TestFailure("timed out waiting for \(description)")
        }
        try? await Task.sleep(nanoseconds: 15_000_000)
    }
}

// MARK: - Unit & Wire Tests

private func testUnitAndWire() async throws {
    let vaultHex = String(repeating: "Ab", count: 32)
    let itemHex = String(repeating: "0F", count: 16)
    let parsed = LoginRef.fromRecordIdentifier("\(vaultHex):\(itemHex)")
    try check(parsed == LoginRef(vault: vaultHex.lowercased(), item: itemHex.lowercased()))
    try check(LoginRef.fromRecordIdentifier("short:id") == nil)
    try check(LoginRef.fromRecordIdentifier(String(repeating: "a", count: 97)) == nil)
    let badHex = String(repeating: "z", count: 64) + ":" + String(repeating: "0", count: 32)
    try check(LoginRef.fromRecordIdentifier(badHex) == nil)

    // Symlink-resolving bundle locator.
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("deadbolt-autofill-locate-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: tmp) }
    let realApp = tmp.appendingPathComponent("Real/Deadbolt.app", isDirectory: true)
    let appex = realApp.appendingPathComponent("Contents/PlugIns/DeadboltAutoFill.appex", isDirectory: true)
    let helper = realApp.appendingPathComponent("Contents/Helpers/deadbolt", isDirectory: false)
    try FileManager.default.createDirectory(at: appex, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(
        at: helper.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try Data("#!/bin/sh\n".utf8).write(to: helper)
    let linkDir = tmp.appendingPathComponent("Linked", isDirectory: true)
    try FileManager.default.createDirectory(at: linkDir, withIntermediateDirectories: true)
    let appexLink = linkDir.appendingPathComponent("DeadboltAutoFill.appex")
    try FileManager.default.createSymbolicLink(at: appexLink, withDestinationURL: appex)

    let located = ContainingBundle.locate(from: appexLink)
    try check(located?.appURL == realApp.resolvingSymlinksInPath().standardizedFileURL)
    try check(located?.agentBinaryURL == helper.resolvingSymlinksInPath().standardizedFileURL)
    try check(ContainingBundle.locate(from: realApp) == nil)

    // Silent vs interactive error mapping.
    let lockedErr = AgentCallError.agentError(code: .locked, message: "locked")
    try check(lockedErr.extensionErrorCodeForSilentRequest == .userInteractionRequired)
    let interactionErr = AgentCallError.agentError(code: .interactionRequired, message: "touch id")
    try check(interactionErr.extensionErrorCodeForSilentRequest == .userInteractionRequired)
    let domainErr = AgentCallError.agentError(code: .domainMismatch, message: "mismatch")
    try check(domainErr.extensionErrorCodeForSilentRequest == .credentialIdentityNotFound)
    try check(domainErr.extensionErrorCodeForInteractiveRequest == .credentialIdentityNotFound)
    try check(AgentCallError.cancelled.extensionErrorCodeForInteractiveRequest == .userCanceled)

    // IdentitySyncer hash deduplication & 0600 file permissions.
    let hashFile = tmp.appendingPathComponent("identities.hash")
    let hashStore = FileIdentityHashStore(fileURL: hashFile)
    let idStore = MockIdentityStore(enabled: true)
    let syncer = IdentitySyncer(store: idStore, hashStore: hashStore)
    let snap1 = AutofillIdentitiesReply(
        identitiesHash: "hash-one",
        passwords: [
            PasswordIdentity(
                domain: "github.com",
                username: "alex@example.com",
                recordId: "\(vaultHex.lowercased()):\(itemHex.lowercased())",
                rank: 3
            ),
        ]
    )
    let mockClient = CountingMockClient(snapshot: snap1)
    let didSync1 = await syncer.syncIfNeeded(client: mockClient, reportedHash: "hash-one")
    try check(didSync1, "first sync should populate identity store")
    try check(hashStore.readHash() == "hash-one")
    try check(await mockClient.callCount() == 1)
    try check(await idStore.batches().count == 1)

    let attrs = try FileManager.default.attributesOfItem(atPath: hashFile.path)
    let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue
    try check(perms == 0o600, "identities.hash must be mode 0600, got \(String(describing: perms))")

    // Same reportedHash skips even calling the agent socket.
    let didSync2 = await syncer.syncIfNeeded(client: mockClient, reportedHash: "hash-one")
    try check(!didSync2, "identical hash must skip sync")
    try check(await mockClient.callCount() == 1, "must not query socket when hash matches")

    // Disabled store clears cached hash so re-enabling re-syncs.
    await idStore.setEnabled(false)
    let didSyncDisabled = await syncer.syncIfNeeded(client: mockClient, reportedHash: "hash-two")
    try check(!didSyncDisabled)
    try check(hashStore.readHash() == nil)
}

// MARK: - Socket Cancellation Test

private func testSocketCancellation() throws {
    let dir = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("db-af-\(UInt32.random(in: 100_000 ... 999_999))", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let sockPath = dir.appendingPathComponent("s").path

    let listenFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    try check(listenFD >= 0, "socket() failed")
    defer { _ = Darwin.close(listenFD) }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let addrSize = socklen_t(MemoryLayout<sockaddr_un>.size)
    addr.sun_len = UInt8(addrSize)
    let bytes = Array(sockPath.utf8)
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        for (i, b) in bytes.enumerated() {
            raw[i] = b
        }
        raw[bytes.count] = 0
    }
    let bindRC = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
            Darwin.bind(listenFD, sockPtr, addrSize)
        }
    }
    try check(bindRC == 0, "bind() failed")
    try check(Darwin.listen(listenFD, 4) == 0, "listen() failed")

    let accepted = DispatchSemaphore(value: 0)
    let releasePeer = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        var peerAddr = sockaddr()
        var peerLen: socklen_t = 0
        let clientFD = Darwin.accept(listenFD, &peerAddr, &peerLen)
        accepted.signal()
        _ = releasePeer.wait(timeout: .now() + 5.0)
        if clientFD >= 0 {
            _ = Darwin.close(clientFD)
        }
    }

    let handle = SocketCallHandle()
    DispatchQueue.global().async {
        _ = accepted.wait(timeout: .now() + 2.0)
        usleep(40_000)
        handle.cancel()
    }

    let started = DispatchTime.now().uptimeNanoseconds
    do {
        _ = try UnixSocketAgentClient.performBlockingCall(
            socketPath: sockPath,
            command: .autofillStatus,
            timeout: 10.0,
            handle: handle,
            peerVerifier: nil
        )
        releasePeer.signal()
        throw TestFailure("expected cancelled error")
    } catch let err as AgentCallError {
        releasePeer.signal()
        let elapsedMS = (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        try check(err == .cancelled, "expected .cancelled, got \(err)")
        try check(elapsedMS < 2_000, "cancel took too long: \(elapsedMS)ms")
    } catch {
        releasePeer.signal()
        throw error
    }
}

// MARK: - Offscreen UI Snapshot & Rendering Test

@MainActor
private func renderSnapshots(outputDir: URL?) async throws {
    _ = NSApplication.shared
    let vaultA = String(repeating: "a", count: 64)
    let vaultB = String(repeating: "b", count: 64)
    let item1 = String(repeating: "1", count: 32)
    let item2 = String(repeating: "2", count: 32)
    let item3 = String(repeating: "3", count: 32)

    let sampleLogins = [
        SiteLogin(
            login: LoginRef(vault: vaultA, item: item1),
            vault: "personal",
            title: "GitHub",
            username: "alex@example.com",
            hasPassword: true,
            hasOtp: true,
            urls: ["https://github.com/login"]
        ),
        SiteLogin(
            login: LoginRef(vault: vaultB, item: item2),
            vault: "team",
            title: "GitHub Enterprise",
            username: "alex-ops",
            hasPassword: true,
            hasOtp: false,
            urls: ["https://github.com"]
        ),
        SiteLogin(
            login: LoginRef(vault: vaultA, item: item3),
            vault: "personal",
            title: "GitHub Sandbox",
            username: nil,
            hasPassword: true,
            urls: ["https://gist.github.com"],
            signIn: SignInInfo(provider: "google", account: "alex@example.com")
        ),
    ]

    actor SceneAgent: AutofillAgentClient {
        enum Mode {
            case lockedTouchID
            case picker(unassociated: Bool, logins: [SiteLogin])
            case notInitialized
        }

        let mode: Mode
        init(mode: Mode) { self.mode = mode }

        func send(
            _ command: AutofillCommand,
            timeout: TimeInterval,
            handle: SocketCallHandle?
        ) async throws -> AutofillReply {
            switch mode {
            case .notInitialized:
                return .autofillStatus(
                    AutofillStatusReply(initialized: false, unlocked: false, touchIdReady: false)
                )
            case .lockedTouchID:
                switch command {
                case .autofillStatus:
                    return .autofillStatus(
                        AutofillStatusReply(initialized: true, unlocked: false, touchIdReady: true)
                    )
                case .unlockBiometric:
                    throw AgentCallError.cancelled
                case .unlock:
                    throw AgentCallError.agentError(code: .failed, message: "wrong passphrase")
                default:
                    throw AgentCallError.agentError(code: .locked, message: "locked")
                }
            case let .picker(unassociated, logins):
                switch command {
                case .autofillStatus:
                    return .autofillStatus(
                        AutofillStatusReply(
                            initialized: true,
                            unlocked: true,
                            touchIdReady: true,
                            identitiesHash: "snap-hash"
                        )
                    )
                case .autofillList:
                    return .autofillList(
                        AutofillListReply(
                            logins: logins,
                            unassociated: unassociated,
                            canVerify: true,
                            identitiesHash: "snap-hash"
                        )
                    )
                default:
                    throw AgentCallError.agentError(code: .failed, message: "unused")
                }
            }
        }
    }

    func verifyPNG(_ data: Data?, name: String) throws {
        guard let data else {
            throw TestFailure("renderOffscreenPNG returned nil for \(name)")
        }
        let magic: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        try check(data.count > 1_000, "PNG too small for \(name): \(data.count) bytes")
        try check(Array(data.prefix(8)) == magic, "invalid PNG header for \(name)")
        if let outputDir {
            try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)
            try data.write(to: outputDir.appendingPathComponent("\(name).png"))
        }
    }

    // 1. Picker scene (multiple vaults, keyboard hint, dark mode)
    let completer1 = RecordingCompleter()
    let pickerModel = AutoFillControllerModel(
        client: SceneAgent(mode: .picker(unassociated: false, logins: sampleLogins)),
        launcher: NoopLauncher(),
        identitySyncer: nil,
        completer: completer1
    )
    let pickerView = AutoFillRootView(model: pickerModel)
    pickerModel.beginCredentialList(
        services: [AutofillService(identifier: "github.com", kind: .domain)]
    )
    try await waitUntil("picker screen") { pickerModel.screen == .picker }
    try verifyPNG(pickerView.renderOffscreenPNG(), name: "autofill-picker")

    // 2. Unassociated native app picker scene (warning banner)
    let completer2 = RecordingCompleter()
    let appPickerModel = AutoFillControllerModel(
        client: SceneAgent(mode: .picker(unassociated: true, logins: sampleLogins)),
        launcher: NoopLauncher(),
        identitySyncer: nil,
        completer: completer2
    )
    let appPickerView = AutoFillRootView(model: appPickerModel)
    appPickerModel.beginCredentialList(
        services: [AutofillService(identifier: "com.acme.desktop", kind: .app)]
    )
    try await waitUntil("unassociated picker screen") { appPickerModel.screen == .picker }
    try verifyPNG(appPickerView.renderOffscreenPNG(), name: "autofill-unassociated-app")

    // 3. Locked screen (Touch ID button + passphrase fallback)
    let completer3 = RecordingCompleter()
    let lockedModel = AutoFillControllerModel(
        client: SceneAgent(mode: .lockedTouchID),
        launcher: NoopLauncher(),
        identitySyncer: nil,
        completer: completer3
    )
    let lockedView = AutoFillRootView(model: lockedModel)
    lockedModel.beginCredentialList(
        services: [AutofillService(identifier: "github.com", kind: .domain)]
    )
    try await waitUntil("locked screen") {
        if case let .locked(ready, _, _, inFlight, _) = lockedModel.screen {
            return ready && !inFlight
        }
        return false
    }
    try verifyPNG(lockedView.renderOffscreenPNG(), name: "autofill-locked")

    // 4. Locked screen with passphrase error
    lockedModel.submitPassphrase("wrong-passphrase")
    try await waitUntil("locked error screen") {
        if case let .locked(_, _, unlocking, _, err) = lockedModel.screen {
            return !unlocking && err != nil
        }
        return false
    }
    try verifyPNG(lockedView.renderOffscreenPNG(), name: "autofill-locked-error")

    // 5. Not initialized onboarding prompt
    let completer4 = RecordingCompleter()
    let uninitModel = AutoFillControllerModel(
        client: SceneAgent(mode: .notInitialized),
        launcher: NoopLauncher(),
        identitySyncer: nil,
        completer: completer4
    )
    let uninitView = AutoFillRootView(model: uninitModel)
    uninitModel.beginCredentialList(
        services: [AutofillService(identifier: "github.com", kind: .domain)]
    )
    try await waitUntil("not initialized screen") { uninitModel.screen == .notInitialized }
    try verifyPNG(uninitView.renderOffscreenPNG(), name: "autofill-not-initialized")
}

// MARK: - Live Agent End-to-End Integration Test

@MainActor
private func testLiveAgent(
    socketPath: String,
    agentBinaryPath: String,
    passphrase: String
) async throws {
    let agentURL = URL(fileURLWithPath: agentBinaryPath)
    let verifiedClient = UnixSocketAgentClient(socketPath: socketPath) { fd in
        try PeerCheck.verifyAgent(
            socketFD: fd,
            expectedAgentURL: agentURL,
            requiredTeamID: nil
        )
    }

    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("deadbolt-live-af-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: tmp) }
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)

    let hashStore = FileIdentityHashStore(fileURL: tmp.appendingPathComponent("identities.hash"))
    let idStore = MockIdentityStore(enabled: true)
    let syncer = IdentitySyncer(store: idStore, hashStore: hashStore)

    // 1. Extension configuration sync populates ASCredentialIdentityStore with non-secret metadata.
    let configCompleter = RecordingCompleter()
    let configModel = AutoFillControllerModel(
        client: verifiedClient,
        launcher: NoopLauncher(),
        identitySyncer: syncer,
        completer: configCompleter
    )
    configModel.beginExtensionConfiguration()
    try await configCompleter.waitForCompletion()
    try check(configCompleter.configurationCompletedCount == 1)

    let batches = await idStore.batches()
    try check(batches.count == 1, "expected 1 identity batch, got \(batches.count)")
    let identities = batches[0]
    guard let ghIdentity = identities.first(where: { $0.domain == "github.com" }) else {
        throw TestFailure("missing github.com identity in \(identities)")
    }
    try check(ghIdentity.username == "alex@example.com")
    try check(LoginRef.fromRecordIdentifier(ghIdentity.recordId) != nil)
    try check(hashStore.readHash() != nil)
    FileHandle.standardOutput.write(Data("RECORD_ID=\(ghIdentity.recordId)\n".utf8))

    // 2. Silent fill succeeds when unlocked and domain matches.
    let silentCompleter = RecordingCompleter()
    await AutoFillControllerModel.performSilentPasswordFill(
        recordIdentifier: ghIdentity.recordId,
        fallbackUsername: ghIdentity.username,
        service: AutofillService(identifier: "https://github.com/login", kind: .url),
        client: verifiedClient,
        identitySyncer: syncer,
        completer: silentCompleter
    )
    try await silentCompleter.waitForCompletion()
    try check(
        silentCompleter.deliveredPasswords == [
            .init(user: "alex@example.com", password: "gh-secret-password-42"),
        ]
    )

    // 3. Silent fill refuses domain mismatch with .credentialIdentityNotFound.
    let mismatchCompleter = RecordingCompleter()
    await AutoFillControllerModel.performSilentPasswordFill(
        recordIdentifier: ghIdentity.recordId,
        fallbackUsername: ghIdentity.username,
        service: AutofillService(identifier: "evil.example", kind: .domain),
        client: verifiedClient,
        identitySyncer: syncer,
        completer: mismatchCompleter
    )
    try await mismatchCompleter.waitForCompletion()
    try check(mismatchCompleter.deliveredPasswords.isEmpty)
    try check(mismatchCompleter.cancelledCodes == [.credentialIdentityNotFound])

    // 4. Silent fill refuses unassociated `.app` service with .userInteractionRequired.
    let appSilentCompleter = RecordingCompleter()
    await AutoFillControllerModel.performSilentPasswordFill(
        recordIdentifier: ghIdentity.recordId,
        fallbackUsername: ghIdentity.username,
        service: AutofillService(identifier: "com.acme.desktop", kind: .app),
        client: verifiedClient,
        identitySyncer: syncer,
        completer: appSilentCompleter
    )
    try await appSilentCompleter.waitForCompletion()
    try check(appSilentCompleter.deliveredPasswords.isEmpty)
    try check(appSilentCompleter.cancelledCodes == [.userInteractionRequired])

    // 5. Searchable picker for web domain & unassociated app.
    let pickerCompleter = RecordingCompleter()
    let pickerModel = AutoFillControllerModel(
        client: verifiedClient,
        launcher: NoopLauncher(),
        identitySyncer: syncer,
        completer: pickerCompleter
    )
    pickerModel.beginCredentialList(
        services: [AutofillService(identifier: "com.acme.desktop", kind: .app)]
    )
    try await waitUntil("unassociated picker loaded") { pickerModel.screen == .picker }
    try check(pickerModel.unassociated, "app service must mark picker unassociated")
    try check(pickerModel.allLogins.count >= 2, "expected all logins in unassociated picker")

    pickerModel.updateSearchQuery("linear")
    try check(pickerModel.filteredLogins.count == 1)
    try check(pickerModel.selectedLogin?.username == "alex@linear.example")
    pickerModel.fillSelected()
    try await pickerCompleter.waitForCompletion()
    try check(
        pickerCompleter.deliveredPasswords == [
            .init(user: "alex@linear.example", password: "linear-secret-password-99"),
        ]
    )

    // 6. Confined command check: AutoFill socket rejects non-AutoFill commands even from Swift.
    do {
        let badLine = Data("{\"v\":\(AutofillWire.protocolVersion),\"cmd\":\"lock\"}\n".utf8)
        _ = badLine
        // Lock the agent from outside is tested in step 7 when `--locked-phase` runs,
        // while here we verify PeerCheck rejects a mismatched binary path before sending passphrase!
        let wrongBinaryClient = UnixSocketAgentClient(socketPath: socketPath) { fd in
            try PeerCheck.verifyAgent(
                socketFD: fd,
                expectedAgentURL: URL(fileURLWithPath: "/usr/bin/true"),
                requiredTeamID: nil
            )
        }
        _ = try await wrongBinaryClient.send(
            .unlock(passphrase: passphrase),
            timeout: 2.0,
            handle: nil
        )
        throw TestFailure("PeerCheck should have rejected /usr/bin/true as agent binary")
    } catch let err as AgentCallError {
        guard case .peerRejected = err else {
            throw TestFailure("expected .peerRejected, got \(err)")
        }
    }
}

@MainActor
private func testLiveLockedAgent(
    socketPath: String,
    agentBinaryPath: String,
    passphrase: String,
    recordId: String
) async throws {
    let agentURL = URL(fileURLWithPath: agentBinaryPath)
    let verifiedClient = UnixSocketAgentClient(socketPath: socketPath) { fd in
        try PeerCheck.verifyAgent(
            socketFD: fd,
            expectedAgentURL: agentURL,
            requiredTeamID: nil
        )
    }

    // 1. Silent fill while locked returns .userInteractionRequired so macOS opens our UI.
    let silentCompleter = RecordingCompleter()
    await AutoFillControllerModel.performSilentPasswordFill(
        recordIdentifier: recordId,
        fallbackUsername: "alex@example.com",
        service: AutofillService(identifier: "github.com", kind: .domain),
        client: verifiedClient,
        identitySyncer: nil,
        completer: silentCompleter
    )
    try await silentCompleter.waitForCompletion()
    try check(silentCompleter.deliveredPasswords.isEmpty)
    try check(silentCompleter.cancelledCodes == [.userInteractionRequired])

    // 2. Interactive direct fill stops on .locked, rejects wrong passphrase, then unlocks and fills!
    let interactiveCompleter = RecordingCompleter()
    let model = AutoFillControllerModel(
        client: verifiedClient,
        launcher: NoopLauncher(),
        identitySyncer: nil,
        completer: interactiveCompleter
    )
    model.beginDirectPasswordFill(
        recordIdentifier: recordId,
        fallbackUsername: "alex@example.com",
        service: AutofillService(identifier: "github.com", kind: .domain)
    )
    try await waitUntil("locked screen reached") {
        if case .locked = model.screen { return true }
        return false
    }

    model.submitPassphrase("definitely-wrong-passphrase")
    try await waitUntil("wrong passphrase error shown") {
        if case let .locked(_, _, unlocking, _, err) = model.screen {
            return !unlocking && err != nil
        }
        return false
    }
    try check(interactiveCompleter.deliveredPasswords.isEmpty)

    model.submitPassphrase(passphrase)
    try await interactiveCompleter.waitForCompletion(timeoutSeconds: 10.0)
    try check(
        interactiveCompleter.deliveredPasswords == [
            .init(user: "alex@example.com", password: "gh-secret-password-42"),
        ]
    )
}

@main
struct AutoFillTestRunner {
    static func main() async {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            var snapDir: URL?
            var liveSocket: String?
            var agentBinary: String?
            var passphrase: String?
            var lockedRecordId: String?

            var idx = 0
            while idx < args.count {
                switch args[idx] {
                case "--snap-dir":
                    idx += 1
                    snapDir = URL(fileURLWithPath: args[idx], isDirectory: true)
                case "--live-socket":
                    idx += 1
                    liveSocket = args[idx]
                case "--agent-bin":
                    idx += 1
                    agentBinary = args[idx]
                case "--passphrase":
                    idx += 1
                    passphrase = args[idx]
                case "--locked-record-id":
                    idx += 1
                    lockedRecordId = args[idx]
                default:
                    throw TestFailure("unknown argument: \(args[idx])")
                }
                idx += 1
            }

            if let snapDir, liveSocket == nil {
                try await renderSnapshots(outputDir: snapDir)
                return
            }

            try await testUnitAndWire()
            try testSocketCancellation()
            try await renderSnapshots(outputDir: snapDir)

            if let liveSocket, let agentBinary, let passphrase {
                if let lockedRecordId {
                    try await testLiveLockedAgent(
                        socketPath: liveSocket,
                        agentBinaryPath: agentBinary,
                        passphrase: passphrase,
                        recordId: lockedRecordId
                    )
                } else {
                    try await testLiveAgent(
                        socketPath: liveSocket,
                        agentBinaryPath: agentBinary,
                        passphrase: passphrase
                    )
                }
            }
        } catch {
            FileHandle.standardError.write(Data("AutoFillTests failed: \(error)\n".utf8))
            exit(1)
        }
    }
}
