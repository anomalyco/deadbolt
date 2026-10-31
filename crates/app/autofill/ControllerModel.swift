// State machine driving `DeadboltAutoFill.appex` across silent fill, unlock,
// searchable credential picker, and extension configuration sync.

import AuthenticationServices
import Foundation

@MainActor
public protocol ExtensionContextCompleting: AnyObject {
    func completePassword(
        user: String,
        password: String,
        afterDelivery: (@Sendable () async -> Void)?
    )
    func completeExtensionConfiguration()
    func cancelRequest(code: ASExtensionError.Code)
}

@MainActor
public final class AutoFillControllerModel {
    public static let silentTimeout: TimeInterval = 2.4
    public static let statusTimeout: TimeInterval = 2.0
    public static let interactiveTimeout: TimeInterval = 120.0

    public enum Screen: Equatable, Sendable {
        case connecting(String)
        case notInitialized
        case locked(
            touchIdReady: Bool,
            touchIdReset: Bool,
            unlocking: Bool,
            touchIdInFlight: Bool,
            error: String?
        )
        case syncingConfiguration
        case picker
        case failed(String)
    }

    public enum Mode: Equatable, Sendable {
        case idle
        case directPasswordFill(
            login: LoginRef,
            fallbackUsername: String,
            service: AutofillService
        )
        case picker(services: [AutofillService])
        case configuration
    }

    private let client: any AutofillAgentClient
    private let launcher: any AgentLaunching
    private let identitySyncer: IdentitySyncer?
    private weak var completer: (any ExtensionContextCompleting)?
    private let pollIntervalsMS: [UInt64]

    public private(set) var mode: Mode = .idle
    public private(set) var screen: Screen = .connecting("Starting Deadbolt…")
    public private(set) var contextLabel: String = "Deadbolt"

    public private(set) var allLogins: [SiteLogin] = []
    public private(set) var filteredLogins: [SiteLogin] = []
    public private(set) var selectedIndex: Int = 0
    public private(set) var searchQuery: String = ""
    public private(set) var unassociated: Bool = false
    public private(set) var filling: Bool = false
    public private(set) var pickerError: String?

    private var touchIdReady = false
    private var touchIdReset = false
    private var unlocking = false
    private var touchIdInFlight = false
    private var unlockError: String?
    private var pendingPickerFill: SiteLogin?

    private var activeCall: SocketCallHandle?
    private var currentTask: Task<Void, Never>?
    private var finished = false

    public var onChange: (@MainActor () -> Void)?

    public init(
        client: any AutofillAgentClient,
        launcher: any AgentLaunching,
        identitySyncer: IdentitySyncer?,
        completer: any ExtensionContextCompleting,
        pollIntervalsMS: [UInt64] = [40, 80, 120, 180, 250, 300, 350, 400, 500, 600, 600, 600]
    ) {
        self.client = client
        self.launcher = launcher
        self.identitySyncer = identitySyncer
        self.completer = completer
        self.pollIntervalsMS = pollIntervalsMS
    }

    public var hasMultipleVaults: Bool {
        Set(allLogins.map(\.vault)).count > 1
    }

    public var selectedLogin: SiteLogin? {
        guard selectedIndex >= 0, selectedIndex < filteredLogins.count else {
            return nil
        }
        return filteredLogins[selectedIndex]
    }

    // MARK: - Silent fill (`provideCredentialWithoutUserInteraction`)

    public static func performSilentPasswordFill(
        recordIdentifier: String?,
        fallbackUsername: String,
        service: AutofillService,
        client: any AutofillAgentClient,
        identitySyncer: IdentitySyncer?,
        completer: any ExtensionContextCompleting
    ) async {
        guard let rawRecord = recordIdentifier,
              let loginRef = LoginRef.fromRecordIdentifier(rawRecord)
        else {
            completer.cancelRequest(code: .credentialIdentityNotFound)
            return
        }
        guard service.kind != .app else {
            completer.cancelRequest(code: .userInteractionRequired)
            return
        }
        do {
            let reply = try await client.send(
                .autofillFill(
                    service: service,
                    login: loginRef,
                    want: [.username, .password],
                    interactive: false
                ),
                timeout: silentTimeout,
                handle: nil
            )
            guard case let .autofillFill(fill) = reply,
                  let password = fill.values.password,
                  !password.isEmpty
            else {
                completer.cancelRequest(code: .credentialIdentityNotFound)
                return
            }
            let user = fill.values.username ?? fallbackUsername
            let reportedHash = fill.identitiesHash
            let syncer = identitySyncer
            completer.completePassword(user: user, password: password) {
                if let syncer {
                    _ = await syncer.syncIfNeeded(client: client, reportedHash: reportedHash)
                }
            }
        } catch let callError as AgentCallError {
            completer.cancelRequest(code: callError.extensionErrorCodeForSilentRequest)
        } catch {
            completer.cancelRequest(code: .failed)
        }
    }

    // MARK: - Interactive entry points

    public func beginDirectPasswordFill(
        recordIdentifier: String?,
        fallbackUsername: String,
        service: AutofillService
    ) {
        cancelInFlightWork()
        finished = false
        contextLabel = service.displayHost
        guard let rawRecord = recordIdentifier,
              let loginRef = LoginRef.fromRecordIdentifier(rawRecord)
        else {
            finishCancel(.credentialIdentityNotFound)
            return
        }
        mode = .directPasswordFill(
            login: loginRef,
            fallbackUsername: fallbackUsername,
            service: service
        )
        setScreen(.connecting("Connecting to Deadbolt…"))
        runTask { [weak self] in
            await self?.driveDirectPasswordFill(
                login: loginRef,
                fallbackUsername: fallbackUsername,
                service: service
            )
        }
    }

    public func beginCredentialList(services: [AutofillService]) {
        cancelInFlightWork()
        finished = false
        mode = .picker(services: services)
        if let web = services.first(where: { $0.kind != .app }) {
            contextLabel = web.displayHost
        } else {
            contextLabel = "All Passwords"
        }
        searchQuery = ""
        allLogins = []
        filteredLogins = []
        selectedIndex = 0
        unassociated = false
        pickerError = nil
        pendingPickerFill = nil
        setScreen(.connecting("Connecting to Deadbolt…"))
        runTask { [weak self] in
            await self?.driveCredentialList(services: services)
        }
    }

    public func beginExtensionConfiguration() {
        cancelInFlightWork()
        finished = false
        mode = .configuration
        contextLabel = "AutoFill Setup"
        setScreen(.connecting("Connecting to Deadbolt…"))
        runTask { [weak self] in
            await self?.driveExtensionConfiguration()
        }
    }

    // MARK: - User actions

    public func cancelByUser() {
        cancelInFlightWork()
        finishCancel(.userCanceled)
    }

    public func handleViewDisappearing() {
        cancelInFlightWork()
    }

    public func openDeadboltApp() {
        cancelInFlightWork()
        Task { @MainActor [launcher, weak self] in
            _ = await launcher.openContainingApp()
            self?.finishCancel(.userCanceled)
        }
    }

    public func retryConnection() {
        switch mode {
        case .idle:
            break
        case let .directPasswordFill(login, fallbackUsername, service):
            beginDirectPasswordFill(
                recordIdentifier: login.recordIdentifier,
                fallbackUsername: fallbackUsername,
                service: service
            )
        case let .picker(services):
            beginCredentialList(services: services)
        case .configuration:
            beginExtensionConfiguration()
        }
    }

    public func clearUnlockError() {
        guard unlockError != nil else { return }
        unlockError = nil
        refreshLockedScreen()
    }

    public func promptTouchID() {
        guard touchIdReady, !unlocking, !touchIdInFlight, !finished else { return }
        unlockError = nil
        if case let .directPasswordFill(login, fallbackUsername, service) = mode {
            touchIdInFlight = true
            refreshLockedScreen()
            runTask { [weak self] in
                await self?.executeInteractiveDirectFill(
                    login: login,
                    fallbackUsername: fallbackUsername,
                    service: service
                )
            }
            return
        }

        touchIdInFlight = true
        refreshLockedScreen()
        runTask { [weak self] in
            guard let self else { return }
            do {
                _ = try await self.callAgent(.unlockBiometric, timeout: Self.interactiveTimeout)
                self.touchIdInFlight = false
                await self.resumeAfterUnlock()
            } catch let err as AgentCallError {
                self.touchIdInFlight = false
                if !err.isBiometricCancelled {
                    self.unlockError = err.userFacingUnlockMessage
                }
                await self.refreshStatusAfterFailedBiometric()
            } catch {
                self.touchIdInFlight = false
                self.unlockError = "Could not unlock with Touch ID."
                self.refreshLockedScreen()
            }
        }
    }

    public func submitPassphrase(_ rawPassphrase: String) {
        guard !unlocking, !finished else { return }
        if rawPassphrase.isEmpty {
            if touchIdReady && !touchIdInFlight {
                promptTouchID()
            }
            return
        }
        // Cancel an in-flight Touch ID prompt if the user submitted their passphrase instead.
        activeCall?.cancel()
        touchIdInFlight = false
        unlocking = true
        unlockError = nil
        refreshLockedScreen()

        runTask { [weak self] in
            guard let self else { return }
            do {
                _ = try await self.callAgent(
                    .unlock(passphrase: rawPassphrase),
                    timeout: Self.interactiveTimeout
                )
                self.unlocking = false
                await self.resumeAfterUnlock()
            } catch let err as AgentCallError {
                self.unlocking = false
                self.unlockError = err.userFacingUnlockMessage
                self.refreshLockedScreen()
            } catch {
                self.unlocking = false
                self.unlockError = "That passphrase didn't unlock this device."
                self.refreshLockedScreen()
            }
        }
    }

    public func updateSearchQuery(_ query: String) {
        searchQuery = query
        pickerError = nil
        applyFilter()
        notify()
    }

    public func moveSelection(delta: Int) {
        guard !filteredLogins.isEmpty else { return }
        let next = max(0, min(filteredLogins.count - 1, selectedIndex + delta))
        guard next != selectedIndex else { return }
        selectedIndex = next
        notify()
    }

    public func selectRow(_ index: Int) {
        guard index >= 0, index < filteredLogins.count else { return }
        selectedIndex = index
        pickerError = nil
        notify()
    }

    public func fillSelected() {
        guard let item = selectedLogin, !filling, !finished else { return }
        fillPickerLogin(item)
    }

    public func fillRow(_ index: Int) {
        guard index >= 0, index < filteredLogins.count, !filling, !finished else { return }
        selectedIndex = index
        fillPickerLogin(filteredLogins[index])
    }

    // MARK: - Internal flows

    private func driveDirectPasswordFill(
        login: LoginRef,
        fallbackUsername: String,
        service: AutofillService
    ) async {
        guard let status = await connectAndFetchStatus() else { return }
        guard status.initialized else {
            setScreen(.notInitialized)
            return
        }
        touchIdReady = status.touchIdReady
        touchIdReset = status.touchIdReset

        if status.unlocked || status.touchIdReady {
            if !status.unlocked {
                touchIdInFlight = true
                refreshLockedScreen()
            }
            await executeInteractiveDirectFill(
                login: login,
                fallbackUsername: fallbackUsername,
                service: service
            )
        } else {
            touchIdInFlight = false
            unlocking = false
            unlockError = nil
            refreshLockedScreen()
        }
    }

    private func executeInteractiveDirectFill(
        login: LoginRef,
        fallbackUsername: String,
        service: AutofillService
    ) async {
        let targetService: AutofillService? = service.kind == .app ? nil : service
        do {
            let reply = try await callAgent(
                .autofillFill(
                    service: targetService,
                    login: login,
                    want: [.username, .password],
                    interactive: true
                ),
                timeout: Self.interactiveTimeout
            )
            touchIdInFlight = false
            guard case let .autofillFill(fill) = reply,
                  let password = fill.values.password,
                  !password.isEmpty
            else {
                finishCancel(.credentialIdentityNotFound)
                return
            }
            let user = fill.values.username ?? fallbackUsername
            deliverPassword(
                user: user,
                password: password,
                reportedHash: fill.identitiesHash
            )
        } catch let err as AgentCallError {
            touchIdInFlight = false
            if err.isBiometricCancelled {
                await refreshStatusAfterFailedBiometric()
                return
            }
            switch err {
            case let .agentError(code, message):
                switch code {
                case .locked:
                    unlockError = nil
                    refreshLockedScreen()
                case .notInitialized:
                    setScreen(.notInitialized)
                case .notFound, .domainMismatch:
                    finishCancel(.credentialIdentityNotFound)
                default:
                    unlockError = message
                    refreshLockedScreen()
                }
            default:
                setScreen(.failed(err.userFacingUnlockMessage))
            }
        } catch {
            touchIdInFlight = false
            setScreen(.failed("Could not fill password from Deadbolt."))
        }
    }

    private func driveCredentialList(services: [AutofillService]) async {
        guard let status = await connectAndFetchStatus() else { return }
        guard status.initialized else {
            setScreen(.notInitialized)
            return
        }
        touchIdReady = status.touchIdReady
        touchIdReset = status.touchIdReset

        if status.unlocked {
            await loadPickerItems(services: services)
        } else {
            unlocking = false
            unlockError = nil
            touchIdInFlight = false
            refreshLockedScreen()
            if status.touchIdReady {
                promptTouchID()
            }
        }
    }

    private func driveExtensionConfiguration() async {
        guard let status = await connectAndFetchStatus() else { return }
        guard status.initialized else {
            setScreen(.notInitialized)
            return
        }
        touchIdReady = status.touchIdReady
        touchIdReset = status.touchIdReset

        if status.unlocked {
            await syncConfigurationAndFinish(reportedHash: nil)
        } else {
            unlocking = false
            unlockError = nil
            touchIdInFlight = false
            refreshLockedScreen()
            if status.touchIdReady {
                promptTouchID()
            }
        }
    }

    private func resumeAfterUnlock() async {
        switch mode {
        case .idle:
            break
        case let .directPasswordFill(login, fallbackUsername, service):
            setScreen(.connecting("Filling password…"))
            await executeInteractiveDirectFill(
                login: login,
                fallbackUsername: fallbackUsername,
                service: service
            )
        case let .picker(services):
            if let pending = pendingPickerFill {
                pendingPickerFill = nil
                fillPickerLogin(pending)
            } else {
                await loadPickerItems(services: services)
            }
        case .configuration:
            await syncConfigurationAndFinish(reportedHash: nil)
        }
    }

    private func syncConfigurationAndFinish(reportedHash: String?) async {
        setScreen(.syncingConfiguration)
        if let syncer = identitySyncer {
            _ = await syncer.syncIfNeeded(
                client: client,
                reportedHash: reportedHash,
                timeout: 10.0
            )
        }
        guard !finished else { return }
        finished = true
        completer?.completeExtensionConfiguration()
    }

    private func loadPickerItems(services: [AutofillService]) async {
        do {
            let reply = try await callAgent(
                .autofillList(services: services),
                timeout: Self.statusTimeout
            )
            guard case let .autofillList(list) = reply else {
                setScreen(.failed("Unexpected response from Deadbolt."))
                return
            }
            allLogins = list.logins
            unassociated = list.unassociated
            pickerError = nil
            applyFilter()
            setScreen(.picker)
            if let syncer = identitySyncer {
                let clientRef = client
                let hash = list.identitiesHash
                Task {
                    _ = await syncer.syncIfNeeded(client: clientRef, reportedHash: hash)
                }
            }
        } catch let err as AgentCallError {
            if case let .agentError(code, _) = err, code == .locked {
                refreshLockedScreen()
                return
            }
            setScreen(.failed(err.userFacingUnlockMessage))
        } catch {
            setScreen(.failed("Could not load logins from Deadbolt."))
        }
    }

    private func fillPickerLogin(_ item: SiteLogin) {
        guard case let .picker(services) = mode else { return }
        let targetService: AutofillService? = unassociated
            ? nil
            : services.first(where: { $0.kind != .app })
        filling = true
        pickerError = nil
        notify()

        runTask { [weak self] in
            guard let self else { return }
            do {
                let reply = try await self.callAgent(
                    .autofillFill(
                        service: targetService,
                        login: item.login,
                        want: [.username, .password],
                        interactive: true
                    ),
                    timeout: Self.interactiveTimeout
                )
                self.filling = false
                guard case let .autofillFill(fill) = reply,
                      let password = fill.values.password,
                      !password.isEmpty
                else {
                    self.pickerError = "This login does not have a password."
                    self.notify()
                    return
                }
                let user = fill.values.username ?? item.username ?? ""
                self.deliverPassword(
                    user: user,
                    password: password,
                    reportedHash: fill.identitiesHash
                )
            } catch let err as AgentCallError {
                self.filling = false
                if err.isBiometricCancelled {
                    self.notify()
                    return
                }
                if case let .agentError(code, _) = err, code == .locked {
                    self.pendingPickerFill = item
                    self.refreshLockedScreen()
                    if self.touchIdReady {
                        self.promptTouchID()
                    }
                    return
                }
                self.pickerError = err.userFacingUnlockMessage
                self.notify()
            } catch {
                self.filling = false
                self.pickerError = "Could not fill password."
                self.notify()
            }
        }
    }

    private func connectAndFetchStatus() async -> AutofillStatusReply? {
        do {
            if case let .autofillStatus(st) = try await callAgent(
                .autofillStatus,
                timeout: Self.statusTimeout
            ) {
                return st
            }
        } catch let err as AgentCallError {
            if case .cancelled = err {
                return nil
            }
            if case .agentUnavailable = err {
                setScreen(.connecting("Starting Deadbolt…"))
                _ = await launcher.startInBackground()
                for waitMS in pollIntervalsMS {
                    if Task.isCancelled || finished {
                        return nil
                    }
                    try? await Task.sleep(nanoseconds: waitMS * 1_000_000)
                    if Task.isCancelled || finished {
                        return nil
                    }
                    if let reply = try? await callAgent(.autofillStatus, timeout: 1.0),
                       case let .autofillStatus(st) = reply
                    {
                        return st
                    }
                }
                setScreen(
                    .failed("Can't reach Deadbolt. Open Deadbolt to start its background agent.")
                )
                return nil
            }
            setScreen(.failed(err.userFacingUnlockMessage))
            return nil
        } catch {
            setScreen(.failed("Can't reach Deadbolt."))
            return nil
        }
        setScreen(.failed("Unexpected status reply from Deadbolt."))
        return nil
    }

    private func refreshStatusAfterFailedBiometric() async {
        if let reply = try? await callAgent(.autofillStatus, timeout: Self.statusTimeout),
           case let .autofillStatus(st) = reply
        {
            touchIdReady = st.touchIdReady
            touchIdReset = st.touchIdReset
            if st.unlocked {
                await resumeAfterUnlock()
                return
            }
        }
        refreshLockedScreen()
    }

    private func applyFilter() {
        filteredLogins = allLogins.filter { $0.matchesSearch(searchQuery) }
        if filteredLogins.isEmpty {
            selectedIndex = 0
        } else if selectedIndex >= filteredLogins.count {
            selectedIndex = filteredLogins.count - 1
        }
    }

    private func callAgent(
        _ command: AutofillCommand,
        timeout: TimeInterval
    ) async throws -> AutofillReply {
        let handle = SocketCallHandle()
        activeCall = handle
        defer {
            if activeCall === handle {
                activeCall = nil
            }
        }
        return try await client.send(command, timeout: timeout, handle: handle)
    }

    private func runTask(_ block: @escaping @MainActor () async -> Void) {
        currentTask?.cancel()
        currentTask = Task { @MainActor in
            await block()
        }
    }

    private func cancelInFlightWork() {
        activeCall?.cancel()
        activeCall = nil
        currentTask?.cancel()
        currentTask = nil
    }

    private func refreshLockedScreen() {
        setScreen(
            .locked(
                touchIdReady: touchIdReady,
                touchIdReset: touchIdReset,
                unlocking: unlocking,
                touchIdInFlight: touchIdInFlight,
                error: unlockError
            )
        )
    }

    private func setScreen(_ next: Screen) {
        screen = next
        notify()
    }

    private func notify() {
        onChange?()
    }

    private func deliverPassword(
        user: String,
        password: String,
        reportedHash: String
    ) {
        guard !finished else { return }
        finished = true
        let syncer = identitySyncer
        let clientRef = client
        completer?.completePassword(user: user, password: password) {
            if let syncer {
                _ = await syncer.syncIfNeeded(client: clientRef, reportedHash: reportedHash)
            }
        }
    }

    private func finishCancel(_ code: ASExtensionError.Code) {
        guard !finished else { return }
        finished = true
        completer?.cancelRequest(code: code)
    }
}
