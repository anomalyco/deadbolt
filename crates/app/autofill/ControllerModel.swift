// State machine driving the Deadbolt credential provider across silent fill,
// unlock, searchable credential picker, and extension configuration sync.
// Shared by macOS (socket client to `deadbolt agent`) and iOS (in-process
// core, a fresh biometric unseal per request). iOS adds one-time codes
// (iOS 18+) and passkey assertion and registration; macOS keeps its
// password-only behavior.

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
    #if os(iOS)
    func completeOneTimeCode(_ code: String)
    func completePasskeyAssertion(_ assertion: PasskeyAssertion)
    func completePasskeyRegistration(_ registration: PasskeyRegistration)
    #endif
}

#if os(iOS)
/// The OS's passkey assertion request: relying party, its 32-byte
/// `clientDataHash` and the site's user-verification preference.
public struct PasskeyAssertionTarget: Equatable, Sendable {
    public let rpId: String
    public let clientDataHash: Data
    public let verify: PasskeyVerify

    public init(rpId: String, clientDataHash: Data, verify: PasskeyVerify) {
        self.rpId = rpId
        self.clientDataHash = clientDataHash
        self.verify = verify
    }
}

/// The OS's passkey registration request, exactly as Apple supplies it.
public struct PasskeyRegistrationTarget: Equatable, Sendable {
    public let rpId: String
    public let clientDataHash: Data
    public let userHandle: Data
    public let userName: String
    public let userDisplayName: String
    public let excludedCredentials: [Data]
    public let verify: PasskeyVerify

    public init(
        rpId: String,
        clientDataHash: Data,
        userHandle: Data,
        userName: String,
        userDisplayName: String,
        excludedCredentials: [Data],
        verify: PasskeyVerify
    ) {
        self.rpId = rpId
        self.clientDataHash = clientDataHash
        self.userHandle = userHandle
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.excludedCredentials = excludedCredentials
        self.verify = verify
    }

    var request: ProviderRequest {
        .passkeyCreate(
            rpId: rpId,
            clientDataHash: Base64URL.encode(clientDataHash),
            userId: Base64URL.encode(userHandle),
            userName: userName,
            userDisplayName: userDisplayName,
            exclude: excludedCredentials.map(Base64URL.encode),
            verify: verify,
            interactive: true
        )
    }
}

extension PasskeyAssertionTarget {
    func request(allowedCredentials: [Data]) -> ProviderRequest {
        .passkeyGet(
            rpId: rpId,
            allowedCredentials: allowedCredentials.map(Base64URL.encode),
            clientDataHash: Base64URL.encode(clientDataHash),
            verify: verify,
            interactive: true
        )
    }
}
#endif

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
        #if os(iOS)
        case directOneTimeCode(login: LoginRef, service: AutofillService)
        case directPasskey(passkey: LoginRef, target: PasskeyAssertionTarget)
        case passkeyRegistration(PasskeyRegistrationTarget)
        case oneTimeCodePicker(services: [AutofillService])
        case passkeyPicker(
            services: [AutofillService],
            target: PasskeyAssertionTarget,
            allowedCredentials: [Data]
        )
        #endif
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
    /// Passkeys offered beside logins for a passkey request (iOS).
    public private(set) var allPasskeys: [SitePasskey] = []
    public private(set) var filteredPasskeys: [SitePasskey] = []
    /// What the locked screen unlocks for, when not just a fill.
    public private(set) var lockedPrompt: String?

    private var touchIdReady = false
    private var touchIdReset = false
    private var unlocking = false
    private var touchIdInFlight = false
    private var unlockError: String?
    private var pendingPickerFill: SiteLogin?
    private var pendingPickerPasskey: SitePasskey?

    private var activeCall: AutofillCallHandle?
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
        lockedPrompt = nil
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
        client.beginRequest(.password(services: [service], interactive: true))
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
        startPicker(
            mode: .picker(services: services),
            services: services,
            request: .password(services: services, interactive: true)
        )
    }

    private func startPicker(mode next: Mode, services: [AutofillService], request: ProviderRequest) {
        cancelInFlightWork()
        finished = false
        lockedPrompt = nil
        mode = next
        client.beginRequest(request)
        if let web = services.first(where: { $0.kind != .app }) {
            contextLabel = web.displayHost
        } else {
            contextLabel = "All Passwords"
        }
        searchQuery = ""
        allLogins = []
        filteredLogins = []
        allPasskeys = []
        filteredPasskeys = []
        selectedIndex = 0
        unassociated = false
        pickerError = nil
        pendingPickerFill = nil
        pendingPickerPasskey = nil
        setScreen(.connecting("Connecting to Deadbolt…"))
        runTask { [weak self] in
            await self?.driveCredentialList(services: services)
        }
    }

    public func beginExtensionConfiguration() {
        cancelInFlightWork()
        finished = false
        lockedPrompt = nil
        mode = .configuration
        contextLabel = "AutoFill Setup"
        #if os(iOS)
        // The iOS app publishes the identity store from its own unlocked
        // session; enabling the provider needs no unlock here.
        finished = true
        completer?.completeExtensionConfiguration()
        client.endRequest()
        #else
        setScreen(.connecting("Connecting to Deadbolt…"))
        runTask { [weak self] in
            await self?.driveExtensionConfiguration()
        }
        #endif
    }

    // MARK: - User actions

    public func cancelByUser() {
        cancelInFlightWork()
        finishCancel(.userCanceled)
    }

    public func handleViewDisappearing() {
        cancelInFlightWork()
        client.endRequest()
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
        #if os(iOS)
        case let .directOneTimeCode(login, service):
            beginDirectOneTimeCode(recordIdentifier: login.recordIdentifier, service: service)
        case let .directPasskey(passkey, target):
            beginDirectPasskeyAssertion(recordIdentifier: passkey.recordIdentifier, target: target)
        case let .passkeyRegistration(target):
            beginPasskeyRegistration(target)
        case let .oneTimeCodePicker(services):
            beginOneTimeCodeList(services: services)
        case let .passkeyPicker(services, target, allowed):
            beginPasskeyList(services: services, target: target, allowedCredentials: allowed)
        #endif
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
        // macOS: the agent raises Touch ID itself, so one tap unlocks and
        // fills. iOS unseals the biometric slot here, then fills.
        #if os(macOS)
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
        #endif

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
        #if os(iOS)
        // The core refuses a passphrase for a verified passkey ceremony.
        guard !needsBiometricVerification else { return }
        #endif
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

        #if os(iOS)
        if status.unlocked {
            await executeInteractiveDirectFill(
                login: login,
                fallbackUsername: fallbackUsername,
                service: service
            )
        } else {
            showLockedAndPrompt()
        }
        #else
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
        #endif
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
                    #if os(iOS)
                    await relockRefreshingStatus(message)
                    #else
                    relock(message)
                    #endif
                case .notInitialized:
                    setScreen(.notInitialized)
                case .notFound, .domainMismatch:
                    finishCancel(.credentialIdentityNotFound)
                #if os(iOS)
                case .busy:
                    // The app still holds the vault: quiet, with Try again.
                    fail(message)
                default:
                    await relockRefreshingStatus(message)
                #else
                default:
                    unlockError = message
                    refreshLockedScreen()
                #endif
                }
            default:
                fail(err.userFacingUnlockMessage)
            }
        } catch {
            touchIdInFlight = false
            fail("Could not fill password from Deadbolt.")
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
            await resumePicker(services: services)
        case .configuration:
            await syncConfigurationAndFinish(reportedHash: nil)
        #if os(iOS)
        case let .oneTimeCodePicker(services):
            await resumePicker(services: services)
        case let .passkeyPicker(services, _, _):
            await resumePicker(services: services)
        case .directOneTimeCode, .directPasskey, .passkeyRegistration:
            setScreen(.connecting(workingMessage))
            await performDirectRequest()
        #endif
        }
    }

    private func resumePicker(services: [AutofillService]) async {
        #if os(iOS)
        // iOS checks the unlock only in the next core call, which also raises
        // Face ID: show progress, not a locked screen that still takes taps.
        let picking = pendingPickerFill != nil || pendingPickerPasskey != nil
        setScreen(.connecting(picking ? workingMessage : "Unlocking…"))
        #endif
        if let pending = pendingPickerFill {
            pendingPickerFill = nil
            fillPickerLogin(pending)
        } else if let pending = pendingPickerPasskey {
            pendingPickerPasskey = nil
            #if os(iOS)
            fillPickerPasskey(pending)
            #else
            _ = pending
            #endif
        } else {
            await loadPickerItems(services: services)
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
        client.endRequest()
    }

    private func loadPickerItems(services: [AutofillService]) async {
        do {
            let reply = try await callAgent(
                listCommand(services: services),
                timeout: Self.statusTimeout
            )
            guard case let .autofillList(list) = reply else {
                fail("Unexpected response from Deadbolt.")
                return
            }
            allLogins = list.logins
            allPasskeys = list.passkeys
            unassociated = list.unassociated
            pickerError = nil
            applyFilter()
            setScreen(.picker)
            if let syncer = fillSyncer {
                let clientRef = client
                let hash = list.identitiesHash
                Task {
                    _ = await syncer.syncIfNeeded(client: clientRef, reportedHash: hash)
                }
            }
        } catch let err as AgentCallError {
            if case let .agentError(code, message) = err, code == .locked {
                #if os(iOS)
                await relockRefreshingStatus(message)
                #else
                relock(message)
                #endif
                return
            }
            #if os(iOS)
            if err.isBiometricCancelled {
                await refreshStatusAfterFailedBiometric()
                return
            }
            #endif
            fail(err.userFacingUnlockMessage)
        } catch {
            fail("Could not load logins from Deadbolt.")
        }
    }

    private func listCommand(services: [AutofillService]) -> AutofillCommand {
        #if os(iOS)
        switch mode {
        case .oneTimeCodePicker:
            return .autofillList(services: services, forOtp: true)
        case let .passkeyPicker(_, target, allowed):
            return .autofillList(
                services: services,
                rpId: target.rpId,
                allowedCredentials: allowed.map(Base64URL.encode)
            )
        default:
            break
        }
        #endif
        return .autofillList(services: services)
    }

    private var pickerServices: [AutofillService]? {
        switch mode {
        case let .picker(services):
            return services
        #if os(iOS)
        case let .oneTimeCodePicker(services):
            return services
        case let .passkeyPicker(services, _, _):
            return services
        #endif
        default:
            return nil
        }
    }

    /// The OS service a picked login fills for: the one it was matched to
    /// (`SiteLogin.service`, one of the request's own), never just the first
    /// one offered. The iOS core rechecks the item against the request's
    /// services itself when completing.
    private func pickerTargetService(
        for item: SiteLogin,
        services: [AutofillService]
    ) -> AutofillService?? {
        if unassociated {
            return .some(nil)
        }
        if let matched = item.service {
            guard matched.kind != .app, services.contains(matched) else {
                return nil
            }
            return .some(matched)
        }
        #if os(iOS)
        // The in-process core always reports the matched service.
        return nil
        #else
        // `deadbolt agent` doesn't report it; keep its existing behavior.
        return .some(services.first(where: { $0.kind != .app }))
        #endif
    }

    private func fillPickerLogin(_ item: SiteLogin) {
        guard let services = pickerServices else { return }
        guard let targetService = pickerTargetService(for: item, services: services) else {
            showPicker(error: "Deadbolt couldn't tell which site this login is for.")
            return
        }
        #if os(iOS)
        var wantCode = false
        if case .oneTimeCodePicker = mode {
            wantCode = true
        }
        let want: [FillField] = wantCode ? [.totp] : [.username, .password]
        #else
        let want: [FillField] = [.username, .password]
        #endif
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
                        want: want,
                        interactive: true
                    ),
                    timeout: Self.interactiveTimeout
                )
                self.filling = false
                #if os(iOS)
                if wantCode {
                    guard case let .autofillFill(fill) = reply,
                          let code = fill.values.totp,
                          !code.isEmpty
                    else {
                        self.showPicker(error: "This login does not have a one-time code.")
                        return
                    }
                    self.deliverOneTimeCode(code)
                    return
                }
                #endif
                guard case let .autofillFill(fill) = reply,
                      let password = fill.values.password,
                      !password.isEmpty
                else {
                    self.showPicker(error: "This login does not have a password.")
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
                    self.showPicker(error: nil)
                    return
                }
                if case let .agentError(code, message) = err, code == .locked {
                    self.pendingPickerFill = item
                    #if os(iOS)
                    // Prompt only for a plain "not unlocked yet", with fresh
                    // readiness; a refused key never retries by itself.
                    await self.relockRefreshingStatus(message)
                    if message.isEmpty, self.touchIdReady, !self.finished {
                        self.promptTouchID()
                    }
                    #else
                    self.relock(message, refresh: false)
                    self.refreshLockedScreen()
                    if self.touchIdReady {
                        self.promptTouchID()
                    }
                    #endif
                    return
                }
                self.showPicker(error: err.userFacingUnlockMessage)
            } catch {
                self.filling = false
                self.showPicker(error: "Could not fill password.")
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
            #if os(iOS)
            // No agent to start: the core runs in this process.
            if case let .agentUnavailable(reason) = err {
                fail(reason)
                return nil
            }
            #endif
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
            fail(err.userFacingUnlockMessage)
            return nil
        } catch {
            fail("Can't reach Deadbolt.")
            return nil
        }
        fail("Unexpected status reply from Deadbolt.")
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
        filteredPasskeys = allPasskeys.filter { $0.matchesSearch(searchQuery) }
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
        let handle = AutofillCallHandle()
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
        let clientRef = client
        if let syncer = fillSyncer {
            completer?.completePassword(user: user, password: password) {
                _ = await syncer.syncIfNeeded(client: clientRef, reportedHash: reportedHash)
            }
        } else {
            completer?.completePassword(user: user, password: password, afterDelivery: nil)
        }
        client.endRequest()
    }

    /// The syncer fills may refresh identities with. iOS never publishes the
    /// identity store around a delivery (the app publishes it); macOS keeps
    /// its existing sync.
    private var fillSyncer: IdentitySyncer? {
        #if os(iOS)
        return nil
        #else
        return identitySyncer
        #endif
    }

    private func finishCancel(_ code: ASExtensionError.Code) {
        guard !finished else { return }
        finished = true
        completer?.cancelRequest(code: code)
        client.endRequest()
    }

    /// Back to the locked screen. On iOS the core checks the passphrase or
    /// biometric key only when it runs a request, so a refusal arrives here
    /// as `locked` carrying the reason; macOS's agent reports it at unlock.
    private func relock(_ message: String, refresh: Bool = true) {
        #if os(iOS)
        unlockError = message.isEmpty ? nil : message
        #else
        unlockError = nil
        #endif
        if refresh {
            refreshLockedScreen()
        }
    }

    /// A failed screen offers Try again, which begins a new request. On iOS
    /// this request ends now, so its passphrase or Face ID choice isn't kept.
    private func fail(_ message: String) {
        #if os(iOS)
        client.endRequest()
        #endif
        setScreen(.failed(message))
    }

    /// Shows a picked login's failure on the picker. On iOS a pick resumed
    /// after unlock is still on its progress screen, so return to the list.
    private func showPicker(error: String?) {
        pickerError = error
        #if os(iOS)
        if screen != .picker {
            setScreen(.picker)
            return
        }
        #endif
        notify()
    }

    #if os(iOS)
    /// Back to the locked screen after the core refused this request's
    /// unlock. Face ID readiness is read again first (an expired, reset or
    /// damaged slot turns it off), so the screen never offers a Face ID that
    /// can't work. The passphrase stays available; nothing prompts by itself.
    private func relockRefreshingStatus(_ message: String) async {
        unlockError = message.isEmpty ? nil : message
        await refreshBiometricReadiness()
        guard !finished, !Task.isCancelled else { return }
        refreshLockedScreen()
    }

    private func refreshBiometricReadiness() async {
        if let reply = try? await callAgent(.autofillStatus, timeout: Self.statusTimeout),
           case let .autofillStatus(status) = reply
        {
            touchIdReady = status.touchIdReady
            touchIdReset = status.touchIdReset
        } else {
            touchIdReady = false
        }
    }
    #endif

    private func showLockedAndPrompt() {
        unlocking = false
        unlockError = nil
        touchIdInFlight = false
        refreshLockedScreen()
        if touchIdReady {
            promptTouchID()
        }
    }

    // MARK: - iOS one-time codes and passkeys

    #if os(iOS)
    public func beginDirectOneTimeCode(recordIdentifier: String?, service: AutofillService) {
        guard let login = startDirect(recordIdentifier: recordIdentifier, label: service.displayHost) else {
            return
        }
        mode = .directOneTimeCode(login: login, service: service)
        client.beginRequest(.oneTimeCode(services: [service], interactive: true))
        driveDirect()
    }

    public func beginDirectPasskeyAssertion(recordIdentifier: String?, target: PasskeyAssertionTarget) {
        guard let passkey = startDirect(recordIdentifier: recordIdentifier, label: target.rpId) else {
            return
        }
        lockedPrompt = "Sign in to \(target.rpId) with a passkey."
        mode = .directPasskey(passkey: passkey, target: target)
        client.beginRequest(target.request(allowedCredentials: []))
        driveDirect()
    }

    public func beginPasskeyRegistration(_ target: PasskeyRegistrationTarget) {
        cancelInFlightWork()
        finished = false
        contextLabel = target.rpId
        let account = target.userName.isEmpty ? target.userDisplayName : target.userName
        lockedPrompt = account.isEmpty
            ? "Save a passkey for \(target.rpId)."
            : "Save a passkey for \(account) on \(target.rpId)."
        mode = .passkeyRegistration(target)
        client.beginRequest(target.request)
        driveDirect()
    }

    public func beginOneTimeCodeList(services: [AutofillService]) {
        startPicker(
            mode: .oneTimeCodePicker(services: services),
            services: services,
            request: .oneTimeCode(services: services, interactive: true)
        )
    }

    public func beginPasskeyList(
        services: [AutofillService],
        target: PasskeyAssertionTarget,
        allowedCredentials: [Data]
    ) {
        startPicker(
            mode: .passkeyPicker(services: services, target: target, allowedCredentials: allowedCredentials),
            services: services,
            request: target.request(allowedCredentials: allowedCredentials)
        )
        contextLabel = target.rpId
        lockedPrompt = "Sign in to \(target.rpId) with a passkey."
        notify()
    }

    public func fillPasskeyRow(_ index: Int) {
        guard index >= 0, index < filteredPasskeys.count, !filling, !finished else { return }
        fillPickerPasskey(filteredPasskeys[index])
    }

    private func startDirect(recordIdentifier: String?, label: String) -> LoginRef? {
        cancelInFlightWork()
        finished = false
        lockedPrompt = nil
        contextLabel = label
        guard let raw = recordIdentifier, let ref = LoginRef.fromRecordIdentifier(raw) else {
            finishCancel(.credentialIdentityNotFound)
            return nil
        }
        return ref
    }

    private func driveDirect() {
        setScreen(.connecting("Connecting to Deadbolt…"))
        runTask { [weak self] in
            guard let self, let status = await self.connectAndFetchStatus() else { return }
            guard status.initialized else {
                self.setScreen(.notInitialized)
                return
            }
            self.touchIdReady = status.touchIdReady
            self.touchIdReset = status.touchIdReset
            if status.unlocked {
                await self.performDirectRequest()
            } else {
                self.showLockedAndPrompt()
            }
        }
    }

    private var workingMessage: String {
        switch mode {
        case .directOneTimeCode, .oneTimeCodePicker:
            return "Filling code…"
        case .directPasswordFill, .picker:
            return "Filling password…"
        case .passkeyRegistration:
            return "Saving passkey…"
        default:
            return "Signing in…"
        }
    }

    private func performDirectRequest() async {
        switch mode {
        case let .directOneTimeCode(login, service):
            await runRequest(
                .autofillFill(service: service, login: login, want: [.totp], interactive: true)
            ) { model, reply in
                guard case let .autofillFill(fill) = reply, let code = fill.values.totp, !code.isEmpty else {
                    model.finishCancel(.credentialIdentityNotFound)
                    return
                }
                model.deliverOneTimeCode(code)
            }
        case let .directPasskey(passkey, target):
            await runRequest(
                .autofillPasskeyGet(
                    rpId: target.rpId,
                    passkey: passkey,
                    clientDataHash: Base64URL.encode(target.clientDataHash),
                    verify: target.verify,
                    interactive: true
                )
            ) { model, reply in
                guard case let .autofillPasskeyAssertion(assertion) = reply else {
                    throw AgentCallError.invalidResponse("Unexpected response from Deadbolt.")
                }
                model.deliverPasskeyAssertion(
                    try PasskeyAssertion(reply: assertion, rpId: target.rpId, clientDataHash: target.clientDataHash)
                )
            }
        case let .passkeyRegistration(target):
            await runRequest(
                .autofillPasskeyCreate(
                    rpId: target.rpId,
                    clientDataHash: Base64URL.encode(target.clientDataHash),
                    userId: Base64URL.encode(target.userHandle),
                    userName: target.userName,
                    userDisplayName: target.userDisplayName,
                    exclude: target.excludedCredentials.map(Base64URL.encode),
                    verify: target.verify,
                    interactive: true
                )
            ) { model, reply in
                guard case let .autofillPasskeyCreated(created) = reply else {
                    throw AgentCallError.invalidResponse("Unexpected response from Deadbolt.")
                }
                model.deliverPasskeyRegistration(
                    try PasskeyRegistration(reply: created, rpId: target.rpId, clientDataHash: target.clientDataHash)
                )
            }
        default:
            break
        }
    }

    /// Runs one direct request and maps its failure the way the password
    /// fill does; a passkey needing fresh verification returns to Face ID.
    private func runRequest(
        _ command: AutofillCommand,
        deliver: @MainActor (AutoFillControllerModel, AutofillReply) throws -> Void
    ) async {
        do {
            let reply = try await callAgent(command, timeout: Self.interactiveTimeout)
            touchIdInFlight = false
            try deliver(self, reply)
        } catch let err as AgentCallError {
            touchIdInFlight = false
            if err.isBiometricCancelled {
                await refreshStatusAfterFailedBiometric()
                return
            }
            guard case let .agentError(code, message) = err else {
                fail(err.userFacingUnlockMessage)
                return
            }
            switch code {
            case .locked:
                await relockRefreshingStatus(message)
            case .interactionRequired:
                // The passphrase can't confirm a passkey; the locked screen
                // offers Face ID (or says how to turn it on).
                await relockRefreshingStatus(Self.verificationNeeded)
            case .notInitialized:
                setScreen(.notInitialized)
            case .notFound, .domainMismatch:
                finishCancel(.credentialIdentityNotFound)
            case .exists:
                if #available(iOS 18.0, *) {
                    finishCancel(.matchedExcludedCredential)
                } else {
                    finishCancel(.failed)
                }
            default:
                fail(message)
            }
        } catch {
            touchIdInFlight = false
            fail("Deadbolt couldn't complete this request.")
        }
    }

    private func fillPickerPasskey(_ item: SitePasskey) {
        guard case let .passkeyPicker(_, target, _) = mode else { return }
        filling = true
        pickerError = nil
        notify()
        runTask { [weak self] in
            guard let self else { return }
            do {
                let reply = try await self.callAgent(
                    .autofillPasskeyGet(
                        rpId: target.rpId,
                        passkey: item.passkey,
                        clientDataHash: Base64URL.encode(target.clientDataHash),
                        verify: target.verify,
                        interactive: true
                    ),
                    timeout: Self.interactiveTimeout
                )
                self.filling = false
                guard case let .autofillPasskeyAssertion(assertion) = reply else {
                    self.showPicker(error: "Unexpected response from Deadbolt.")
                    return
                }
                self.deliverPasskeyAssertion(
                    try PasskeyAssertion(reply: assertion, rpId: target.rpId, clientDataHash: target.clientDataHash)
                )
            } catch let err as AgentCallError {
                self.filling = false
                if err.isBiometricCancelled {
                    self.showPicker(error: nil)
                    return
                }
                if case let .agentError(code, message) = err, code == .locked || code == .interactionRequired {
                    self.pendingPickerPasskey = item
                    let plain = code == .locked && message.isEmpty
                    await self.relockRefreshingStatus(code == .interactionRequired ? Self.verificationNeeded : message)
                    if plain, self.touchIdReady, !self.finished {
                        self.promptTouchID()
                    }
                    return
                }
                self.showPicker(error: err.userFacingUnlockMessage)
            } catch {
                self.filling = false
                self.showPicker(error: "Could not sign in with this passkey.")
            }
        }
    }

    static let verificationNeeded = "This site asks Deadbolt to confirm it's you. Your passphrase can't do that."

    /// A passkey ceremony the site wants verified (WebAuthn `required` or
    /// `preferred`). Only a fresh biometric match satisfies it, so the locked
    /// screen offers no passphrase for it.
    public var needsBiometricVerification: Bool {
        switch mode {
        case let .directPasskey(_, target):
            return target.verify != .discouraged
        case let .passkeyPicker(_, target, _):
            return target.verify != .discouraged
        case let .passkeyRegistration(target):
            return target.verify != .discouraged
        default:
            return false
        }
    }

    private func deliverOneTimeCode(_ code: String) {
        guard !finished else { return }
        finished = true
        completer?.completeOneTimeCode(code)
        client.endRequest()
    }

    private func deliverPasskeyAssertion(_ assertion: PasskeyAssertion) {
        guard !finished else { return }
        finished = true
        completer?.completePasskeyAssertion(assertion)
        client.endRequest()
    }

    private func deliverPasskeyRegistration(_ registration: PasskeyRegistration) {
        guard !finished else { return }
        finished = true
        completer?.completePasskeyRegistration(registration)
        client.endRequest()
    }
    #endif
}

extension SitePasskey {
    public func matchesSearch(_ query: String) -> Bool {
        let tokens = query.split(whereSeparator: \.isWhitespace).map { $0.lowercased() }
        guard !tokens.isEmpty else {
            return true
        }
        let haystacks = [vault.lowercased(), (username ?? "").lowercased()]
        return tokens.allSatisfy { token in haystacks.contains { $0.contains(token) } }
    }
}
