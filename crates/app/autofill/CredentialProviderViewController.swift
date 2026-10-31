// Principal `NSExtension` view controller (`DeadboltAutoFill.CredentialProviderViewController`)
// for macOS AutoFill (`System Settings › General › AutoFill & Passwords`) and
// the iOS credential provider (`Settings › General › AutoFill & Passwords`).
// macOS advertises passwords only (Info.plist.in); iOS also handles one-time
// codes (iOS 18+) and passkey assertion and registration
// (mobile/ios/AutoFill/Info.plist).

#if os(macOS)
import AppKit
#else
import SwiftUI
import UIKit
#endif
import AuthenticationServices
import Foundation

@MainActor
private final class SystemExtensionCompleter: ExtensionContextCompleting {
    weak var controller: ASCredentialProviderViewController?

    init(controller: ASCredentialProviderViewController) {
        self.controller = controller
    }

    func completePassword(
        user: String,
        password: String,
        afterDelivery: (@Sendable () async -> Void)?
    ) {
        guard let ctx = controller?.extensionContext else { return }
        let credential = ASPasswordCredential(user: user, password: password)
        Task { @MainActor in
            if let afterDelivery {
                await afterDelivery()
            }
            ctx.completeRequest(withSelectedCredential: credential)
        }
    }

    func completeExtensionConfiguration() {
        controller?.extensionContext.completeExtensionConfigurationRequest()
    }

    func cancelRequest(code: ASExtensionError.Code) {
        let error = NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        controller?.extensionContext.cancelRequest(withError: error)
    }

    #if os(iOS)
    func completeOneTimeCode(_ code: String) {
        guard let ctx = controller?.extensionContext else { return }
        guard #available(iOS 18.0, *) else {
            cancelRequest(code: .failed)
            return
        }
        ctx.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
    }

    func completePasskeyAssertion(_ assertion: PasskeyAssertion) {
        let credential = ASPasskeyAssertionCredential(
            userHandle: assertion.userHandle,
            relyingParty: assertion.relyingParty,
            signature: assertion.signature,
            clientDataHash: assertion.clientDataHash,
            authenticatorData: assertion.authenticatorData,
            credentialID: assertion.credentialID
        )
        controller?.extensionContext.completeAssertionRequest(using: credential)
    }

    func completePasskeyRegistration(_ registration: PasskeyRegistration) {
        let credential = ASPasskeyRegistrationCredential(
            relyingParty: registration.relyingParty,
            clientDataHash: registration.clientDataHash,
            credentialID: registration.credentialID,
            attestationObject: registration.attestationObject
        )
        controller?.extensionContext.completeRegistrationRequest(using: credential)
    }
    #endif
}

#if os(macOS)
public final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var completer = SystemExtensionCompleter(controller: self)
    private lazy var client = UnixSocketAgentClient.live()
    private lazy var syncer = IdentitySyncer()
    private lazy var model: AutoFillControllerModel = {
        let m = AutoFillControllerModel(
            client: client,
            launcher: WorkspaceAgentLauncher(),
            identitySyncer: syncer,
            completer: completer
        )
        m.onChange = { [weak self] in
            guard let self, self.isViewLoaded else { return }
            self.rootView.render()
            self.preferredContentSize = self.rootView.preferredSheetSize
        }
        return m
    }()

    private lazy var rootView = AutoFillRootView(model: model)

    override public func loadView() {
        view = rootView
        preferredContentSize = rootView.preferredSheetSize
    }

    override public func viewWillDisappear() {
        super.viewWillDisappear()
        rootView.clearSecrets()
        model.handleViewDisappearing()
    }

    // MARK: - Silent AutoFill (`provideCredentialWithoutUserInteraction`)

    override public func provideCredentialWithoutUserInteraction(
        for credentialRequest: any ASCredentialRequest
    ) {
        guard credentialRequest.type == .password,
              let passwordReq = credentialRequest as? ASPasswordCredentialRequest,
              let identity = passwordReq.credentialIdentity as? ASPasswordCredentialIdentity
        else {
            completer.cancelRequest(code: .userInteractionRequired)
            return
        }

        let recordId = identity.recordIdentifier
        let user = identity.user
        let service = AutofillService.from(identity.serviceIdentifier)
        let clientRef = client
        let syncerRef = syncer
        let completerRef = completer

        Task { @MainActor in
            await AutoFillControllerModel.performSilentPasswordFill(
                recordIdentifier: recordId,
                fallbackUsername: user,
                service: service,
                client: clientRef,
                identitySyncer: syncerRef,
                completer: completerRef
            )
        }
    }

    // MARK: - Interactive AutoFill (`prepareInterfaceToProvideCredential`)

    override public func prepareInterfaceToProvideCredential(
        for credentialRequest: any ASCredentialRequest
    ) {
        _ = view
        guard credentialRequest.type == .password,
              let passwordReq = credentialRequest as? ASPasswordCredentialRequest,
              let identity = passwordReq.credentialIdentity as? ASPasswordCredentialIdentity
        else {
            completer.cancelRequest(code: .failed)
            return
        }

        let service = AutofillService.from(identity.serviceIdentifier)
        model.beginDirectPasswordFill(
            recordIdentifier: identity.recordIdentifier,
            fallbackUsername: identity.user,
            service: service
        )
        preferredContentSize = rootView.preferredSheetSize
    }

    // MARK: - Credential Picker (`prepareCredentialList`)

    override public func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        _ = view
        let services = serviceIdentifiers.map(AutofillService.from)
        model.beginCredentialList(services: services)
        preferredContentSize = rootView.preferredSheetSize
    }

    override public func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        // Passkey rows arrive in PR 4 (`ProvidesPasskeys = true`). Until then,
        // offer matching password logins for the requested service identifiers.
        prepareCredentialList(for: serviceIdentifiers)
    }

    // MARK: - System Settings Enablement (`prepareInterfaceForExtensionConfiguration`)

    override public func prepareInterfaceForExtensionConfiguration() {
        _ = view
        model.beginExtensionConfiguration()
        preferredContentSize = rootView.preferredSheetSize
    }
}
#endif

#if os(iOS)
/// iOS: every request opens the vault store in-process for its own duration
/// and unseals the biometric slot afresh; nothing stays unlocked between
/// requests, so nothing is filled without the provider's UI.
public final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var completer = SystemExtensionCompleter(controller: self)
    private lazy var client = InProcessProviderClient.live()
    private lazy var model: AutoFillControllerModel = {
        let m = AutoFillControllerModel(
            client: client,
            launcher: NoAgentLauncher(),
            identitySyncer: IdentitySyncer(),
            completer: completer
        )
        m.onChange = { [weak self] in
            self?.observer.revision &+= 1
        }
        return m
    }()

    private let observer = AutoFillObserver()

    override public func viewDidLoad() {
        super.viewDidLoad()
        RuneFonts.register()
        let host = UIHostingController(rootView: AutoFillRootView(model: model, observer: observer))
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        host.view.backgroundColor = .clear
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        host.didMove(toParent: self)
    }

    override public func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        model.handleViewDisappearing()
    }

    // MARK: - Silent AutoFill

    /// Always needs the UI: a fill takes a fresh Face ID or passphrase
    /// unlock, which can't be shown here.
    override public func provideCredentialWithoutUserInteraction(
        for credentialRequest: any ASCredentialRequest
    ) {
        completer.cancelRequest(code: .userInteractionRequired)
    }

    // MARK: - Interactive AutoFill

    override public func prepareInterfaceToProvideCredential(
        for credentialRequest: any ASCredentialRequest
    ) {
        _ = view
        switch credentialRequest.type {
        case .password:
            guard let request = credentialRequest as? ASPasswordCredentialRequest,
                  let identity = request.credentialIdentity as? ASPasswordCredentialIdentity
            else {
                completer.cancelRequest(code: .failed)
                return
            }
            model.beginDirectPasswordFill(
                recordIdentifier: identity.recordIdentifier,
                fallbackUsername: identity.user,
                service: AutofillService.from(identity.serviceIdentifier)
            )
        case .passkeyAssertion:
            guard let request = credentialRequest as? ASPasskeyCredentialRequest,
                  let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
            else {
                completer.cancelRequest(code: .failed)
                return
            }
            model.beginDirectPasskeyAssertion(
                recordIdentifier: identity.recordIdentifier,
                target: PasskeyAssertionTarget(
                    rpId: identity.relyingPartyIdentifier,
                    clientDataHash: request.clientDataHash,
                    verify: PasskeyVerify(request.userVerificationPreference)
                )
            )
        default:
            if #available(iOS 18.0, *),
               credentialRequest.type == .oneTimeCode,
               let request = credentialRequest as? ASOneTimeCodeCredentialRequest,
               let identity = request.credentialIdentity as? ASOneTimeCodeCredentialIdentity
            {
                model.beginDirectOneTimeCode(
                    recordIdentifier: identity.recordIdentifier,
                    service: AutofillService.from(identity.serviceIdentifier)
                )
                return
            }
            completer.cancelRequest(code: .failed)
        }
    }

    // MARK: - Credential pickers

    override public func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        _ = view
        model.beginCredentialList(services: serviceIdentifiers.map(AutofillService.from))
    }

    override public func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        _ = view
        model.beginPasskeyList(
            services: serviceIdentifiers.map(AutofillService.from),
            target: PasskeyAssertionTarget(
                rpId: requestParameters.relyingPartyIdentifier,
                clientDataHash: requestParameters.clientDataHash,
                verify: PasskeyVerify(requestParameters.userVerificationPreference)
            ),
            allowedCredentials: requestParameters.allowedCredentials
        )
    }

    @available(iOS 18.0, *)
    override public func prepareOneTimeCodeCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        _ = view
        model.beginOneTimeCodeList(services: serviceIdentifiers.map(AutofillService.from))
    }

    // MARK: - Passkey registration

    override public func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        _ = view
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            completer.cancelRequest(code: .failed)
            return
        }
        // Deadbolt's passkeys are ES256 (COSE -7); refuse a request that
        // doesn't accept it rather than return a credential the site rejects.
        guard request.supportedAlgorithms.contains(.ES256) else {
            completer.cancelRequest(code: .failed)
            return
        }
        var excluded: [Data] = []
        if #available(iOS 18.0, *) {
            excluded = request.excludedCredentials?.map(\.credentialID) ?? []
        }
        model.beginPasskeyRegistration(
            PasskeyRegistrationTarget(
                rpId: identity.relyingPartyIdentifier,
                clientDataHash: request.clientDataHash,
                userHandle: identity.userHandle,
                userName: identity.userName,
                userDisplayName: "",
                excludedCredentials: excluded,
                verify: PasskeyVerify(request.userVerificationPreference)
            )
        )
    }

    // MARK: - Settings enablement

    override public func prepareInterfaceForExtensionConfiguration() {
        _ = view
        model.beginExtensionConfiguration()
    }
}

/// iOS has no agent to start or app to open from the provider.
struct NoAgentLauncher: AgentLaunching {
    func startInBackground() async -> Bool { false }
    func openContainingApp() async -> Bool { false }
}

extension PasskeyVerify {
    /// Apple's preference strings are WebAuthn's own; anything else is
    /// treated as the WebAuthn default, `preferred`.
    init(_ preference: ASAuthorizationPublicKeyCredentialUserVerificationPreference) {
        self = PasskeyVerify(rawValue: preference.rawValue) ?? .preferred
    }
}
#endif
