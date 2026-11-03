// Principal `NSExtension` view controller (`DeadboltAutoFill.CredentialProviderViewController`)
// for macOS AutoFill (`System Settings › General › AutoFill & Passwords`).

import AppKit
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
}

public final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var completer = SystemExtensionCompleter(controller: self)
    private lazy var client = UnixSocketDaemonClient.live()
    private lazy var syncer = IdentitySyncer()
    private lazy var model: AutoFillControllerModel = {
        let m = AutoFillControllerModel(
            client: client,
            launcher: WorkspaceDaemonLauncher(),
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
