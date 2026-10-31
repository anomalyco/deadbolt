// iOS provider only: binds ProviderClient.swift to the generated UniFFI
// `MobileCredentialProvider` and the app's Secure Enclave slot
// (mobile/ios/Deadbolt/Enclave.swift, compiled into this target too).
// The store is the app's own: `group.pw.deadbolt`/Deadbolt (AppModel.storePath).

import Foundation

final class GeneratedProviderCore: ProviderCore, @unchecked Sendable {
    private let provider: MobileCredentialProvider
    private let directory: URL

    init(directory: URL) {
        self.directory = directory
        self.provider = MobileCredentialProvider(path: directory.path)
    }

    func storeExists() -> Bool {
        FileManager.default.fileExists(atPath: directory.appendingPathComponent("store.redb").path)
    }

    func begin(_ request: String) throws -> UInt64 {
        try bridged { try provider.begin(request: request) }
    }

    func biometricToken(_ requestId: UInt64) throws -> Data {
        try bridged { try provider.biometricToken(requestId: requestId) }
    }

    /// ProviderClient resets its owned Data after this call. Generated UniFFI
    /// serialization can make additional copies that are not explicitly zeroed.
    func list(_ requestId: UInt64, _ authentication: ProviderAuthentication) throws -> String {
        try bridged { try provider.list(requestId: requestId, authentication: Self.lower(authentication)) }
    }

    func complete(_ requestId: UInt64, recordId: String?, _ authentication: ProviderAuthentication) throws -> String {
        try bridged {
            try provider.complete(requestId: requestId, recordId: recordId, authentication: Self.lower(authentication))
        }
    }

    func cancel(_ requestId: UInt64) {
        provider.cancel(requestId: requestId)
    }

    private static func lower(_ authentication: ProviderAuthentication) -> MobileProviderAuthentication {
        switch authentication {
        case let .passphrase(value):
            return .passphrase(value: value)
        case let .biometric(key):
            return .biometric(key: key)
        }
    }

    private func bridged<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let error as MobileProviderError {
            throw Self.map(error)
        }
    }

    static func map(_ error: MobileProviderError) -> ProviderCoreError {
        switch error {
        case let .InUse(message): ProviderCoreError(.inUse, message)
        case let .Busy(message): ProviderCoreError(.busy, message)
        case let .Cancelled(message): ProviderCoreError(.cancelled, message)
        case let .Authentication(message): ProviderCoreError(.authentication, message)
        case let .InvalidRequest(message): ProviderCoreError(.invalidRequest, message)
        case let .DomainMismatch(message): ProviderCoreError(.domainMismatch, message)
        case let .NotFound(message): ProviderCoreError(.notFound, message)
        case let .InteractionRequired(message): ProviderCoreError(.interactionRequired, message)
        case let .VerificationRequired(message): ProviderCoreError(.verificationRequired, message)
        case let .AlreadyExists(message): ProviderCoreError(.alreadyExists, message)
        case let .Storage(message): ProviderCoreError(.storage, message)
        case let .InvalidVault(message): ProviderCoreError(.invalidVault, message)
        case let .UnconfirmedWrite(message): ProviderCoreError(.unconfirmedWrite, message)
        case let .Internal(message): ProviderCoreError(.internal, message)
        }
    }
}

extension InProcessProviderClient {
    /// The provider's client over the app's store, or one that reports why
    /// the store can't be reached.
    static func live() -> InProcessProviderClient {
        let directory = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AutofillWire.iosAppGroup)?
            .appendingPathComponent("Deadbolt", isDirectory: true)
        let core: any ProviderCore = directory.map { GeneratedProviderCore(directory: $0) } ?? MissingStoreCore()
        return InProcessProviderClient(
            core: core,
            unseal: { token in
                do {
                    return try Enclave.unseal(token, reason: "Fill from Deadbolt")
                } catch let failure as EnclaveFailure {
                    switch failure {
                    case .cancelled:
                        throw AgentCallError.cancelled
                    case .invalidated, .unavailable, .malformed:
                        // The slot can't open any more: the passphrase it is.
                        throw AgentCallError.agentError(
                            code: .locked,
                            message: failure.errorDescription ?? "Enter your passphrase."
                        )
                    default:
                        throw AgentCallError.agentError(
                            code: .failed,
                            message: failure.errorDescription ?? "Face ID didn't unlock Deadbolt."
                        )
                    }
                }
            },
            biometricAvailable: { Enclave.unavailableReason == nil },
            tokenUsable: { Enclave.isUsable($0) }
        )
    }
}

/// The App Group container is missing (an unsigned or misconfigured build).
private final class MissingStoreCore: ProviderCore, @unchecked Sendable {
    private var error: ProviderCoreError {
        ProviderCoreError(.storage, "This copy of Deadbolt can't reach its storage. Reinstall it.")
    }

    func storeExists() -> Bool { true }
    func begin(_ request: String) throws -> UInt64 { throw error }
    func biometricToken(_ requestId: UInt64) throws -> Data { throw error }
    func list(_ requestId: UInt64, _ authentication: ProviderAuthentication) throws -> String { throw error }
    func complete(_ requestId: UInt64, recordId: String?, _ authentication: ProviderAuthentication) throws -> String {
        throw error
    }
    func cancel(_ requestId: UInt64) {}
}
