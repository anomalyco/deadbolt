// iOS credential provider: the in-process client to the Rust core's
// `MobileCredentialProvider` (crates/mobile-core/src/provider.rs). It
// implements the same `AutofillAgentClient` seam as macOS's socket client,
// so the shared ControllerModel drives both; there is no socket, no agent
// and no network.
//
// Every extension request is bound to the core with the OS-supplied
// services, relying party and hash (`beginRequest`) before anything is
// shown. The core opens the store only inside `list` and `complete`, replays
// the signed log offline, and closes it before returning; redb's exclusive
// lock stays authoritative, so while the Deadbolt app holds the store the
// core answers `InUse` and this client reports a quiet `busy`.
//
// Unlock material lives for one request only and never outlives
// `endRequest()`. Biometric unlock never keeps a key: every `list` and every
// `complete` unseals the Secure Enclave envelope afresh (Enclave.swift
// through `unseal`, one system prompt each) and zeroes the key bytes as soon
// as the core call returns. The core's `verified` flag only means that one
// call's key unwrapped the slot, so a key from the picker's `list` is never
// reused to complete. No Boolean `LAContext` gate, no passcode or software
// fallback.
//
// Foundation only, so the macOS host can exercise it with a fake core.

import Foundation

/// How a `list` or `complete` call unlocks the store. A biometric key is
/// freshly unsealed for that one call; the client resets its owned Data after it.
public enum ProviderAuthentication: Sendable {
    case passphrase(String)
    case biometric(Data)
}

/// How this request was unlocked. Biometric holds no key, only the choice.
private enum Unlock {
    case passphrase(String)
    case biometric
}

/// A `MobileProviderError`, as CoreBridge.swift maps the generated enum.
public struct ProviderCoreError: Error, Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case inUse, busy, cancelled, authentication, invalidRequest, domainMismatch
        case notFound, interactionRequired, verificationRequired, alreadyExists
        case storage, invalidVault, unconfirmedWrite, notInitialized, `internal`
    }

    public let kind: Kind
    public let message: String

    public init(_ kind: Kind, _ message: String) {
        self.kind = kind
        self.message = message
    }
}

/// The Rust core's `MobileCredentialProvider`. Every method blocks; call it
/// off the main thread.
public protocol ProviderCore: AnyObject, Sendable {
    /// Whether the device has a vault store at all.
    func storeExists() -> Bool
    func begin(_ request: String) throws -> UInt64
    func biometricToken(_ requestId: UInt64) throws -> Data
    func list(_ requestId: UInt64, _ authentication: ProviderAuthentication) throws -> String
    func complete(_ requestId: UInt64, recordId: String?, _ authentication: ProviderAuthentication) throws -> String
    func cancel(_ requestId: UInt64)
}

public final class InProcessProviderClient: AutofillAgentClient, @unchecked Sendable {
    /// Opens a biometric envelope with a fresh system biometric prompt,
    /// returning the slot key or throwing an `AgentCallError`.
    public typealias Unseal = @Sendable (_ token: Data) throws -> Data

    private let core: any ProviderCore
    private let unseal: Unseal
    private let biometricAvailable: @Sendable () -> Bool
    /// Whether the envelope could open now (age and enrolled biometric set),
    /// checked without a prompt.
    private let tokenUsable: @Sendable (Data) -> Bool
    /// Calls run one at a time, in order, after the request's `begin`.
    private let queue = DispatchQueue(label: "pw.deadbolt.autofill.provider", qos: .userInitiated)
    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var state = RequestState()

    private struct RequestState {
        /// The core's id for this request, or why `begin` refused it.
        var begun: Result<UInt64, AgentCallError>?
        var unlock: Unlock?
        var biometricEnrolled = false
    }

    public init(
        core: any ProviderCore,
        unseal: @escaping Unseal,
        biometricAvailable: @escaping @Sendable () -> Bool,
        tokenUsable: @escaping @Sendable (Data) -> Bool
    ) {
        self.core = core
        self.unseal = unseal
        self.biometricAvailable = biometricAvailable
        self.tokenUsable = tokenUsable
    }

    public func beginRequest(_ request: ProviderRequest) {
        let line: String
        do {
            line = String(decoding: try JSONEncoder().encode(request), as: UTF8.self)
        } catch {
            line = ""
        }
        lock.lock()
        generation &+= 1
        let current = generation
        let previous = state.begun
        state = RequestState()
        lock.unlock()
        let core = self.core
        queue.async {
            if case let .success(id)? = previous {
                core.cancel(id)
            }
            let begun: Result<UInt64, AgentCallError>
            do {
                begun = .success(try core.begin(line))
            } catch {
                begun = .failure(Self.map(error, biometricReady: false))
            }
            self.lock.lock()
            if self.generation == current {
                self.state.begun = begun
                self.lock.unlock()
            } else {
                self.lock.unlock()
                if case let .success(id) = begun {
                    core.cancel(id)
                }
            }
        }
    }

    public func endRequest() {
        lock.lock()
        generation &+= 1
        let begun = state.begun
        state = RequestState()
        lock.unlock()
        if case let .success(id)? = begun {
            // Revokes publication at once, even of a call still running.
            core.cancel(id)
        }
    }

    public func send(
        _ command: AutofillCommand,
        timeout: TimeInterval,
        handle: AutofillCallHandle?
    ) async throws -> AutofillReply {
        let current = currentGeneration()
        // The core can't be interrupted mid-call: a cancelled task or handle
        // discards the result, and `endRequest()` revokes the core request.
        if Task.isCancelled || handle?.isCancelled == true {
            throw AgentCallError.cancelled
        }
        let reply: AutofillReply = try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try self.perform(command, generation: current) })
            }
        }
        // Final check after the FFI returned: never deliver for a request
        // that ended or was replaced meanwhile.
        let stale = currentGeneration() != current
        if Task.isCancelled || stale || handle?.isCancelled == true {
            throw AgentCallError.cancelled
        }
        return reply
    }

    // MARK: - Commands

    private func perform(_ command: AutofillCommand, generation current: UInt64) throws -> AutofillReply {
        let id = try requestId(current)
        switch command {
        case .autofillStatus:
            return .autofillStatus(try status(id, generation: current))
        case let .unlock(passphrase):
            update(current) { $0.unlock = .passphrase(passphrase) }
            return .done
        case .unlockBiometric:
            guard biometricAvailable() else {
                throw AgentCallError.agentError(code: .failed, message: "Biometric unlock isn't available on this iPhone.")
            }
            // The prompt comes with the call that needs the key.
            update(current) { $0.unlock = .biometric }
            return .done
        case .autofillList:
            let line = try authenticated(id, generation: current) { auth in try core.list(id, auth) }
            return .autofillList(try Self.decodeList(line))
        case let .autofillFill(_, login, _, _):
            let line = try completion(id, record: login.recordIdentifier, generation: current)
            let fill = try Self.decode(FillLine.self, line)
            return .autofillFill(AutofillFillReply(values: fill.values, identitiesHash: ""))
        case let .autofillPasskeyGet(_, passkey, _, _, _):
            let line = try completion(id, record: passkey.recordIdentifier, generation: current)
            return .autofillPasskeyAssertion(try Self.decode(AutofillPasskeyAssertionReply.self, line))
        case .autofillPasskeyCreate:
            let line = try completion(id, record: nil, generation: current)
            return .autofillPasskeyCreated(try Self.decode(AutofillPasskeyCreatedReply.self, line))
        case .status, .autofillIdentities:
            // The iOS app publishes identities; the provider never does.
            throw AgentCallError.agentError(code: .forbidden, message: "Not available in the iOS provider.")
        }
    }

    private func status(_ id: UInt64, generation current: UInt64) throws -> AutofillStatusReply {
        guard core.storeExists() else {
            return AutofillStatusReply(initialized: false, unlocked: false, touchIdReady: false)
        }
        // Reading the envelope also shows whether the app holds the store.
        // An expired or re-enrolled envelope isn't offered: unsealing it
        // could only fail.
        var ready = false
        do {
            let token = try core.biometricToken(id)
            ready = !token.isEmpty && biometricAvailable() && tokenUsable(token)
        } catch let error as ProviderCoreError where error.kind == .authentication {
            ready = false
        } catch {
            throw Self.map(error, biometricReady: false)
        }
        var unlocked = false
        update(current) {
            $0.biometricEnrolled = ready
            unlocked = $0.unlock != nil
        }
        return AutofillStatusReply(initialized: true, unlocked: unlocked, touchIdReady: ready, canVerify: ready)
    }

    private func completion(_ id: UInt64, record: String?, generation current: UInt64) throws -> String {
        try authenticated(id, generation: current) { auth in
            try core.complete(id, recordId: record, auth)
        }
    }

    /// Runs one core call with this request's unlock: the passphrase, or a
    /// biometric key unsealed for this call alone and zeroed right after it.
    private func authenticated(
        _ id: UInt64,
        generation current: UInt64,
        _ body: (ProviderAuthentication) throws -> String
    ) throws -> String {
        switch try unlockChoice(current) {
        case let .passphrase(value):
            return try mapped(current) { try body(.passphrase(value)) }
        case .biometric:
            let token = try mapped(current) { try core.biometricToken(id) }
            var key: Data
            do {
                key = try unseal(token)
            } catch {
                // Cancelled or refused: back to the locked screen, which
                // offers Face ID again only when the person asks. An
                // envelope that can no longer open (`locked`, with its
                // reason) stops being offered, so the passphrase is.
                update(current) {
                    $0.unlock = nil
                    if case let AgentCallError.agentError(code, _) = error, code == .locked {
                        $0.biometricEnrolled = false
                    }
                }
                throw Self.map(error, biometricReady: false)
            }
            // The only zeroing that reaches the key's storage: by now the
            // FFI has copied the bytes and every shared copy is released.
            defer { key.resetBytes(in: 0 ..< key.count) }
            return try mapped(current) { try body(.biometric(key)) }
        }
    }

    // MARK: - State

    private func currentGeneration() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return generation
    }

    private func requestId(_ current: UInt64) throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        guard generation == current else {
            throw AgentCallError.cancelled
        }
        switch state.begun {
        case let .success(id)?:
            return id
        case let .failure(error)?:
            throw error
        case nil:
            // Ended (or never begun): nothing may run for it.
            throw AgentCallError.cancelled
        }
    }

    private func unlockChoice(_ current: UInt64) throws -> Unlock {
        lock.lock()
        defer { lock.unlock() }
        guard generation == current else {
            throw AgentCallError.cancelled
        }
        guard let unlock = state.unlock else {
            throw AgentCallError.agentError(code: .locked, message: "")
        }
        return unlock
    }

    private func update(_ current: UInt64, _ change: (inout RequestState) -> Void) {
        lock.lock()
        if generation == current {
            change(&state)
        }
        lock.unlock()
    }

    /// Runs a core call, mapping its error. A refused unlock forgets the
    /// passphrase or key so the locked screen asks again.
    private func mapped<T>(_ current: UInt64? = nil, _ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch {
            var ready = false
            if let current {
                update(current) {
                    ready = $0.biometricEnrolled
                    if let core = error as? ProviderCoreError, core.kind == .authentication {
                        $0.unlock = nil
                    }
                }
            }
            throw Self.map(error, biometricReady: ready)
        }
    }

    static func map(_ error: Error, biometricReady: Bool) -> AgentCallError {
        if let error = error as? AgentCallError {
            return error
        }
        guard let error = error as? ProviderCoreError else {
            return .agentError(code: .failed, message: error.localizedDescription)
        }
        switch error.kind {
        case .inUse, .busy:
            // The app (or a previous request still finishing its replay) holds
            // the store: recoverable, offered as "Try again".
            return .agentError(code: .busy, message: error.message)
        case .cancelled:
            return .cancelled
        case .authentication:
            return .agentError(code: .locked, message: "That didn't unlock Deadbolt. Try again.")
        case .domainMismatch:
            return .agentError(code: .domainMismatch, message: error.message)
        case .notFound:
            return .agentError(code: .notFound, message: error.message)
        case .interactionRequired:
            return .agentError(code: .interactionRequired, message: error.message)
        case .verificationRequired:
            // Only a fresh biometric unlock verifies a passkey ceremony.
            return biometricReady
                ? .agentError(code: .interactionRequired, message: error.message)
                : .agentError(code: .failed, message: "This site needs Face ID or Touch ID. Turn it on in Deadbolt.")
        case .alreadyExists:
            return .agentError(code: .exists, message: error.message)
        case .notInitialized:
            return .agentError(code: .notInitialized, message: error.message)
        case .invalidRequest, .storage, .invalidVault, .unconfirmedWrite, .internal:
            return .agentError(code: .failed, message: error.message)
        }
    }

    // MARK: - Replies

    private struct FillLine: Decodable {
        let values: SiteValues
    }

    private struct ListLine: Decodable {
        let logins: [SiteLogin]
        let passkeys: [SitePasskey]
        let unassociated: Bool
        let biometricEnrolled: Bool

        enum CodingKeys: String, CodingKey {
            case logins
            case passkeys
            case unassociated
            case biometricEnrolled = "biometric_enrolled"
        }
    }

    static func decodeList(_ line: String) throws -> AutofillListReply {
        let list = try decode(ListLine.self, line)
        return AutofillListReply(
            logins: list.logins,
            passkeys: list.passkeys,
            unassociated: list.unassociated,
            canVerify: list.biometricEnrolled,
            identitiesHash: ""
        )
    }

    static func decode<T: Decodable>(_ type: T.Type, _ line: String) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: Data(line.utf8))
        } catch {
            throw AgentCallError.invalidResponse("Deadbolt sent a reply it couldn't read.")
        }
    }
}
