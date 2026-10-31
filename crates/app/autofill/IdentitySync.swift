// Synchronizes non-secret credential lookup metadata into the system
// `ASCredentialIdentityStore` (`docs/macos-autofill.md`, `docs/mobile.md`).
// macOS publishes password identities only, matching its advertised
// capabilities. iOS also publishes passkey and (iOS 18+) one-time-code
// identities; the iOS app publishes through `IdentitySyncer.publish(_:)`,
// never the provider around a fill.
//
// Passwords, OTP seeds/codes, passkey private keys, notes, and custom fields
// never enter `ASCredentialIdentityStore`.

import AuthenticationServices
import Darwin
import Foundation

public protocol IdentityStoreProviding: Sendable {
    func isEnabled() async -> Bool
    /// Replaces every identity with those of `snapshot` this platform offers.
    func replaceIdentities(_ snapshot: AutofillIdentitiesReply) async throws
    func removeAllIdentities() async throws
}

public struct SystemIdentityStoreAdapter: IdentityStoreProviding {
    public init() {}

    public func isEnabled() async -> Bool {
        let state = await ASCredentialIdentityStore.shared.state()
        return state.isEnabled
    }

    public func replaceIdentities(_ snapshot: AutofillIdentitiesReply) async throws {
        try await replace(Self.entries(snapshot))
    }

    /// The system identities for `snapshot`: passwords everywhere; passkeys
    /// and one-time codes on iOS only (macOS doesn't advertise them).
    public static func entries(_ snapshot: AutofillIdentitiesReply) -> [any ASCredentialIdentity] {
        var entries: [any ASCredentialIdentity] = snapshot.passwords.map { item in
            let service = ASCredentialServiceIdentifier(
                identifier: item.domain,
                type: .domain
            )
            let identity = ASPasswordCredentialIdentity(
                serviceIdentifier: service,
                user: item.username,
                recordIdentifier: item.recordId
            )
            identity.rank = Int(clamping: item.rank)
            return identity
        }
        #if os(iOS)
        for item in snapshot.passkeys {
            guard let credentialID = Base64URL.decode(item.credentialId),
                  let userHandle = Base64URL.decode(item.userHandle)
            else {
                continue
            }
            let identity = ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: item.rpId,
                userName: item.username,
                credentialID: credentialID,
                userHandle: userHandle,
                recordIdentifier: item.recordId
            )
            identity.rank = Int(clamping: item.rank)
            entries.append(identity)
        }
        if #available(iOS 18.0, *) {
            for item in snapshot.oneTimeCodes {
                let identity = ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: item.domain, type: .domain),
                    label: item.label,
                    recordIdentifier: item.recordId
                )
                identity.rank = Int(clamping: item.rank)
                entries.append(identity)
            }
        }
        #endif
        return entries
    }

    private func replace(_ entries: [any ASCredentialIdentity]) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(entries) { ok, error in
                if ok {
                    cont.resume(returning: ())
                } else {
                    cont.resume(
                        throwing: error ?? NSError(
                            domain: ASCredentialIdentityStoreErrorDomain,
                            code: ASCredentialIdentityStoreError.internalError.rawValue
                        )
                    )
                }
            }
        }
    }

    public func removeAllIdentities() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            ASCredentialIdentityStore.shared.removeAllCredentialIdentities { ok, error in
                if ok {
                    cont.resume(returning: ())
                } else {
                    cont.resume(
                        throwing: error ?? NSError(
                            domain: ASCredentialIdentityStoreErrorDomain,
                            code: ASCredentialIdentityStoreError.internalError.rawValue
                        )
                    )
                }
            }
        }
    }
}

public protocol IdentityHashPersisting: Sendable {
    func readHash() -> String?
    func writeHash(_ hash: String)
    func clearHash()
}

public struct FileIdentityHashStore: IdentityHashPersisting {
    public let fileURL: URL?

    public init(fileURL: URL?) {
        self.fileURL = fileURL
    }

    public static func live() -> FileIdentityHashStore {
        #if os(iOS)
        let url = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AutofillWire.iosAppGroup)?
            .appendingPathComponent("identities.hash", isDirectory: false)
        #else
        let group = AppGroupContainer.resolve()
        let url = group.socketURL?.deletingLastPathComponent()
            .appendingPathComponent("identities.hash", isDirectory: false)
        #endif
        return FileIdentityHashStore(fileURL: url)
    }

    public func readHash() -> String? {
        guard let fileURL,
              let data = try? Data(contentsOf: fileURL),
              let raw = String(data: data, encoding: .utf8)
        else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    public func writeHash(_ hash: String) {
        guard let fileURL else { return }
        let data = Data((hash + "\n").utf8)
        try? data.write(to: fileURL, options: .atomic)
        _ = fileURL.path.withCString { Darwin.chmod($0, mode_t(0o600)) }
    }

    public func clearHash() {
        guard let fileURL else { return }
        try? FileManager.default.removeItem(at: fileURL)
    }
}

public struct IdentitySyncer: Sendable {
    public let store: any IdentityStoreProviding
    public let hashStore: any IdentityHashPersisting

    public init(
        store: any IdentityStoreProviding = SystemIdentityStoreAdapter(),
        hashStore: any IdentityHashPersisting = FileIdentityHashStore.live()
    ) {
        self.store = store
        self.hashStore = hashStore
    }

    /// Syncs `ASCredentialIdentityStore` from `autofill-identities` when the
    /// store is enabled and `reportedHash` differs from the last synced hash.
    /// Pass `reportedHash: nil` to force a check against the agent.
    @discardableResult
    public func syncIfNeeded(
        client: any AutofillAgentClient,
        reportedHash: String? = nil,
        timeout: TimeInterval = 5.0
    ) async -> Bool {
        guard await store.isEnabled() else {
            hashStore.clearHash()
            return false
        }
        if let reportedHash, hashStore.readHash() == reportedHash {
            return false
        }
        guard let reply = try? await client.send(
            .autofillIdentities,
            timeout: timeout,
            handle: nil
        ),
            case let .autofillIdentities(snapshot) = reply
        else {
            return false
        }
        return await publish(snapshot)
    }

    /// Publishes `snapshot` unless the store is disabled or already holds
    /// it. The iOS app calls this with the core's identity snapshot.
    @discardableResult
    public func publish(_ snapshot: AutofillIdentitiesReply) async -> Bool {
        guard await store.isEnabled() else {
            hashStore.clearHash()
            return false
        }
        if hashStore.readHash() == snapshot.identitiesHash {
            return false
        }
        do {
            try await store.replaceIdentities(snapshot)
            hashStore.writeHash(snapshot.identitiesHash)
            return true
        } catch {
            return false
        }
    }
}
