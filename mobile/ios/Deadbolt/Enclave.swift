// Face ID / Touch ID unlock key protection on iOS, following docs/touch-id.md
// ("Chosen design", option 3b): a random 32-byte slot key is sealed to a
// Secure Enclave P-256 key-agreement key created with
// `[.privateKeyUsage, .biometryCurrentSet]` and
// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Opening it needs the Secure
// Enclave to run ECDH, which it refuses without a live biometric match from the
// currently enrolled set. There is no boolean `LAContext` gate anywhere: the
// key itself is unreachable without the match.
//
// The token is the same `DBSE` envelope as the macOS helper
// (crates/cli/src/agent/enclave.swift), header included, with the header as
// the external AAD:
//
//   "DBSE" | version 1 | flags (bit 0 = biometryCurrentSet) | created_at u64 LE
//   | state_hash_len u8 | state_hash | se_len u16 LE | se_blob
//   | eph_pub (65) | AES-256-GCM nonce ‖ ciphertext ‖ tag (60)
//
// The iOS Simulator has no Secure Enclave. This file has no simulator
// substitute: in the Simulator biometric unlock is reported unavailable.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum EnclaveFailure: LocalizedError, Equatable {
    /// No Secure Enclave or no enrolled biometrics (always so in the Simulator).
    case unavailable(String)
    /// The person cancelled the Face ID sheet.
    case cancelled
    /// The enrolled faces or fingers changed since enrollment, or the slot is
    /// older than 14 days: the passphrase is needed.
    case invalidated
    case malformed
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let why): why
        case .cancelled: "Cancelled."
        case .invalidated: "\(Enclave.biometryName) was reset. Enter your passphrase."
        case .malformed: "The saved \(Enclave.biometryName) key is damaged. Enter your passphrase."
        case .failed(let why): why
        }
    }
}

enum Enclave {
    static let slotKeyLength = 32
    /// docs/touch-id.md: the passphrase must be entered at least every 14 days.
    static let maxAge: TimeInterval = 14 * 24 * 60 * 60

    private static let magic = Data("DBSE".utf8)
    private static let version: UInt8 = 1
    private static let flagBiometryCurrentSet: UInt8 = 1
    private static let headerLength = 4 + 1 + 1 + 8
    private static let ephPubLength = 65
    private static let gcmBoxLength = 12 + slotKeyLength + 16
    private static let hkdfInfoPrefix = Data("deadbolt-enclave/v1".utf8)
    private static let aadDomain = Data("deadbolt-enclave/v1/aad".utf8)

    static var biometryName: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Face ID"
        }
    }

    /// Why biometric unlock can't be offered right now, or nil when it can.
    static var unavailableReason: String? {
        #if targetEnvironment(simulator)
        return "The iOS Simulator has no Secure Enclave. \(biometryName) unlock needs a physical iPhone."
        #else
        guard SecureEnclave.isAvailable else {
            return "This iPhone has no Secure Enclave."
        }
        guard currentStateHash() != nil else {
            return "Set up \(biometryName) in Settings first."
        }
        return nil
        #endif
    }

    static func randomSlotKey() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: slotKeyLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw EnclaveFailure.failed("Couldn't generate a key (\(status)).")
        }
        return Data(bytes)
    }

    /// Seals `key` to a fresh Secure Enclave key. No prompt: encrypting to
    /// the public key needs no biometric match.
    static func seal(_ key: Data, now: Date = Date()) throws -> Data {
        if let reason = unavailableReason {
            throw EnclaveFailure.unavailable(reason)
        }
        guard key.count == slotKeyLength, let stateHash = currentStateHash(), stateHash.count <= Int(UInt8.max) else {
            throw EnclaveFailure.unavailable("Set up \(biometryName) in Settings first.")
        }
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &acError
        ) else {
            let error = acError?.takeRetainedValue()
            throw EnclaveFailure.failed("Couldn't create the access control: \(String(describing: error))")
        }
        let context = LAContext()
        context.interactionNotAllowed = true
        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
        } catch {
            throw classify(error)
        }
        let seBlob = seKey.dataRepresentation
        guard seBlob.count <= Int(UInt16.max) else { throw EnclaveFailure.malformed }

        var header = Data(magic)
        header.append(version)
        header.append(flagBiometryCurrentSet)
        appendU64LE(UInt64(max(0, now.timeIntervalSince1970)), to: &header)

        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        do {
            let shared = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
            let symKey = derive(shared, ephPub: ephPub, sePub: seKey.publicKey.x963Representation)
            let aad = buildAAD(stateHash: stateHash, seBlob: seBlob, ephPub: ephPub, header: header)
            let box = try AES.GCM.seal(key, using: symKey, authenticating: aad)
            guard let combined = box.combined, combined.count == gcmBoxLength else {
                throw EnclaveFailure.malformed
            }
            var out = header
            out.append(UInt8(stateHash.count))
            out.append(stateHash)
            appendU16LE(seBlob.count, to: &out)
            out.append(seBlob)
            out.append(ephPub)
            out.append(combined)
            return out
        } catch let failure as EnclaveFailure {
            throw failure
        } catch {
            throw classify(error)
        }
    }

    /// Opens `token`, showing the system biometric sheet. Blocks while the
    /// sheet is up, so call it off the main thread.
    static func unseal(_ token: Data, reason: String, now: Date = Date()) throws -> Data {
        if let why = unavailableReason {
            throw EnclaveFailure.unavailable(why)
        }
        let parsed = try parse(token)
        let createdAt = Date(timeIntervalSince1970: TimeInterval(parsed.createdAt))
        guard createdAt <= now, now.timeIntervalSince(createdAt) <= maxAge else {
            throw EnclaveFailure.invalidated
        }
        if currentStateHash() != parsed.stateHash {
            throw EnclaveFailure.invalidated
        }
        let ephPub: P256.KeyAgreement.PublicKey
        let box: AES.GCM.SealedBox
        do {
            ephPub = try P256.KeyAgreement.PublicKey(x963Representation: parsed.ephPub)
            box = try AES.GCM.SealedBox(combined: parsed.box)
        } catch {
            throw EnclaveFailure.malformed
        }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.localizedReason = reason
        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        let shared: SharedSecret
        do {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: parsed.seBlob,
                authenticationContext: context
            )
            shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub)
        } catch {
            if currentStateHash() != parsed.stateHash {
                throw EnclaveFailure.invalidated
            }
            throw classify(error)
        }
        let symKey = derive(shared, ephPub: parsed.ephPub, sePub: seKey.publicKey.x963Representation)
        let aad = buildAAD(stateHash: parsed.stateHash, seBlob: parsed.seBlob, ephPub: parsed.ephPub, header: parsed.header)
        do {
            let opened = try AES.GCM.open(box, using: symKey, authenticating: aad)
            guard opened.count == slotKeyLength else { throw EnclaveFailure.malformed }
            return opened
        } catch {
            throw EnclaveFailure.malformed
        }
    }

    /// Whether `unseal` could open `token` now, checked without a prompt:
    /// the envelope parses, is no older than `maxAge`, and was sealed to the
    /// currently enrolled biometric set. Only a preflight; `unseal` still
    /// needs the live biometric match.
    static func isUsable(_ token: Data, now: Date = Date()) -> Bool {
        guard unavailableReason == nil, let parsed = try? parse(token) else { return false }
        let createdAt = Date(timeIntervalSince1970: TimeInterval(parsed.createdAt))
        guard createdAt <= now, now.timeIntervalSince(createdAt) <= maxAge else { return false }
        return currentStateHash() == parsed.stateHash
    }

    /// The enrollment time recorded in `token`, if it parses.
    static func createdAt(_ token: Data) -> Date? {
        guard let parsed = try? parse(token) else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(parsed.createdAt))
    }

    // MARK: Envelope

    private struct Parsed {
        var header: Data
        var createdAt: UInt64
        var stateHash: Data
        var seBlob: Data
        var ephPub: Data
        var box: Data
    }

    private static func parse(_ token: Data) throws -> Parsed {
        let bytes = [UInt8](token)
        guard bytes.count > headerLength + 1,
              Data(bytes[0 ..< 4]) == magic,
              bytes[4] == version,
              bytes[5] & flagBiometryCurrentSet != 0
        else {
            throw EnclaveFailure.malformed
        }
        var createdAt: UInt64 = 0
        for i in 0 ..< 8 {
            createdAt |= UInt64(bytes[6 + i]) << (8 * UInt64(i))
        }
        let hashLength = Int(bytes[headerLength])
        let seLengthOffset = headerLength + 1 + hashLength
        guard hashLength > 0, bytes.count >= seLengthOffset + 2 else { throw EnclaveFailure.malformed }
        let seLength = Int(bytes[seLengthOffset]) | (Int(bytes[seLengthOffset + 1]) << 8)
        let seStart = seLengthOffset + 2
        let ephStart = seStart + seLength
        let boxStart = ephStart + ephPubLength
        guard seLength > 0, bytes.count == boxStart + gcmBoxLength else { throw EnclaveFailure.malformed }
        return Parsed(
            header: Data(bytes[0 ..< headerLength]),
            createdAt: createdAt,
            stateHash: Data(bytes[(headerLength + 1) ..< seLengthOffset]),
            seBlob: Data(bytes[seStart ..< ephStart]),
            ephPub: Data(bytes[ephStart ..< boxStart]),
            box: Data(bytes[boxStart...])
        )
    }

    private static func derive(_ shared: SharedSecret, ephPub: Data, sePub: Data) -> SymmetricKey {
        var info = hkdfInfoPrefix
        info.append(sePub)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephPub,
            sharedInfo: info,
            outputByteCount: slotKeyLength
        )
    }

    private static func buildAAD(stateHash: Data, seBlob: Data, ephPub: Data, header: Data) -> Data {
        var aad = aadDomain
        for part in [stateHash, seBlob, ephPub, header] {
            appendU64LE(UInt64(part.count), to: &aad)
            aad.append(part)
        }
        return aad
    }

    private static func appendU16LE(_ value: Int, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
    }

    private static func appendU64LE(_ value: UInt64, to data: inout Data) {
        for shift in stride(from: 0, to: 64, by: 8) {
            data.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    // MARK: Biometry state

    /// A digest of the enrolled biometric set, which changes when a face or
    /// finger is added or removed. Nil when nothing is enrolled.
    private static func currentStateHash() -> Data? {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        if #available(iOS 18.0, *) {
            if let hash = context.domainState.biometry.stateHash, !hash.isEmpty {
                return hash
            }
        }
        if let legacy = context.evaluatedPolicyDomainState, !legacy.isEmpty {
            return legacy
        }
        return nil
    }

    private static func classify(_ error: Error) -> EnclaveFailure {
        let ns = error as NSError
        if ns.domain == LAError.errorDomain, let code = LAError.Code(rawValue: ns.code) {
            switch code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                return .cancelled
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .passcodeNotSet:
                return .unavailable(ns.localizedDescription)
            case .authenticationFailed:
                return .failed("\(biometryName) didn't recognize you.")
            default:
                return .failed(ns.localizedDescription)
            }
        }
        if ns.domain == NSOSStatusErrorDomain, OSStatus(ns.code) == errSecUserCanceled {
            return .cancelled
        }
        return .failed(ns.localizedDescription)
    }
}
