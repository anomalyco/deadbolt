// Secure Enclave helper for Deadbolt Touch ID unlock.
//
// Compiled by `crates/cli/build.rs` into `deadbolt-enclave` with an embedded
// `__TEXT,__info_plist` section (`CFBundleIdentifier = "pw.deadbolt.app.enclave"`,
// `CFBundleDisplayName = "Deadbolt"`), pinned by SHA-256 in the agent binary,
// and invoked over stdin/stdout pipes by `crates/cli/src/agent/biometric.rs`.
//
// Commands:
//   deadbolt-enclave status
//   deadbolt-enclave seal
//   deadbolt-enclave unseal [--non-interactive] [--reason <text>]
//   deadbolt-enclave identify          (identify.swift)
//
// Exit codes:
//   0  success
//   2  usage error
//   10 user or system cancelled Touch ID prompt
//   11 Touch ID unavailable right now (lid closed, not enrolled, locked out, or auth failed)
//   12 enrolled Touch ID fingerprint set changed (`stateHash` mismatch)
//   13 malformed or tampered sealed token
//   14 unexpected error (never wipes enrollment)
//   15 identify: no process has that audit token (it exited)

import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security

private let secretLen = 32
private let ephPubLen = 65
private let gcmBoxLen = 12 + secretLen + 16
private let hkdfInfoPrefix = Data("deadbolt-enclave/v1".utf8)
private let aadDomainPrefix = Data("deadbolt-enclave/v1/aad".utf8)
private let testFallbackStateHash = Data(repeating: 0xaa, count: 32)

private enum ExitCode: Int32 {
    case ok = 0
    case usage = 2
    case cancelled = 10
    case unavailable = 11
    case invalidated = 12
    case invalidInput = 13
    case failed = 14
}

private func fail(_ code: ExitCode, _ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code.rawValue)
}

private func readU16LE(_ data: Data, at offset: Int) -> Int {
    let base = data.startIndex + offset
    let b0 = Int(data[base])
    let b1 = Int(data[base + 1])
    return b0 | (b1 << 8)
}

private func appendU16LE(_ value: Int, to data: inout Data) {
    data.append(UInt8(truncatingIfNeeded: value & 0xff))
    data.append(UInt8(truncatingIfNeeded: (value >> 8) & 0xff))
}

private func appendU64LE(_ value: Int, to data: inout Data) {
    let u = UInt64(value)
    for shift in stride(from: 0, to: 64, by: 8) {
        data.append(UInt8(truncatingIfNeeded: (u >> shift) & 0xff))
    }
}

private func buildHKDFInfo(sePubKey: Data) -> Data {
    var info = Data(capacity: hkdfInfoPrefix.count + sePubKey.count)
    info.append(hkdfInfoPrefix)
    info.append(sePubKey)
    return info
}

private func buildAAD(
    stateHash: Data,
    seBlob: Data,
    ephPub: Data,
    externalAAD: Data
) -> Data {
    var aad = Data()
    aad.append(aadDomainPrefix)
    for part in [stateHash, seBlob, ephPub, externalAAD] {
        appendU64LE(part.count, to: &aad)
        aad.append(part)
    }
    return aad
}

private func currentBiometryState() -> (hash: Data?, notEnrolled: Bool) {
    let ctx = LAContext()
    var laError: NSError?
    _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError)
    if #available(macOS 15.0, *) {
        if let hash = ctx.domainState.biometry.stateHash, !hash.isEmpty {
            return (hash, false)
        }
    }
    if let legacy = ctx.evaluatedPolicyDomainState, !legacy.isEmpty {
        return (legacy, false)
    }
    let notEnrolled = laError?.domain == LAError.errorDomain
        && laError?.code == LAError.Code.biometryNotEnrolled.rawValue
    return (nil, notEnrolled)
}

private func isBiometrySetChanged(recordedStateHash: Data, requireBiometry: Bool) -> Bool {
    guard !recordedStateHash.isEmpty else {
        return false
    }
    let (currentHash, notEnrolled) = currentBiometryState()
    #if DEADBOLT_TEST
    if !requireBiometry {
        let expected = currentHash ?? testFallbackStateHash
        return recordedStateHash != expected
    }
    #endif
    if let currentHash = currentHash {
        return currentHash != recordedStateHash
    }
    if notEnrolled {
        return true
    }
    return false
}

private func classifyError(_ error: Error, nonInteractive: Bool) -> ExitCode {
    let ns = error as NSError
    if ns.domain == LAError.errorDomain, let code = LAError.Code(rawValue: ns.code) {
        switch code {
        case .userCancel, .appCancel, .systemCancel, .userFallback:
            return nonInteractive ? .unavailable : .cancelled
        case .notInteractive,
             .biometryNotAvailable,
             .biometryNotEnrolled,
             .biometryDisconnected,
             .biometryNotPaired,
             .passcodeNotSet,
             .biometryLockout,
             .authenticationFailed,
             .invalidContext:
            return .unavailable
        default:
            return .failed
        }
    }
    if ns.domain == TKError.errorDomain || ns.domain == "com.apple.CryptoTokenKit" {
        if let code = TKError.Code(rawValue: ns.code) {
            switch code {
            case .authenticationFailed, .authenticationNeeded, .communicationError, .tokenNotFound:
                return .unavailable
            case .corruptedData:
                return .invalidInput
            default:
                return .failed
            }
        }
        return .failed
    }
    if ns.domain == NSOSStatusErrorDomain {
        switch OSStatus(ns.code) {
        case errSecUserCanceled:
            return nonInteractive ? .unavailable : .cancelled
        case errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed:
            return .unavailable
        default:
            return .failed
        }
    }
    return .failed
}

private func isEnclaveAvailable() -> Bool {
    #if DEADBOLT_TEST
    if ProcessInfo.processInfo.environment["DEADBOLT_TEST_NO_ENCLAVE"] == "1" {
        return false
    }
    #endif
    return SecureEnclave.isAvailable
}

private func runStatus() -> Never {
    let enclave = isEnclaveAvailable()
    let bio = enclave && currentBiometryState().hash != nil
    let out = "enclave=\(enclave ? 1 : 0)\nbiometrics=\(bio ? 1 : 0)\n"
    FileHandle.standardOutput.write(Data(out.utf8))
    exit(ExitCode.ok.rawValue)
}

private func runSeal(requireBiometry: Bool) -> Never {
    guard isEnclaveAvailable() else {
        fail(.unavailable, "Secure Enclave is not available on this Mac")
    }
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count >= secretLen else {
        fail(.invalidInput, "expected at least \(secretLen) bytes on stdin, got \(input.count)")
    }
    let secret = input.prefix(secretLen)
    let externalAAD = Data(input.dropFirst(secretLen))

    let stateHash: Data
    if requireBiometry {
        guard let current = currentBiometryState().hash else {
            fail(.unavailable, "Touch ID is not enrolled on this Mac")
        }
        stateHash = current
    } else {
        stateHash = currentBiometryState().hash ?? testFallbackStateHash
    }
    guard stateHash.count <= Int(UInt8.max) else {
        fail(.invalidInput, "biometry stateHash too long (\(stateHash.count) bytes)")
    }

    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if requireBiometry {
        flags.insert(.biometryCurrentSet)
    }
    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &acError
    ) else {
        let err = acError?.takeRetainedValue() as Error?
        fail(.unavailable, "SecAccessControlCreateWithFlags failed: \(String(describing: err))")
    }

    let ctx = LAContext()
    ctx.interactionNotAllowed = true
    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access,
            authenticationContext: ctx
        )
    } catch {
        fail(
            classifyError(error, nonInteractive: true),
            "Secure Enclave key generation failed: \(error)"
        )
    }

    let seBlob = seKey.dataRepresentation
    let sePubBytes = seKey.publicKey.x963Representation
    guard seBlob.count <= Int(UInt16.max) else {
        fail(.invalidInput, "Secure Enclave key blob too large (\(seBlob.count) bytes)")
    }

    do {
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let shared = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let symKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephPub,
            sharedInfo: buildHKDFInfo(sePubKey: sePubBytes),
            outputByteCount: secretLen
        )
        let aad = buildAAD(
            stateHash: stateHash,
            seBlob: seBlob,
            ephPub: ephPub,
            externalAAD: externalAAD
        )
        let sealed = try AES.GCM.seal(secret, using: symKey, authenticating: aad)
        guard let combined = sealed.combined, combined.count == gcmBoxLen else {
            fail(.invalidInput, "unexpected AES-GCM combined length")
        }

        var out = Data(capacity: 1 + stateHash.count + 2 + seBlob.count + ephPubLen + gcmBoxLen)
        out.append(UInt8(stateHash.count))
        out.append(stateHash)
        appendU16LE(seBlob.count, to: &out)
        out.append(seBlob)
        out.append(ephPub)
        out.append(combined)
        FileHandle.standardOutput.write(out)
        exit(ExitCode.ok.rawValue)
    } catch {
        fail(classifyError(error, nonInteractive: true), "key agreement seal failed: \(error)")
    }
}

private func runUnseal(nonInteractive: Bool, requireBiometry: Bool, reason: String) -> Never {
    guard isEnclaveAvailable() else {
        fail(.unavailable, "Secure Enclave is not available on this Mac")
    }
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count >= 3 else {
        fail(.invalidInput, "sealed input too short")
    }
    let aadLen = readU16LE(input, at: 0)
    guard input.count >= 2 + aadLen + 1 else {
        fail(.invalidInput, "sealed input truncated before stateHash")
    }
    let externalAAD = input.subdata(in: 2 ..< (2 + aadLen))
    let envStart = 2 + aadLen
    let stateHashLen = Int(input[input.startIndex + envStart])
    let seLenOffset = envStart + 1 + stateHashLen
    guard stateHashLen > 0, input.count >= seLenOffset + 2 else {
        fail(.invalidInput, "sealed input truncated before seLen")
    }
    let recordedStateHash = input.subdata(in: (envStart + 1) ..< seLenOffset)
    let seLen = readU16LE(input, at: seLenOffset)
    let seStart = seLenOffset + 2
    let expectedLen = seStart + seLen + ephPubLen + gcmBoxLen
    guard seLen > 0, input.count == expectedLen else {
        fail(.invalidInput, "sealed input length mismatch (got \(input.count), expected \(expectedLen))")
    }

    if isBiometrySetChanged(recordedStateHash: recordedStateHash, requireBiometry: requireBiometry) {
        fail(.invalidated, "enrolled Touch ID fingerprints changed")
    }

    let seBlob = input.subdata(in: seStart ..< (seStart + seLen))
    let ephStart = seStart + seLen
    let ephPubBytes = input.subdata(in: ephStart ..< (ephStart + ephPubLen))
    let boxBytes = input.subdata(in: (ephStart + ephPubLen) ..< expectedLen)

    let ephPub: P256.KeyAgreement.PublicKey
    let box: AES.GCM.SealedBox
    do {
        ephPub = try P256.KeyAgreement.PublicKey(x963Representation: ephPubBytes)
        box = try AES.GCM.SealedBox(combined: boxBytes)
    } catch {
        fail(.invalidInput, "malformed public key or sealed box: \(error)")
    }

    let ctx = LAContext()
    ctx.localizedFallbackTitle = ""
    if nonInteractive {
        ctx.interactionNotAllowed = true
    } else if !reason.isEmpty {
        ctx.localizedReason = reason
    }

    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    let shared: SharedSecret
    do {
        seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: seBlob,
            authenticationContext: ctx
        )
        shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub)
    } catch {
        if isBiometrySetChanged(recordedStateHash: recordedStateHash, requireBiometry: requireBiometry) {
            fail(.invalidated, "enrolled Touch ID fingerprints changed")
        }
        fail(
            classifyError(error, nonInteractive: nonInteractive),
            "Secure Enclave key agreement failed: \(error)"
        )
    }

    let sePubBytes = seKey.publicKey.x963Representation
    let symKey = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephPubBytes,
        sharedInfo: buildHKDFInfo(sePubKey: sePubBytes),
        outputByteCount: secretLen
    )
    let aad = buildAAD(
        stateHash: recordedStateHash,
        seBlob: seBlob,
        ephPub: ephPubBytes,
        externalAAD: externalAAD
    )
    do {
        let opened = try AES.GCM.open(box, using: symKey, authenticating: aad)
        guard opened.count == secretLen else {
            fail(.invalidInput, "unexpected plaintext length")
        }
        FileHandle.standardOutput.write(opened)
        exit(ExitCode.ok.rawValue)
    } catch {
        fail(.invalidInput, "AES-GCM open failed: \(error)")
    }
}

@main
private enum EnclaveHelper {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let cmd = args.first else {
            fail(.usage, "usage: deadbolt-enclave <status|seal|unseal|identify>")
        }

        switch cmd {
        case "status":
            guard args.count == 1 else {
                fail(.usage, "status takes no arguments")
            }
            runStatus()
        case "seal":
            #if DEADBOLT_TEST
            var requireBiometry = true
            for arg in args.dropFirst() {
                if arg == "--no-biometry" {
                    requireBiometry = false
                } else {
                    fail(.usage, "unknown seal argument: \(arg)")
                }
            }
            runSeal(requireBiometry: requireBiometry)
            #else
            guard args.count == 1 else {
                fail(.usage, "seal takes no arguments")
            }
            runSeal(requireBiometry: true)
            #endif
        case "identify":
            guard args.count == 1 else {
                fail(.usage, "identify takes no arguments")
            }
            runIdentify()
        case "unseal":
            var nonInteractive = false
            var requireBiometry = true
            var reason = "unlock your Deadbolt vaults"
            #if DEADBOLT_TEST
            var sleepMs = 0
            #endif
            var i = 1
            while i < args.count {
                switch args[i] {
                case "--non-interactive":
                    nonInteractive = true
                    i += 1
                case "--reason":
                    guard i + 1 < args.count else {
                        fail(.usage, "--reason requires an argument")
                    }
                    reason = args[i + 1]
                    i += 2
                default:
                    #if DEADBOLT_TEST
                    if args[i] == "--no-biometry" {
                        requireBiometry = false
                        i += 1
                        continue
                    }
                    if args[i] == "--sleep-ms" {
                        guard i + 1 < args.count, let ms = Int(args[i + 1]), ms >= 0 else {
                            fail(.usage, "--sleep-ms requires a non-negative integer")
                        }
                        sleepMs = ms
                        i += 2
                        continue
                    }
                    #endif
                    fail(.usage, "unknown argument: \(args[i])")
                }
            }
            #if DEADBOLT_TEST
            if sleepMs > 0 {
                Thread.sleep(forTimeInterval: Double(sleepMs) / 1000.0)
            }
            #endif
            runUnseal(
                nonInteractive: nonInteractive,
                requireBiometry: requireBiometry,
                reason: reason
            )
        default:
            fail(.usage, "unknown command: \(cmd)")
        }
    }
}
