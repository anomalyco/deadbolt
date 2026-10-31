// Unit tests against the real compiled core (DeadboltCore via UniFFI), hosted
// in the app. Each test opens its own store directory. There is no stand-in
// core: if the Rust library doesn't build, these don't build either.

import XCTest
@testable import Deadbolt

final class CoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("deadbolt-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func open() async throws -> Core {
        try await Core.open(path: dir.path, name: "Deadbolt Tests")
    }

    func testCoreFailurePreservesGeneratedErrorMessage() {
        let message = "core authentication marker"
        let failure = CoreFailure(MobileError.Authentication(message: message))
        XCTAssertEqual(failure.code, "Authentication")
        XCTAssertEqual(failure.message, message)
        let wrapped = CoreFailure(failure)
        XCTAssertEqual(wrapped.code, failure.code)
        XCTAssertEqual(wrapped.message, message)
    }

    func testFreshStoreIsNotSetUpOrUnlocked() async throws {
        let core = try await open()
        let status = try await core.status()
        XCTAssertFalse(status.initialized)
        XCTAssertFalse(status.unlocked)
        XCTAssertFalse(status.biometricReady)
        XCTAssertNil(status.deviceId)
    }

    func testUnlockWithoutAVaultFailsAndStaysLocked() async throws {
        let core = try await open()
        do {
            try await core.unlock(passphrase: "not a vault")
            XCTFail("unlock succeeded on an empty store")
        } catch {
            XCTAssertTrue(error is CoreFailure)
        }
        let status = try await core.status()
        XCTAssertFalse(status.unlocked)
    }

    func testLockedStoreRefusesVaultReads() async throws {
        let core = try await open()
        for read in [
            { _ = try await core.items(query: "") },
            { _ = try await core.secret(id: "0:0", field: "password") },
            { _ = try await core.code(id: "0:0") },
        ] as [() async throws -> Void] {
            do {
                try await read()
                XCTFail("a locked store answered a vault read")
            } catch let failure as CoreFailure {
                XCTAssertEqual(failure.code, "Locked")
            }
        }
    }

    /// Lock while unlocks are in flight, many times over: the store must end
    /// locked and every call must return.
    func testLockRacingUnlockEndsLocked() async throws {
        let core = try await open()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 20 {
                group.addTask { try? await core.unlock(passphrase: "racing") }
                group.addTask { try? await core.lock() }
            }
        }
        try await core.lock()
        let status = try await core.status()
        XCTAssertFalse(status.unlocked)
    }

    /// Locking during pairing cancels it: nothing is saved and no pairing is
    /// left running, whether or not join-start had returned yet.
    func testLockCancelsPairing() async throws {
        let core = try await open()
        let start = Task { try await core.joinStart(passphrase: "pairing passphrase") }
        try await core.lock()
        _ = try? await start.value
        try await core.lock()
        let join = try await core.joinStatus()
        XCTAssertEqual(join.state, .error)
        let status = try await core.status()
        XCTAssertFalse(status.initialized)
        XCTAssertFalse(status.unlocked)
    }

    func testBiometricUnlockWithoutASlotFails() async throws {
        let core = try await open()
        if let token = try? await core.biometricToken() {
            XCTAssertTrue(token.isEmpty)
        }
        do {
            try await core.unlockBiometric(key: Enclave.randomSlotKey())
            XCTFail("a random key unlocked a store with no biometric slot")
        } catch {
            XCTAssertTrue(error is CoreFailure)
        }
        let status = try await core.status()
        XCTAssertFalse(status.unlocked)
    }

    func testBiometricEnrollNeedsAnUnlockedStore() async throws {
        let core = try await open()
        do {
            try await core.biometricEnroll(key: Enclave.randomSlotKey(), token: Data(repeating: 1, count: 64))
            XCTFail("enrolled a biometric slot while locked")
        } catch let failure as CoreFailure {
            XCTAssertEqual(failure.code, "Locked")
        }
    }
}

final class EnclaveTests: XCTestCase {
    func testSlotKeysAreRandom32Bytes() throws {
        let a = try Enclave.randomSlotKey()
        let b = try Enclave.randomSlotKey()
        XCTAssertEqual(a.count, 32)
        XCTAssertNotEqual(a, b)
    }

    #if targetEnvironment(simulator)
    /// The Simulator has no Secure Enclave. There is no software stand-in:
    /// sealing and opening both refuse, so no key ever comes back.
    func testSimulatorHasNoBiometricKeyPath() throws {
        XCTAssertNotNil(Enclave.unavailableReason)
        XCTAssertThrowsError(try Enclave.seal(Enclave.randomSlotKey())) { error in
            guard case .unavailable = error as? EnclaveFailure else {
                return XCTFail("expected unavailable, got \(error)")
            }
        }
        XCTAssertThrowsError(try Enclave.unseal(Data(repeating: 0, count: 700), reason: "test")) { error in
            guard case .unavailable = error as? EnclaveFailure else {
                return XCTFail("expected unavailable, got \(error)")
            }
        }
    }
    #endif

    func testEnvelopeHeaderParsesAndMalformedTokensDont() {
        var token = Data("DBSE".utf8)
        token.append(1) // version
        token.append(1) // flags: biometryCurrentSet
        let createdAt: UInt64 = 1_790_000_000
        for shift in stride(from: 0, to: 64, by: 8) {
            token.append(UInt8(truncatingIfNeeded: createdAt >> UInt64(shift)))
        }
        token.append(32) // state hash length
        token.append(Data(repeating: 0xAA, count: 32))
        let seBlob = Data(repeating: 0x55, count: 40)
        token.append(UInt8(seBlob.count))
        token.append(0)
        token.append(seBlob)
        token.append(Data(repeating: 0x04, count: 65)) // ephemeral public key
        token.append(Data(repeating: 0x00, count: 60)) // AES-GCM box

        XCTAssertEqual(Enclave.createdAt(token), Date(timeIntervalSince1970: TimeInterval(createdAt)))
        XCTAssertNil(Enclave.createdAt(token.dropLast()))
        XCTAssertNil(Enclave.createdAt(token + Data([0])))
        var noBiometry = token
        noBiometry[noBiometry.startIndex + 5] = 0
        XCTAssertNil(Enclave.createdAt(noBiometry))
        var wrongMagic = token
        wrongMagic[wrongMagic.startIndex] = UInt8(ascii: "X")
        XCTAssertNil(Enclave.createdAt(wrongMagic))
    }
}

@MainActor
final class AppModelTests: XCTestCase {
    /// With no biometric slot, the unlock button's path is a no-op: no
    /// prompt, no notice, still locked.
    func testBiometricUnlockWithoutASlotDoesNothing() async {
        let model = AppModel()
        await model.unlockWithBiometrics()
        XCTAssertNil(model.notice)
        XCTAssertFalse(model.busy)
    }
}
