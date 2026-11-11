import Foundation

/// The native UI's asynchronous boundary. Production always uses Core;
/// lifecycle tests can delay individual replies without loading a vault.
protocol CoreAPI: Sendable {
    func status() async throws -> CoreStatus
    func joinStart(passphrase: String) async throws -> JoinStart
    func joinStatus() async throws -> JoinStatus
    func joinCancel() async throws
    func unlock(passphrase: String) async throws
    func lock() async throws
    func foreground() async throws
    func sync() async throws
    func items(query: String) async throws -> [ItemSummary]
    func item(id: String) async throws -> ItemDetail
    func secret(id: String, field: String) async throws -> String
    func code(id: String) async throws -> OneTimeCode
    func biometricEnroll(key: Data, token: Data) async throws
    func biometricToken() async throws -> Data
    func unlockBiometric(key: Data) async throws
    func approvalPending() async throws -> PendingApproval?
    func approvalRespond(id: String, allow: Bool, key: Data) async throws
    func credentialIdentities() async throws -> String
}

struct CoreFailure: LocalizedError, Sendable {
    var code: String?
    let message: String
    var errorDescription: String? { message }
}

struct CoreStatus: Decodable, Sendable, Equatable {
    var initialized: Bool
    var unlocked: Bool
    var deviceId: String?
    var biometricReady: Bool
}

struct JoinStart: Decodable, Sendable {
    var code: String
}

struct JoinStatus: Decodable, Sendable {
    enum State: String, Decodable, Sendable {
        case waiting, joined, error
    }
    var state: State
    var error: String?
}

struct ItemSummary: Decodable, Sendable, Identifiable, Hashable {
    var id: String
    var title: String
    var username: String?
    var kind: String
}

struct ItemDetail: Decodable, Sendable, Equatable {
    var id: String
    var title: String
    var username: String?
    var url: String?
    var hasPassword: Bool
    var hasOtp: Bool
}

struct OneTimeCode: Decodable, Sendable, Equatable {
    var code: String
    var remaining: Int
    var period: Int
}

struct PendingApproval: Decodable, Sendable, Equatable, Identifiable {
    var id: String
    var origin: String
    var expiresAt: UInt64
    var vault: String
    var item: String
    var field: String
    var title: String
    var originName: String
    var caller: String

    var expired: Bool { Date().timeIntervalSince1970 >= Double(expiresAt) }
}
