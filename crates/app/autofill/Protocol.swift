// Wire protocol between `DeadboltAutoFill.appex` and `deadbolt agent` over the
// App Group Unix socket (`~/Library/Group Containers/<TEAM>.pw.deadbolt/s`).
// Mirrors `crates/client/src/protocol.rs` (`generatedProtocolVersion` is
// stamped from `PROTOCOL_VERSION` at build time).

import AuthenticationServices
import Foundation

public enum AutofillWire {
    public static let protocolVersion: UInt32 = generatedProtocolVersion
    public static let maxLineBytes: Int = 64 * 1024
    public static let sunPathMax: Int = 103
    public static let socketName: String = "s"
    public static let appGroupSuffix: String = "pw.deadbolt"
    public static let appBundleID: String = "pw.deadbolt.app"
    public static let autofillBundleID: String = "pw.deadbolt.app.autofill"
    public static let agentSigningIDs: Set<String> = ["pw.deadbolt.cli", "deadbolt"]
}

public enum AutofillServiceKind: String, Codable, Equatable, Sendable {
    case domain
    case url
    case app
}

public struct AutofillService: Codable, Equatable, Sendable {
    public let identifier: String
    public let kind: AutofillServiceKind

    public init(identifier: String, kind: AutofillServiceKind) {
        self.identifier = identifier
        self.kind = kind
    }

    public static func from(_ serviceIdentifier: ASCredentialServiceIdentifier) -> AutofillService {
        let kind: AutofillServiceKind
        switch serviceIdentifier.type {
        case .domain:
            kind = .domain
        case .URL:
            kind = .url
        default:
            kind = .app
        }
        return AutofillService(identifier: serviceIdentifier.identifier, kind: kind)
    }

    public var displayHost: String {
        switch kind {
        case .domain:
            return identifier
        case .url:
            if let url = URL(string: identifier), let host = url.host, !host.isEmpty {
                return host
            }
            return identifier
        case .app:
            return identifier
        }
    }
}

public struct LoginRef: Codable, Equatable, Hashable, Sendable {
    public let vault: String
    public let item: String

    public init(vault: String, item: String) {
        self.vault = vault
        self.item = item
    }

    public var recordIdentifier: String {
        "\(vault):\(item)"
    }

    /// Parses `<64 hex vault id>:<32 hex item id>` from `ASCredentialIdentityStore`.
    public static func fromRecordIdentifier(_ raw: String) -> LoginRef? {
        let bytes = Array(raw.utf8)
        guard bytes.count == 97, bytes[64] == UInt8(ascii: ":") else {
            return nil
        }
        let vaultSlice = bytes[0 ..< 64]
        let itemSlice = bytes[65 ..< 97]
        guard vaultSlice.allSatisfy(Self.isAsciiHex), itemSlice.allSatisfy(Self.isAsciiHex) else {
            return nil
        }
        let vault = String(decoding: vaultSlice, as: UTF8.self).lowercased()
        let item = String(decoding: itemSlice, as: UTF8.self).lowercased()
        return LoginRef(vault: vault, item: item)
    }

    private static func isAsciiHex(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
            || (UInt8(ascii: "a") ... UInt8(ascii: "f")).contains(byte)
            || (UInt8(ascii: "A") ... UInt8(ascii: "F")).contains(byte)
    }
}

public enum FillField: String, Codable, Equatable, Sendable {
    case username
    case password
    case totp
}

public enum PasskeyVerify: String, Codable, Equatable, Sendable {
    case required
    case preferred
    case discouraged
}

public struct PasswordIdentity: Codable, Equatable, Sendable {
    public let domain: String
    public let username: String
    public let recordId: String
    public let rank: Int64

    enum CodingKeys: String, CodingKey {
        case domain
        case username
        case recordId = "record_id"
        case rank
    }

    public init(domain: String, username: String, recordId: String, rank: Int64) {
        self.domain = domain
        self.username = username
        self.recordId = recordId
        self.rank = rank
    }
}

public struct PasskeyIdentity: Codable, Equatable, Sendable {
    public let rpId: String
    public let username: String
    public let credentialId: String
    public let userHandle: String
    public let recordId: String
    public let rank: Int64

    enum CodingKeys: String, CodingKey {
        case rpId = "rp_id"
        case username
        case credentialId = "credential_id"
        case userHandle = "user_handle"
        case recordId = "record_id"
        case rank
    }

    public init(
        rpId: String,
        username: String,
        credentialId: String,
        userHandle: String,
        recordId: String,
        rank: Int64
    ) {
        self.rpId = rpId
        self.username = username
        self.credentialId = credentialId
        self.userHandle = userHandle
        self.recordId = recordId
        self.rank = rank
    }
}

public struct OneTimeCodeIdentity: Codable, Equatable, Sendable {
    public let domain: String
    public let label: String
    public let recordId: String
    public let rank: Int64

    enum CodingKeys: String, CodingKey {
        case domain
        case label
        case recordId = "record_id"
        case rank
    }

    public init(domain: String, label: String, recordId: String, rank: Int64) {
        self.domain = domain
        self.label = label
        self.recordId = recordId
        self.rank = rank
    }
}

public struct SignInInfo: Codable, Equatable, Sendable {
    public let provider: String
    public let account: String?

    public init(provider: String, account: String? = nil) {
        self.provider = provider
        self.account = account
    }
}

public struct SiteLogin: Codable, Equatable, Sendable {
    public let login: LoginRef
    public let vault: String
    public let title: String
    public let username: String?
    public let hasPassword: Bool
    public let hasOtp: Bool
    public let urls: [String]
    public let signIn: SignInInfo?

    enum CodingKeys: String, CodingKey {
        case login
        case vault
        case title
        case username
        case hasPassword = "has_password"
        case hasOtp = "has_otp"
        case urls
        case signIn = "sign_in"
    }

    public init(
        login: LoginRef,
        vault: String,
        title: String,
        username: String?,
        hasPassword: Bool,
        hasOtp: Bool = false,
        urls: [String] = [],
        signIn: SignInInfo? = nil
    ) {
        self.login = login
        self.vault = vault
        self.title = title
        self.username = username
        self.hasPassword = hasPassword
        self.hasOtp = hasOtp
        self.urls = urls
        self.signIn = signIn
    }

    public var primaryURLHost: String? {
        for raw in urls {
            if let url = URL(string: raw), let host = url.host, !host.isEmpty {
                return host
            }
            if let url = URL(string: "https://\(raw)"), let host = url.host, !host.isEmpty {
                return host
            }
        }
        return nil
    }

    public var subtitle: String {
        if let user = username, !user.isEmpty {
            return user
        }
        if let signIn {
            if let account = signIn.account, !account.isEmpty {
                return "Sign in with \(signIn.provider.capitalized) (\(account))"
            }
            return "Sign in with \(signIn.provider.capitalized)"
        }
        return primaryURLHost ?? vault
    }

    public func matchesSearch(_ query: String) -> Bool {
        let tokens = query
            .split(whereSeparator: \.isWhitespace)
            .map { $0.lowercased() }
        guard !tokens.isEmpty else {
            return true
        }
        var haystacks: [String] = [title.lowercased(), vault.lowercased()]
        if let username {
            haystacks.append(username.lowercased())
        }
        for url in urls {
            haystacks.append(url.lowercased())
        }
        if let signIn {
            haystacks.append(signIn.provider.lowercased())
            if let account = signIn.account {
                haystacks.append(account.lowercased())
            }
        }
        return tokens.allSatisfy { token in
            haystacks.contains { $0.contains(token) }
        }
    }
}

public struct SitePasskey: Codable, Equatable, Sendable {
    public let passkey: LoginRef
    public let vault: String
    public let credentialId: String
    public let username: String?
    public let created: String?

    enum CodingKeys: String, CodingKey {
        case passkey
        case vault
        case credentialId = "credential_id"
        case username
        case created
    }

    public init(
        passkey: LoginRef,
        vault: String,
        credentialId: String,
        username: String?,
        created: String?
    ) {
        self.passkey = passkey
        self.vault = vault
        self.credentialId = credentialId
        self.username = username
        self.created = created
    }
}

public struct SiteValues: Codable, Equatable, Sendable {
    public let username: String?
    public let password: String?
    public let totp: String?

    public init(username: String? = nil, password: String? = nil, totp: String? = nil) {
        self.username = username
        self.password = password
        self.totp = totp
    }
}

public enum AutofillCommand: Equatable, Sendable {
    case status
    case unlock(passphrase: String)
    case unlockBiometric
    case autofillStatus
    case autofillIdentities
    case autofillList(
        services: [AutofillService],
        rpId: String? = nil,
        allowedCredentials: [String] = [],
        forOtp: Bool = false
    )
    case autofillFill(
        service: AutofillService?,
        login: LoginRef,
        want: [FillField],
        interactive: Bool
    )

    public var carriesPassphrase: Bool {
        switch self {
        case .unlock:
            return true
        default:
            return false
        }
    }

    public func encodeLine() throws -> Data {
        let encoder = JSONEncoder()
        var data = try encoder.encode(WireRequest(command: self))
        data.append(UInt8(ascii: "\n"))
        return data
    }
}

private struct WireRequest: Encodable {
    let command: AutofillCommand

    enum CodingKeys: String, CodingKey {
        case v
        case cmd
        case passphrase
        case timeoutSecs = "timeout_secs"
        case services
        case rpId = "rp_id"
        case allowedCredentials = "allowed_credentials"
        case forOtp = "for_otp"
        case service
        case login
        case want
        case interactive
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(AutofillWire.protocolVersion, forKey: .v)
        switch command {
        case .status:
            try c.encode("status", forKey: .cmd)
        case let .unlock(passphrase):
            try c.encode("unlock", forKey: .cmd)
            try c.encode(passphrase, forKey: .passphrase)
            try c.encodeNil(forKey: .timeoutSecs)
        case .unlockBiometric:
            try c.encode("unlock-biometric", forKey: .cmd)
            try c.encodeNil(forKey: .timeoutSecs)
        case .autofillStatus:
            try c.encode("autofill-status", forKey: .cmd)
        case .autofillIdentities:
            try c.encode("autofill-identities", forKey: .cmd)
        case let .autofillList(services, rpId, allowedCredentials, forOtp):
            try c.encode("autofill-list", forKey: .cmd)
            try c.encode(services, forKey: .services)
            try c.encode(rpId, forKey: .rpId)
            try c.encode(allowedCredentials, forKey: .allowedCredentials)
            try c.encode(forOtp, forKey: .forOtp)
        case let .autofillFill(service, login, want, interactive):
            try c.encode("autofill-fill", forKey: .cmd)
            try c.encode(service, forKey: .service)
            try c.encode(login, forKey: .login)
            try c.encode(want, forKey: .want)
            try c.encode(interactive, forKey: .interactive)
        }
    }
}

public struct AutofillStatusReply: Codable, Equatable, Sendable {
    public let initialized: Bool
    public let unlocked: Bool
    public let touchIdReady: Bool
    public let touchIdReset: Bool
    public let canVerify: Bool
    public let identitiesHash: String?

    enum CodingKeys: String, CodingKey {
        case initialized
        case unlocked
        case touchIdReady = "touch_id_ready"
        case touchIdReset = "touch_id_reset"
        case canVerify = "can_verify"
        case identitiesHash = "identities_hash"
    }

    public init(
        initialized: Bool,
        unlocked: Bool,
        touchIdReady: Bool,
        touchIdReset: Bool = false,
        canVerify: Bool = false,
        identitiesHash: String? = nil
    ) {
        self.initialized = initialized
        self.unlocked = unlocked
        self.touchIdReady = touchIdReady
        self.touchIdReset = touchIdReset
        self.canVerify = canVerify
        self.identitiesHash = identitiesHash
    }
}

public struct AutofillIdentitiesReply: Codable, Equatable, Sendable {
    public let identitiesHash: String
    public let passwords: [PasswordIdentity]
    public let passkeys: [PasskeyIdentity]
    public let oneTimeCodes: [OneTimeCodeIdentity]

    enum CodingKeys: String, CodingKey {
        case identitiesHash = "identities_hash"
        case passwords
        case passkeys
        case oneTimeCodes = "one_time_codes"
    }

    public init(
        identitiesHash: String,
        passwords: [PasswordIdentity],
        passkeys: [PasskeyIdentity] = [],
        oneTimeCodes: [OneTimeCodeIdentity] = []
    ) {
        self.identitiesHash = identitiesHash
        self.passwords = passwords
        self.passkeys = passkeys
        self.oneTimeCodes = oneTimeCodes
    }
}

public struct AutofillListReply: Codable, Equatable, Sendable {
    public let logins: [SiteLogin]
    public let passkeys: [SitePasskey]
    public let unassociated: Bool
    public let canVerify: Bool
    public let identitiesHash: String

    enum CodingKeys: String, CodingKey {
        case logins
        case passkeys
        case unassociated
        case canVerify = "can_verify"
        case identitiesHash = "identities_hash"
    }

    public init(
        logins: [SiteLogin],
        passkeys: [SitePasskey] = [],
        unassociated: Bool = false,
        canVerify: Bool = false,
        identitiesHash: String
    ) {
        self.logins = logins
        self.passkeys = passkeys
        self.unassociated = unassociated
        self.canVerify = canVerify
        self.identitiesHash = identitiesHash
    }
}

public struct AutofillFillReply: Codable, Equatable, Sendable {
    public let values: SiteValues
    public let identitiesHash: String

    enum CodingKeys: String, CodingKey {
        case values
        case identitiesHash = "identities_hash"
    }

    public init(values: SiteValues, identitiesHash: String) {
        self.values = values
        self.identitiesHash = identitiesHash
    }
}

public enum AutofillReply: Equatable, Sendable {
    case done
    case autofillStatus(AutofillStatusReply)
    case autofillIdentities(AutofillIdentitiesReply)
    case autofillList(AutofillListReply)
    case autofillFill(AutofillFillReply)
    case other(String)
}

public enum AgentErrorCode: String, Equatable, Sendable {
    case locked
    case notInitialized = "not-initialized"
    case notFound = "not-found"
    case domainMismatch = "domain-mismatch"
    case exists
    case version
    case weak
    case forbidden
    case notGranted = "not-granted"
    case rateLimited = "rate-limited"
    case choosePasskey = "choose-passkey"
    case interactionRequired = "interaction-required"
    case cancelled
    case failed
    case unknown
}

public enum AgentCallError: Error, Equatable, Sendable {
    case agentUnavailable(String)
    case timedOut
    case cancelled
    case peerRejected(String)
    case invalidResponse(String)
    case agentError(code: AgentErrorCode, message: String)

    public var extensionErrorCodeForSilentRequest: ASExtensionError.Code {
        switch self {
        case .agentUnavailable, .timedOut:
            return .userInteractionRequired
        case .cancelled:
            return .userCanceled
        case .peerRejected, .invalidResponse:
            return .failed
        case let .agentError(code, _):
            switch code {
            case .locked, .interactionRequired, .notInitialized:
                return .userInteractionRequired
            case .notFound, .domainMismatch:
                return .credentialIdentityNotFound
            case .cancelled:
                return .userCanceled
            default:
                return .failed
            }
        }
    }

    public var extensionErrorCodeForInteractiveRequest: ASExtensionError.Code {
        switch self {
        case .cancelled:
            return .userCanceled
        case let .agentError(code, _):
            switch code {
            case .notFound, .domainMismatch:
                return .credentialIdentityNotFound
            case .cancelled:
                return .userCanceled
            default:
                return .failed
            }
        default:
            return .failed
        }
    }

    public var isBiometricCancelled: Bool {
        switch self {
        case .cancelled:
            return true
        case let .agentError(code, message):
            return code == .cancelled || message.localizedCaseInsensitiveContains("cancelled")
        default:
            return false
        }
    }

    public var userFacingUnlockMessage: String {
        switch self {
        case let .agentError(code, message):
            if code == .rateLimited {
                return message
            }
            if message.localizedCaseInsensitiveContains("passphrase")
                || message.localizedCaseInsensitiveContains("decrypt")
            {
                return "That passphrase didn't unlock this device."
            }
            return message
        case let .peerRejected(reason):
            return reason
        case let .agentUnavailable(reason):
            return reason
        case .timedOut:
            return "Deadbolt took too long to respond."
        case .cancelled:
            return "Cancelled."
        case let .invalidResponse(reason):
            return reason
        }
    }
}

public enum WireDecoder {
    private struct Envelope: Decodable {
        let type: String
        let code: String?
        let message: String?
        let reply: ReplyTag?
    }

    private struct ReplyTag: Decodable {
        let reply: String
    }

    private struct OkEnvelope<T: Decodable>: Decodable {
        let reply: T
    }

    public static func decodeMessage(_ line: Data) throws -> AutofillReply {
        let decoder = JSONDecoder()
        let env: Envelope
        do {
            env = try decoder.decode(Envelope.self, from: line)
        } catch {
            throw AgentCallError.invalidResponse("malformed JSON from agent: \(error.localizedDescription)")
        }
        switch env.type {
        case "error":
            let code = env.code.flatMap(AgentErrorCode.init(rawValue:)) ?? .unknown
            let msg = env.message ?? "agent request failed"
            throw AgentCallError.agentError(code: code, message: msg)
        case "ok":
            guard let tag = env.reply?.reply else {
                throw AgentCallError.invalidResponse("missing reply tag from agent")
            }
            switch tag {
            case "done":
                return .done
            case "autofill-status":
                let ok = try decoder.decode(OkEnvelope<AutofillStatusReply>.self, from: line)
                return .autofillStatus(ok.reply)
            case "autofill-identities":
                let ok = try decoder.decode(OkEnvelope<AutofillIdentitiesReply>.self, from: line)
                return .autofillIdentities(ok.reply)
            case "autofill-list":
                let ok = try decoder.decode(OkEnvelope<AutofillListReply>.self, from: line)
                return .autofillList(ok.reply)
            case "autofill-fill":
                let ok = try decoder.decode(OkEnvelope<AutofillFillReply>.self, from: line)
                return .autofillFill(ok.reply)
            default:
                return .other(tag)
            }
        default:
            throw AgentCallError.invalidResponse("unexpected message type '\(env.type)'")
        }
    }
}
