// What `DeadboltAutoFill.appex` adds to the AutoFill types `deadbolt-ffi`
// generates from `crates/ffi/src/autofill.rs`: AuthenticationServices
// mappings, and how the sheet shows a login.

import AuthenticationServices
import Foundation

extension AutofillService {
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
        if kind == .url, let host = URL(string: identifier)?.host, !host.isEmpty {
            return host
        }
        return identifier
    }
}

extension LoginRef {
    public var recordIdentifier: String {
        loginRefRecordIdentifier(login: self)
    }

    /// Parses `<64 hex vault id>:<32 hex item id>` from `ASCredentialIdentityStore`.
    public static func fromRecordIdentifier(_ raw: String) -> LoginRef? {
        loginRefFromRecordIdentifier(raw: raw)
    }
}

extension SiteLogin {
    public var primaryURLHost: String? {
        for raw in urls {
            if let host = URL(string: raw)?.host, !host.isEmpty {
                return host
            }
            if let host = URL(string: "https://\(raw)")?.host, !host.isEmpty {
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

extension DaemonCallError: Error {
    public var extensionErrorCodeForSilentRequest: ASExtensionError.Code {
        switch self {
        case .daemonUnavailable, .timedOut:
            return .userInteractionRequired
        case .cancelled:
            return .userCanceled
        case .peerRejected, .invalidResponse:
            return .failed
        case let .daemonError(code, _):
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
        case let .daemonError(code, _):
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
        case let .daemonError(code, message):
            return code == .cancelled || message.localizedCaseInsensitiveContains("cancelled")
        default:
            return false
        }
    }

    public var userFacingUnlockMessage: String {
        switch self {
        case let .daemonError(code, message):
            if code == .rateLimited {
                return message
            }
            if message.localizedCaseInsensitiveContains("passphrase")
                || message.localizedCaseInsensitiveContains("decrypt")
            {
                return "That passphrase didn't unlock this device."
            }
            return message
        case let .peerRejected(reason), let .daemonUnavailable(reason), let .invalidResponse(reason):
            return reason
        case .timedOut:
            return "Deadbolt took too long to respond."
        case .cancelled:
            return "Cancelled."
        }
    }
}
