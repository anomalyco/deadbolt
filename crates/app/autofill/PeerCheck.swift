// Mutual code-signature verification and bundle/App-Group discovery for
// `DeadboltAutoFill.appex` (`docs/macos-autofill.md`).
//
// Mirrors `crates/client/src/peer.rs`, `crates/cli/src/agent/identify.swift`,
// and `crates/cli/src/agent/enclave.swift`.

import Darwin
import Foundation
import Security

private let solLocal: Int32 = 0
private let localPeerTokenOpt: Int32 = 0x006

#if arch(arm64)
private let currentCPUType: Int = 0x0100_000c
#else
private let currentCPUType: Int = 0x0100_0007
#endif

public struct ContainingBundle: Equatable, Sendable {
    public let appURL: URL
    public let agentBinaryURL: URL

    public init(appURL: URL, agentBinaryURL: URL) {
        self.appURL = appURL
        self.agentBinaryURL = agentBinaryURL
    }

    /// Resolves `Deadbolt.app` and `Contents/Helpers/deadbolt` from the
    /// running `DeadboltAutoFill.appex` bundle path, resolving symlinks first
    /// so separate installations never cross.
    public static func locate(from extensionBundleURL: URL = Bundle.main.bundleURL) -> ContainingBundle? {
        let resolvedExt = extensionBundleURL.resolvingSymlinksInPath().standardizedFileURL
        guard resolvedExt.pathExtension == "appex" else {
            return nil
        }
        let plugIns = resolvedExt.deletingLastPathComponent()
        let contents = plugIns.deletingLastPathComponent()
        let app = contents.deletingLastPathComponent()
        guard plugIns.lastPathComponent == "PlugIns",
              contents.lastPathComponent == "Contents",
              app.pathExtension == "app"
        else {
            return nil
        }
        let agent = contents.appendingPathComponent("Helpers/deadbolt").resolvingSymlinksInPath()
        return ContainingBundle(appURL: app, agentBinaryURL: agent)
    }
}

public enum AppGroupContainer {
    public struct Resolved: Equatable, Sendable {
        public let teamID: String?
        public let socketURL: URL?

        public init(teamID: String?, socketURL: URL?) {
            self.teamID = teamID
            self.socketURL = socketURL
        }
    }

    /// Inspects this process's own Apple-anchored code signature and
    /// `com.apple.security.application-groups` entitlement before calling
    /// `containerURL(forSecurityApplicationGroupIdentifier:)`, avoiding macOS 15
    /// TCC prompts when running ad-hoc in local builds or tests.
    public static func resolve(suffix: String = AutofillWire.appGroupSuffix) -> Resolved {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else {
            return Resolved(teamID: nil, socketURL: nil)
        }
        let staticMe = unsafeBitCast(me, to: SecStaticCode.self)
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation)
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticMe, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any],
              SecCodeCheckValidity(me, [], nil) == errSecSuccess
        else {
            return Resolved(teamID: nil, socketURL: nil)
        }

        guard let team = dict[kSecCodeInfoTeamIdentifier as String] as? String,
              let req = PeerCheck.appleTeamRequirement(team: team),
              SecCodeCheckValidity(me, [], req) == errSecSuccess
        else {
            return Resolved(teamID: nil, socketURL: nil)
        }

        let group = "\(team).\(suffix)"
        let wildcard = "\(team).*"
        guard let entitlements = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let groups = entitlements["com.apple.security.application-groups"] as? [String],
              groups.contains(group) || groups.contains(wildcard),
              let container = FileManager.default.containerURL(
                  forSecurityApplicationGroupIdentifier: group
              ),
              !container.path.isEmpty
        else {
            return Resolved(teamID: team, socketURL: nil)
        }
        return Resolved(
            teamID: team,
            socketURL: container.appendingPathComponent(AutofillWire.socketName, isDirectory: false)
        )
    }
}

public enum PeerCheck {
    public static func isTeamIdentifier(_ team: String) -> Bool {
        team.utf8.count == 10 && team.utf8.allSatisfy { byte in
            (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
                || (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte)
                || (UInt8(ascii: "a") ... UInt8(ascii: "z")).contains(byte)
        }
    }

    public static func appleTeamRequirement(team: String) -> SecRequirement? {
        guard isTeamIdentifier(team) else {
            return nil
        }
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        var req: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &req) == errSecSuccess else {
            return nil
        }
        return req
    }

    /// Verifies that the process listening on `socketFD` runs as this UID from
    /// `expectedAgentURL` (canonicalized) and carries Deadbolt's valid signature:
    /// - Signed builds (`requiredTeamID != nil`): Apple-anchored signature for
    ///   `requiredTeamID` with identifier in `allowedSigningIDs`.
    /// - Ad-hoc builds (`requiredTeamID == nil`): dynamic `cdhash` equals the
    ///   valid static `cdhash` of `expectedAgentURL` on disk.
    public static func verifyAgent(
        socketFD: Int32,
        expectedAgentURL: URL,
        requiredTeamID: String?,
        allowedSigningIDs: Set<String> = AutofillWire.agentSigningIDs
    ) throws {
        var token = audit_token_t()
        var tokenLen = socklen_t(MemoryLayout<audit_token_t>.size)
        let rc = withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: Int(tokenLen)) { raw in
                getsockopt(socketFD, solLocal, localPeerTokenOpt, raw, &tokenLen)
            }
        }
        guard rc == 0, Int(tokenLen) == MemoryLayout<audit_token_t>.size else {
            throw AgentCallError.peerRejected("could not read the agent's audit token")
        }

        let words: [UInt32] = withUnsafeBytes(of: &token.val) { raw in
            (0 ..< 8).map { idx in
                raw.load(fromByteOffset: idx * 4, as: UInt32.self)
            }
        }
        let peerUID = words[1]
        let peerPID = Int32(bitPattern: words[5])
        guard peerUID == getuid() else {
            throw AgentCallError.peerRejected("the agent (pid \(peerPID)) runs as another user")
        }

        let expectedCanonical = expectedAgentURL.resolvingSymlinksInPath().standardizedFileURL.path
        guard FileManager.default.isExecutableFile(atPath: expectedCanonical) else {
            throw AgentCallError.peerRejected("Deadbolt's agent binary is missing at \(expectedCanonical)")
        }

        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let guestAttrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var guestCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, guestAttrs, [], &guestCode) == errSecSuccess,
              let guestCode
        else {
            throw AgentCallError.peerRejected("the agent (pid \(peerPID)) exited")
        }

        let runningInfo = try readSignature(
            unsafeBitCast(guestCode, to: SecStaticCode.self),
            dynamic: true
        ) { req in
            SecCodeCheckValidity(guestCode, [], req) == errSecSuccess
        }

        var guestAgain: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, guestAttrs, [], &guestAgain) == errSecSuccess else {
            throw AgentCallError.peerRejected("the agent (pid \(peerPID)) exited while being verified")
        }

        guard let runningPath = runningInfo.path else {
            throw AgentCallError.peerRejected("could not resolve the running agent's executable path")
        }
        let runningCanonical = URL(fileURLWithPath: runningPath)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
        guard runningCanonical == expectedCanonical else {
            throw AgentCallError.peerRejected(
                "the socket peer runs \(runningCanonical), not \(expectedCanonical)"
            )
        }
        guard runningInfo.valid else {
            throw AgentCallError.peerRejected("the running agent has an invalid code signature")
        }

        if let requiredTeamID {
            guard runningInfo.teamID == requiredTeamID,
                  let signingID = runningInfo.signingID,
                  allowedSigningIDs.contains(signingID)
            else {
                throw AgentCallError.peerRejected(
                    "the running agent is not signed by team \(requiredTeamID) as Deadbolt"
                )
            }
        } else {
            let diskInfo = try readDiskSignature(atPath: expectedCanonical)
            guard diskInfo.valid,
                  let diskHash = diskInfo.cdhash,
                  !diskHash.isEmpty,
                  runningInfo.cdhash == diskHash
            else {
                throw AgentCallError.peerRejected(
                    "the running agent does not match Deadbolt's binary on disk"
                )
            }
        }
    }

    private struct SignatureFacts {
        let path: String?
        let signingID: String?
        let teamID: String?
        let cdhash: Data?
        let valid: Bool
    }

    private static func readSignature(
        _ staticCode: SecStaticCode,
        dynamic: Bool,
        check: (SecRequirement?) -> Bool
    ) throws -> SignatureFacts {
        var resolvedPath: String?
        var pathURL: CFURL?
        if SecCodeCopyPath(staticCode, [], &pathURL) == errSecSuccess, let url = pathURL as URL? {
            resolvedPath = url.path
        }

        var flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        if dynamic {
            flags.insert(SecCSFlags(rawValue: kSecCSDynamicInformation))
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else {
            return SignatureFacts(
                path: resolvedPath,
                signingID: nil,
                teamID: nil,
                cdhash: nil,
                valid: false
            )
        }

        if let mainExec = dict[kSecCodeInfoMainExecutable as String] as? URL {
            resolvedPath = mainExec.path
        }
        let signingID = dict[kSecCodeInfoIdentifier as String] as? String
        let cdhash = dict[kSecCodeInfoUnique as String] as? Data
        let valid = check(nil)
        var verifiedTeam: String?
        if valid,
           let team = dict[kSecCodeInfoTeamIdentifier as String] as? String,
           let req = appleTeamRequirement(team: team),
           check(req)
        {
            verifiedTeam = team
        }
        return SignatureFacts(
            path: resolvedPath,
            signingID: signingID,
            teamID: verifiedTeam,
            cdhash: cdhash,
            valid: valid
        )
    }

    private static func readDiskSignature(atPath path: String) throws -> SignatureFacts {
        var staticCode: SecStaticCode?
        let attrs = [kSecCodeAttributeArchitecture: NSNumber(value: currentCPUType)] as CFDictionary
        guard SecStaticCodeCreateWithPathAndAttributes(
            URL(fileURLWithPath: path) as CFURL,
            [],
            attrs,
            &staticCode
        ) == errSecSuccess, let staticCode
        else {
            throw AgentCallError.peerRejected("could not inspect \(path)")
        }
        let checkFlags = SecCSFlags(
            rawValue: kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources
        )
        return try readSignature(staticCode, dynamic: false) { req in
            SecStaticCodeCheckValidity(staticCode, checkFlags, req) == errSecSuccess
        }
    }
}
