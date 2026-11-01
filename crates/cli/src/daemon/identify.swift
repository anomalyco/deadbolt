// `deadbolt-enclave identify`: who is on the other end of the daemon's socket.
//
// Reads JSON on stdin:
//   {"token": [8 x u32], "files": ["/path/to/a/binary", ...]}
// `token` is the peer's audit token (`LOCAL_PEERTOKEN`); both are optional.
// Writes JSON on stdout:
//   {"code": Signature, "process": Process, "files": [Signature | null, ...]}
// with `code` and `process` only for a token. Files are read for this
// helper's own architecture, the one Deadbolt's binaries run as.
// where Signature is {"path", "signing_id", "team_id", "cdhash", "valid"}
// (`path` is the main executable, inside the bundle for an app) and
// Process is {"ppid", "started", "tty", "session_started", "args", "ancestry"}.
//
// The process facts are read by pid first, and the code is looked up by the
// audit token after, which fails once that pid version is gone. So when this
// succeeds, the pid still belonged to the token's process throughout: a
// reused pid can't lend its facts to a dead caller.
//
// `team_id` is only reported when it is 10 ASCII letters or digits and the
// signature chains to Apple's Developer ID roots for that team, so a
// self-signed certificate naming a team can't claim one. `valid` is SecCodeCheckValidity for the running code
// (the kernel's view of its pages and the code directory's signature).
//
// Exits 15 when the token's process is gone, 13 on malformed input.

import Darwin
import Foundation
import Security

private let identifyGone: Int32 = 15
private let identifyBadInput: Int32 = 13

private func identifyFail(_ code: Int32, _ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

private func cString<T>(_ tuple: T) -> String {
    withUnsafeBytes(of: tuple) { raw in
        let bytes = raw.prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self)
    }
}

private func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else {
        return nil
    }
    return info
}

private func pidPath(_ pid: pid_t) -> String? {
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
        return nil
    }
    return String(cString: buffer)
}

private func processName(_ info: proc_bsdinfo) -> String {
    let name = cString(info.pbi_name)
    return name.isEmpty ? cString(info.pbi_comm) : name
}

/// The process's arguments from `KERN_PROCARGS2`: argc, the exec path and
/// its NUL, padded with NULs to a multiple of 8 bytes, then argc strings of
/// argv (any of them may be empty), then the environment.
private func arguments(_ pid: pid_t) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else {
        return []
    }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > 4 else {
        return []
    }
    let argc = buffer.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
    var i = 4
    while i < size && buffer[i] != 0 { i += 1 }
    // Only the padding is skipped: skipping every NUL would take empty
    // arguments for padding and the environment for arguments.
    let argv = 4 + (i - 4 + 1 + 7) / 8 * 8
    guard argv <= size, buffer[i ..< argv].allSatisfy({ $0 == 0 }) else {
        return []
    }
    i = argv
    var args: [String] = []
    while args.count < Int(argc) && i < size {
        let start = i
        while i < size && buffer[i] != 0 { i += 1 }
        args.append(String(decoding: buffer[start ..< i], as: UTF8.self))
        i += 1
    }
    return args
}

private func process(_ pid: pid_t) -> [String: Any] {
    var out: [String: Any] = [:]
    guard let info = bsdInfo(pid) else {
        return out
    }
    out["ppid"] = Int(info.pbi_ppid)
    out["started"] = Int(info.pbi_start_tvsec)
    if info.e_tdev != UInt32.max, let name = devname(dev_t(bitPattern: info.e_tdev), S_IFCHR) {
        out["tty"] = "/dev/" + String(cString: name)
    }
    let sid = getsid(pid)
    if sid > 0, let leader = bsdInfo(sid) {
        out["session_started"] = Int(leader.pbi_start_tvsec)
    }
    out["args"] = arguments(pid)
    var ancestry: [[String: Any]] = []
    var next = pid_t(info.pbi_ppid)
    while next > 0 && ancestry.count < 32, let parent = bsdInfo(next) {
        var entry: [String: Any] = ["pid": Int(next), "name": processName(parent)]
        if let path = pidPath(next) {
            entry["path"] = path
        }
        ancestry.append(entry)
        if next == 1 { break }
        next = pid_t(parent.pbi_ppid)
    }
    out["ancestry"] = ancestry
    return out
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

/// Whether `team` has a team identifier's shape: 10 ASCII letters or digits.
/// Anything else is never put into a requirement's text.
private func isTeamIdentifier(_ team: String) -> Bool {
    team.utf8.count == 10 && team.utf8.allSatisfy { byte in
        (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
            || (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte)
            || (UInt8(ascii: "a") ... UInt8(ascii: "z")).contains(byte)
    }
}

private func requirement(team: String) -> SecRequirement? {
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

/// What a static code's signing information says, with `team_id` kept only
/// when `check` accepts the team's Apple-anchored requirement.
private func signature(
    _ staticCode: SecStaticCode,
    dynamic: Bool,
    check: (SecRequirement?) -> Bool
) -> [String: Any] {
    var out: [String: Any] = [:]
    // The bundle, for an app; its main executable is what it runs.
    var url: CFURL?
    if SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url = url as URL? {
        out["path"] = url.path
    }
    var flags = SecCSFlags(rawValue: kSecCSSigningInformation)
    if dynamic {
        flags.insert(SecCSFlags(rawValue: kSecCSDynamicInformation))
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
          let dict = info as? [String: Any]
    else {
        out["valid"] = false
        return out
    }
    if let main = dict[kSecCodeInfoMainExecutable as String] as? URL {
        out["path"] = main.path
    }
    if let id = dict[kSecCodeInfoIdentifier as String] as? String {
        out["signing_id"] = id
    }
    if let cdhash = dict[kSecCodeInfoUnique as String] as? Data {
        out["cdhash"] = hex(cdhash)
    }
    let valid = check(nil)
    out["valid"] = valid
    if valid, let team = dict[kSecCodeInfoTeamIdentifier as String] as? String,
       let req = requirement(team: team), check(req)
    {
        out["team_id"] = team
    }
    return out
}

func runIdentify() -> Never {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard let json = try? JSONSerialization.jsonObject(with: input) as? [String: Any] else {
        identifyFail(identifyBadInput, "expected {\"token\": [8 numbers], \"files\": [...]}")
    }
    var out: [String: Any] = [:]
    if let words = json["token"] {
        guard let words = words as? [NSNumber], words.count == 8 else {
            identifyFail(identifyBadInput, "a token is 8 numbers")
        }
        (out["code"], out["process"]) = identifyPeer(words)
    }
    let files = json["files"] as? [String] ?? []
    out["files"] = files.map(fileSignature)
    guard let data = try? JSONSerialization.data(withJSONObject: out) else {
        identifyFail(14, "could not encode the result")
    }
    FileHandle.standardOutput.write(data)
    exit(0)
}

private func identifyPeer(_ words: [NSNumber]) -> ([String: Any], [String: Any]) {
    var token = audit_token_t()
    withUnsafeMutableBytes(of: &token.val) { raw in
        for (i, word) in words.enumerated() {
            raw.storeBytes(of: word.uint32Value, toByteOffset: i * 4, as: UInt32.self)
        }
    }
    let pid = pid_t(bitPattern: words[5].uint32Value)

    // Facts by pid first; the token lookup below proves they were this process's.
    let facts = process(pid)

    let tokenData = withUnsafeBytes(of: &token) { Data($0) }
    var code: SecCode?
    let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
          let code
    else {
        identifyFail(identifyGone, "no process has that audit token")
    }
    let running = signature(unsafeBitCast(code, to: SecStaticCode.self), dynamic: true) { req in
        SecCodeCheckValidity(code, [], req) == errSecSuccess
    }
    // Again after reading everything: the process may have exited meanwhile.
    var again: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &again) == errSecSuccess else {
        identifyFail(identifyGone, "the process exited while being identified")
    }
    return (running, facts)
}

#if arch(arm64)
private let ownArchitecture = 0x0100_000c // CPU_TYPE_ARM64
#else
private let ownArchitecture = 0x0100_0007 // CPU_TYPE_X86_64
#endif

private func fileSignature(_ path: String) -> Any {
    var staticCode: SecStaticCode?
    let attributes = [kSecCodeAttributeArchitecture: NSNumber(value: ownArchitecture)]
    guard SecStaticCodeCreateWithPathAndAttributes(
        URL(fileURLWithPath: path) as CFURL, [], attributes as CFDictionary, &staticCode
    ) == errSecSuccess, let staticCode
    else {
        return NSNull()
    }
    // The code directory's signature, not every page: the running code's
    // cdhash is compared against this one, and the kernel checks its pages.
    let flags = SecCSFlags(rawValue: kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources)
    return signature(staticCode, dynamic: false) { req in
        SecStaticCodeCheckValidity(staticCode, flags, req) == errSecSuccess
    }
}
