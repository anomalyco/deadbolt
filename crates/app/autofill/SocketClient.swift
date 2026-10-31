// Cancellation-safe POSIX `AF_UNIX` client and `NSWorkspace` agent launcher
// for `DeadboltAutoFill.appex`.

import AppKit
import Darwin
import Foundation

/// Thread-safe handle to an in-flight socket request. Calling `cancel()` (for
/// example from `viewWillDisappear`) shuts down the socket immediately, waking
/// `poll()` here and triggering `conv.closed()` in `deadbolt agent` so an
/// open Touch ID sheet is dismissed right away.
public final class SocketCallHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var fd: Int32 = -1
    private var cancelled = false

    public init() {}

    public var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    public func cancel() {
        lock.lock()
        cancelled = true
        let current = fd
        lock.unlock()
        if current >= 0 {
            _ = Darwin.shutdown(current, SHUT_RDWR)
        }
    }

    fileprivate func attach(socketFD: Int32) -> Bool {
        lock.lock()
        if cancelled {
            lock.unlock()
            _ = Darwin.shutdown(socketFD, SHUT_RDWR)
            return false
        }
        fd = socketFD
        lock.unlock()
        return true
    }

    fileprivate func detach() {
        lock.lock()
        fd = -1
        lock.unlock()
    }
}

public protocol AutofillAgentClient: Sendable {
    func send(
        _ command: AutofillCommand,
        timeout: TimeInterval,
        handle: SocketCallHandle?
    ) async throws -> AutofillReply
}

public protocol AgentLaunching: Sendable {
    func startInBackground() async -> Bool
    func openContainingApp() async -> Bool
}

public struct WorkspaceAgentLauncher: AgentLaunching {
    public let bundle: ContainingBundle?

    public init(bundle: ContainingBundle? = ContainingBundle.locate()) {
        self.bundle = bundle
    }

    public func startInBackground() async -> Bool {
        await launch(activate: false)
    }

    public func openContainingApp() async -> Bool {
        await launch(activate: true)
    }

    private func launch(activate: Bool) async -> Bool {
        guard let appURL = bundle?.appURL else {
            return false
        }
        let config = NSWorkspace.OpenConfiguration()
        config.activates = activate
        config.hides = !activate
        config.addsToRecentItems = false
        config.promptsUserIfNeeded = activate
        config.allowsRunningApplicationSubstitution = false
        return await withCheckedContinuation { continuation in
            NSWorkspace.shared.openApplication(at: appURL, configuration: config) { app, error in
                continuation.resume(returning: app != nil && error == nil)
            }
        }
    }
}

public struct UnixSocketAgentClient: AutofillAgentClient {
    public typealias PeerVerifyFn = @Sendable (Int32) throws -> Void

    public let socketPathProvider: @Sendable () -> String?
    public let peerVerifier: PeerVerifyFn?

    public init(
        socketPath: String,
        peerVerifier: PeerVerifyFn? = nil
    ) {
        self.socketPathProvider = { socketPath }
        self.peerVerifier = peerVerifier
    }

    public init(
        socketPathProvider: @escaping @Sendable () -> String?,
        peerVerifier: PeerVerifyFn?
    ) {
        self.socketPathProvider = socketPathProvider
        self.peerVerifier = peerVerifier
    }

    public static func live() -> UnixSocketAgentClient {
        let bundle = ContainingBundle.locate()
        let resolvedGroup = AppGroupContainer.resolve()
        let verifier: PeerVerifyFn? = { fd in
            guard let expectedAgent = bundle?.agentBinaryURL else {
                throw AgentCallError.peerRejected(
                    "DeadboltAutoFill is not running inside Deadbolt.app"
                )
            }
            try PeerCheck.verifyAgent(
                socketFD: fd,
                expectedAgentURL: expectedAgent,
                requiredTeamID: resolvedGroup.teamID
            )
        }
        return UnixSocketAgentClient(
            socketPathProvider: {
                if let url = resolvedGroup.socketURL {
                    return url.path
                }
                return AppGroupContainer.resolve().socketURL?.path
            },
            peerVerifier: verifier
        )
    }

    public func send(
        _ command: AutofillCommand,
        timeout: TimeInterval,
        handle: SocketCallHandle? = nil
    ) async throws -> AutofillReply {
        guard let socketPath = socketPathProvider(), !socketPath.isEmpty else {
            throw AgentCallError.agentUnavailable(
                "Deadbolt's macOS AutoFill App Group container is unavailable on an unsigned build."
            )
        }
        let verifier = peerVerifier
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let reply = try Self.performBlockingCall(
                        socketPath: socketPath,
                        command: command,
                        timeout: timeout,
                        handle: handle,
                        peerVerifier: verifier
                    )
                    continuation.resume(returning: reply)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public static func performBlockingCall(
        socketPath: String,
        command: AutofillCommand,
        timeout: TimeInterval,
        handle: SocketCallHandle? = nil,
        peerVerifier: PeerVerifyFn? = nil
    ) throws -> AutofillReply {
        if handle?.isCancelled == true {
            throw AgentCallError.cancelled
        }

        let pathBytes = Array(socketPath.utf8)
        guard !pathBytes.isEmpty, pathBytes.count <= AutofillWire.sunPathMax else {
            throw AgentCallError.agentUnavailable("AutoFill socket path exceeds sun_path limit")
        }

        let deadlineNanos: UInt64 = {
            let now = DispatchTime.now().uptimeNanoseconds
            let delta = UInt64(max(0.05, timeout) * 1_000_000_000)
            return now &+ delta
        }()

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw AgentCallError.agentUnavailable("could not create Unix socket")
        }
        defer {
            handle?.detach()
            _ = Darwin.close(fd)
        }

        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 {
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }

        guard handle?.attach(socketFD: fd) ?? true else {
            throw AgentCallError.cancelled
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let addrSize = socklen_t(MemoryLayout<sockaddr_un>.size)
        addr.sun_len = UInt8(addrSize)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (idx, byte) in pathBytes.enumerated() {
                raw[idx] = byte
            }
            raw[pathBytes.count] = 0
        }

        let connectRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, addrSize)
            }
        }
        if connectRC != 0 {
            let err = errno
            if err == EINPROGRESS {
                try waitSocket(fd: fd, events: Int16(POLLOUT), deadlineNanos: deadlineNanos, handle: handle)
                var sockErr: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                if getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &len) != 0 || sockErr != 0 {
                    throw AgentCallError.agentUnavailable("Deadbolt's agent is not running")
                }
            } else {
                throw AgentCallError.agentUnavailable("Deadbolt's agent is not running")
            }
        }

        if command.carriesPassphrase {
            guard let peerVerifier else {
                throw AgentCallError.peerRejected(
                    "refusing to send passphrase without verifying Deadbolt's agent signature"
                )
            }
            try peerVerifier(fd)
        }

        var payload = try command.encodeLine()
        defer {
            if !payload.isEmpty {
                payload.resetBytes(in: 0 ..< payload.count)
            }
        }

        try writeAll(fd: fd, data: payload, deadlineNanos: deadlineNanos, handle: handle)

        var responseLine = try readLine(
            fd: fd,
            maxBytes: AutofillWire.maxLineBytes,
            deadlineNanos: deadlineNanos,
            handle: handle
        )
        defer {
            if !responseLine.isEmpty {
                responseLine.resetBytes(in: 0 ..< responseLine.count)
            }
        }

        return try WireDecoder.decodeMessage(responseLine)
    }

    private static func remainingPollMillis(deadlineNanos: UInt64) throws -> Int32 {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadlineNanos else {
            throw AgentCallError.timedOut
        }
        let millis = (deadlineNanos - now) / 1_000_000
        return Int32(min(max(1, millis), UInt64(Int32.max)))
    }

    private static func waitSocket(
        fd: Int32,
        events: Int16,
        deadlineNanos: UInt64,
        handle: SocketCallHandle?
    ) throws {
        while true {
            if handle?.isCancelled == true {
                throw AgentCallError.cancelled
            }
            let timeoutMS = try remainingPollMillis(deadlineNanos: deadlineNanos)
            var pfd = pollfd(fd: fd, events: events, revents: 0)
            let rc = Darwin.poll(&pfd, 1, timeoutMS)
            if handle?.isCancelled == true {
                throw AgentCallError.cancelled
            }
            if rc > 0 {
                if (pfd.revents & Int16(POLLNVAL)) != 0 {
                    throw AgentCallError.agentUnavailable("AutoFill socket closed")
                }
                return
            }
            if rc == 0 {
                throw AgentCallError.timedOut
            }
            if errno == EINTR {
                continue
            }
            throw AgentCallError.agentUnavailable("waiting on AutoFill socket failed")
        }
    }

    private static func writeAll(
        fd: Int32,
        data: Data,
        deadlineNanos: UInt64,
        handle: SocketCallHandle?
    ) throws {
        var offset = 0
        while offset < data.count {
            if handle?.isCancelled == true {
                throw AgentCallError.cancelled
            }
            let written: Int = data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return 0 }
                return Darwin.write(fd, base.advanced(by: offset), data.count - offset)
            }
            if written > 0 {
                offset += written
                continue
            }
            if written < 0 {
                let err = errno
                if err == EINTR {
                    continue
                }
                if err == EAGAIN || err == EWOULDBLOCK {
                    try waitSocket(
                        fd: fd,
                        events: Int16(POLLOUT),
                        deadlineNanos: deadlineNanos,
                        handle: handle
                    )
                    continue
                }
            }
            if handle?.isCancelled == true {
                throw AgentCallError.cancelled
            }
            throw AgentCallError.agentUnavailable("writing to Deadbolt's agent failed")
        }
    }

    private static func readLine(
        fd: Int32,
        maxBytes: Int,
        deadlineNanos: UInt64,
        handle: SocketCallHandle?
    ) throws -> Data {
        var buffer = Data()
        buffer.reserveCapacity(1024)
        var scratch = [UInt8](repeating: 0, count: 4096)
        defer {
            for i in scratch.indices {
                scratch[i] = 0
            }
        }

        while true {
            if handle?.isCancelled == true {
                if !buffer.isEmpty {
                    buffer.resetBytes(in: 0 ..< buffer.count)
                }
                throw AgentCallError.cancelled
            }
            let n = Darwin.read(fd, &scratch, scratch.count)
            if n > 0 {
                if let newline = scratch[0 ..< n].firstIndex(of: UInt8(ascii: "\n")) {
                    guard buffer.count + newline <= maxBytes else {
                        if !buffer.isEmpty {
                            buffer.resetBytes(in: 0 ..< buffer.count)
                        }
                        throw AgentCallError.invalidResponse("agent reply exceeded max line size")
                    }
                    buffer.append(contentsOf: scratch[0 ..< newline])
                    return buffer
                }
                guard buffer.count + n <= maxBytes else {
                    if !buffer.isEmpty {
                        buffer.resetBytes(in: 0 ..< buffer.count)
                    }
                    throw AgentCallError.invalidResponse("agent reply exceeded max line size")
                }
                buffer.append(contentsOf: scratch[0 ..< n])
                continue
            }
            if n == 0 {
                if handle?.isCancelled == true {
                    if !buffer.isEmpty {
                        buffer.resetBytes(in: 0 ..< buffer.count)
                    }
                    throw AgentCallError.cancelled
                }
                if !buffer.isEmpty {
                    return buffer
                }
                throw AgentCallError.agentUnavailable("Deadbolt's agent closed the connection")
            }
            let err = errno
            if err == EINTR {
                continue
            }
            if err == EAGAIN || err == EWOULDBLOCK {
                try waitSocket(
                    fd: fd,
                    events: Int16(POLLIN),
                    deadlineNanos: deadlineNanos,
                    handle: handle
                )
                continue
            }
            if !buffer.isEmpty {
                buffer.resetBytes(in: 0 ..< buffer.count)
            }
            if handle?.isCancelled == true {
                throw AgentCallError.cancelled
            }
            throw AgentCallError.agentUnavailable("reading from Deadbolt's agent failed")
        }
    }
}
