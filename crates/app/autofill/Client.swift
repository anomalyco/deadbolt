// `DeadboltAutoFill.appex`'s daemon client, the part that needs AppKit or
// Foundation: where Deadbolt.app and its App Group container are, launching
// the app, and an async face on `deadbolt-ffi`'s blocking `autofillCall`.
// The socket, the protocol and the check of the daemon's code signature
// are Rust's (`crates/ffi`).

import AppKit
import Foundation

public protocol AutofillDaemonClient: Sendable {
    func send(
        _ command: AutofillCommand,
        timeout: TimeInterval,
        handle: CallHandle?
    ) async throws -> AutofillReply
}

public protocol DaemonLaunching: Sendable {
    func startInBackground() async -> Bool
    func openContainingApp() async -> Bool
}

public struct ContainingBundle: Equatable, Sendable {
    public let appURL: URL
    public let daemonBinaryURL: URL

    public init(appURL: URL, daemonBinaryURL: URL) {
        self.appURL = appURL
        self.daemonBinaryURL = daemonBinaryURL
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
        let daemon = contents.appendingPathComponent("Helpers/deadbolt").resolvingSymlinksInPath()
        return ContainingBundle(appURL: app, daemonBinaryURL: daemon)
    }
}

public enum AppGroupContainer {
    /// The AutoFill socket in Deadbolt's App Group container. `ownAppGroup`
    /// checks this process's signature and entitlements first, so an ad-hoc
    /// build never asks macOS for a container and never prompts.
    public static func socketURL() -> URL? {
        guard let group = ownAppGroup(),
              let container = FileManager.default.containerURL(
                  forSecurityApplicationGroupIdentifier: group
              ),
              !container.path.isEmpty
        else {
            return nil
        }
        return container.appendingPathComponent(autofillSocketName(), isDirectory: false)
    }
}

public struct WorkspaceDaemonLauncher: DaemonLaunching {
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

public struct UnixSocketDaemonClient: AutofillDaemonClient {
    public let socketPathProvider: @Sendable () -> String?
    /// The daemon binary the socket's peer must run, by code signature,
    /// before anything is sent (`Contents/Helpers/deadbolt`). Without one,
    /// the passphrase never is.
    public let daemonBinary: String?

    public init(socketPath: String, daemonBinary: String?) {
        self.init(socketPathProvider: { socketPath }, daemonBinary: daemonBinary)
    }

    public init(socketPathProvider: @escaping @Sendable () -> String?, daemonBinary: String?) {
        self.socketPathProvider = socketPathProvider
        self.daemonBinary = daemonBinary
    }

    public static func live() -> UnixSocketDaemonClient {
        let resolved = AppGroupContainer.socketURL()?.path
        return UnixSocketDaemonClient(
            socketPathProvider: { resolved ?? AppGroupContainer.socketURL()?.path },
            daemonBinary: ContainingBundle.locate()?.daemonBinaryURL.path
        )
    }

    public func send(
        _ command: AutofillCommand,
        timeout: TimeInterval,
        handle: CallHandle? = nil
    ) async throws -> AutofillReply {
        guard let socketPath = socketPathProvider(), !socketPath.isEmpty else {
            throw DaemonCallError.daemonUnavailable(
                reason: "Deadbolt's macOS AutoFill App Group container is unavailable on an unsigned build."
            )
        }
        let daemon = daemonBinary
        // Every call gets a handle, so cancelling the Swift task cancels the
        // call (and dismisses any Touch ID sheet the daemon has up), even
        // when the caller passed none.
        let callHandle = handle ?? CallHandle()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    let outcome = autofillCall(
                        socketPath: socketPath,
                        command: command,
                        timeoutSecs: timeout,
                        handle: callHandle,
                        daemon: daemon
                    )
                    switch outcome {
                    case let .replied(reply):
                        continuation.resume(returning: reply)
                    case let .failed(error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            callHandle.cancel()
        }
    }
}
