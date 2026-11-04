# Deadbolt for iOS (proof)

A SwiftUI app over the Rust core in `crates/mobile-core` (UniFFI module
`DeadboltCore`). It pairs with an existing device, unlocks with a passphrase or
Face ID / Touch ID, searches, shows and copies logins and one-time codes, and
syncs. Screens use the real core; these are implemented paths, not a claim that
all device flows have passed. See [the verification status](../../docs/mobile.md).

The Rust iOS target builds with the exact netwatch revision in the workspace
manifest. Its public Network.framework monitor replaces the temporary no-event
backend and forced-rebind workaround; normal foreground vault sync remains.
No netdev fork or libc downgrade is needed. Physical network handoffs remain
unverified; see the verification status above.
Earlier first-launch and pairing-code media came from a scratch build with
libc 0.2.189 and are labeled experimental; they do not verify this checkout.
No simulator software biometric fallback is provided.

## Build (headless)

```sh
mobile/ios/scripts/build-core.sh sim         # Rust core, Swift bindings, fonts
xcodegen generate --spec mobile/ios/project.yml
xcodebuild -project mobile/ios/Deadbolt.xcodeproj -scheme Deadbolt \
  -destination "id=<simulator udid>" -derivedDataPath build build
```

`build-core.sh device` builds the `aarch64-apple-ios` slice. Anomaly development
signing and profiles for both targets have been verified; device builds use
`CODE_SIGN_STYLE=Automatic CODE_SIGN_IDENTITY="Apple Development"` with team
`5NZ4Q7NXJ4`. Physical testing is deferred until Ryan returns.
Use a dedicated simulator (`xcrun simctl create "Deadbolt Mobile
Proof" …`) and `simctl boot/install/launch`; Simulator.app is never needed.

`Generated/` (bindings, xcframework, fonts) and the `.xcodeproj` are build
output and not checked in.

## Identifiers and entitlements

| | Value |
| --- | --- |
| App bundle ID | `pw.deadbolt.app` (team `5NZ4Q7NXJ4`) |
| Embedded AutoFill extension | `pw.deadbolt.app.autofill` |
| `com.apple.security.application-groups` | `group.pw.deadbolt` |
| `keychain-access-groups` | `$(AppIdentifierPrefix)pw.deadbolt.app` → `5NZ4Q7NXJ4.pw.deadbolt.app` |

- The store lives in the App Group container (`<group>/Deadbolt`) so the
  AutoFill extension can open it. The app refuses to start without the group
  rather than falling back to a private directory.
- The keychain group is declared for the app and extension to share; the
  biometric slot does not use the keychain (see below).
- The macOS group `5NZ4Q7NXJ4.pw.deadbolt` is unchanged and unrelated.
- An Anomaly-team Apple Development identity and both Deadbolt-specific iOS
  development profiles are installed and verified. Physical tests are deferred.
  Simulator builds are signed ad hoc (`CODE_SIGN_IDENTITY=-`) and Xcode embeds
  the entitlements above as simulator entitlements (checked in
  `Deadbolt.app-Simulated.xcent`). Personal team certificates are not used.

## Face ID / Touch ID

`Enclave.swift` implements docs/touch-id.md's design on iOS: a random 32-byte
slot key (handed to the core with `biometric_enroll`) is sealed to a Secure
Enclave P-256 key-agreement key created with
`[.privateKeyUsage, .biometryCurrentSet]` and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; the token is the same `DBSE`
envelope as the macOS helper (ECDH, HKDF-SHA256, AES-256-GCM, header as AAD).
Opening it needs the Secure Enclave to do ECDH, which it refuses without a
live match from the currently enrolled set. There is no boolean `LAContext`
gate, no `.devicePasscode` fallback, and no software or keychain substitute.
The slot expires after 14 days or when the enrolled set changes, and every
passphrase unlock rotates it.

The iOS Simulator has no Secure Enclave, so there the app reports biometric
unlock as unavailable. Physical verification needs a signed device build.

## Look

`Theme.swift` is Rune's opencode theme as the desktop app and the Chrome
extension use it (`extension/static/theme.css`, checked against the Rune pin
in `crates/app/Cargo.toml`), with Rune's fonts copied from the pinned
`rune-theme-opencode`. iOS keeps its navigation, gestures, Dynamic Type and
the system biometric sheet; type is scaled by 15/13 and controls are at least
44pt for touch.

## Timing

The app prints `deadbolt-metric` lines to stdout (`simctl launch
--console-pty`): `launch_to_lock_ms` (process start to the lock screen),
`unlock_to_list_ms` and `search_ms` (with the item count). No vault data is
logged.
