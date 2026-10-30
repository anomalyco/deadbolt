# macOS AutoFill provider

2026-10-30. Feasibility, architecture, security argument, and rollout plan for shipping Deadbolt as a system Credential Provider on macOS (`System Settings › General › AutoFill & Passwords`), covering passwords, passkeys, and verification codes in Safari and native macOS apps.

## Feasibility for a Developer ID app

**Yes, a Developer ID-signed and notarized macOS app outside the Mac App Store can ship an AutoFill Credential Provider extension** (`ASCredentialProviderViewController`, `com.apple.developer.authentication-services.autofill-credential-provider`), covering passwords, passkeys, and one-time codes. Doing so requires two explicit App IDs and two embedded Developer ID provisioning profiles from the Apple Developer portal, plus a Team-ID-prefixed App Group so the sandboxed extension can talk to Deadbolt's background agent.

### Primary sources

1. **Apple's capability matrix ([Supported capabilities (macOS)](https://developer.apple.com/help/account/reference/supported-capabilities-macos/)):** marks **AutoFill credential provider**, **App groups**, **App Sandbox**, and **Hardened runtime** as supported for **Developer ID** distribution as well as Mac App Store distribution. **AutoFill credential provider** is absent from the free *Apple Developer* column, which makes `com.apple.developer.authentication-services.autofill-credential-provider` a **restricted entitlement** under [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles).
2. **Restricted entitlement enforcement (`amfid` and `AuthenticationServicesAgent`):** on macOS, any binary signed with a restricted entitlement without a matching `Contents/embedded.provisionprofile` is killed at `execve` with `SIGKILL` (`docs/touch-id.md`, Phase 1). Apple's `AuthenticationServicesAgent` also requires **both** the containing `.app` (`Deadbolt.app`) and the nested `.appex` (`DeadboltAutoFill.appex`) to carry `com.apple.developer.authentication-services.autofill-credential-provider = true` and matching embedded provisioning profiles; if the host app lacks the entitlement, `ASCredentialIdentityStore.shared.state()` reports `isEnabled = false` and rejects writes with `ASCredentialIdentityStoreErrorCodeStoreDisabled` ([Apple Developer Forums #828372](https://developer.apple.com/forums/thread/828372)).
3. **App Groups on macOS 15+ ([App Groups: macOS vs iOS: Working Towards Harmony](https://developer.apple.com/forums/thread/721701)):** Apple DTS documents two App Group naming conventions on macOS:
   - iOS-style `group.<name>` requires provisioning-profile allowlisting on every binary that claims it, which rules out bare Mach-O executables such as `Contents/Helpers/deadbolt`.
   - macOS-style `<TeamID>.<name>` (`5NZ4Q7NXJ4.pw.deadbolt`) is an **unrestricted** entitlement on macOS (bare Mach-O binaries may claim it without an `embedded.provisionprofile`), satisfies macOS 15 Sequoia's App Group Container Protection without raising a TCC prompt because it starts with the signing certificate's Team ID, and is automatically allowlisted as `5NZ4Q7NXJ4.*` in macOS provisioning profiles when the **App Groups** capability is enabled on the App ID.

### Shipping precedent

| App | Distribution | AutoFill status and IPC |
| --- | --- | --- |
| **1Password 8** (`2BUA8C4S2C`) | Developer ID only (Electron, notarized) | Shipped macOS AutoFill in beta in May 2026 (8.12.22), GA in August 2026 ([8.12.32](https://releases.1password.com/mac/stable/8.12.32/)) for logins and passkeys, and one-time codes in October 2026 ([8.12.40](https://releases.1password.com/mac/stable/)). Signs `1Password.app` with `autofill-credential-provider` and `application-groups` ([support guide](https://support.1password.com/macos-autofill/)). Requires macOS 14+. |
| **Bitwarden Desktop** (`LTZ2PFU5D6`) | Developer ID and Mac App Store (`bitwarden/clients`) | Embeds `Contents/PlugIns/autofill-extension.appex` signed with Developer ID profile `PM Stable Desktop-ExtAutofill Distrib` inside `Bitwarden.app` (`bitwarden_stable_desktop_developer_id.provisionprofile`). Communicates with its Rust `desktop_native` IPC server over a Unix domain socket in `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/`. |
| **Strongbox** | Mac App Store, Setapp, and Developer ID (`strongbox-password-safe/Strongbox`) | Ships `Strongbox AutoFill.appex` (`Strongbox_AutoFill-setapp.entitlements`). Talks to `Strongbox.app` over a Unix domain socket (`F`, capped at 103 bytes for `sun_path`) inside its App Group container (`macbox/autofill-proxy/AutoFillProxy.m`). |
| **KeePassXC** / **MacPass** | Developer ID | KeePassXC has an open end-to-end tested PR ([#13051](https://github.com/keepassxreboot/keepassxc/pull/13051)) building `keepassxc-autofill.appex` without Xcode (`-fapplication-extension -Wl,-e,_NSExtensionMain`) and talking to the main app over `CFMessagePort` via a sandbox `mach-lookup.global-name` exception; notes that `.xpc` bundles in `Contents/XPCServices/` fail from an `.appex` (`error 3: No such process`) because `launchd` scopes them to the host app's PID namespace. MacPass ([#1178](https://github.com/MacPass/MacPass/issues/1178)) has not implemented it. |

## macOS version requirements

Verified from `AuthenticationServices.framework` headers in the macOS SDK:

| Feature | Key types and `Info.plist` capability | Minimum macOS |
| --- | --- | --- |
| **Passwords** (legacy identity methods) | `ASCredentialProviderViewController`, `ASPasswordCredentialIdentity`, `ASPasswordCredential`, `ASCredentialIdentityStore` | **macOS 11.0** (Big Sur) |
| **Passwords** (unified request API) + **Passkeys** (sign-in & registration) | `provideCredentialWithoutUserInteraction(for:)`, `prepareInterfaceToProvideCredential(for:)`, `ASPasswordCredentialRequest`, `ASPasskeyCredentialIdentity`, `ASPasskeyCredentialRequest`, `ASPasskeyCredentialRequestParameters`, `ASPasskeyAssertionCredential`, `ASPasskeyRegistrationCredential`, `ASSettingsHelper.openCredentialProviderAppSettings` (`ProvidesPasskeys = true`) | **macOS 14.0** (Sonoma) |
| **Identity store inspection** | `ASCredentialIdentityStore.getCredentialIdentities(forService:credentialIdentityTypes:)` | **macOS 14.4** |
| **One-time codes** (TOTP AutoFill) | `ASOneTimeCodeCredential`, `ASOneTimeCodeCredentialIdentity`, `ASOneTimeCodeCredentialRequest`, `prepareOneTimeCodeCredentialList(for:)`, `completeOneTimeCodeRequest(using:)` (`ProvidesOneTimeCodes = true`) | **macOS 15.0** (Sequoia) |
| **In-app enablement prompt & passkey exclusions** | `ASSettingsHelper.requestToTurnOnCredentialProviderExtension`, `ASPasskeyCredentialRequest.excludedCredentials`, `ASExtensionErrorCodeMatchedExcludedCredential`, conditional passkey upgrades (`SupportsConditionalPasskeyRegistration`) | **macOS 15.0** (Sequoia) |
| **Native app display names** | `ASCredentialServiceIdentifierTypeApp`, `ASCredentialServiceIdentifier.displayName` (`ASSavePasswordRequest` and `ASGeneratePasswordsRequest` remain `API_UNAVAILABLE(macos)` through the macOS 27 SDK) | **macOS 26.2** (Tahoe) |

**Target choice:** keep `Deadbolt.app` and `deadbolt` at `MACOSX_DEPLOYMENT_TARGET = 12.0` (`LSMinimumSystemVersion = 12.0`) so existing Macs are unaffected, and set `DeadboltAutoFill.appex` to **`LSMinimumSystemVersion = 14.0`** (matching 1Password 8). That lets passwords and passkeys share the single macOS 14 `ASCredentialRequest` API without carrying deprecated macOS 11–13 overrides, while gating one-time codes, `excludedCredentials`, and `requestToTurnOnCredentialProviderExtension` behind `if #available(macOS 15.0, *)`. On macOS 12–13, `Deadbolt.app` runs normally and `pluginkit` ignores the 14.0+ extension.

## Architecture

```text
Safari / native app
  │
  ▼  AuthenticationServices (system sheet or inline QuickType suggestion)
DeadboltAutoFill.appex  (sandboxed, pw.deadbolt.app.autofill, holds no keys or store)
  │
  │  Unix socket: ~/Library/Group Containers/5NZ4Q7NXJ4.pw.deadbolt/s (0600, dir 0700)
  ▼  LOCAL_PEERTOKEN checked via deadbolt-enclave identify
deadbolt agent          (Contents/Helpers/deadbolt, sole process opening store.redb)
  │
  ▼  Touch ID / SEP unseal when locked or when passkey UV requires it
deadbolt-enclave        (Contents/Helpers/deadbolt-enclave, SHA-256 pinned)
```

### Why a second Unix socket in the App Group container

Every macOS `.appex` (`CFBundlePackageType = XPC!`) must run under App Sandbox (`com.apple.security.app-sandbox = true`). Inside App Sandbox, the extension cannot reach `$TMPDIR/deadbolt-<uid>/agent.sock` or `~/.local/share/deadbolt/store.redb`. Comparing the four ways across the sandbox boundary:

1. **Dedicated Unix socket in `5NZ4Q7NXJ4.pw.deadbolt` (chosen):**
   - `DeadboltAutoFill.appex` claims `com.apple.security.application-groups = ["5NZ4Q7NXJ4.pw.deadbolt"]`. macOS's built-in `application-group` sandbox profile allows `AF_UNIX` `connect` inside `~/Library/Group Containers/5NZ4Q7NXJ4.pw.deadbolt/` with zero network entitlements and zero `temporary-exception` keys (the same mechanism Bitwarden and Strongbox ship).
   - A short socket filename (`s`) keeps `/Users/<user>/Library/Group Containers/5NZ4Q7NXJ4.pw.deadbolt/s` well under `sockaddr_un.sun_path`'s 104-byte limit.
   - `deadbolt` and `deadbolt-enclave` remain bare Mach-O executables without provisioning profiles, claiming only the unrestricted `5NZ4Q7NXJ4.pw.deadbolt` group. `deadbolt-enclave` resolves `FileManager.default.containerURL(forSecurityApplicationGroupIdentifier:)` once at agent startup so `containermanagerd` provisions the container cleanly on macOS 15+ without `unsafe` FFI in Rust.
   - Unlike KeePassXC, Strongbox, and Bitwarden (whose AutoFill servers live inside the GUI app and die on `⌘Q`), `deadbolt agent` stays running in the background after `Deadbolt.app` closes (`docs/app.md`), so AutoFill keeps working while the main window is closed.
2. **XPC or `CFMessagePort` (rejected):** nested `.xpc` bundles cannot be looked up from an `.appex` (`launchd` PID-namespace scoping). A global Mach port (`CFMessagePort`) needs `com.apple.security.temporary-exception.mach-lookup.global-name` and would either pull Objective-C/CoreFoundation FFI (`unsafe`) into `deadbolt-cli` or force `Deadbolt.app` to stay open as a relay.
3. **Reading `store.redb` directly in the extension (rejected):** breaks Deadbolt's invariant that only `deadbolt agent` opens `store.redb` and holds vault keys, collides with `redb`'s single-process exclusive file lock while the agent is unlocked, and scatters unlock, rate-limit, and Activity rules across two processes.
4. **Moving `agent.sock` itself into the App Group container (rejected):** standalone Linux and unsigned local CLI builds have no App Group container. Keeping `agent.sock` where it is (`crates/client/src/paths.rs`) and binding `<group-container>/s` as an additional listener on macOS when the group container is available leaves CLI, Linux, and test paths untouched, and lets the agent restrict `<group-container>/s` to `CallerClass::AutoFill` alone.

### Request flows

- **Silent fill while unlocked (`provideCredentialWithoutUserInteraction(for:)`):**
  macOS calls this with a ~3 s deadline and no view on screen after the user picks an inline suggestion (and after macOS's own *Use Touch ID for autofilling passwords* check, when enabled in System Settings).
  - For `ASPasswordCredentialRequest` and `ASOneTimeCodeCredentialRequest`: if `<group-container>/s` answers and the agent is unlocked, the agent checks `serviceIdentifier` against the item's saved URLs, computes any TOTP code in-process, logs Activity where applicable, and returns the requested values; the extension calls `completeRequest(withSelectedCredential:)` or `completeOneTimeCodeRequest(using:)`.
  - If the agent is not running, is locked, or the request is an `ASPasskeyCredentialRequest` that requires a Touch ID ceremony (`UV`), the extension immediately cancels with `ASExtensionError(.userInteractionRequired)` instead of blocking past the 3 s silent deadline.
- **Interactive unlock, picker, or passkey ceremony (`prepareInterfaceToProvideCredential(for:)`, `prepareCredentialList(for:)`, `prepareInterfaceForPasskeyRegistration(_:)`):**
  macOS presents the extension's out-of-process view controller sheet.
  - **Agent not running:** the extension locates its containing `Deadbolt.app` by bundle path (`Bundle.main.bundleURL` up three components, symlinks resolved, so multiple installs never cross) and starts the agent via `NSWorkspace.shared.openApplication` (launching `Deadbolt.app` in background/panel mode, which spawns `Contents/Helpers/deadbolt`).
  - **Locked:** if `status.touch_id_ready` is true, the extension immediately requests `UnlockBiometric` (raising Deadbolt's Secure Enclave Touch ID prompt via `deadbolt-enclave`) alongside a secure passphrase field fallback. Once unlocked, a `prepareInterfaceToProvideCredential` call completes the pending request straight away without making the user pick the account a second time.
  - **Account picker (`prepareCredentialList`):** queries the agent for matching logins (and passkeys when `requestParameters` is non-nil) for `serviceIdentifiers`, ranked by Deadbolt's existing `autofill::rank` (`crates/cli/src/agent/autofill.rs`). Double-click or `⏎` fills; `Esc` cancels with `ASExtensionError(.userCanceled)`. If the sheet disappears while a Touch ID prompt is in flight (`viewWillDisappear`), closing the socket cancels the prompt in the agent (`conv.closed()`).
- **Passkey `clientDataHash` adapter (`crates/core/src/webauthn.rs`, `passkeys.rs`):**
  Unlike the Chromium extension (which sends `origin` and `challenge` so the agent builds `clientDataJSON`), macOS `AuthenticationServices` builds `clientDataJSON` inside WebKit / `AuthenticationServicesAgent` after checking the Safari frame origin or the app's `webcredentials:` Associated Domains, and hands the extension `relyingPartyIdentifier` plus the 32-byte SHA-256 `clientDataHash`. `deadbolt_core::webauthn` gains `assert_hash(rp_id, private_key, client_data_hash, verified)` alongside `assert`: `attest` already takes only `rp_id`, and `ASPasskeyRegistrationCredential` echoes `clientDataHash` alongside `attestationObject` and `credentialID`.

### `ASCredentialIdentityStore` without leaking secrets

`ASCredentialIdentityStore.shared` is a local index managed by `AuthenticationServicesAgent` so Safari and native apps can offer inline suggestions before spawning the extension.

- **What goes into it:**
  - `ASPasswordCredentialIdentity`: `(serviceIdentifier: domain, user: username, recordIdentifier: "<vault_hex>:<item_hex>", rank)` for each login with both a non-empty `username` and a `password`, one entry per normalized host in `url`, `url-2`, … (`crates/cli/src/site.rs`). `sign-in-with`-only logins and items without URLs are omitted.
  - `ASPasskeyCredentialIdentity`: `(relyingPartyIdentifier: rp_id, userName: username, credentialID, userHandle, recordIdentifier: "<vault_hex>:<item_hex>", rank)`.
  - `ASOneTimeCodeCredentialIdentity` (macOS 15+): `(serviceIdentifier: domain, label: username_or_title, recordIdentifier: "<vault_hex>:<item_hex>", rank)` for logins with a non-empty `otp` field.
- **What never enters it:** passwords, OTP seeds or codes, passkey private keys, notes, custom fields, vault names, or item titles (save when a TOTP login has no username and needs a label). `recordIdentifier` is `<64-hex vault id>:<32-hex item id>`.
- **Who writes it:** `deadbolt` (a bare Mach-O) cannot call `ASCredentialIdentityStore` because it carries no provisioning profile. Both `Deadbolt.app` and `DeadboltAutoFill.appex` carry `autofill-credential-provider` and can:
  1. `DeadboltAutoFill.appex` syncs the store in `prepareInterfaceForExtensionConfiguration` when enabled in System Settings, after passkey registration, and whenever an agent reply reports a newer `identities_hash`.
  2. `Deadbolt.app` (`crates/app`, via a small Swift bridge compiled on macOS when signed) syncs the store whenever its `watch` stream sees `unlocked`, `items`, or `resync`, and calls `ASSettingsHelper` from Settings.
- **When it is cleared:** `removeAllCredentialIdentities` runs when the user disables macOS AutoFill in Deadbolt Settings or when this device is removed from all vaults; macOS also wipes and disables the store automatically when the user toggles Deadbolt off in System Settings. Across normal locks (idle, sleep, `⌘L`), keeping identities registered lets Safari show inline suggestions while locked and unlock-and-fill in a single Touch ID tap (see Open questions).

## Security argument

1. **The agent remains the sole decryptor and policy engine.** `store.redb`, `KeySet`, passkey PKCS#8 scalars, and TOTP seeds never leave `deadbolt agent`. `DeadboltAutoFill.appex` has no file access to `~/.local/share/deadbolt` and receives only secret-free listings or the single credential chosen for the current request, held briefly in memory to call `extensionContext.complete*` and never persisted or logged.
2. **Mutual code-signature authentication on the App Group socket.**
   - **Agent checks caller:** on every connection to `<group-container>/s`, the agent reads the kernel's `LOCAL_PEERTOKEN` (`pid` + `pid_version`) and verifies via `deadbolt-enclave identify` (`SecCodeCopyGuestWithAttributes`) that the peer is validly signed by `DEADBOLT_TEAM_ID` (`5NZ4Q7NXJ4`) with identifier `pw.deadbolt.app.autofill` (`CallerClass::AutoFill`). Any other same-UID process that connects to `<group-container>/s` is refused.
   - **Extension checks agent:** before sending a passphrase in the fallback unlock view, `DeadboltAutoFill.appex` reads the socket peer's `LOCAL_PEERTOKEN` and checks with `SecCodeCopyGuestWithAttributes` in-process that the listener is validly signed by `5NZ4Q7NXJ4` as `pw.deadbolt.cli` (or `deadbolt` in dev builds) inside its own containing `Deadbolt.app/Contents/Helpers/deadbolt`, matching `deadbolt_client::peer::check`.
3. **Narrow capability even if the extension were compromised.** `CallerClass::AutoFill` may call only AutoFill status/list/fill/passkey-ceremony and unlock commands. It is denied `ItemGet`, `ItemList` (arbitrary kinds), `Resolve`, `Import`, `ItemSet`, `ItemRemove`, `SyncOnePassword`, pairing, and grant management. Secrets for secure notes, SSH keys, API credentials, cards, and identities are unreachable from `<group-container>/s`.
4. **Domain binding on both sides.** For Safari pages and Associated-Domain native apps, WebKit and `AuthenticationServicesAgent` determine `serviceIdentifier` / `relyingPartyIdentifier` and `clientDataHash` out of reach of the web page or extension. The agent independently re-checks `Site::matches` on login/OTP fills and `passkeys::validate(item, rp_id)` on passkey assertions before releasing a value or signature, refusing mismatches with `domain_mismatch`.
5. **Honest User Verification (`UV`) and no synthetic-click bypass.**
   - While locked, no value or signature leaves the agent without a live Touch ID unseal of `"keyset.biometric"` inside the Secure Enclave (`deadbolt-enclave unseal`) or the vault passphrase (subject to the agent's global `Guesses` backoff).
   - For passkeys (`UV = required` or `preferred` with Touch ID enrolled), `UV = 1` is set in `authenticatorData` **only** when Deadbolt's own Secure Enclave biometric key was unsealed for this ceremony (either by unlocking the vault via Touch ID inside this request, so a locked fill takes one tap rather than two, or by `verify_user` when already unlocked). Clicking an AutoFill row alone never sets `UV = 1`.
6. **Idle lock, rate limits, and Activity.** `autofill-status`, `autofill-identities`, `site-logins`, and `passkey-list` do not reset the agent's idle timer; actual fills and passkey ceremonies do, and an in-flight Touch ID prompt holds `Agent::busy` only until answered or cancelled. Fills and passkey ceremonies from `CallerClass::AutoFill` are rate-limited and recorded in Activity (naming `"macOS AutoFill"`, the service/RP, item, and outcome, never values).

## Build and release pipeline

Deadbolt compiles `DeadboltAutoFill.appex` directly with `swiftc -application-extension -Xlinker -e -Xlinker _NSExtensionMain` (linking `AuthenticationServices`, `AppKit`, and `Foundation`), with **no Xcode project and no `xcodebuild`**, keeping the existing `build-macos` → `sign-macos` security split intact:

1. **`crates/app/scripts/bundle.sh` (`build-macos`, no secrets):**
   - Compiles `DeadboltAutoFill` for `arm64-apple-macosx14.0` and `x86_64-apple-macosx14.0` (with `--universal`), runs `lipo -create`, writes `Deadbolt.app/Contents/PlugIns/DeadboltAutoFill.appex/Contents/Info.plist`, and signs ad-hoc (`codesign --sign -`, no restricted entitlements) when no signing identity and profiles are supplied.
   - Local ad-hoc builds (`bundle.sh`, `snap.sh`, `cargo test -p deadbolt-app`) continue to run on developer Macs without `amfid` `SIGKILL`. Local signed AutoFill testing accepts `DEADBOLT_APPLE_SIGNING_IDENTITY`, `DEADBOLT_APP_PROVISION_PROFILE`, and `DEADBOLT_AUTOFILL_PROVISION_PROFILE`.
2. **`.github/release/` (`sign-enclave` and `sign-macos`, sparse checkout, treats build output as data):**
   - Entitlements live inside the protected `.github/release/` boundary:
     - `enclave.entitlements` & `cli.entitlements`: `com.apple.security.application-groups = ["5NZ4Q7NXJ4.pw.deadbolt"]`.
     - `app.entitlements`: `application-identifier = "5NZ4Q7NXJ4.pw.deadbolt.app"`, `team-identifier = "5NZ4Q7NXJ4"`, `autofill-credential-provider = true`, `application-groups = ["5NZ4Q7NXJ4.pw.deadbolt"]`.
     - `autofill.entitlements`: `application-identifier = "5NZ4Q7NXJ4.pw.deadbolt.app.autofill"`, `team-identifier = "5NZ4Q7NXJ4"`, `autofill-credential-provider = true`, `app-sandbox = true`, `application-groups = ["5NZ4Q7NXJ4.pw.deadbolt"]`.
   - `sign-enclave.sh` signs the thin `deadbolt-enclave` binaries with `enclave.entitlements` before `build-macos` pins `DEADBOLT_ENCLAVE_SHA256`.
   - `sign-macos.sh` updates its expected universal Mach-O allowlist to the exact four binaries (`Contents/Helpers/deadbolt`, `Contents/Helpers/deadbolt-enclave`, `Contents/MacOS/Deadbolt`, `Contents/PlugIns/DeadboltAutoFill.appex/Contents/MacOS/DeadboltAutoFill`), decodes and validates the two Developer ID `.provisionprofile` files via `security cms -D -i` (checking Team ID `5NZ4Q7NXJ4`, bundle IDs, `autofill-credential-provider`, and expiration), writes them to `DeadboltAutoFill.appex/Contents/embedded.provisionprofile` and `Deadbolt.app/Contents/embedded.provisionprofile`, and signs inside-out (`deadbolt` → `DeadboltAutoFill.appex` → `Deadbolt.app`) without touching `deadbolt-enclave`, then notarizes and staples `Deadbolt.app` and the DMG.
   - `scripts/verify-macos-release.sh` verifies `check_developer_id` on `DeadboltAutoFill.appex` (`pw.deadbolt.app.autofill`), validates both embedded profiles, and confirms `codesign --verify --deep --strict -R=<update-requirement.txt>` and `spctl --assess`. `deadbolt update` (`crates/cli/src/update.rs`) already allows nested regular files/directories inside `Deadbolt.app` and verifies `--deep` against `update-requirement.txt`.

## Apple Developer portal steps (team `5NZ4Q7NXJ4`)

Neither `pw.deadbolt.app` nor `pw.deadbolt.app.autofill` is registered yet in Apple Developer Portal for team `5NZ4Q7NXJ4`. Only an **Account Holder** or **Admin** on the Apple Developer team can complete these steps:

1. **Register two explicit App IDs** at [Certificates, Identifiers & Profiles › Identifiers](https://developer.apple.com/account/resources/identifiers/list) under team `5NZ4Q7NXJ4`:
   - `pw.deadbolt.app` (*Deadbolt*): enable **AutoFill Credential Provider** and **App Groups**.
   - `pw.deadbolt.app.autofill` (*Deadbolt AutoFill*): enable **AutoFill Credential Provider** and **App Groups**.
   *(No `group.*` identifier registration is needed for the macOS-style `5NZ4Q7NXJ4.pw.deadbolt` group; enabling **App Groups** on macOS App IDs automatically authorizes `5NZ4Q7NXJ4.*` in generated macOS profiles.)*
2. **Create two Developer ID provisioning profiles** at [Profiles](https://developer.apple.com/account/resources/profiles/list) › `+` › Distribution › **Developer ID** › macOS, selecting Anomaly's `Developer ID Application` certificate (`5NZ4Q7NXJ4`):
   - One for `pw.deadbolt.app` (`Deadbolt Developer ID`).
   - One for `pw.deadbolt.app.autofill` (`Deadbolt AutoFill Developer ID`).
   Verify each downloaded `.provisionprofile` with `security cms -D -i <file>` to confirm `Entitlements` includes `com.apple.developer.authentication-services.autofill-credential-provider = true` and `com.apple.security.application-groups = ["5NZ4Q7NXJ4.*"]`.
3. **Add two secrets to the `release` GitHub Actions environment** on `anomalyco/deadbolt`:
   - `APPLE_PROVISIONING_PROFILE_APP`: `base64 < Deadbolt_Developer_ID.provisionprofile`
   - `APPLE_PROVISIONING_PROFILE_AUTOFILL`: `base64 < Deadbolt_AutoFill_Developer_ID.provisionprofile`
4. *(Optional, for local SIP-on testing before CI signing)* Create two **macOS App Development** profiles for `pw.deadbolt.app` and `pw.deadbolt.app.autofill` bound to an `Apple Development` certificate and the test Mac's Hardware UDID.

## PR plan

1. **PR 1: Core `clientDataHash` passkey support and agent App Group AutoFill socket (`crates/core`, `crates/client`, `crates/cli`).**
   Add `webauthn::assert_hash` and `passkeys` hash-based helpers; add `deadbolt-enclave group-container`; add `CallerClass::AutoFill` (`pw.deadbolt.app.autofill`) in `caller.rs`; bind the optional `<group-container>/s` Unix listener in `agent/mod.rs` restricted to `CallerClass::AutoFill` with `autofill-status`, `autofill-identities`, domain-checked password/OTP fills, passkey hash ceremonies (coalescing single-tap Touch ID unlock + `UV`), rate limits, and Activity entries; integration tests over socket pairs.
2. **PR 2: `DeadboltAutoFill.appex` for passwords, unlock UI, and `ASCredentialIdentityStore` (`crates/app`, `bundle.sh`).**
   Build the Swift `ASCredentialProviderViewController` extension into `Deadbolt.app/Contents/PlugIns/DeadboltAutoFill.appex` via `swiftc -application-extension` in `bundle.sh`; implement silent password fill when unlocked, Touch ID + passphrase unlock sheet when locked, searchable credential picker, `NSWorkspace` agent auto-start, and `ASCredentialIdentityStore` sync; wire optional local profile/entitlement signing in `bundle.sh` while keeping ad-hoc builds unentitled.
3. **PR 3: Release signing boundary and Settings onboarding (`.github/release/`, `.github/workflows/release.yml`, `scripts/verify-macos-release.sh`, `crates/app`).**
   Add `.github/release/{app,autofill,cli,enclave}.entitlements`, profile validation and inside-out `.appex` signing in `sign-enclave.sh` and `sign-macos.sh`, release verification checks in `verify-macos-release.sh`, and **Settings › macOS AutoFill** (`ASSettingsHelper` enable button + live identity sync on `watch` changes) in `Deadbolt.app`.
4. **PR 4: Passkeys in macOS AutoFill (`ProvidesPasskeys = true`, macOS 14+).**
   Register `ASPasskeyCredentialIdentity` records, handle `ASPasskeyCredentialRequest` assertions (with `allowedCredentials` filtering, SEP `UV` enforcement, and `viewWillDisappear` Touch ID cancellation), and handle `prepareInterfaceForPasskeyRegistration` (with macOS 15+ `excludedCredentials` checks).
5. **PR 5: One-time codes in macOS AutoFill (`ProvidesOneTimeCodes = true`, macOS 15+).**
   Register `ASOneTimeCodeCredentialIdentity` records behind `#available(macOS 15.0, *)` and fulfill `ASOneTimeCodeCredentialRequest` and `prepareOneTimeCodeCredentialList(for:)` with agent-computed TOTP codes.

## Open questions to confirm before PR 1

1. **Keep identities in `ASCredentialIdentityStore` across normal locks?** Recommended: **yes** (wipe only when macOS AutoFill is turned off in Settings or this device leaves all vaults, with an optional *Clear AutoFill suggestions when locked* toggle). Keeping `(domain, username, opaque ref)` registered while locked is what lets Safari show Deadbolt inline suggestions and conditional passkeys right after sleep/reboot and unlock-and-fill with one Touch ID tap, as 1Password and Strongbox do; the trade-off is that macOS's local `AuthenticationServices` database retains `(domain, username)` pairs under FileVault while Deadbolt is locked.
2. **Extension minimum OS of macOS 14.0 (Sonoma)?** Recommended: **yes**, while keeping `Deadbolt.app` and `deadbolt` at macOS 12.0. Supporting passwords on macOS 12–13 is possible via the deprecated pre-14 `ASPasswordCredentialIdentity` overrides if needed.
3. **Unassociated native apps (`serviceIdentifiers` is empty)?** Recommended: allow searching and picking a login in `DeadboltAutoFill.appex`'s manual picker sheet, gated by an explicit Touch ID confirmation naming the fill when no `serviceIdentifier` binds the target app to the login's domain (matching 1Password 8.12.40).
