# Touch ID unlock on macOS

2026-10-26. Design for unlocking Deadbolt's local store (`crates/store`) with Touch ID from the background agent (`crates/cli`, `Deadbolt.app/Contents/Helpers/deadbolt`).

## Summary

Deadbolt uses a **Secure Enclave P-256 key (`CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey`) whose hardware-sealed `dataRepresentation` blob is stored in `store.redb`** alongside a second AEAD-wrapped key-set slot (`"keyset.biometric"`).

- **Hardware-bound to Touch ID:** the private key is generated inside the Secure Enclave with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `[.privateKeyUsage, .biometryCurrentSet]`. The private scalar never leaves the Secure Enclave; decrypting the store's wrapping key requires a live Touch ID match from the currently enrolled fingerprint set.
- **No Keychain state, no restricted entitlements, no provisioning profile:** unlike `kSecUseDataProtectionKeychain` (which stores items in `secd` and fails with `errSecMissingEntitlement = -34018` or gets `SIGKILL`ed by `amfid` unless every executable is wrapped in an `.app` bundle with an Apple-issued `Contents/embedded.provisionprofile`), `CryptoKit.SecureEnclave`'s `dataRepresentation` is an opaque blob encrypted by the Secure Enclave's hardware UID key and stored in `store.redb`.
- **Authenticated helper beside the agent:** a small Swift helper (`deadbolt-enclave`, ~50 KB stripped, `CFBundleIdentifier = "pw.deadbolt.app.enclave"`) is compiled once, signed, pinned by the SHA-256 digest of those exact signed bytes (`DEADBOLT_ENCLAVE_SHA256`) inside `deadbolt`, and shipped next to the agent: at `Deadbolt.app/Contents/Helpers/deadbolt-enclave`, and beside `deadbolt` in the macOS CLI tarballs (install script, Homebrew formula). A `deadbolt` without its helper beside it reports `touch_id_available = false` unless talking to a running `Deadbolt.app` agent over the control socket.
- **Zero `unsafe` in Rust and zero new crate dependencies:** the agent verifies the helper's SHA-256 before spawning it and reads the 32-byte key from `stdout` directly into a fixed `Zeroizing<[u8; 32]>` buffer.

---

## Phase 1 — The macOS options and their security

### 1. Data-protection keychain (`kSecUseDataProtectionKeychain`) + `SecAccessControl`

Stores a 256-bit wrapping key (or the 64-byte `KeySet`) as a `kSecClassGenericPassword` item in `secd`'s iOS-style Data Protection Keychain (`~/Library/Keychains/<UUID>/keychain-2.db`) with:

```swift
SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet,
    &error
)
```

- **Security:** Strong. `secd` seals the item in the Secure Enclave under the current biometric set digest (`bioc`) and checks the calling process's code-signed `application-identifier` / `keychain-access-groups` entitlement before releasing it.
- **Signing and entitlement requirements (verified on macOS 15):**
  - Requires `com.apple.application-identifier` (`<TEAM>.pw.deadbolt.app`), `com.apple.developer.team-identifier` (`<TEAM>`), and `keychain-access-groups` (`["<TEAM>.pw.deadbolt.app"]`) in the binary's code signature entitlements.
  - On macOS (Apple TN3137, *On Mac keychain APIs and implementations*), `com.apple.application-identifier` and `keychain-access-groups` are **restricted entitlements** that must be authorized by an embedded provisioning profile (`Contents/embedded.provisionprofile`).
  - Empirical verification on this fleet:
    1. **Ad-hoc signed without entitlements (`codesign -s -`):** `SecItemAdd` fails with `-34018` (`errSecMissingEntitlement: A required entitlement is not present`).
    2. **Ad-hoc signed with entitlements:** `amfid` kills the process at `execve` with `SIGKILL` (exit 137).
    3. **`Apple Development` or `Developer ID Application` signed without entitlements:** `SecItemAdd` fails with `-34018` (`errSecMissingEntitlement`).
    4. **`Apple Development` or `Developer ID Application` signed with entitlements, but no `Contents/embedded.provisionprofile`:** `amfid` kills the process at `execve` with `SIGKILL` (exit 137).
- **Process ownership problem (`Deadbolt.app` vs `Contents/Helpers/deadbolt`):**
  - `amfid` only validates `Contents/embedded.provisionprofile` for an `.app` bundle's main executable (`Contents/MacOS/Deadbolt`).
  - `Deadbolt.app/Contents/Helpers/deadbolt` is a bare Mach-O executable, not an `.app` bundle. Giving it restricted entitlements causes `amfid` to `SIGKILL` it unless `deadbolt` is repackaged inside its own nested `.app` bundle with its own `Info.plist` and `embedded.provisionprofile`.
  - Moving keychain ownership into `Deadbolt.app` instead of the agent would violate Deadbolt's architecture (`docs/app.md`: *"It holds no keys and reads no store files"*).
  - Local `cargo test` builds and ad-hoc `bundle.sh` builds cannot embed a provisioning profile and therefore cannot use the Data Protection Keychain.

### 2. Legacy file-based keychain (`login.keychain-db`) + `LAContext.evaluatePolicy` gate

Stores the wrapping key in the legacy macOS file keychain (`SecItemAdd` without `kSecUseDataProtectionKeychain` or `SecAccessControl`) and calls `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` in userspace before reading it.

- **Security:** Weak.
  - `LAContext.evaluatePolicy` only returns a `Bool` to userspace; the secret in `~/Library/Keychains/login.keychain-db` is encrypted under the user's login keychain key, which remains unlocked in `securityd` for the entire macOS login session.
  - The Secure Enclave never gates the key material itself. Any code path in the binary (or calling `SecItemCopyMatching` directly without `evaluatePolicy`) reads the plaintext secret with zero biometric interaction.
  - Enrolling a new fingerprint in System Settings does not invalidate the keychain item in hardware.

### 3. Secure Enclave key (`kSecAttrTokenIDSecureEnclave`) wrapping a store key

Generates a 256-bit P-256 private key inside the Secure Enclave (`com.apple.setoken`) with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `[.privateKeyUsage, .biometryCurrentSet]`, and uses ECDH + HKDF + AEAD to wrap a 256-bit store unlock key.

There are two ways to persist the Secure Enclave key handle on macOS:

- **3a. Keychain-stored token reference (`SecKeyCreateRandomKey` with `kSecAttrIsPermanent: true`):**
  `Security.framework` asks `secd` to store the Secure Enclave's key token blob in the Data Protection Keychain. This hits the exact same `-34018` (`errSecMissingEntitlement`) and `embedded.provisionprofile` requirement as Option 1.
- **3b. Store-held Secure Enclave token (`CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation`):**
  The Secure Enclave has no general-purpose NVRAM for user keys; even when `secd` is used, the Secure Enclave exports an opaque ~569-byte ASN.1 record (`toid` / `dataRepresentation`) containing the P-256 private scalar and its access-control policy (`aku;ock(true);...;bioc(<fingerprint-set-digest>)`), encrypted and authenticated under the Secure Enclave's hardware UID key.
  Apple's `CryptoKit` (`@available(macOS 10.15, *)`) exposes `SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation` as a public API so applications can store the hardware-sealed key blob in their own database without going through `secd`:
  - **Private key stays in hardware:** `extr = 0`; the private scalar can only ever be unwrapped inside this specific Mac's Secure Enclave.
  - **Biometric check is hardware-enforced:** calling `sharedSecretFromKeyAgreement` passes the sealed `dataRepresentation` and the `LAContext` to the Secure Enclave, which refuses to perform ECDH unless `coreauthd` supplies a live Touch ID token matching the `biometryCurrentSet` digest sealed into the blob.
  - **No entitlements or provisioning profile required:** works in ad-hoc `bundle.sh` builds, `cargo test`, `Contents/Helpers/deadbolt`, and Developer ID builds alike.

### Security trade-offs of Option 3b (explicit threat model)

1. **The gate is a physical finger tap, not Deadbolt's code identity:**
   Because `secd` is not in the path, there is no `keychain-access-groups` code-signature check before `coreauthd` raises a Touch ID dialog. Any process running as the same UNIX user (`uid`) that can read `~/.local/share/deadbolt/store.redb` (`0600`) can pass the `dataRepresentation` blob to `CryptoKit.SecureEnclave` (or invoke `deadbolt-enclave`) and raise a genuine-looking macOS Touch ID prompt on screen. It still cannot decrypt `"keyset.biometric"` without the user physically touching the sensor, and same-UID code running while Deadbolt is already unlocked can talk to the `0600` control socket directly.
2. **Copied `store.redb` blobs on the same Mac remain unlockable with a finger tap until fingerprints change:**
   The Secure Enclave does not maintain per-key revocation state in NVRAM. Removing `"keyset.biometric"` from the live `store.redb` (on passphrase change, Settings toggle-off, or the 14-day timer) prevents Deadbolt from offering Touch ID, and changing the passphrase re-wraps `"keyset"` under a new Argon2id salt, but `data_key` is unchanged. An attacker with local access to **this same Mac** who kept an earlier copy of `store.redb` containing `"biometric.token"` and `"keyset.biometric"` could still unlock that copy if they also obtain a live Touch ID tap from the user on this Mac before the enrolled fingerprint set changes. A copied `store.redb` moved to any other machine is useless because the `dataRepresentation` blob is sealed under this Mac's Secure Enclave UID key.

| Property | 1. Data Protection Keychain (`secd`) | 2. Legacy File Keychain + `LAContext` | 3b. Secure Enclave `dataRepresentation` in `store.redb` |
| --- | --- | --- | --- |
| Key gated in Secure Enclave hardware | Yes | **No** (userspace boolean only) | **Yes** (P-256 ECDH in SEP) |
| Invalidated in hardware when fingers change (`.biometryCurrentSet`) | Yes | **No** | **Yes** |
| Caller code-signature checked by `secd` before prompt | **Yes** | No | **No** (gate is a finger tap) |
| Works in `Contents/Helpers/deadbolt` without nested `.app` | **No** | Yes | **Yes** |
| Works in `cargo test` and ad-hoc `bundle.sh` builds | **No** (`-34018` or `SIGKILL`) | Prompts legacy ACL dialog | **Yes** |
| Needs `embedded.provisionprofile` + `keychain-access-groups` | **Yes** | No | **No** |

---

## How other password managers and tools do it on macOS

- **1Password 8** (verified from `/Applications/1Password.app/Contents/Frameworks/index.node` symbols and entitlements on this host, plus `support.1password.com/touch-id-apple-watch-security-mac/`):
  Imports `kSecAttrTokenIDSecureEnclave`, `SecKeyCreateRandomKey`, `SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData`, `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`, and `kSecAccessControlBiometryCurrentSet` inside `index.node`, which is loaded in-process by the main Electron executable (`1Password.app/Contents/MacOS/1Password`) covered by `1Password.app/Contents/embedded.provisionprofile` (`keychain-access-groups: ["2BUA8C4S2C.*"]`).
- **KeePassXC** (verified from `src/quickunlock/TouchID.mm` and `share/macosx/keepassxc.entitlements` in `keepassxreboot/keepassxc`):
  Generates a random AES-256-GCM key + IV, keeps the AES-encrypted database master key in process memory only (`m_encryptedMasterKeys`), and stores the AES key + IV in the Data Protection Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `kSecAccessControlBiometryCurrentSet`. Official builds embed `share/macosx/embedded.provisionprofile`; local unsigned builds cannot use Touch ID, and quitting the app clears the in-memory ciphertext.
- **Bitwarden Desktop** (verified from `apps/desktop/src/key-management/biometrics/os-biometrics-mac.service.ts` and `apps/desktop/desktop_native/core/src/password/macos.rs` in `bitwarden/clients`):
  Calls `systemPreferences.promptTouchID()` (`LAContext.evaluatePolicy`) in Electron and then reads the key from the legacy file-based login keychain via `security_framework::passwords::get_generic_password` (`Option 2` above).
- **`jdx/mise` (`src/enclave/macos.swift`, PR #14413):**
  Uses `CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey` with `dataRepresentation` stored on disk alongside the ephemeral P-256 public key and AES-GCM ciphertext (`Option 3b` above).

---

## Why `.biometryCurrentSet` only (no `.devicePasscode`)

- **Use `.biometryCurrentSet`, not `.biometryAny`:** enrolling a new fingerprint in macOS System Settings only requires the user's macOS login password. With `.biometryCurrentSet`, adding or removing a fingerprint changes the SEP's biometric database digest and immediately invalidates the Secure Enclave key in hardware.
- **Do not add `.or | .devicePasscode`:** allowing the macOS login password to satisfy the access control would reduce the vault's security to the user's macOS login password. Deadbolt's fallback is always the **vault passphrase**. We set `LAContext.localizedFallbackTitle = ""` so the macOS Touch ID sheet shows only **Cancel**.

---

## Chosen design

### 1. What is stored where

#### In `store.redb` (`crates/store`)

Two optional entries in the existing `header` table (`TableDefinition<&str, &[u8]>`), written and removed together in one two-phase-commit `redb` write transaction:

| Table | Key | Value |
| --- | --- | --- |
| `header` | `"biometric.token"` | Opaque platform token bytes (on macOS, the `deadbolt-enclave` sealed envelope) |
| `header` | `"keyset.biometric"` | `AEAD(biometric_key, data_key ‖ device_secret)` (104 bytes: 24-byte nonce + 64-byte keyset + 16-byte tag) |

- **`biometric_key`:** a fresh random 256-bit key (`Zeroizing<[u8; 32]>`, generated by `deadbolt_store::generate_biometric_key()`).
- **AAD for `"keyset.biometric"`:** `"deadbolt-store/v1/keyset.biometric" ‖ format_version (u32 LE) ‖ token_len (u64 LE) ‖ biometric.token`. Tampering with `"biometric.token"`, swapping it from another store, or flipping any byte in `"keyset.biometric"` fails AEAD verification with `Error::InvalidBiometric`.
- **Single-file invariant preserved:** `store.redb` remains the only file in the data directory. Existing stores without `"keyset.biometric"` require no format migration (`FORMAT_VERSION` stays `2`).

#### Inside `"biometric.token"` (the `deadbolt-enclave` binary envelope)

```text
magic           "DBSE" (4 bytes)
version         1 (u8)
flags           bit 0 = biometryCurrentSet (u8)
created_at      Unix seconds when enrolled (u64 LE, 8 bytes)
state_hash_len  length of LAContext.domainState.biometry.stateHash (u8, 32 bytes)
state_hash      biometry stateHash at enrollment (fallback evaluatedPolicyDomainState)
se_len          length of SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation (u16 LE)
se_blob         SEP-sealed P-256 private key (~569 bytes)
eph_pub         ephemeral P-256 public key, X9.63 uncompressed (65 bytes)
aes_gcm_box     AES-256-GCM(hkdf_key, nonce (12) ‖ ciphertext (32) ‖ tag (16)) (60 bytes)
```

- `hkdf_key` is derived from `ECDH(ephemeral, se_key)` via `HKDF-SHA256` with `salt = eph_pub` and `info = "deadbolt-enclave/v1" ‖ se_key.publicKey.x963Representation`.
- `aes_gcm_box` seals the 32-byte `biometric_key` and authenticates the length-prefixed tuple `("deadbolt-enclave/v1/aad", len(state_hash) ‖ state_hash, len(se_blob) ‖ se_blob, len(eph_pub) ‖ eph_pub, len(header) ‖ header)` as AES-GCM AAD.

#### In `config.toml` (`crates/cli/src/config.rs`)

```toml
# Unlock with Touch ID on macOS after unlocking once with your passphrase
# (default false).
touch_id = true
```

### 2. Helper authentication and packaging

- `crates/cli/build.rs` compiles `crates/cli/src/agent/enclave.swift` into `deadbolt-enclave` with `CFBundleIdentifier = "pw.deadbolt.app.enclave"` (`crates/cli/src/agent/enclave-Info.plist`), strips it, signs it (with `--options runtime --timestamp --sign "$DEADBOLT_APPLE_SIGNING_IDENTITY"` when `DEADBOLT_APPLE_SIGNING_IDENTITY` is set, or ad-hoc `-` otherwise) **before** hashing, copies it into Cargo's profile directory (`target/<triple?>/<profile>/deadbolt-enclave`), and stamps its whole-file SHA-256 digest into `deadbolt` via `DEADBOLT_ENCLAVE_SHA256`.
- If `swiftc` is unavailable on a macOS build host, `build.rs` emits a `cargo:warning` and sets `DEADBOLT_ENCLAVE_SHA256=""` so the build succeeds with Touch ID disabled.
- **Release builds sign the helper first, then build against it** (`.github/workflows/release.yml`, [releasing.md](releasing.md)). The pin covers the helper's code signature, so the Developer ID signature must exist before `deadbolt` is compiled, and the signing job must never compile repository code. The release splits it into four jobs: `build-enclave` (no secrets) compiles both architectures with `crates/cli/scripts/build-enclave.sh`; `sign-enclave` (the `release` environment, only `.github/release/` checked out) signs each thin helper with the Developer ID (`--options runtime --timestamp --identifier pw.deadbolt.app.enclave`) and changes nothing else; `build-macos` (no secrets) builds `deadbolt` with `DEADBOLT_ENCLAVE_PREBUILT=<dir>`, so `build.rs` takes `<dir>/<arch>/deadbolt-enclave` as is (it must be a thin Mach-O of the target architecture; any failure is a build error, never a Touch-ID-less build) and pins those signed bytes; `sign-macos` signs `deadbolt` and the app around the helper and checks the helper's bytes are unchanged. `verify-macos` then checks that each architecture slice's SHA-256 is the digest compiled into `deadbolt`.
- This keeps the exact-bytes pin for every build, local and released. A code-signing-requirement pin (Developer ID team + identifier, checked through `SecStaticCode`) was rejected: it would accept any helper the team ever signs with that identifier, including older releases' helpers and anything signed with a stolen or misused Developer ID certificate, and checking it from Rust needs `unsafe` FFI or a new dependency. The exact-bytes pin is unaffected by the certificate: a compromised Developer ID certificate cannot produce a helper that already-shipped `deadbolt` binaries accept.
- `crates/app/scripts/bundle.sh` reuses the `deadbolt-enclave` binary staged by `build.rs` (copying it into `Deadbolt.app/Contents/Helpers/deadbolt-enclave`, or `lipo -create`ing the two signed architecture slices for `--universal`) and **never re-signs `deadbolt-enclave`**, because re-signing after `deadbolt` was compiled would change its `__LINKEDIT` code-signature bytes and invalidate `DEADBOLT_ENCLAVE_SHA256`.
- `crates/app/build.rs` pins the same helper into the desktop app (the prebuilt one with `DEADBOLT_ENCLAVE_PREBUILT`, else the one staged above), and the app verifies the `deadbolt-enclave` beside its agent the same way before it uses it to check the agent's code signature.
- At runtime (`cfg(not(test))`), the agent only looks for `deadbolt-enclave` next to its own executable (`Deadbolt.app/Contents/Helpers/deadbolt-enclave`, or beside a tarball or Homebrew `deadbolt`) and verifies that its SHA-256 (or, for a valid `{arm64, x86_64}` universal binary, the current architecture's slice SHA-256) matches `DEADBOLT_ENCLAVE_SHA256` before spawning it. Verification or status probe failures are cached as unavailable for 2 s and logged with `warn!` at most once until a subsequent probe succeeds.

### 3. When the slot is written and wiped

| Event | What happens to `"keyset.biometric"` in `store.redb` |
| --- | --- |
| **Opt-in while unlocked** (`Command::TouchIdSet { enabled: true }` or `deadbolt touchid on`) | Enrolls a fresh Secure Enclave key and writes `"biometric.token"` + `"keyset.biometric"` into `store.redb` (no finger prompt needed to generate the key and encrypt to its public key), then writes `touch_id = true` to `config.toml`. |
| **Passphrase unlock while `touch_id = true`** | Rotates the Secure Enclave key and `biometric_key`, refreshing `created_at` and `state_hash`. |
| **Normal lock** (`deadbolt lock`, ⌘L, idle timeout, sleep, screen lock, agent restart, Mac reboot) | **Kept** on disk. `Session` and `Unlocked` are dropped and zeroized in RAM; the next unlock can use Touch ID. |
| **14 days since last passphrase unlock** (`now < created_at` or `now - created_at > 14d`) | **Wiped**. A "don't forget your passphrase" rule enforced against wall-clock `SystemTime` (`created_at <= now <= created_at + 14d`): requires entering the passphrase at least once every 14 days (and if the system clock moves backward past `created_at`), which automatically re-enrolls Touch ID. |
| **Fingerprint added or removed in System Settings** (`stateHash` mismatch) | `deadbolt-enclave` compares `LAContext.domainState.biometry.stateHash` (fallback `evaluatedPolicyDomainState`) against the `state_hash` recorded at enrollment. On mismatch, exits with code `12` (`invalidated`), and the agent **wipes** the slot and sets `touch_id_reset = true` so the UI explains *"Touch ID was reset; enter your passphrase"*. Upgrading across macOS 14 → macOS 15 transitions the fallback `evaluatedPolicyDomainState` to `domainState.biometry.stateHash`, causing a one-time slot reset on the first unlock after the OS upgrade. |
| **Passphrase changed** (`Unlocked::change_passphrase_with_params` with `old != new`) | **Wiped atomically** in the same `redb` write transaction that rewrites `"keyset"`. |
| **Settings toggle off** (`Command::TouchIdSet { enabled: false }` or `deadbolt touchid off`) | **Wiped** immediately from `store.redb` (works whether the store is currently unlocked or locked) and sets `touch_id = false` in `config.toml`. |
| **This device removed from all its vaults** | **Wiped** when the agent's vault list is non-empty and this device is no longer a member of any vault in `session.vaults`. |
| **User cancels prompt, lid closed, lockout, failed finger tap, or unknown error** | **Kept** on disk (`exit 10` / `exit 11` / `exit 14`). Never wipes enrollment. |

### 4. Protocol, CLI, and App UI

- **Protocol (`crates/client/src/protocol.rs`, since protocol version 5):**
  - `Command::UnlockBiometric { timeout_secs: Option<u64> }`
  - `Command::TouchIdSet { enabled: bool }`
  - `Status` adds:
    - `touch_id_available: bool` (cached with a 60 s TTL when available and 2 s when unavailable or on probe error, warmed at agent startup and refreshed in the background via `spawn_blocking` when stale, as well as on passphrase unlock and `TouchIdSet`, so `status()` never blocks on a subprocess and waking from clamshell mode or reconnecting a Magic Keyboard with Touch ID recovers without restarting the agent)
    - `touch_id_enabled: bool` (`touch_id = true` in `config.toml` and `touch_id_available`)
    - `touch_id_ready: bool` (`touch_id_enabled` and a valid non-expired token is in `store.redb`, tracked in agent memory so `status()` never opens `store.redb`)
    - `touch_id_reset: bool` (true when `touch_id_enabled` is true on an initialized store that previously had a biometric slot enrolled whose slot has since expired or been invalidated/wiped, so the UI shows *"Touch ID was reset; enter your passphrase"* rather than the first-time *"Enter your passphrase once to finish turning on Touch ID"*)
- **Concurrency, timeout, and cancellation (`crates/cli/src/agent`):**
  - Interactive `unseal` runs outside `Agent::transition` with `store.redb` closed and a 60 s deadline (`PROMPT_TIMEOUT`).
  - Concurrent `UnlockBiometric` requests coalesce onto the single in-flight prompt, and the in-flight entry is cleared before broadcasting the outcome to waiters.
  - A passphrase `Unlock` (once the passphrase has opened the store; a wrong one leaves the prompt up), `Lock`, `TouchIdSet`, `Stop`, or `Agent` drop cancels any in-flight Touch ID prompt immediately, killing and reaping `deadbolt-enclave` to dismiss the macOS sheet.
  - While unlocked, `Unlock` and `UnlockBiometric` set a shorter idle timeout at once; a longer one, or never, only with the right passphrase or after a Touch ID prompt succeeds. A request joining another's prompt may only shorten the timeout that request set.
  - After a user-cancelled prompt, a 2 s cooldown prevents rapid window-focus or summon events from immediately re-prompting; programmatic cancellations do not arm the cooldown.
- **CLI (`crates/cli`):**
  - `deadbolt touchid on` / `deadbolt touchid off` / `deadbolt touchid status`.
  - Interactive `deadbolt unlock` (and automatic unlock on interactive commands) tries `Command::UnlockBiometric` first when `status.touch_id_ready` is true, stdin is a TTY, `SSH_CONNECTION` is not set, and neither `DEADBOLT_PASSPHRASE` nor `--passphrase-stdin` was given; on cancel or unavailability, falls back cleanly to the terminal passphrase prompt (printing the error reason on non-cancel failures).
- **App (`crates/app`):**
  - **Auto-prompt rule:** The app auto-triggers `Job::UnlockBiometric` when it launches (and is focused) into a locked store with `touch_id_ready = true`, when the quick panel is summoned while locked, or when the locked main window gains focus after a background lock event (such as locking while another app was active or after sleep/screen-lock unfocused the window). If the store locks while the main window remains focused (e.g. clicking Lock / `⌘L`, or an idle timeout while Deadbolt is still the frontmost focused window), it stays at rest until the user clicks **Touch ID**, presses `⏎` on an empty passphrase field, or switches away and focuses Deadbolt again.
  - **Lock screen:** Shows a **Touch ID** button beside **Unlock** when `touch_id_ready` is true, keeps the passphrase field focused as an always-ready fallback, shows *"Touch ID was reset; enter your passphrase"* when `touch_id_reset` is true, and shows *"Enter your passphrase once to finish turning on Touch ID"* when Touch ID is enabled in `config.toml` before a slot has ever been enrolled.
  - **Quick panel:** When locked with `touch_id_ready`, offers Touch ID (`⏎ Touch ID` when the passphrase field is empty, or auto-prompts on summon) alongside the passphrase field; when Touch ID succeeds it reclaims key focus on the panel and re-arms dismiss-on-blur, and if the panel lost focus while the Touch ID sheet was up and is still unfocused when a cancelled/failed reply lands, it dismisses itself.
  - **Settings popover:** Shows an **Unlock with Touch ID** toggle row when `touch_id_available` is true.
