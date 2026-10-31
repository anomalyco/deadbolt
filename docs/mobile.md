# Mobile devices (experimental)

Security review needed. This proof is not ready for real vaults or distribution.
Use synthetic credentials only. Platform builds and verification results must be
recorded below before treating a feature as working.

### Build status and temporary networking limitation

The Android debug app builds and launches. The Rust iOS simulator target now
builds and passes its five core tests plus real public-network pairing, sync,
foreground notification and restart. The current pinned native iOS build has
also paired and displayed 1,000 synthetic logins; remaining native flows are
separate gates.
The initial iOS dependency failure was reproduced with:

```sh
cargo check -p deadbolt-mobile-core --target aarch64-apple-ios-sim --locked
```

Before the dependency fixes this failed with E0425 at
`netdev-0.46.3/src/os/darwin/ipv6_addr_flags.rs:19`:
`libc::in6_ifreq` is not defined for iOS. The dependency chain is
`deadbolt-mobile-core → deadbolt-net → iroh 1.3.0 → netwatch 0.19.3 → netdev
0.46.3` (also through portmapper). `libc 0.2.190` exposes this type only with
`target_os = "macos"`. netdev 0.47.0 fixes this by gating the entire module on
macOS, but netwatch 0.19.3 requires netdev `^0.46.1`, and iroh 1.3.0 requires
netwatch `^0.19.3`. The compatible minimum 0.46.1 has the same failure; a routine
patch-version update cannot select the fixed 0.47 series. Published iroh 1.4.1
still selects netwatch 0.19.3; netwatch 0.20.0 also requires netdev 0.46.3.
Ryan approved a reproducible upstream fix. The workspace now pins netdev to
upstream commit `b3bfb0fb5595cd143bfa0b9f07d1ad6e0ef0c313`, which still declares
0.46.3 and corrects iOS IPv6 flags, SystemConfiguration and resolver API use.
It includes intervening upstream Illumos support; it is not a one-line local
registry edit. The patch is commented in `Cargo.toml`, locked and explicitly
allowed in `deny.toml`.

Fixing netdev exposed the next dependency, netwatch 0.19.3, which failed with
22 errors because it selects macOS/BSD routing constants on iOS. Current
netwatch 0.20.0 has the same selection; see
[upstream issue #261](https://github.com/n0-computer/net-tools/issues/261).
Ryan authorized two stages: first an iOS-only temporary no-change monitor with
explicit reconnect on foreground/manual sync, then a real public
Network.framework monitor prepared for upstream review. The stub is pinned to
`anomalyco/net-tools` commit `afcef9f16519ef065ae62f7b199926b0b3d5f80e`
(`ios-stub`). All five target graphs resolve that fork because Cargo patches
are global; Ryan explicitly accepted this provenance with byte-identical
non-iOS backend code, which was verified. A real public Network.framework
implementation is prepared separately at `anomalyco/net-tools`
`e7bcd4b61d5d989a39ca450872259e5dbb2adbcb` (`ios-network-framework`, netwatch
0.20.0); independent review and a compatible 0.19.3 backport precede adoption.
Its upstream PR requires Ryan's approval before posting. Earlier simulator media
came from a scratch build with libc 0.2.189 and are labeled experimental, not
proof that this checkout builds.

With the temporary monitor, a network switch while the app remains in the
foreground will not trigger reconnection until the next foreground transition
or manual **Sync now**. macOS, Linux, Android and wasm must retain upstream
monitor behavior. The stub and explicit foreground workaround should be removed
when the real monitor is adopted; record the exact source revisions and
per-target dependency graphs with that change.

`cargo tree --locked --target <target> -i netwatch` was checked for
`aarch64-apple-ios-sim`, `aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-linux-android` and
`wasm32-unknown-unknown`. Each resolves netwatch 0.19.3 at the pinned fork through
iroh 1.3.0 (directly and through portmapper 0.19.3). Only iOS changes backend:
it uses real netdev interface snapshots and the existing no-event monitor;
macOS/BSD, Linux, Android and browser monitors retain their upstream code.

The computer-side synthetic CLI fixture initially refused initialization/import from
OpenCode with its existing “an AI agent can't set Deadbolt up” policy. That guard
has not been changed. Ryan subsequently approved a test-only Rust fixture to
seed an isolated synthetic store for the normal CLI to use. The Rust mobile-core tests exercise real pairing against
a synthetic Rust peer; this is not a claim that a phone has paired with the CLI.
The authorized fixture creates separate 1k and 10k synthetic CLI stores.
Android's 1k run passed native pairing, passphrase/fingerprint unlock,
list/search, TOTP rollover, sensitive copy, sync/background lock and a fresh
biometric approval followed by a signed denial. Android has also paired the
10k fixture, and iOS has paired and displayed its separate 1k fixture. Remaining
flows, performance measurements and physical iOS biometrics are separate gates.
The stock CLI also correctly refuses AI-driven unlock. An ignored Mac test host
therefore uses test-only synthetic unlock/designation and production pairing
and approval code. Its real-phone evidence must be labeled as a test-host proof,
not proof of a human unlocking or designating through the stock CLI.

The offline Rust credential-provider implementation passes host and simulator
tests; shared Swift/iOS extension integration is in progress. This does not yet
establish an end-to-end OS AutoFill ceremony or an acceptable extension memory
footprint. Android's approval proof is complete for its synthetic 1k fixture;
iOS fresh-biometric approval still requires a signed physical-device build.

## Model

The iOS and Android applications are independent Deadbolt devices, not clients of
the Mac agent. Each owns an Ed25519 device key and encrypted redb store, has its
own local passphrase, and joins the existing vault through pairing v3. The phone
shows the five-word code; an unlocked member runs `deadbolt pair <code>`. Device
admission is the existing signed consent/membership protocol, not a mobile API.

`crates/mobile-core` is the native composition root exposed through UniFFI.
SwiftUI and Jetpack Compose handle presentation, lifecycle, clipboard and native
biometric cryptography. Rust owns vault rules, secret selection, TOTP, persistence,
membership and networking. `deadbolt-net::application` remains the shared sync
and pairing application protocol. There is no native-host fallback and no
mobile-specific copy of the signed-log or sync rules.

Sync runs while the app is open, with a manual Sync now action. Backgrounding or
idle lock must drop decrypted state, stop networking and cancel pending work;
timer-driven TOTP refresh and sync are not user activity. A failed durable append
must quarantine the live session until authenticated reopening, as on the other
devices. A delayed unlock/sync result must not reopen a backgrounded app.

## Local unlock

The normal slot uses the existing store's Argon2id passphrase wrapping. The
optional second slot is the existing authenticated biometric key-set slot; the
platform must cryptographically protect its wrapping key, not merely return a
successful `LAContext` or `BiometricPrompt` boolean.

- iOS: Secure Enclave P-256 key agreement, gated by `biometryCurrentSet` and
  `privateKeyUsage`, with a device-only sealed envelope as in
  [Touch ID](touch-id.md). No device-passcode alternative; the fallback is the
  local vault passphrase. The app and provider must be able to use the same slot.
- Android: a non-exportable Android Keystore key with
  `setUserAuthenticationRequired(true)` and per-operation `BIOMETRIC_STRONG`
  authorization, used by `BiometricPrompt.CryptoObject` to unwrap the slot key.
  New enrollment invalidates the key. Keystore support alone does not prove the
  device has hardware-backed storage; physical-device verification is separate.

The iOS Simulator has no Secure Enclave. Simulator biometric events can exercise
presentation and cancellation, but cannot establish hardware-bound key security.
No simulator substitute may silently become the production key path.

## Native presentation

Both apps, including the iOS provider, use Rune's light/dark visual language,
not a separate platform palette. The source is the pinned
`rune-theme-opencode` theme and `extension/static/theme.css`; each platform owns
one theme naming the source revision. Preserve Inter and IBM Plex Mono,
surfaces/elevation, borders, radii, spacing, selected rows, controls and motion.
Native navigation, gestures, safe areas, scalable text and OS biometric sheets
remain native. Follow the system appearance.

Target cold-launch-to-unlock UI below 1 second and warm search below 100 ms on
the named simulator/emulator, with 1k and 10k synthetic items. Unlock/list timing
must report passphrase derivation and biometric interaction separately; an
unmeasured target is not a performance claim. Never wait for sync to render
local items. Quiet status text handles offline/recoverable sync failure, and
failed biometrics return to the passphrase field without an error dialog.
Rank matching AutoFill sites and recent use first; return nothing rather than a
wrong-domain suggestion. Approval wording names the actual requester and exact
requested access. Internal protocol/storage terms do not belong in the UI.

Required visual evidence is a side-by-side of the real desktop still, real
extension popup, iOS Simulator and Android emulator in both appearances. The
first light-mode comparison is published in `mobile/11-native-light-comparison`
under the temporary media root below; dark-mode evidence remains pending. No
mockups stand in for those builds.

| Measurement | iOS Simulator | Android emulator |
| --- | --- | --- |
| Cold launch to unlock UI | Not measured on current pinned build | 1k: 846 / 914 / 948 ms to fingerprint prompt |
| Unlock to list, passphrase | Not measured | 1k: approximately 3 s after submit (recording) |
| Unlock to list, biometric (excluding user wait) | Not measured | 1k: approximately 0.7 s after emulator fingerprint touch |
| Search, 1k / 10k items | Not measured | 1k: 9–34 ms nonempty core queries, 22–84 ms clearing; 10k pending |

Android's current search UI adds a 150 ms typing debounce before the core call.
The core measurements therefore do **not** establish the below-100 ms
user-visible search target. All Android numbers above are debug/emulator
measurements, not physical-device or release-build results.

On the dedicated headless `Deadbolt_API_36` emulator, the debug Android build's
first-launch setup Activity was shown after **2,424 ms**, with first core status
at **1,902 ms**. A second launch was **755 ms / 721 ms** respectively. These are
Activity/status markers, not proof of an unlock prompt or populated list. The
first launch misses the 1-second target; the Rust debug library is unoptimized.
Three later cold setup launches measured **917 / 1,631 / 1,582 ms** to Activity
display and **656 / 1,382 / 1,325 ms** to first core status; two missed the target.

## Apple identifiers and signing

Use Anomaly team **5NZ4Q7NXJ4**, never Ryan's personal signing identities. The
registered App IDs are Universal (shared with macOS), not `pw.deadbolt.ios`.

| Target | Bundle ID | Registered capabilities |
| --- | --- | --- |
| iOS app (Deadbolt, NTN63H4P4C) | `pw.deadbolt.app` | AutoFill Credential Provider, App Groups, Associated Domains |
| iOS provider (Deadbolt AutoFill, 5X8R3V97VL) | `pw.deadbolt.app.autofill` | AutoFill Credential Provider, App Groups |
| Future Safari extension (not in this proof) | `pw.deadbolt.app.safari` | App Groups |

Both iOS targets need:

```xml
<key>com.apple.security.application-groups</key>
<array><string>group.pw.deadbolt</string></array>
<key>keychain-access-groups</key>
<array><string>$(AppIdentifierPrefix)pw.deadbolt.app</string></array>
```

`group.pw.deadbolt` is the registered App Group (QFD72527KV), assigned to all
three App IDs. The build expands `$(AppIdentifierPrefix)` from its profile; do
not leave that literal in a signed entitlements plist. The iOS provider also
needs:

```xml
<key>com.apple.developer.authentication-services.autofill-credential-provider</key>
<true/>
```

Use `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`, not a
constructed container path. Shared Swift code must retain the existing macOS
`5NZ4Q7NXJ4.pw.deadbolt` group and select `group.pw.deadbolt` on iOS. The existing
macOS Developer ID profiles authorize the team-prefixed group via
`5NZ4Q7NXJ4.*`; changing macOS's group would strand its socket/identity state.
Face ID usage needs `NSFaceIDUsageDescription` in each target that authenticates.
Registering Associated Domains does not authorize inventing `webcredentials:`
domains or bypassing OS-supplied service identifiers.

As of this proof's setup, only macOS Developer ID profiles exist under
`/Users/vogel/Documents/Deadbolt/apple/`; **no iOS provisioning profiles and no
Anomaly-team signing identity are installed on this Mac**. Simulator builds use
ad-hoc signing and the intended entitlements. This is not a device-signing test.

Device/TestFlight distribution requires:

1. Apple Development and Apple Distribution certificates with their private keys
   for team 5NZ4Q7NXJ4 installed on the signing machine.
2. iOS Development profiles for **both** bundle IDs, including test-device UDIDs,
   App Group, shared Keychain group and the provider entitlement.
3. App Store distribution profiles for both bundle IDs with matching
   entitlements; the app embeds the separately signed provider.
4. An App Store Connect app record for `pw.deadbolt.app` and TestFlight setup.

## iOS AutoFill, in scope

Reuse `crates/app/autofill/{CredentialProviderViewController,IdentitySync,
AutoFillView,ControllerModel,Protocol}.swift` in one source tree. Platform view
and lifecycle differences belong behind `#if os(iOS)`, not in copied files.
`SocketClient.swift` and `PeerCheck.swift` remain macOS-only. The iOS client calls
the Rust mobile core in-process, against the App Group store, with no agent
process and no network needed to fill.

The provider must share Rust service-identifier resolution, domain matching,
TOTP generation and WebAuthn signing/registration policy with the macOS agent.
OS-provided service identifiers are authority; identity-store entries are only
hints and must be rechecked against the current item. The app publishes only
non-secret domain/account/record metadata to `ASCredentialIdentityStore` for
QuickType. Never publish passwords, OTP seeds or private passkey keys there.

Passwords, interactive list selection, OTP on iOS 18+, and passkey registration
and assertion are required. Apple documents
[`ASOneTimeCodeCredential`](https://developer.apple.com/documentation/authenticationservices/asonetimecodecredential)
and
[`prepareOneTimeCodeCredentialList(for:)`](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller/prepareonetimecodecredentiallist(for:))
on iOS 18+. The existing macOS Swift provider currently presents passwords only;
its Rust backend already supports OTP and passkey commands. Adding iOS must not
silently change macOS's advertised capabilities or behavior.

### Memory and concurrent access

Budget for the credential-provider extension's commonly observed **120 MB**
memory ceiling, with substantial headroom. This is an observed limit, not a
stable Apple API guarantee; OS/device resource pressure can terminate it sooner.
The Simulator does not establish the device's jetsam threshold. See
[KeePassium's AutoFill memory discussion](https://keepassium.com/articles/autofill-memory-limits/)
and [Bitwarden's large-vault identity-sync fix](https://github.com/bitwarden/ios/pull/2046).

Replaying the full signed log, retaining every historical file version, running
Argon2id and replacing every system identity inside each fill can exceed this
budget. Do not reduce the vault's passphrase KDF to make an extension fit.
Measure the existing authoritative replay path before introducing a new cache
format. Biometric unwrap avoids Argon2 but not replay. Any future projection
must remain an authenticated cache of accepted log state, not a second vault
authority; a cache alone cannot authorize a new signed registration entry.
Passkey writes must commit to the signed log before returning a credential.

The initial provider should own its offline store only for its current request,
closing it on completion/cancellation. App background lock relinquishes the
app's handle. redb's exclusive file lock remains authoritative: concurrent use
must return a quiet recoverable busy result, never disable locking or copy a
live database. Multiwindow contention and release/reopen behavior need explicit
verification. If measured replay exceeds the extension budget, that is a failed
gate requiring a storage design change, not permission to weaken authentication.

Required measurements, not yet established:

| Synthetic vault | App peak | Provider peak (password / OTP / passkey) | Device jetsam check |
| --- | --- | --- | --- |
| 1,000 items | Not measured | Not measured | Requires signed physical device |
| 10,000 items | Not measured | Not measured | Requires signed physical device |

Initial offline Rust provider benchmarks (debug, production KDF) measured
simulator list/fill at 236/207 ms for 1k and 819/581 ms for 10k. Isolated
provider-only processes then measured simulator peak physical footprint at
74.6 MiB for either 1k operation, **126.7 MiB for the 10k picker**, and 94.0 MiB
for the 10k selected fill. The picker exceeds the stated budget before native
extension overhead: this gate fails, rather than being excused as test setup.

Fixtures were created in separate processes. An external 2 ms sampler used
`proc_pid_rusage(RUSAGE_INFO_V4)` and acknowledged phase checkpoints. Replay
peaked around 94 MiB; picker materialization raised that to 127 MiB. Closing the
store and dropping the response returned footprint to about 11 MiB. RSS retains
reusable allocator pages and is not the same as physical footprint. Streaming
picker materialization alone did not lower the simulator peak (128.4 MiB).
Moving the existing metadata arrays into the JSON response, instead of cloning
them, lowered the final 10k picker peak to **116.4 MiB (122.03 MB)**. That still
exceeds a literal 120 MB ceiling and provides no useful headroom even against
120 MiB. The memory gate remains failed. No projection or weaker KDF has been
introduced; the actual native extension must be measured before another storage
design is selected.
These are debug simulator processes without Swift/OS extension overhead or
substantial edit history; physical-device certification remains outstanding.

Measure cold launch, biometric unwrap, list/search, selected fill, identity
publication and passkey commit separately; record OS/runtime, process footprint,
sampling method and whether history/attachments are present. Item count alone
does not bound memory when history is unbounded.

## Experimental cross-device approval

Follow [proposal PR #154](https://github.com/anomalyco/deadbolt/pull/154), not an
unsigned UI message. Requests and responses are ephemeral over member-authenticated
iroh, separate from the vault log. The origin signs verified caller, origin,
exact requested item/field/action, nonce and expiry. The designated approver is
explicitly allowed, not every newly admitted device. The phone displays the
signed request, performs fresh biometric key use, and signs the decision bound
to that request's hash. The origin rechecks current membership, expiry and the
outstanding request; first valid answer wins, and authorization is consumed for
that one resolve. Never approve from a click or a reusable unlocked-state flag.
Default CLI policy remains unchanged unless the experimental path is enabled.

## Verification and remaining work

Build evidence and recordings belong under
`/private/var/folders/2j/6mslx1715gx8frsyn66sf1sh0000gn/T/opencode/mobile/`, not in Git.
Run iOS Simulator headlessly with `simctl`; never open Simulator.app. Run Android
emulators with `-no-window -no-audio`. Use a dedicated synthetic CLI store and
relay connectivity, not `DEADBOLT_NET=local` for a phone pairing claim.

Required gates: Rust tests and `bun run check`; iOS `xcodebuild test`; Android
unit tests; real pairing/passphrase/biometric/list/copy/TOTP/approval traces on
both platforms; iOS provider enablement and password/OTP/passkey fills; the
existing macOS Rust and Swift AutoFill tests; 1k/10k provider memory measurements.
Unrun gates are not passing gates.

PR #194 is a draft. Existing GitHub CI covers workspace Rust and browser checks,
not Xcode or Gradle: mobile build, native tests and OS-flow evidence are local
checks. A green CI result must not be described as a complete mobile proof.
Physical iOS Secure Enclave unlock, fresh-biometric approval and device jetsam
validation are blocked on Anomaly signing/provisioning and a test device, not
waived by simulator tests. These gates keep the proof incomplete.

Completed checks during development (not a substitute for the final combined
workspace/platform runs):

- `bun run check:extension`: TypeScript check, 563 tests (2,863 assertions),
  and the native extension build passed.
- Existing headless Linux `extension/e2e/run.ts --only fillAndTotp` on exos:
  login fill, OTP fill, origin/field scope and popup checks passed in both light
  and dark; real popup stills saved as the design reference.
- Shared credential-provider extraction: existing CLI `macos_autofill` tests
  passed before and after (6 each), broader `autofill` tests passed (17), core
  tests passed (145, 1 ignored, including five policy regressions), core/CLI
  Clippy passed. These were isolated from concurrently changing mobile code.
- macOS provider baseline: Swift 6 unit/wire/cancellation/offscreen checks passed;
  `cargo test -p deadbolt-app --test app autofill:: --locked` passed both the
  bundle validation and real-agent Swift end-to-end test.
- Android native tests after review and runtime fixes: 41 passed. Actual 1k
  pairing and approval test-host runs passed, with seven captioned media batches.
- iOS lifecycle tests: 11 passed in the simulator using the built XCTest bundle
  directly, compiling the real AppModel against a delayed test core. The usual
  Instruments-driven test launch failed to connect; this is not a full real-core
  app test. Tests cover background/join/unlock/status races and foreground work.
- Full app integration baseline: 208 passed, 21 failed. Nineteen failures are at
  the CLI `init` fixture step and two are setup timeouts; AI-caller setup refusal
  is a known restriction in this environment. This is not a green app-suite
  result, and production caller guards were not relaxed to make it pass.
- `crates/app/scripts/snap.sh` before and after Rune `1b787190 → 3062e9b8`:
  all 174 headless PNGs are byte-identical. Theme tokens and font assets are
  unchanged by that update.

Follow-up PRs after the requested proof:

- Android Autofill service and OS credential-provider/passkey integration.
- Android passkey provider (iOS provider passkeys are part of this effort).
- Push wake-ups: APNs/FCM carries only a wake hint, never caller/item/request
  contents. Reconnect to the origin over authenticated iroh to fetch a live,
  unexpired request; an offline origin means the request is gone. No durable
  mailbox or background secret release is introduced by a wake hint.
- TestFlight and Play distribution after signing and required physical-device
  biometric, extension-memory and lifecycle validation have passed.
