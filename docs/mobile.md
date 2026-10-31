# Mobile devices (experimental)

Security review needed. This proof is not ready for real vaults or distribution.
Use synthetic credentials only. Platform builds and verification results must be
recorded below before treating a feature as working.

### Build status and iOS networking

The workspace pins netwatch 0.19.3 to `anomalyco/net-tools`
`7c337433a67d6e93e88ac2037da18645e2a4019b`. Its iOS backend uses Apple's public
Network.framework path monitor and `getifaddrs`, not macOS routing constants.
It feeds the existing debounce/rescan actor, owns cancellation through the last
native callback, and bounds the initial path wait to one second. A timeout
returns interface addresses without inventing a default route; later callbacks
still work. A satisfied path may report no gateway.

This replaces the authorized temporary no-event monitor at `afcef9f16519ef065ae62f7b199926b0b3d5f80e`
and removes its forced network-change notifications on foreground/manual sync.
Normal unlocked vault sync on foreground remains. The separate netdev git patch
at `b3bfb0fb5595cd143bfa0b9f07d1ad6e0ef0c313` is no longer needed and was removed.
Registry libc remains 0.2.190. The original failures were missing iOS
`libc::in6_ifreq`, then 22 BSD-routing errors; see
[upstream issue #261](https://github.com/n0-computer/net-tools/issues/261).

Locked dependency trees were checked for iOS device/simulator, macOS, Linux,
Android, wasm and Windows. Every target resolves the exact netwatch fork through
iroh 1.3.0/portmapper 0.19.3. iOS and wasm have no netdev dependency; macOS,
Linux and Android use registry netdev 0.46.3, Windows 0.45.1. Cargo's source
override remains global. Existing non-iOS monitor behavior is preserved; shared
address classification was mechanically extracted and independently reviewed,
so the real implementation is not described as byte-identical source.

The final pin passed five host and five simulator mobile-core tests, a rebuilt
simulator's real public-network pairing/sync/foreground/restart test, Android
library build, wasm extension-core check, host/iOS Clippy and source allowlist.
Native app recordings made with the stub remain labeled with that older pin;
earliest iOS recordings used an explicitly labeled scratch libc 0.2.189 build.
Neither establishes native runtime proof of the final monitor build.

The upstream 0.20 implementation is prepared on `ios-network-framework` at
`93f76dcebac4e2a07e22bc213b5aef53583614f0`; no upstream PR has been posted.
Ryan [offered the branch in #261](https://github.com/n0-computer/net-tools/issues/261#issuecomment-6547184339).
Upstream's AI policy requires
agreement on the approach there first; do not open a PR unless the maintainers
ask for one in the issue.
Physical Wi-Fi/cellular handoff and suspension/resumption are untested. Path
notifications are not a promise of every same-interface address-change event;
these limits are documented in the fork rather than hidden behind the old stub.

The computer-side synthetic CLI fixture initially refused initialization/import from
OpenCode with its existing “an AI agent can't set Deadbolt up” policy. That guard
has not been changed. Ryan subsequently approved a test-only Rust fixture to
seed an isolated synthetic store for the normal CLI to use. The Rust mobile-core tests exercise real pairing against
a synthetic Rust peer; this is not a claim that a phone has paired with the CLI.
The authorized fixture creates separate 1k and 10k synthetic CLI stores.
Android's 1k run passed native pairing, passphrase/fingerprint unlock,
list/search, TOTP rollover, sensitive copy, sync/background lock and a fresh
biometric approval followed by a signed denial. Android has also paired the
10k fixture, and iOS has independently paired its 1k and 10k fixtures. Remaining
OS flows and performance gates are tracked below; physical iOS biometrics are
deferred.
The stock CLI also correctly refuses AI-driven unlock. An ignored Mac test host
therefore uses test-only synthetic unlock/designation and production pairing
and approval code. Its real-phone evidence must be labeled as a test-host proof,
not proof of a human unlocking or designating through the stock CLI.

The offline Rust provider and shared Swift/iOS integration are implemented and
reviewed. Actual OS password and OTP fills pass on iOS 26.5, and fresh non-UV
passkey registration passed independent relying-party verification. The OS
assertion request required biometric verification despite the page requesting
`discouraged`; its signature remains deferred to a physical iPhone. Observed
Release memory is below 120 MB, but with limited rather than substantial headroom.
Android's approval proof is complete for its synthetic 1k fixture. iOS signed
Deny is verified; fresh-biometric Allow is deferred to physical-device testing.

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
light and dark comparisons are published in `mobile/11-native-light-comparison`
under the temporary media root below. No
mockups stand in for those builds.

| Measurement | iOS Simulator | Android emulator |
| --- | --- | --- |
| Cold launch to unlock UI | Release 10k: 917 ms first after install; 589–654 ms warm | Final Release 10k: 228–273 ms; fingerprint prompt 266–280 ms |
| Unlock to list, passphrase | Release 10k: 243 ms | Final Release 10k: 145–165 ms core + 65–73 ms list |
| Unlock to list, biometric (excluding user wait) | Deferred physical-device operation | Final Release 10k: 55–114 ms core + 95–111 ms list |
| Visible search, 1k / 10k items | Debug 1k: 0–53 ms; Release 10k: 15–62 ms, clear 48–63 ms | Final Debug 1k: 34–69 ms; Release 10k: 39–59 ms |

Android's 150 ms debounce has been removed. One active core search and a latest
pending query prevent overlapping FFI work; clearing normally uses the full-list
cache. On the final Release 10k build, a title-only typing burst measured 75 ms,
cached clear 23 ms, and clear after a successful sync with a filtered query in
flight 90 ms (a marginal pass). Clearing during an all-match post-sync refetch is
a separate measurement, not covered by that number. Two follow-up attempts
cleared during an all-match call after sync had invalidated the full-list cache:
fresh data arrived within an upper bound of 89–92 ms from that call's start.
The displayed rows already matched the empty query, so no new visible-frame
marker fired. These attempts did not clear during the sync's own short refetch.
All-match queries whose displayed list did not change cost 40–57 ms in the core;
these are not additional visible-latency samples. The final Debug 10k build still
fails: search 123–175 ms, title burst 528 ms and post-sync clear 312 ms.
Release measurements use non-debuggable Kotlin, optimized Rust, a local debug
signing key and speed-profile compilation; capture protection stayed enabled.
Release visible timings are in-app presentation instrumentation, not recordings;
they exclude input delivery before the field callback and display scan-out.
These are emulator comparisons, not physical-device results. The old
approximately 3 s passphrase estimate included host-side
polling and is superseded by the in-app/frame measurements above. iOS Release
measurements use recorded frames, with 20 search/clear samples giving a standard
median of 55 ms and nearest-rank p95 of 63 ms. Its all-match core timings of
29–31 ms are separate, because those queries did not change the visible rows.

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

Fresh signing metadata corrects the initial inspection: a valid Apple
Development identity with its private key **is installed for team 5NZ4Q7NXJ4**.
The certificate's subject OU confirms Anomaly, even though its common name is
Ryan's. Automatic provisioning subsequently created development profiles for
both Deadbolt bundle IDs, with 22 existing registered devices. The device app
and embedded provider built and passed strict signature verification using the
Anomaly identity, App Group and shared Keychain entitlements. Simulator builds
remain ad-hoc and do not establish physical-device assurance. Ryan has deferred
physical-device testing until he returns from his trip.

Device/TestFlight distribution requires:

1. An Apple Development identity for team 5NZ4Q7NXJ4 (present) for device testing;
   an Anomaly Apple Distribution identity is additionally needed for TestFlight.
2. iOS Development profiles for **both** bundle IDs, including test-device UDIDs,
   App Group, shared Keychain group and the provider entitlement (present).
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

The simulator provider's busy/retry path was exercised by an external process
holding only the store's exclusive file lock, without writes. After release,
Try again reached unlock and the login list. This is synthetic lock-contention
evidence, not a simultaneous real app/provider race: the app released its store
about 1.25 seconds after backgrounding. The app also refused the held lock.
Both now show a recoverable busy message and offer retry; the app unlocked
normally after the synthetic lock was released.

Native measurements so far (simulator/emulator; not device certification):

| Synthetic vault | App peak | Provider peak (password / OTP / passkey) | Device jetsam check |
| --- | --- | --- | --- |
| 1,000 logins | iOS peak not measured | Final merged-core Release password list+fill: 102.2 MiB; suggested fill (v6): 100.3 MiB | Deferred |
| 10,001 logins (after OTP fixture) | Peak not measured; Android 10k unlocked PSS (`dumpsys`): Debug 210,587 kB, Release 157,051 kB | Final merged-core Release password list+fill: 104.5 MiB; OTP: 101.9 MiB; passkey registration: 100.7 MiB; suggested fill (v6): 100.1 MiB | Deferred |

Initial offline Rust provider benchmarks (debug, production KDF) measured
simulator list/fill at 236/207 ms for 1k and 819/581 ms for 10k. Isolated
provider-only processes then measured simulator peak physical footprint at
74.6 MiB for either 1k operation, **126.7 MiB for the 10k picker**, and 94.0 MiB
for the 10k selected fill. That Debug picker exceeded the stated budget before
native extension overhead; it was a failed gate, not excused as test setup.

Fixtures were created in separate processes. An external 2 ms sampler used
`proc_pid_rusage(RUSAGE_INFO_V4)` and acknowledged phase checkpoints. Replay
peaked around 94 MiB; picker materialization raised that to 127 MiB. Closing the
store and dropping the response returned footprint to about 11 MiB. RSS retains
reusable allocator pages and is not the same as physical footprint. Streaming
picker materialization alone did not lower the simulator peak (128.4 MiB).
Moving the existing metadata arrays into the JSON response, instead of cloning
them, lowered the final 10k picker peak to **116.4 MiB (122.03 MB)**. That still
exceeds a literal 120 MB ceiling and provides no useful headroom even against
120 MiB. That Debug memory gate remained failed. No projection or weaker KDF has been
introduced. Subsequent actual native extension measurement confirmed the failed
gate: 148.7 MiB for the 10k list and 119.9 MiB for a suggested login, including
Swift/OS overhead. Further optimization must be measured against this native
path, not just the isolated Rust process.
The isolated measurements exclude Swift/OS overhead; the actual extension
measurements include it. Both used Debug simulator builds without substantial
edit history; physical-device certification remains outstanding.

The subsequent arm64 Release Swift/provider build with optimized Rust reduced
the 10k list-plus-fill peak to **112.6 MiB (118.07 MB)** in two runs, and the
suggested-login peak to **100.3 MiB (105.17 MB)**. Only 1.93 MB remains below the
literal 120 MB ceiling for the list flow: this still fails the substantial-
headroom requirement. These measurements used 10,000 logins plus one passkey,
before adding the origin-matched OTP fixture. Phase-specific inspection is
complete: the displayed picker retained about 12 MiB of metadata during the
selected fill's second KDF. An iOS-only presentation change releases those rows
before filling; measured list loading now peaks at 103.0–103.5 MiB, and selected
fill at 102.7–102.9 MiB. The overall 103.5 MiB is about 108.53 MB, leaving
11.47 MB (9.6%) below the literal ceiling. This is a limited margin, not device
certification. The later v6 cancellation-fix build measured 103.9 MiB for the
10,001-login picker and 101.5 MiB for a completed OTP fill; its fresh 1k picker
was 102.3 MiB. An earlier 31.1 MiB OTP sample ended before unlock and is excluded.
The final Release build on the merged core (`abdadb8` plus the committed picker
batch) measured 104.5 MiB for the 10,001-login picker and fill, 102.2 MiB at 1k,
101.9 MiB for an OTP fill and 100.7 MiB for passkey registration: about 109.6 MB
at worst, roughly 10 MB below the literal ceiling. Row release uses a 32 ms scheduling pause,
not a render acknowledgement, so the observed reduction is not a memory bound
under arbitrary main-thread load.

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

Negative-case evidence lives in the existing tests, not just the phone demo:
`net::approval` checks wrong signers, mutated scope, replay, expiry and monotonic
deadlines; its transport test checks revocation and one response only. The CLI
`experimental_read_from_a_real_mac_socket_requires_one_signed_answer` test
refuses an undesignated approver and ordinary AI reads, releases exactly one
field after approval, rejects a second answer and checks membership revocation.
The mobile-core `approvals_require_fresh_slot_unwrap_and_lock_revokes_pending`
test verifies that a cached unlocked session cannot replace a fresh slot unwrap.

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
Physical iOS Secure Enclave unlock, fresh-biometric approval, user-verified
passkey registration/sign-in and device jetsam validation are deferred until
Ryan returns with a test device, not waived by simulator tests. Anomaly signing
and both development profiles are verified; these are not signing blockers.
Simulator password/OTP flows and rejection of passkeys that require biometric
verification remain testable. A ceremony explicitly discouraging verification,
if exercised, must not be labeled user-verified. These gates keep the proof
incomplete on hardware, but do not block finishing the simulator proof.

Completed checks during development (not a substitute for the final combined
workspace/platform runs):

- After integrating current dev, `bun run check:extension`: TypeScript check,
  564 tests (2,868 assertions), and the native extension build passed.
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
- Android native tests after the UI-owner search/lifecycle batch: 47 passed.
  The final Gradle build reused that cached result with unchanged compiled inputs;
  it did not re-execute the tests.
  Actual 1k pairing and fresh-fingerprint Allow/signed Deny test-host runs passed.
  Final-core 1k offline sync now shows the quiet offline status after about
  15 seconds; online sync succeeds. The fresh 10k fixture paired in 16.5 seconds,
  and final Release measurements meet the search/clear target as detailed above.
  Search keyboard personalization and a possible duplicate post-unlock list
  composition remain follow-ups. Only one core read was observed for the latter;
  its cause is not established.
- iOS XCTest: 12 native tests passed headlessly, including the real-core boundary,
  simulator Secure Enclave refusal and the CoreFailure message regression.
  Separately, 32 lifecycle tests passed against delayed fake cores/clients,
  including
  coalesced search, exact approval-prompt binding, idle lock and identity-
  publication ordering/background cancellation and five iOS picker regressions.
  Replacement both before dispatch and as the successful fill reply returns is
  rejected; the latter regression failed without the final reply guard.
  Shared Swift compiled with
  optimization and warnings denied; five macOS provider stills were unchanged.
  These use simulator `xctest` directly; the Instruments-driven launcher failed
  to connect earlier. Neither suite substitutes for physical biometric testing.
- Actual iOS 26.5 OS password fills passed through the picker and published
  suggestion at 1k and 10k; passkeys requiring biometric verification refused
  without a software fallback. Safari QuickType OTP delivery also passed: the
  provider unlocked by passphrase, filled the code, and an independent TOTP
  recomputation matched the public synthetic seed and capture time.
- A real Safari registration on the controlled tailnet origin, requested with
  user verification discouraged, returned a passkey with UP=1, UV=0 and AT=1.
  Independent relying-party verification accepted the origin, captured challenge,
  RP hash, credential ID and COSE/SPKI key. The historical recorder did not prove
  server challenge issuance or separately capture `rawId`. A fresh registration
  against the stricter one-use, cookie-bound backend was independently verified:
  the server-issued challenge was consumed after 9.26 seconds of its 150-second
  window, `id`/`rawId`/attested ID matched, and the new ES256/P-256 COSE key matched
  SPKI. The fresh response again had UP=1, UV=0 and AT=1.
  `fmt=none` provides neither hardware attestation nor private-key-possession
  proof. Simulator diagnostics show that registration received and mapped
  `discouraged`, but assertion received and mapped `required`, although both
  page requests specify `discouraged`. The provider correctly refused the
  received assertion requirement without a software biometric fallback. Why
  the OS strengthened that preference is not established. No native assertion
  signature or user-verified ceremony is claimed; those need a physical iPhone.
- Wrong-passphrase runtime checks displayed the generated core error in both
  appearances. The coalesced-search Debug build measured 97–183 ms at 10k
  (p95 177 ms), still failing the 100 ms gate. Release search now passes at
  15–62 ms on recorded frames; clear passes at 48–63 ms.
- The pre-optimization iOS extension list/suggestion footprint was
  148.7/119.9 MiB at 10k, above the 120 MB budget; 1k was
  107.5/101.1 MiB. Simulator measurements do not establish device jetsam safety.
  iOS Release list-plus-fill initially improved to 112.6 MiB but still failed
  on headroom. Releasing picker rows subsequently measured 103.0–103.5 MiB,
  pending the final cancellation-fix build; suggested-login fill is 100.3 MiB.
  Android Release search does not establish an iOS memory result.
- The Rust C/assembly deployment metadata now matches iOS 17.0; the BLAKE3
  NEON object no longer declares simulator 27.0 as its minimum. Older-OS runtime
  compatibility remains untested.
- Dev's history-streaming change (`9358d17`, PR #190) is integrated in `abdadb8`.
  Mobile welcomes now use the shared verified replay and lazy durable append;
  outgoing frames recheck live membership, readiness and cancellation per pull.
  Core tests: 151 passed, 1 ignored; mobile: 12 passed, 3 ignored; net application:
  4 passed; CLI simulations: 19 passed, 1 ignored. The separately invoked public-
  relay mobile-core pairing/restart/sync regression passed too. Workspace and
  wasm Clippy and formatting passed. The rebuilt optimized iOS archive is
  `ee53ada2ad1cad50353273e1773e966462a9a9ce0b46bcc1c1dd84f1de7363ea`;
  all 653 Mach-O deployment minimums are at or below iOS 17.0.
- Full app integration baseline: 208 passed, 21 failed. Nineteen failures are at
  the CLI `init` fixture step and two are setup timeouts; AI-caller setup refusal
  is a known restriction in this environment. This is not a green app-suite
  result, and production caller guards were not relaxed to make it pass.
- [PR #194 CI](https://github.com/anomalyco/deadbolt/actions/runs/41232497486)
  on `ea04910`: all 15 PR jobs passed (nightly skipped), including
  Linux/macOS Rust, cargo-deny, browser cores and extension native/standalone
  smoke, security and end-to-end shards. This includes the committed provider,
  native integrations, typed-row optimization, offline-sync fix, synthetic OTP
  helper and iOS search/prompt fixes. Remaining local changes still require CI
  on their final pushed head.
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
