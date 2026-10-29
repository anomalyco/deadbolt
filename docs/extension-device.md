# The extension as a device

The extension is its own Deadbolt device: a fresh Ed25519 `DeviceSecret`, a
membership entry and an encrypted vault replica. A CLI on the same computer is
another peer, not a required helper. The standalone build supports daily login
autofill, save/update offers, password generation and identity/card filling.
Passkeys and the other limitations below still use the browser's own fallback;
there is no silent fallback to a native host.

## Architecture

`crates/ext-core` is the wasm-bindgen composition root. It uses `deadbolt-core`
unchanged for device identity, signed entries, typed items, causal history, consent
and membership. `deadbolt-store` and `deadbolt-net` have platform-specific adapters,
not copies of their crypto or protocols. JavaScript only routes commands and
renders browser UI.

The path is content script / popup → background `VaultBackend` → offscreen document
→ dedicated worker → Rust. The native-host build (`bg/host.ts`, talking to
`deadbolt browser-host`) stays the default: `bun run build` and releases ship it,
and the native e2e suite runs against it. The standalone device is an explicit
opt-in build, `bun scripts/build.ts --standalone` (`bun run build:standalone`);
`--native` still names the default, and passing both is an error. The intended
later flip makes the standalone device the default, with a first run that detects
an installed native host and offers "Pair with Deadbolt on this Mac" instead of
creating a separate vault; neither the flip nor that first run is in this proof.

The device supports a single vault, login create/update/list/fill, save/update
offers after sign-in, generated passwords, identity/card fills, passphrase
lock/unlock, joining an existing vault or inviting a CLI device, and bidirectional
sync. Unsupported operations fail rather than silently delegating to a native host.

### Shared autofill rules

Both the native agent and wasm device call `deadbolt-core::site`, moved from the
CLI without changing its policy: the full Public Suffix List including private
suffixes, same-site subdomains, every saved URL field, and origin/host/parent/site
ranking. Recent fills break ranking ties in encrypted local metadata. The same
shared policy gates list, fill, credential checks and saves. The existing
background frame, user-gesture, navigation and menu clickjacking checks still run;
a frame asks for its own origin, never its parent's credentials.

Save offers use the existing `bg/save.ts` flow. Both adapters call core’s login
check, ranking and title helpers, so native tests exercise the wasm rules too.
Checks use shared trimmed,
case-insensitive username comparison and constant-time password hash comparison;
without a username they match by password alone. A confirmed update changes only
the existing login's password, preserving its title, username and saved URLs.
New logins and updates commit to the encrypted log before being announced, then
wake background sync. “Never for this site” remains the background's local
`neverSave` preference, shared with the native build; it is not a vault command
and does not sync.

Password generation uses the same Rust page-rule planning, vendored Apple site
rules and bounded candidate/kept-password lifecycle as native. `generate-check`
works while locked; generation requires unlock. Candidates last two minutes,
kept passwords fifteen minutes, are bound to the requesting origin, and are
forgotten on save, drop or lock. The existing signup/change-password menu and
post-submit save flow use these commands unchanged.

The standalone backend applies the native host’s token buckets before forwarding
requests: `check`/`generate-check` share 20 tokens, refilling one per second;
`fill`/`generate`/`fill-form` share 60, refilling four per second. Exhaustion returns
`rate_limited` without asking the vault. The buckets last for the service worker’s
lifetime, like the native host’s buckets last for its connection.

`forms` and `fill-form` use shared Rust identity/card field allowlists and labels.
Only requested fields leave the vault; identity ID numbers, notes and card PINs
never fill. Strict requires the local passphrase for every card-number/CVV fill,
enforced in Rust's `policy.rs`, not just the extension UI. The card menu says it
will ask for the passphrase. The two-minute prompt timer stops when confirmation
starts, so a slow KDF is not mistaken for an unanswered prompt; cancellation,
locking and replacement still end the fill. Only `device-preset` and opening
commands may change the worker’s preset; extra `preset` fields on ordinary
requests cannot weaken it. Comfortable and Relaxed
follow the native Touch-ID-off rule: the explicit menu pick is sufficient. There
is no standalone Activity log, so card fills are **not** recorded as Activity.
Identities and cards can be synced from another device; the standalone editor
still edits logins only. Its website input now uses the same site policy too:
public suffixes and single-label intranet hosts cannot be saved by hand. Synced
OTP fields use core's current-code generator; the editor does not create OTP fields.

### Storage: redb over OPFS

Use redb's `StorageBackend` over an OPFS `FileSystemSyncAccessHandle` in the dedicated
worker. This preserves the existing redb transactions, sealed log-length check,
blinded metadata keys, XChaCha20-Poly1305 record encryption and Argon2id key wrapping.
Only ciphertext enters OPFS. The backend calls `flush()` on redb durability barriers,
checks complete reads/writes, and holds OPFS's exclusive file lock until close.
No plaintext snapshot or unwrapped key is stored in IndexedDB or extension storage.

OPFS is preferable to a new IndexedDB key-value implementation for this proof:
redb already supplies atomic multi-record updates and crash recovery; replacing it
would introduce a second transaction implementation around the security-sensitive
log. OPFS synchronous access requires a dedicated worker; it is not available in
the MV3 service worker or directly in the offscreen document. Handles never move
between workers. An opaque handle id in Rust avoids claiming that a JS object is
thread-safe; this build has no wasm threads/shared memory.

Local writes and incoming sync batches stage a validated core vault, append the
new encrypted entries durably, and only then publish the staged state. This retains
the native invariant that a failed write must not advance live signed-log heads.
Browser storage is local to the extension's origin/profile. Removing the extension
or clearing its storage destroys this replica; it is not a recovery mechanism.

The proof uses `KdfParams::DEFAULT` (Argon2id v1.3, 64 MiB, three passes, one lane)
without a browser fast mode. `DEADBOLT_KDF=fast` is used only for the disposable
native CLI in the e2e. Initialization writes an exclusive pending OPFS file; only after the header and
genesis are durable and its handle is closed does an atomic OPFS move publish the
vault. A restart can retry an abandoned pending initialization without overwriting
an existing published vault.

### Network and membership

The browser is relay-only: iroh over WebSocket to n0's public relays. Native peers
can still use direct connections and relays. Both endpoints must have access to a
common relay network; `DEADBOLT_NET=local` deliberately cannot connect a browser.
The full e2e sets `DEADBOLT_NET=relay` for its CLI.

`deadbolt-net` uses n0-future tasks/time on wasm and the native runtime on native.
Socket binding, DNS lookup and directory rendezvous remain native-only. Browser
address lookup and pairing rendezvous use pkarr over HTTPS. A native joiner may publish a direct-only rendezvous record before selecting its
home relay. Browsers wait for its republished relay address rather than waste the
find deadline dialing an unusable IP address. Browser sync likewise omits direct
addresses so id-based relay lookup remains available. The PAKE, TLS-exporter
binding, one-guess/single-use code, signatures and connection membership hooks are
unchanged.

The proof invites a CLI started with `deadbolt join`, accepting its four-word code
in the extension's device page. Rust checks the new device's vault/inviter-bound
consent, commits its signed Add before sending the welcome, and sends the existing
CLI application's versioned envelopes and signed entries. Sync uses the same
membership-first/data-second protocol. The startup barrier contacts all current
members, including those learned during the round, before serving data. Dial
failures count as unreachable, post-connect failures retry, and the native
30-second best-effort deadline is preserved. A learned removal immediately closes
open sync connections; a stale offline replica has the same documented residual
risk as the CLI.

### First-run join of an existing vault

An uninitialized browser can instead show a code for an existing device to admit.
`device-join-start {deviceName}` checks relay reachability and starts the shared
pairing listener before returning `{type: "device-join-start", code, phase:
"waiting"}`. It uses the same short code, SPAKE2 proof, HMAC confirmation,
one-guess/single-use policy and default five-minute expiry as `deadbolt join`.
`device-join-status` returns `waiting` (with the code once listening), `admitted`
(with the vault name), `failed` (with an explanation), or `idle`. The worker keeps
the code across device-page reloads, but drops it on admission or failure. Failed
attempts can start again; codes and secrets are never logged.

Like the CLI's `Fresh`, the joining node uses a fresh device key and refuses all
sync. It reuses `application::read_offer`, `join_blob` and `verify_welcome`, keeping
the admitted vault and key only in memory. No local passphrase or OPFS write is
needed until admission. `device-join-finish {passphrase, deviceName}` writes the
encrypted key, complete welcome log and peer hints into the exclusive pending
OPFS file, closes it, and atomically publishes it without replacing an existing
store. It then starts the normal membership-first background sync and returns
`{type: "device-join-finish", ok: true}`; local logins are available immediately.
Pending-write failures retain the admitted vault for retry; after publication,
a startup failure is recovered by unlocking the saved vault.

This passphrase protects only this browser's local replica. It need not match the
CLI's passphrase and is not sent to the other device. First run offers "Pair with
an existing device" before "Create a new vault"; admission then asks the user to
choose and confirm this local passphrase. The code can be copied, and waiting can
be cancelled. Expiry, a spent wrong-code attempt, refusal and relay failure are
explained without logging the code.

The join task has an owned abort handle and generation-checked completion, and
holds no mutex or RefCell borrow across an await. Create, unlock and another join
are refused while joining or admitted. The offscreen setup queue also serializes
start and finish with create/unlock. Cancel uses the same worker termination as
lock, discarding the code, key and unpersisted welcome. Cancelling after admission
can leave an unused member on the inviter, just as CLI Fresh does; remove it on
an existing device. No native control messages or protocol version change.

## MV3 runtime and lifetime

The service worker is a router, not the owner of unlocked keys or live connections.
An offscreen document with the `WORKERS` reason owns the dedicated wasm worker.
Normal service-worker suspension therefore does not discard the unlocked device.

The offscreen document queues vault creation, unlock, join start and join finish,
so those setup operations never overlap each other. Everything else
(hello, list, fill, save, sync, pairing) goes to the worker as it arrives; the Rust
core interleaves requests at its await points, so a sync or pairing waiting on the
network does not hold up a list or fill. Locking bypasses all of it: the offscreen
document terminates the worker and rejects in-flight and queued requests. A new
worker reopens the encrypted file only after passphrase unlock.

Pairing's Argon2 rendezvous-key derivation is an exception: on wasm it runs
synchronously on the vault worker and can stall its other requests for about
one second (hardware-dependent). Background network waits do not block local
reads, but this CPU-bound pairing step still does; isolating it is follow-up work.

Sync runs in the background. Create and unlock start the startup membership round,
a five-minute alarm and user wakeups (at most every 30 seconds) catch up, and the
device page refreshes its login list on worker change events. Local list/fill
requests remain available immediately after unlock, even during the startup
membership round. That barrier gates peer data exchange and invitations, not
local reads. While the offscreen document exists, iroh can
receive connections independently of the service worker, so peers can sync with
the extension without it asking. Chrome may still discard the offscreen document
or renderer. This proof fails closed in that case: the vault relocks, even under
Comfortable. It does **not** claim guaranteed offscreen lifetime or any session-key
restoration.

## Security compared with the native-host model

With the native host, the unlocked database and device key reside in the native
agent process; the extension receives selected fields over native messaging. In
standalone mode **the unlocked vault lives in the browser process**, in wasm memory
owned by the extension worker. Compromising the extension, its privileged renderer
or its update supply chain can disclose every unlocked item and the device key.
Wasm is not an enclave and does not isolate secrets from compromised extension JS.

The passphrase necessarily crosses the trusted extension page, service worker and
offscreen messaging boundary. Rust zeroizes its owned passphrase/key buffers, but
JS strings, structured-clone copies and browser process memory cannot be reliably
wiped. Lock terminates the worker and closes its network endpoint; it does not
promise forensic erasure from RAM. No key is persisted unencrypted in this proof.

The management command route accepts only the exact extension device page and the
toolbar popup, which show the same vault UI (`extension/src/vault`); content
scripts and web pages cannot create/unlock/pair a device or invoke arbitrary worker
commands. The offscreen route accepts only the extension service worker. Neither
the pages, offscreen document, worker nor wasm module is web-accessible.
There is no externally-connectable API and no native-host fallback. Extension CSP
allows local wasm execution, not remotely hosted executable code. Passphrases and
vault contents must never enter logs or telemetry.

At-rest protection has the native model's limits: restoring an old entire database
can roll it back, losing every admitted device loses the vault, and revocation
cannot retract secrets already received by a removed member.

## Lock presets

These are the target product contract, not a claim that all settings ship in Phase 1.
The Unwrapped key row for Comfortable and Relaxed is a proposal, not a settled
decision: keeping the unwrapped key in `chrome.storage.session` needs its own
security review before anything implements it.

| | Strict | Comfortable (default) | Relaxed |
| --- | --- | --- | --- |
| Idle lock | 5 min | 1 h | 12 h |
| Screen lock / sleep (`chrome.idle` locked) | locks | locks | stays unlocked |
| Browser quit | locks | locks | locks |
| Unwrapped key | offscreen memory only | proposed: memory + `chrome.storage.session` for offscreen restart | proposed: same as Comfortable |
| Touch ID / passkey unlock | allowed | allowed | allowed |
| Reveal/copy password; card number/CVV | re-auth every time | re-auth card number/CVV | no re-auth |

Use means a pick, fill, save, opening the popup, opening a login, or reveal. Passive
listing for a page menu is not use, and neither is a page reading the vault again
(an open login's details ask for each new one-time code). The standalone build
implements the three presets' idle limits and screen-lock handling, and Strict's
passphrase check before a password is shown or copied. The choice is a setting in
`chrome.storage.local`, never a key. The service worker sends it to the vault's
worker with every unlock and change, and the Rust core enforces Strict itself
(`crates/ext-core/src/policy.rs`): under Strict it returns no password without a
passphrase, which it checks against the open store's key set, and a worker that
was never told assumes Strict. Card number/CVV fills also require the passphrase on every Strict fill.
Comfortable and Relaxed currently follow the native rule with Touch ID off (the
explicit pick is enough), rather than claiming biometric reauthentication.
Touch ID/passkey unlock is not implemented. The unwrapped key stays in worker memory only under every
preset: session-key restoration and passkey PRF wrapping need their own security
review and browser capability handling, so an offscreen restart still locks under
Comfortable and Relaxed.

Wrong passphrases back off. After three in a row, for unlocking or for Strict's
check before a password, the service worker refuses the next try for 1 s, then 2,
4, … up to 60 s, without reaching the vault; a right passphrase starts over. The
count lives in `chrome.storage.session`, so a restarted service worker keeps it.
This slows guessing through Deadbolt's own pages: someone at an unattended browser,
or a script driving the popup. It does nothing against an attacker who has copied
the encrypted OPFS file, who meets only the passphrase KDF.

### Copied passwords

The vault UI copies a password or one-time code when asked (the native popup still
never copies passwords). It can clear it again 30 seconds later, or when Deadbolt
locks, whichever is first, and only if the clipboard still holds that value, so
nothing the user copied since is lost. The service worker keeps no copy: only a
salted SHA-256 of the value, in memory and in `chrome.storage.session`, and a
one-shot alarm. The page computes that digest before sending `device-copied
{salt, hash}`; the plaintext copy is never sent to the service worker. The offscreen document (opened with the `CLIPBOARD` reason too)
reads the clipboard, compares, and empties it.

Reading and writing the clipboard from there needs `clipboardRead` and
`clipboardWrite`. Each adds an install warning ("Read data you copy and paste",
"Modify data you copy and paste", measured with
`chrome.management.getPermissionWarningsByManifest`), so both are optional
permissions, asked for together: by the "Clear copied passwords after 30 seconds"
switch in Settings, when the user chooses Strict, and once on the first copy under
Strict. Without them nothing is cleared, and nothing is cleared blindly.

The `favicon` permission, for site icons in the list from Chrome's own cache, adds
no warning to this manifest: alone it says "Read the icons of the websites you
visit", which the content scripts' all-sites access already covers.

## Verification

Run on Linux, headless only. The default (native-host) build needs only Bun. The
standalone build also needs the `wasm32-unknown-unknown` Rust target and
`wasm-bindgen-cli` at the exact version `crates/ext-core/Cargo.toml` pins; the
shared `scripts/wasm.sh <crate dir> <out dir>` checks the pin, builds the crate
and finds it in cargo's target directory (`CARGO_TARGET_DIR` included). The
site's `site/scripts/wasm.sh` uses the same script for `crates/send-web`. Both
generated wasm directories are ignored, not checked into Git. The shared script
uses release LTO and `opt-level="z"` for browser downloads without changing native
release optimization. CI builds standalone wasm for its smoke run; published
extension releases still build the default native-host extension (no wasm).

```sh
bun run check
cd extension
bun e2e/standalone.ts --smoke
cargo build -p deadbolt-cli --locked
bun e2e/standalone.ts --deadbolt "${CARGO_TARGET_DIR:-../target}/debug/deadbolt"
bun e2e/standalone.ts --join --deadbolt "${CARGO_TARGET_DIR:-../target}/debug/deadbolt"
```

The smoke (`--smoke`, run in CI) needs no CLI and no network: Chromium resolves
only the loopback fixtures and reaches nothing beyond loopback. It creates a vault through the device
page, saves a login there and sees it listed without a click, checks hello, list
and fill answer within the latency limit, fills it through the real inline menu,
locks, checks OPFS holds no plaintext markers, rejects reads while locked and a
wrong passphrase, unlocks with the real KDF, and restarts Chrome to check the
vault persists and starts locked. It also fills a login saved for `acme.test` on
`accounts.acme.test`, rejects lookalike sites, and exercises save/update offers
and generated passwords on signup and password-change forms. Submit flows use
trusted localhost: HTTP `.test` pages lack Web Crypto, so the shared content
script cannot track typed password values there.

The full run adds a real CLI over n0's public relays, so it stays out of CI. It
pairs a CLI started with `deadbolt join`, checks the browser's login reached it and
both devices are listed, and never asks the extension to sync: a browser write
reaches the CLI through the CLI's own sync, and a login the CLI writes while the
extension is locked appears on the device page after unlock through background
sync. It fills that login through the inline menu, then suspends the CLI agent
(`SIGSTOP`, a peer that stops answering mid-connection), fires the sync alarm, and
checks hello, list and fill each answer within the limit while that sync waits.
`--latency-ms` sets the limit (default 1000 ms, 1500 ms when `CI` is set); the
times are vault RPC round trips from the service worker through the offscreen
document and worker, not a KDF benchmark.

The `--join` run starts with a CLI vault containing five logins on different sites,
one with TOTP. A fresh extension starts and cancels a join, retries with a new code,
and retains that code across a page reload. The CLI pairs to that code. The browser
sets its separate local passphrase, lists both devices and all five logins, and
fills the synced login and current TOTP. Lock/unlock and browser restart verify the
joined replica persists. The offline smoke also checks the no-relay failure.

Both online runs also exercise signup, generated password changes and two-step
sign-in on `https://acme-demo.i.vogel.dev`, plus synced identities and cards on
localhost and the demo checkout. Strict card fills reject a wrong passphrase and
require the right one for every fill; Comfortable and Relaxed fill on the explicit
menu pick, following the native Touch-ID-off rule. The demo keeps its password
change form visible after success; if the shared save heuristic does not offer an
update there, the test verifies the update at the next successful sign-in.
`--video <dir>` saves headless WebM recordings of these synthetic flows.

All runs trap native messaging, use a profile with no native host manifest, and
use only synthetic credentials; the profile and CLI store are deleted at the end.
The native fake-host suite (`bun run e2e`, `bun run e2e:parallel`) builds with
`--native` as before.

## Follow-up PRs

1. Make the standalone device the default build, with a first run that detects an
   installed native host and offers "Pair with Deadbolt on this Mac". Complete
   native-host discovery, QR presentation, multi-vault selection and
   error UX, and run the full CLI e2e in CI against a local relay.
2. Extend the shared application protocol's simulator coverage to browser-client
   storage/lifetime adapters, and exercise
   suspended/resumed/offline relays and storage exhaustion/corruption. Parallelize
   startup contacts (the proof dials sequentially within the same 30-second budget).
3. Offscreen session-key restoration (security review first), stronger
   browser-lifetime guarantees and biometric card reauthentication.
4. Add WebAuthn PRF/passkey unlock with capability detection; review key wrapping,
   extension origin binding and memory/permission boundaries.
5. Finish OTP/identity/card editing, passkeys and learning; harden
   packaging/update/CSP permissions, measure wasm size/unlock across devices, and
   decide native-path retirement.

## Remaining limitations

- One vault per browser device; no native-host discovery or automatic migration.
- No passkey registration/assertion capability and no biometric/PRF unlock.
  WebAuthn falls back to the browser. A headless check with an unlocked standalone
  vault verified browser-owned ES256 resident-key registration and assertion with
  required user verification, no advertised passkey capability and no native
  messaging. Standalone passkey storage is a separate extraction across
  `cli/src/webauthn.rs` (ES256/CBOR/client data), `agent/passkeys.rs` (RP and
  exclusion checks, listing, signing and mutation planning) and the browser host's
  ceremony adapter. Move the pure crypto and validation into core, then add
  wasm storage/consent/cancellation adapters, registration and assertion e2e,
  and durable-save/exclusion-race checks. Initially report `canVerify=false` and
  UV=false, handing required-UV ceremonies to the browser; passphrase card
  reauthentication must not silently claim native Touch ID verification.
- No standalone Activity log or learning log. Neither capability is advertised.
- The vault UI edits logins only: other item kinds and OTP secrets must be created
  on a peer and synced. No automatic save/update offers for identities or cards.
- Worker/offscreen loss locks every preset; no session-key restoration. Chrome
  extension removal or storage clearing destroys this replica.
