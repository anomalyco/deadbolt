# The extension as a device — Phase 1 proof

The extension is its own Deadbolt device: a fresh Ed25519 `DeviceSecret`, a
membership entry and an encrypted vault replica. A CLI on the same computer is
another peer, not a required helper. This branch is a proof, not a feature-complete
replacement for the native-backed extension.

## Architecture

`crates/ext-core` is the wasm-bindgen composition root. It uses `deadbolt-core`
unchanged for device identity, signed entries, typed items, causal history, consent
and membership. `deadbolt-store` and `deadbolt-net` have platform-specific adapters,
not copies of their crypto or protocols. JavaScript only routes commands and
renders browser UI.

The path is content script / popup → background `VaultBackend` → offscreen document
→ dedicated worker → Rust. The standalone backend is the default. An explicit
native build retains the existing `Host` implementation and native-host tests.
The proof supports a single vault, login create/update/list/fill, passphrase
lock/unlock, invitation of a CLI joining device, and bidirectional sync. Unsupported
operations fail rather than silently delegating to a native host.

The proof deliberately limits login matching to an **exact origin**. The existing
background frame, user-gesture, navigation and menu clickjacking checks are reused.
The full CLI public-suffix matching policy is a follow-up; the proof does not
broaden where a login may be filled. It advertises no passkey, card reauthentication,
TOTP or password-generation capability.

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
The e2e explicitly overrides the dev box's default local-only environment.

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

## MV3 runtime and lifetime

The service worker is a router, not the owner of unlocked keys or live connections.
An offscreen document with the `WORKERS` reason owns the dedicated wasm worker.
Normal service-worker suspension therefore does not discard the unlocked device.
Commands are serialized in the worker; locking bypasses queued network/KDF work by
terminating the worker and rejecting in-flight requests. A new worker reopens the
encrypted file only after passphrase unlock.

A five-minute alarm and user wakeups drive sync catch-up. While the offscreen document exists,
iroh can receive connections independently of the service worker. Chrome may still
discard the offscreen document or renderer. This proof fails closed in that case:
the vault relocks, even under Comfortable. It does **not** claim guaranteed offscreen
lifetime or completed Comfortable session-key restoration.

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

The management command route accepts only the exact extension device page; content
scripts and web pages cannot create/unlock/pair a device or invoke arbitrary worker
commands. The offscreen route accepts only the extension service worker. Neither
the device page, offscreen document, worker nor wasm module is web-accessible.
There is no externally-connectable API and no native-host fallback. Extension CSP
allows local wasm execution, not remotely hosted executable code. Passphrases and
vault contents must never enter logs or telemetry.

At-rest protection has the native model's limits: restoring an old entire database
can roll it back, losing every admitted device loses the vault, and revocation
cannot retract secrets already received by a removed member.

## Settled lock presets

These are the target product contract, not a claim that all settings ship in Phase 1.

| | Strict | Comfortable (default) | Relaxed |
| --- | --- | --- | --- |
| Idle lock | 5 min | 1 h | 12 h |
| Screen lock / sleep (`chrome.idle` locked) | locks | locks | stays unlocked |
| Browser quit | locks | locks | locks |
| Unwrapped key | offscreen memory only | memory + `chrome.storage.session` for offscreen restart | same as Comfortable |
| Touch ID / passkey unlock | allowed | allowed | allowed |
| Reveal/copy password; card number/CVV | re-auth every time | re-auth card number/CVV | no re-auth |

Use means a pick, fill, save, opening the popup, or reveal. Passive listing for a
page menu is not use. Phase 1 implements passphrase locking, a one-hour idle limit
and screen-lock handling, without exposing the unimplemented preset selector or
biometric promises. Session-key restoration and passkey PRF wrapping need their own
security review and browser capability handling.

## Verification

Run on Linux, headless only. Install the `wasm32-unknown-unknown` Rust target and
`wasm-bindgen-cli` at the exact version pinned by `crates/ext-core/Cargo.toml`
(currently 0.2.129). The default extension build compiles and packages wasm;
`bun scripts/build.ts --native` skips it for native-host consumers.

```sh
export CARGO_TARGET_DIR="$HOME/.cache/cargo-target/ext-device"
bun run check
cargo build -p deadbolt-cli --locked
cd extension
bun e2e/standalone.ts --deadbolt "$CARGO_TARGET_DIR/debug/deadbolt"
```

The standalone e2e creates an extension vault, adds a login, invites a disposable
CLI over n0 relays, verifies writes in both directions (including a post-pair
browser write), clicks the real inline menu to fill the CLI login, rejects reads
while locked and a wrong passphrase, measures real-KDF unlock, and restarts Chrome
to verify encrypted persistence and startup locking. Its profile has no native host
manifest and native messaging calls are trapped. All credentials are synthetic;
the browser profile and CLI store are deleted at the end.

On exos (c7i.8xlarge, headless Chromium), the final full e2e measured **613 ms**
for real-KDF unlock over the extension management RPC, including worker loading,
OPFS reopen, log reconstruction and endpoint setup. Earlier full runs measured
339 ms and 717 ms. A direct warm wasm worker probe measured **179 ms** including
store reopen and endpoint setup. These are not KDF-only microbenchmarks. An exos x86 result is not an M-series measurement; the <1.5-second M-series target
must be verified separately on that hardware.

Checks completed on exos:

- `bun run check`: passed (extension typecheck, 389 tests and standalone build;
  workspace formatting, native Clippy, wasm Clippy, workspace tests and cargo-deny).
  Cargo-deny's existing duplicate-version warnings remain warnings.
- After review changes: `cargo +stable fmt --all -- --check`, `bun run check:wasm`,
  and `cd extension && bun run check`: passed. No native Rust behavior changed in
  this final wasm/UI batch.
- `bun e2e/standalone.ts --deadbolt "$CARGO_TARGET_DIR/debug/deadbolt"`: passed,
  including actual create/save/list UI and actual inline-menu autofill.
- Existing `bun scripts/e2e-parallel.ts` native fake-host suite: all six shards
  passed; the native backend remains selectable with `--native`.
- Store backend/native interoperability tests and actual Chromium OPFS handle,
  persistence, exclusivity and atomic-move probes passed. Rust review approved
  after restoring rejected-entry skipping so valid removals cannot be discarded.

## Follow-up PRs

1. Complete first-run pairing in both directions, QR presentation, device list,
   multi-vault selection and error UX.
2. Extract shared application sync/pair envelope handling from the CLI and proof,
   add deterministic browser-client membership/revocation/crash tests, and exercise
   suspended/resumed/offline relays and storage exhaustion/corruption. Parallelize
   startup contacts (the proof dials sequentially within the same 30-second budget).
3. Finish the three lock presets, trusted-use accounting, offscreen session-key
   restoration, browser-quit semantics and re-authentication gates.
4. Add WebAuthn PRF/passkey unlock with capability detection; review key wrapping,
   extension origin binding and memory/permission boundaries.
5. Reach native autofill feature parity (PSL policy, TOTP, generation, passkeys,
   cards/identities, SSO and learning), harden packaging/update/CSP permissions,
   measure wasm size/unlock across devices, and decide native-path retirement.
