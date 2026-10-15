# Deadbolt — design proposal v0

Status: draft for critique, 2026-10-15. Sources: `01-inkandswitch.md`, `02-rust-sync-stacks.md`, `03-mailbox-pairing-keys.md` in this directory. All Rust.

## Goals (from dax)
- Every device syncs the vault directly with every other device (iroh).
- No accounts. A new device joins only by pairing from an existing device.
- Later: a mailbox that stores ciphertext so devices can catch up / restore when all other devices are offline.
- The store generalises into a personal data store with general CRDT replication.

## Non-goals for v1
- Sharing between different people (multi-user groups). Keep IDs/roles compatible so it can be added.
- Browser autofill/passkey provider integration (plan for CXF-compatible item schema, ship later).
- Forward secrecy for history on a still-trusted device (a password manager must read its own past).

## Threat model (v1)
- Mailbox, relay, DNS/discovery, and network are untrusted for confidentiality and integrity; trusted only for availability (and we hedge that with multiple backends).
- A device that is lost/stolen-while-locked must not leak the vault (local encryption at rest + OS keystore + unlock).
- A removed device keeps everything it already synced. We can only protect *new* data, and we prompt the user to rotate the real passwords it could see.
- Malicious-server lessons (ETH Zürich 2026 study of Bitwarden/LastPass/Dashlane/1Password): never accept unauthenticated public keys, never let synced data pick ciphers/KDF params, bind context into every AEAD, authenticate every key wrap.

## Architecture (layers)

```
 app (cli / sdk / ui)
 ── collections ── vault items (LWW map)   |  later: Loro docs per collection
 ── replication ── per-device signed, encrypted append-only logs (ciphertext "segments")
 ── membership  ── signed causal log of device add/remove → epoch keys
 ── transports  ── iroh (live peer sync)  |  mailbox backends (S3/R2, folder, storage-peer)
```

### 1. Identity & membership
- Each device: Ed25519 identity key = its iroh NodeId; X25519 key for HPKE wraps. Private keys in OS keystore / Secure Enclave where available.
- A vault = vault ID + **membership log**: signed ops `AddDevice(pubkeys, sponsor)`, `RemoveDevice(id)`, `Rekey(epoch)`. Ops form a causal DAG (each op references heads). Small n (≤ ~20 devices), so linear-cost rekeying is fine; no MLS/TreeKEM.
- Conflict rules (deterministic, all devices compute same result):
  - Remove wins over concurrent add/update of the same device.
  - A device removed in one branch cannot sponsor adds that are concurrent with or after its removal.
  - Mutual concurrent removal (A removes B while B removes A): both removed? Deterministic tiebreak? → **open question**, see below.
- Signed membership **heads expire** (e.g. 30 days): devices periodically re-sign the current head; a device that hasn't seen a fresh head warns; nobody wraps new keys to a device not in the latest head they know. Bounds how long a withheld removal goes unnoticed.

### 2. Keys
- Hierarchy: device key → **vault epoch key** (wrapped per member device with HPKE Auth mode, bound to vault ID + epoch) → **per-item key** → item content.
- New epoch on every RemoveDevice (and optionally on a schedule). New items/edits use the latest epoch; old segments stay readable to current members because epoch keys are chained (each new epoch key also wraps the previous one).
- Per-item keys make "true delete" possible: deleting an item drops its key from future snapshots; once all devices compact, the old ciphertext is unreadable even though bytes may linger in the mailbox.
- AEAD: XChaCha20-Poly1305; associated data = vault ID ‖ epoch ‖ item ID ‖ schema version ‖ segment ID. Suite fixed per epoch and recorded in the signed membership op; no downgrade.

### 3. Data model & replication (v1)
- Vault items are a **last-writer-wins map** keyed by item ID; value = encrypted item blob; LWW by (hybrid logical clock, device ID). Password items rarely see concurrent field-level edits, and when they do, LWW per *field* is the expected behaviour. Hand-rolled, tiny, auditable. (Optionally a Loro map, but don't take the dependency for v1.)
- Each device appends to **its own log**: segments = batches of encrypted, signed ops. Segment ID = BLAKE3 of ciphertext. Because each log has one writer, there's never a write conflict at the storage layer; merging is done on devices after decryption.
- Sync = exchange per-device log heads (device ID → seq/hash) and fetch missing segments. Works identically over iroh and against a dumb mailbox. No CRDT-library sync protocol needs to run through the untrusted layer.
- Compaction: a device periodically writes an encrypted **snapshot** (full current state at a vector clock). Peers that have the snapshot can drop older segments. Deleted items vanish from snapshots.

### 4. Pairing (onboarding a device)
- Existing device (unlocked) shows a QR: iroh NodeAddr + one-time 256-bit secret + vault ID, valid ~5 minutes.
- New device scans, connects over iroh, proves knowledge of the secret (HMAC over both NodeIds + transcript), sends its public keys.
- Existing device shows "Add <device name, fingerprint>?" → user confirms → signs `AddDevice`, wraps current epoch key to the new device, streams snapshot + logs.
- No camera: short numeric/word code + PAKE (CPace or SPAKE2), single attempt. Crate choice needs review (rust `spake2` unaudited; magic-wormhole crate is EUPL-1.2).

### 5. Recovery
- **Mandatory recovery kit** at vault creation: 256-bit secret, printed as words + QR. The kit *is a member device* in the membership log (a "paper device" with its own keys derived from the secret).
- The kit secret also derives the mailbox location/credentials, so after losing every device: new install → enter kit → fetch from mailbox → act as paper device → admit the new device → rotate epoch.
- No password-only recovery (offline brute force against mailbox ciphertext with no rate limiter).
- Later: optional social recovery (Shamir split of the kit secret).

### 6. Transports
- **iroh 1.x** for live device-to-device sync. Self-host relay (token/allowlist) and DNS discovery server; endpoint admits only NodeIds in the current membership.
- **Mailbox v1**: one small `Mailbox` trait (`put_segment`, `list_heads`, `get_segment`, `put_head` with compare-and-swap) with backends:
  - S3-compatible (R2 free tier covers a vault; conditional writes for heads, append-only unique keys otherwise).
  - Folder (works with any sync tool / NAS / USB).
- **Mailbox v2**: always-on Deadbolt "storage peer" (NAS/VPS/our hosted one) = iroh peer that holds ciphertext and no keys. Optional hosted service is the business model.
- Nostr: not for storage (no retention guarantees, size limits vary, nostr-sdk alpha). Maybe later as a wake-up/notification channel.

### 7. Path to the general personal data store
- Same membership + keys + per-device-log replication; collections become Loro (or Automerge) documents whose update bytes are the encrypted op payloads. Shallow snapshots in Loro give compaction.
- Keep Keyhive-compatible notions (principal = device, person = group of devices, access levels incl. a "relay/pull-only" level) so we can adopt Keyhive/Subduction or p2panda once they're audited and stable, rather than inventing multi-user sharing ourselves.

## What we reuse vs build
- Reuse: iroh 1.x, HPKE (`hpke` crate), XChaCha20-Poly1305, BLAKE3, `object_store`/`opendal` for S3, OS keystores.
- Build: membership log + rekey, per-device encrypted logs + snapshots, pairing, mailbox trait, recovery kit.
- Watch: Keyhive/BeeKEM/Subduction (Ink & Switch, not production yet; Subduction already has an iroh transport), p2panda-encryption (DCGKA), Willow/Meadowcap for capabilities.

## Open questions
1. Concurrent mutual removal and "remove vs sponsor" races — exact rules, and what the UI says.
2. Do we need an external timestamp/witness to stop a compromised-then-removed device from back-dating ops? (Keyhive documents this as unsolved without one.)
3. Epoch-key chaining gives every current member all history — fine for one person; wrong for future multi-user sharing. When do we switch models?
4. Should the hosted storage peer be the default mailbox (better UX) at the cost of the "no server" story?
5. PAKE crate choice and audit.
6. Local unlock: OS biometrics only, or also a master passphrase? (No server-side rate limit exists for anything.)
