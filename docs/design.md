# Deadbolt v1 — simplified design

2026-10-15. Supersedes `history/04-proposal-v0.md` and `history/04b-revision-no-infra.md` for v1. Constraints from dax: iroh device-to-device only (n0 relays are fine), no mailbox in v1 (but don't preclude it), no recovery — lose every device, lose the vault.

## Keys (three)
1. **Device key** (Ed25519, one per device). Is the iroh EndpointId *and* signs everything the device writes. Stored encrypted under (2).
   - Why not separate transport/signing keys: neither can live in Secure Enclave/TPM (P-256 only), both must be in RAM while the app runs, so separating them adds a key without adding protection.
2. **Local unlock key** (per device). Argon2id(passphrase); optionally also stored in the OS keychain behind biometrics for day-to-day unlock. Encrypts the device key, the vault key and the local database.
3. **Vault key** (symmetric, 256-bit, shared by current members). Encrypts every log entry (XChaCha20-Poly1305, random nonce, AAD = vault id ‖ key version ‖ author ‖ seq). Replaced on every device removal.
   - Distributed only over authenticated iroh connections (pairing, or a peer handing the new version to a member). No per-device X25519 keys, no HPKE wraps in v1.
   - Strictly, v1 could skip it (peers never talk to non-members), but it's what makes a mailbox drop-in later and costs one symmetric key.

Dropped from earlier drafts: separate iroh key, X25519/HPKE, per-item and per-edit keys, key commitment (only one key ever decrypts an entry), recovery kit + tiers, expiring heads, PAKE, mailbox trait.

## Membership
- Signed log of `Add(device)` / `Remove(device)` ops, each referencing the ops it saw (causal).
- `Add` carries the new device's signature too (it consents to joining *this* vault).
- `Remove(B)` records the last entry of B's log the remover had seen; anything B wrote beyond that is ignored. Removed keys can never be re-added.
- Concurrent mutual removal: the device that was added earlier wins.
- Sync always exchanges membership first; a device refuses connections from non-members and never accepts data whose membership dependencies it lacks. So any device holding post-removal data already knows about the removal and won't talk to the removed device.

## Data
- Each device appends to its own signed log. Entries reference the entries they were based on (causal), never wall-clock time.
- Items are maps of fields. An edit replaces a field only if it was based on the previous value; truly concurrent edits keep one (tie broken by entry hash) and push the other into the item's history, so nothing is silently lost.
- Sync = "here are my heads, send me what I'm missing", over iroh. Only the encrypted entries move; the same format can later go to a mailbox.
- No compaction in v1. Deleted items stay in the encrypted history on your own devices. (Later: snapshot + drop old vault key versions.)

## Pairing
- New device shows a QR: its device public key + a one-time secret (+ relay hint).
- Existing device (unlocked) scans, dials it, both prove the secret, new device signs "join vault V", existing device signs `Add`, sends the vault key + data over the same connection.
- No camera: existing device dials via a short code, and both screens show a 6-digit code derived from the connection + both keys; the user confirms they match.

## Removing a device
Sign `Remove(B)`, create a new vault key version, hand it to every remaining member as they connect. B is refused at connection time and can't read anything new; it keeps what it already had (inherent; prompt the user to rotate passwords it saw).

## Later (designed for, not built)
- Mailbox: entries are already encrypted under the vault key and signed; add per-device X25519 keys (or encrypt to the device key) so a new vault key version can be left in a mailbox for offline devices.
- Recovery kit: a paper device with its own device key, added like any other device.
