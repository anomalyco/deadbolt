# Deadbolt v1 — simplified design

2026-10-15. Supersedes `history/04-proposal-v0.md` and `history/04b-revision-no-infra.md` for v1. Constraints from dax: iroh device-to-device only (n0 relays are fine), no mailbox in v1 (but don't preclude it), no recovery — lose every device, lose the vault.

## Keys (two)
1. **Device key** (Ed25519, one per device). Is the iroh EndpointId *and* signs everything the device writes. Stored encrypted under (2).
   - Why not separate transport/signing keys: neither can live in Secure Enclave/TPM (P-256 only), both must be in RAM while the app runs, so separating them adds a key without adding protection.
2. **Local unlock key** (per device). Argon2id(passphrase); optionally also stored in the OS keychain behind biometrics (device-only item, never synced) for day-to-day unlock. Encrypts the device key and the local database.

No shared vault key in v1. Data only ever moves over iroh connections (end-to-end encrypted, authenticated to device keys) between current members, and at rest it is under each device's local unlock key. Re-keying on removal would protect nothing extra: a removed device can only receive data from a member that hasn't learned of the removal, and that member would still be on the old key too.

Accepted cost: removal rests entirely on the membership check (no ciphertext fallback if that check has a bug), and adding a mailbox later means introducing a vault key + re-keying then, which changes the entry format.

Dropped from earlier drafts: shared vault key and re-keying, separate iroh key, X25519/HPKE, per-item and per-edit keys, key commitment, recovery kit + tiers, expiring heads, PAKE, mailbox trait.

## Membership check (security-critical)
- One small function: "is this EndpointId in the current member set?" Applied on accept **and** on dial.
- When a `Remove` arrives, immediately close any open connection to that device, not just refuse new ones.
- On startup, sync membership with every reachable peer before serving data to anyone (shrinks the window where a long-offline device still trusts a removed one).
- Dedicated tests for all of the above.

## Membership
- Signed log of `Add(device)` / `Remove(device)` ops, each referencing the ops it saw (causal).
- `Add` carries the new device's signature too (it consents to joining *this* vault).
- `Remove(B)` records the last entry of B's log the remover had seen; anything B wrote beyond that is ignored. Removed keys can never be re-added.
- Concurrent mutual removal: the device that was added earlier wins.
- Sync always exchanges membership first; a device refuses connections from non-members and never accepts data whose membership dependencies it lacks. So any device holding post-removal data already knows about the removal and won't talk to the removed device.

## Data
- Each device appends to its own signed log. Entries reference the entries they were based on (causal), never wall-clock time.
- Items are maps of fields. An edit replaces a field only if it was based on the previous value; truly concurrent edits keep one (tie broken by entry hash) and push the other into the item's history, so nothing is silently lost.
- Sync = "here are my heads, send me what I'm missing", over iroh. Entries are signed; confidentiality in transit comes from iroh.
- No compaction in v1. Deleted items stay in the history on your own devices, encrypted at rest under the local unlock key. (Later: snapshots.)

## Pairing
- New device shows a QR: its device public key + a one-time secret (+ relay hint).
- Existing device (unlocked) scans, dials it, both prove the secret, new device signs "join vault V", existing device signs `Add`, sends the membership log + data over the same connection.
- No camera: existing device dials via a short code, and both screens show a 6-digit code derived from the connection + both keys; the user confirms they match.

## Removing a device
Sign `Remove(B)`; it spreads to the other members as they sync. B is refused at connection time (and any open connection is closed) and can't get anything new; it keeps what it already had (inherent; prompt the user to rotate passwords it saw).

## Later (designed for, not built)
- Mailbox: add a shared vault key that encrypts entries, re-keyed on removal and wrapped to per-device X25519 keys so offline devices can pick it up from the mailbox. Entry format changes at that point.
- Recovery kit: a paper device with its own device key, added like any other device.
