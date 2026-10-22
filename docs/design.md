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
- `Add` carries the new device's signature too: it consents to joining *this* vault through *this* inviter (vault id, inviter, new device), so the consent can't back anyone else's `Add`.
- `Remove(B)` records the last entry of B's log the remover had seen; anything B wrote beyond that is ignored. Removed keys can never be re-added. Only a current member can be removed.
- A removal cuts every op by B it didn't see, including devices B added that the remover hadn't seen. A device with several `Add`s stays a member while any of them survives, so an extra `Add` never takes membership away.
- Seniority is the DAG depth of a device's first `Add` (ties broken by entry hash). An `Add` must see its inviter's admission, so an invited device always sits deeper than its inviter.
- Conflicting removals (mutual, cycles, or a removal of someone's inviter): removals are considered in their authors' seniority order, and each is kept only if it leaves itself and every earlier kept removal authorized. So in a mutual removal the device added earlier wins. The full rule and its reference model are in `crates/core/src/membership_tests.rs`.
- Known limitations (open; a recovery key or similar is a separate decision):
  - A causal removal is final only when the remover is senior. A removed device that is senior to its remover can sign a removal of the remover with parents from before its own removal, and seniority wins it the race.
  - Seniority ignores cuts: a device keeps the rank of its first `Add` even when that `Add` was cut and only a later one survives. A removed device that had secretly added a device (which consented to it) can thereby lend that device an early rank if another member adds it again. Consent commits to neither seq nor parents, so a single inviter can do the same with one consent if its own first admission was cut and it was admitted again: an early `Add` that gets cut and a later one that survives. Either way this only changes who wins removal races.
- Sync always exchanges membership first; a device refuses connections from non-members and never accepts data whose membership dependencies it lacks. So any device holding post-removal data already knows about the removal and won't talk to the removed device.

## Data
- Each device appends to its own signed log. Entries reference the entries they were based on (causal), never wall-clock time.
- Items are maps of fields. An edit replaces a field only if it was based on the previous value; truly concurrent edits keep one (tie broken by entry hash) and push the other into the item's history, so nothing is silently lost.
- Sync = "here are my heads, send me what I'm missing", over iroh. Entries are signed; confidentiality in transit comes from iroh.
- No compaction in v1. Deleted items stay in the history on your own devices, encrypted at rest under the local unlock key. (Later: snapshots.)

## Items
- Every item has a **type**, fixed at creation. Built-in types in v1: `login` and `card`. User-defined types come later; keep the type an open identifier, not a closed enum on the wire.
- A type defines its known fields, each with a fixed field type, and which of them are required. Items may carry extra fields of any field type on top.
- Field types: `text`, `secret` (hidden unless asked), `url`, `email`, `otp` (TOTP secret; shown as the current code), `month` (stored `YYYY-MM`), `note` (multi-line).
- Guarantees, enforced in core on every device: an item is created in one entry that contains all required fields; a known field always has its fixed field type; required fields can't be removed; the type can't change. Ops that would break this are rejected at commit and ignored (deterministically, op by op, without rejecting the entry) at apply.

| type | field | field type | required |
|---|---|---|---|
| login | password | secret | yes |
| | username | text | |
| | url | url | |
| | otp | otp | |
| | notes | note | |
| card | number | secret (12–19 digits) | yes |
| | expiry | month | |
| | cvv | secret (3–4 digits) | |
| | cardholder | text | |
| | pin | secret | |
| | brand | text | |
| | notes | note | |

- Card brand: the optional `brand` field, shown in the label when set. (Later: derive it from the number's prefix for major networks when the field is empty; a Luhn check as a CLI warning.)
- **Names are optional labels on every item** (alongside the type, not one of its fields), **not identifiers**, and need not be unique. Without a name, an item displays as a derived label (login: the URL's host without `www.`; card: brand + last four digits). Identity is the item id; the CLI shows a short id prefix.
- **Lookup is search**: query words are ANDed, case-insensitive, over name, URL host, username, and for cards cardholder, brand and last four (never secret values). An id prefix also matches. One match: use it. Several: fail listing the candidates (short id, label, username). Scripts that must be unambiguous use the id.
- Two Google accounts are just two logins with the same URL and different usernames; nobody has to invent a naming scheme.
- `new login` without a password generates one.

## CLI
- Agent-first: every command works from flags, env (`DEADBOLT_PASSPHRASE`) and stdin (`field=-`, `--passphrase-stdin`) and never waits for a human without a TTY.
- On a TTY (stdin and stderr), it prompts only for what would otherwise be an error: passphrase, `field=-` values, missing required fields, and confirming the pairing code (`--yes` skips).
- A background agent (`deadbolt agent`, auto-started) holds the unlocked store and the iroh node; commands talk to it over a user-only Unix socket.
- `deadbolt import bitwarden [FILE]` (stdin if omitted or `-`) reads Bitwarden's unencrypted JSON export into the vault: logins and cards only; other item types, folders, favorites, attachments and password history are skipped and counted. All items are checked first, then created together in as few entries as fit (~1 MiB each). No dedupe: running it again imports everything again. Prints only a summary, never values.
- Basics only for now; convenience features (picker, history, generate, TOTP codes, `run`, clipboard, JSON output) get decided together later.

## Pairing
- New device shows a QR: its device public key + a one-time secret (+ relay hint).
- Existing device (unlocked) scans, dials it, both prove the secret, new device signs "join vault V, invited by this device", existing device signs `Add`, sends the membership log + data over the same connection.
- No camera: existing device dials via a short code, and both screens show a 6-digit code derived from the connection + both keys; the user confirms they match.

## Removing a device
Sign `Remove(B)`; it spreads to the other members as they sync. B is refused at connection time (and any open connection is closed) and can't get anything new; it keeps what it already had (inherent; prompt the user to rotate passwords it saw).

## Later (designed for, not built)
- Mailbox: add a shared vault key that encrypts entries, re-keyed on removal and wrapped to per-device X25519 keys so offline devices can pick it up from the mailbox. Entry format changes at that point.
- Recovery kit: a paper device with its own device key, added like any other device.
