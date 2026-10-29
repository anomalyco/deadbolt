# Deadbolt v1 — simplified design

2026-10-15. Supersedes `history/04-proposal-v0.md` and `history/04b-revision-no-infra.md` for v1. Constraints from dax: iroh device-to-device only (n0 relays are fine), no mailbox in v1 (but don't preclude it), no recovery — lose every device, lose the vault.

## Keys (two)
1. **Device key** (Ed25519, one per device). Is the iroh EndpointId *and* signs everything the device writes. Stored encrypted under (2).
   - Why not separate transport/signing keys: neither can live in Secure Enclave/TPM (P-256 only), both must be in RAM while the app runs, so separating them adds a key without adding protection.
2. **Local unlock key** (per device). Argon2id(passphrase); optionally also wrapped by a hardware-bound Secure Enclave key behind Touch ID (`docs/touch-id.md`, device-only, never synced) for day-to-day unlock. Encrypts the device key and the local database.

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
- `Remove(B)` records the last entry of B's log the remover had seen; anything B wrote beyond that is ignored. Removed keys can never be re-added (`Vault::add` and `Vault::apply` reject an `Add` of a removed key, and any concurrent `Add` that did not see the removal is ignored once resolved). Only a current member can be removed.
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
- Limits: an entry travels as one frame (16 MiB), so core refuses at commit an entry that would encode larger (`MAX_ENTRY_LEN`) rather than store one that can never sync; an import splits into ~1 MiB entries and fails only on an item too large on its own. A receiver hands entries on in batches of at most 64 Ki entries or 32 MiB plus one frame, so a session's size is unbounded but its memory is not, and closes a session a peer opened that runs past 60 seconds (the CLI gives up on its own after 15). A new device accepts at most 16 pairing dialers proving the ticket at once and queues 16 more.
- No compaction in v1. Deleted items stay in the history on your own devices, encrypted at rest under the local unlock key. (Later: snapshots.)

## Items
- Every item has a **type**, fixed at creation. Built-in types in v1: `login`, `card`, `note` (a secure note), `ssh` (an SSH key) and `identity`. User-defined types come later; keep the type an open identifier, not a closed enum on the wire.
- A type defines its known fields, each with a fixed field type, and which of them are required. Items may carry extra fields of any field type on top.
- Field types: `text`, `secret` (hidden unless asked), `url`, `email`, `otp` (TOTP secret: an `otpauth://totp/` URI or a bare base32 secret; shown as the current code), `month` (stored `YYYY-MM`), `date` (stored `YYYY-MM-DD`), `note` (multi-line). A known field may be marked multi-line (a secure note's body, a private key, notes) so forms and the detail pane give it lines.
- Guarantees, enforced in core on every device: an item is created in one entry that contains all required fields; a known field always has its fixed field type; required fields can't be removed; the type can't change. Ops that would break this are rejected at commit and ignored (deterministically, op by op, without rejecting the entry) at apply.
- New `otp` values must also be TOTP secrets (SHA-1/256/512, 6–8 digits; HOTP and Steam codes are refused). The agent checks this on every write and an import keeps a value that fails it as an extra secret field; entries are not held to it, so values written before the check stay valid everywhere.

| type | field | field type | required |
|---|---|---|---|
| login | password | secret | |
| | username | text | |
| | url | url | |
| | otp | otp | |
| | notes | note | |
| | sign-in-with | text (one line, at most 64 characters) | |
| | sign-in-account | text (an item id, 32 lowercase hex digits) | |
| card | number | secret (12–19 digits) | yes |
| | expiry | month | |
| | cvv | secret (3–4 digits) | |
| | cardholder | text | |
| | pin | secret | |
| | brand | text | |
| | notes | note | |
| note | notes | secret, multi-line | |
| ssh | private-key | secret, multi-line | yes |
| | public-key | text | |
| | fingerprint | text | |
| | passphrase | secret | |
| | comment | text | |
| | notes | note | |
| identity | name | text | |
| | email | email | |
| | phone | text | |
| | address | note | |
| | birthday | date | |
| | national-id | secret | |
| | passport | secret | |
| | license | secret | |
| | notes | note | |

- Card brand: the optional `brand` field, shown in the label when set. (Later: derive it from the number's prefix for major networks when the field is empty; a Luhn check as a CLI warning.)
- A login needs no password (a passkey-only or SSO account, an export's login without one); `new login` without one still generates one. No item may have neither a name nor a field (core rejects it at create), so a note or identity needs only one of them.
- Each type has one field ⏎ and `get` use by default: login password, card number, note body, SSH private key, identity email.
- **Names are optional labels on every item** (alongside the type, not one of its fields), **not identifiers**, and need not be unique. Without a name, an item displays as a derived label (login: the URL's host without `www.`; card: brand + last four digits; ssh: the comment, else "SSH key"; identity: the name, else the email). Identity is the item id; the CLI shows a short id prefix.
- **Lookup is search**: query words are ANDed, case-insensitive, over name, URL host, username, for cards cardholder, brand and last four, for SSH keys the comment and for identities the name and email (never secret values, so never a note's body). An id prefix also matches. One match: use it. Several: fail listing the candidates (short id, label, username). Scripts that must be unambiguous use the id.
- Two Google accounts are just two logins with the same URL and different usernames; nobody has to invent a naming scheme.

## CLI
- Agent-first: every command works from flags, env (`DEADBOLT_PASSPHRASE`) and stdin (`field=-`, `--passphrase-stdin`) and never waits for a human without a TTY.
- On a TTY (stdin and stderr), it prompts only for what would otherwise be an error: passphrase, `field=-` values, missing required fields, and confirming the pairing code (`--yes` skips).
- A background agent (`deadbolt agent`, auto-started) holds the unlocked store and the iroh node; commands talk to it over a user-only Unix socket.
- `deadbolt import [FILE] [--dry-run]` (stdin if omitted or `-`) imports another password manager's export into the vault: 1Password's `.1pux` or CSV, Apple Passwords' CSV, Bitwarden's unencrypted JSON, or any CSV with a password column. The client only turns the file into text (from a `.1pux` it reads only `export.data`, never the attachments); the agent detects the format and maps it. Logins, cards, secure notes, SSH keys and identities (1Password's other categories become secure notes with their fields, its ID and account numbers secret; its dates become the nearest day); documents, other item types, tags, folders, favorites, attachments and password history are skipped and counted, and a value that isn't valid for its field is kept as an extra field with a warning. Items the vault already has (a login with the same URL host, username and password, or for a login without a password the same name and every field, a card with the same number, an SSH key with the same private key, or a note or identity with the same name and every field the same) or that the export repeats are skipped, so importing again changes nothing (a login's `sign-in-account` doesn't count as content here). 1Password's "Sign in with Google" logins keep their provider as `sign-in-with`, and their link to the provider's login becomes `sign-in-account` (see `docs/autofill.md`). All items are checked first, then created together in as few entries as fit (~1 MiB each); `--dry-run` writes nothing. Prints only a summary, never values.
- `deadbolt sync 1password [--account A] [--op-vault V]... [--dry-run] [--quiet]` mirrors 1Password into the vault one way, through the 1Password CLI run by the agent (`docs/sync-1password.md`). Items map as a `.1pux` import's do. A mirrored item records its source (`1password/<account>/<vault>/<item>`) and a version (1Password's `updated_at`, a digest of what was mirrored, and for an item taken over the fields 1Password wrote) in a hidden `source` register, set at create (`Create` wire tag 2) or by `Change::Source` (tag 4). A sync adds what's new, writes only the fields that differ (1Password wins), deletes only items it created, takes over an item imported from it, one with the same content or the one login with the same username and URL (keeping fields only deadbolt has), and never touches the user's other items. The app's Settings has "Sync from 1Password"; `ItemInfo.source` names the app an item is mirrored from. Protocol 8.
- `deadbolt code <query>` prints the item's current TOTP code. The agent computes it (`ItemCode`), so the secret never leaves the agent. `show` prints the current code with its time left in the otp field's place; the secret takes `show --reveal` or `get -f` naming a field of type otp (`-f otp` asks up front; another otp field comes back empty, so `get` asks again by id). Only then does `ItemGet` carry otp secrets (`otp: true`): otherwise every field of type otp comes back empty, so the app never receives one. An import's second otp becomes an extra secret field, since only one gives codes.
- Asking for a code doesn't count as use for the idle lock (`unlock_timeout`): the app asks once a period for as long as an item shows, which would otherwise keep the vault unlocked forever. Copying one, from the app or the CLI, is the same request, so it doesn't either; the other commands around it (opening the item, `show`) do.
- `deadbolt send` hands files, a secret or vault items to anyone through a one-time link that opens in a browser (`deadbolt.pw/r`), served live by the agent from an iroh endpoint of its own until picked up, expired (default 1h) or revoked; `deadbolt sends` lists, shows and revokes them. Model, threat model and protocol: `docs/proposals/send.md`. Protocol 10.
- `deadbolt whoami` shows how the agent sees the calling process (its verified program, signature, terminal and parents, and what it claims), and `deadbolt activity [--since 1h]` lists what callers asked for and what the app showed or copied, never values. Entries are sealed in `store.redb` on this device for 90 days; those made while locked wait in memory until unlock. Nothing is refused on that basis yet (`docs/agent-control.md`). Protocol 11.
- Basics only for now; convenience features (picker, history, generate, `run`, clipboard, JSON output) get decided together later.

## Pairing
- New device shows a QR: its device public key + a one-time secret (+ relay hint).
- Existing device (unlocked) scans, dials it, both prove the secret, existing device sends the offer (vault id and name, inviter device name and addresses), both confirm the 6-digit code derived from the connection + both keys (`--yes` skips on a TTY), new device signs "join vault V, invited by this device", existing device signs `Add`, and sends the membership log + data over the same connection.
- Because the offer precedes code confirmation so the joining screen can name the vault and inviter in its prompt, a party that observed the one-time ticket can learn the offer metadata (vault id/name, inviter name/addresses) before the inviter rejects the mismatched code; neither join consent nor vault entries are sent before confirmation.

## Removing a device
Sign `Remove(B)`; it spreads to the other members as they sync. B is refused at connection time (and any open connection is closed) and can't get anything new; it keeps what it already had (inherent; prompt the user to rotate passwords it saw).

## Later (designed for, not built)
- Mailbox: add a shared vault key that encrypts entries, re-keyed on removal and wrapped to per-device X25519 keys so offline devices can pick it up from the mailbox. Entry format changes at that point.
- Recovery kit: a paper device with its own device key, added like any other device.
