# Deadbolt v1 — simplified design

2026-10-15. Supersedes `history/04-proposal-v0.md` and `history/04b-revision-no-infra.md` for v1. Constraints from dax: iroh device-to-device only (n0 relays are fine), no mailbox in v1 (but don't preclude it), no recovery — lose every device, lose the vault.

## Keys (two)
1. **Device key** (Ed25519, one per device). Is the iroh EndpointId *and* signs everything the device writes. Stored encrypted under (2).
   - Why not separate transport/signing keys: neither can live in Secure Enclave/TPM (P-256 only), both must be in RAM while the app runs, so separating them adds a key without adding protection.
2. **Local unlock key** (per device). Argon2id(passphrase); optionally also wrapped by a hardware-bound Secure Enclave key behind Touch ID (`docs/touch-id.md`, device-only, never synced) for day-to-day unlock. Encrypts the device key and the local database.

No shared vault key in v1. Data only ever moves over iroh connections (end-to-end encrypted, authenticated to device keys) between current members, and at rest it is under each device's local unlock key. Re-keying on removal would protect nothing extra: a removed device can only receive data from a member that hasn't learned of the removal, and that member would still be on the old key too.

Accepted cost: removal rests entirely on the membership check (no ciphertext fallback if that check has a bug), and adding a mailbox later means introducing a vault key + re-keying then, which changes the entry format.

Dropped from earlier drafts: shared vault key and re-keying, separate iroh key, X25519/HPKE, per-item and per-edit keys, key commitment, recovery kit + tiers, expiring heads, mailbox trait. (A PAKE came back for pairing; see Pairing.)

## Membership check (security-critical)
- One small function: "is this EndpointId in the current member set?" Applied on accept **and** on dial.
- When a `Remove` arrives, immediately close any open connection to that device, not just refuse new ones.
- On startup, sync membership with every reachable peer before serving data to anyone (shrinks the window where a long-offline device still trusts a removed one).
- Dedicated tests for all of the above.

## Membership
- Signed log of `Add(device)` / `Remove(device)` ops, each referencing the ops it saw (causal).
- Each author has a lifetime budget of **1,000 non-removal membership entries per vault**, including the creator's genesis; data has a separate log. `Remove` is exempt so an exhausted author can still revoke a compromised device, but cannot `Rename` or `Add`. Commit and apply count non-removal entries in the author's contiguous, fork-rejecting signed chain, independent of other authors' arrival order. This is a per-author bound, not a bound on Sybil devices or total membership growth. Historical over-budget histories are unavailable: the CLI retains and lists them with an error while other vaults remain usable, never silently changing the default or replacing the history; the single-vault browser reports the failure and preserves storage. Older peers can still create over-budget histories, and joining one is rejected, so mixed-version rollout needs review.
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
- Limits: an entry travels as one frame (16 MiB), so core refuses at commit an entry that would encode larger (`MAX_ENTRY_LEN`) rather than store one that can never sync; an import splits into ~1 MiB entries and fails only on an item too large on its own. A receiver hands entries on in batches of at most 64 Ki entries or 32 MiB plus one frame, so a session's size is unbounded but its memory is not, and closes a session a peer opened that runs past 60 seconds (the CLI gives up on its own after 15). A new device runs at most 16 pairing attempts at once and queues 16 more. A node allows 256 concurrent inbound handshakes with a 5-second timeout, separate from 32 established inbound sync connections reserved for authenticated members (at most two per member). Pairing uses its own bounds after handoff; outbound connections consume neither inbound budget. Sync connections close after 60 seconds idle waiting for the first or next stream, independently of each session deadline. A sender must first answer a QUIC Retry (source address validation; over a relay, only an extra round trip) before taking a handshake slot. Excess handshakes are refused before TLS (`CONNECTION_REFUSED`, which the QUIC transport can also return for its own limits); excess authenticated sync connections are closed after TLS with `BUSY` (code 9). Both surface as `Rejected` and startup retries rather than counting the peer as unreachable or contacted. Unfinished or nonmember handshakes cannot take the 32 established sync slots. These are resource bounds, not network-level DoS protection: reachable attackers can still saturate the handshake budget or network, and enough admitted members can fill the sync budget; idle expiry reclaims silent connections but does not prevent continual reconnects.
- A sender takes a fixed snapshot of the missing author chains after reading the peer’s heads (or committing the pairing admission). For each chain it keeps only its next sequence and signed last hash. The contiguous, fork-rejecting chain pins every predecessor; later appends never leak into an older transfer. A small heap merges these cursors by dependency depth, all vaults’ membership before any data. Each pull checks live authority and readiness under the state lock, encodes one entry and releases the lock before transport I/O. In ordinary sync, a resolved `Remove(peer)` drops any remaining membership and data cursors for that vault for the rest of the exchange, but only if another vault in the original exchange still admits the peer. A missing vault or pending signed tip, loss of admission without a resolved `Remove(peer)` (including a cut of the inviter’s `Add`), or a closed data gate aborts; pairing always aborts if either party loses membership. These checks prevent new pulls; they cannot retract a frame already handed to the transport. This bounds sender scratch to one frame plus frontier/metadata, not total unlocked state, concurrent transfers or transport buffers. Wire framing and receiver verification are unchanged.
- **Throughput follow-up:** encoding a single near-16 MiB entry is synchronous under the session mutex. Network I/O is outside the lock, but local callers (and the standalone vault worker) can still wait on the encode. Measure lock hold time and concurrent local request latency during large transfers before changing ownership or moving encoding off-lock; retain the per-frame live authority check and one-frame scratch bound.
- No compaction in v1. Deleted items stay in the history on your own devices, encrypted at rest under the local unlock key. (Later: snapshots.)

### Catch-up across interrupted sessions

Sync hands the first complete entry to the normal validating transaction, then
prefixes of 2, 4, 8, … entries up to the existing count/byte limits. Waiting for
`DONE` or a 32 MiB batch before publishing *anything* can strand a backlog on a
slow link: every 15 s round redials with the same heads. Doubling keeps the
number of extra transactions logarithmic on fast links. On native, each batch
still publishes changes to watchers and enforces membership. Admissions and
removals wake sync immediately. Data and vault renames for another peer wake
forwarding once at `DONE`, even if that last batch is empty or all duplicates.
A cut drops only that stream’s pending wake, not its durable prefix; periodic
anti-entropy can still send it. Neither wire framing,
peer admission, verification nor startup readiness changes. The next heads
exchange resumes at durable entries, **not** at a byte offset. An individual
frame that never completes within a session still cannot sync on that path:
a 10 MiB file takes over 100 s at 1 Mbit/s once base64-encoded. Earlier commits
of preceding entries don't solve that separate limit.

## Items
- Every item has a **type**, fixed at creation. Built-in types: `login`, `card`, `note` (a secure note), `ssh` (an SSH key), `identity`, `passkey`, `api` (an API credential), `database`, `server`, `wifi` (a Wi-Fi network), `license` (a software license), `bank` (a bank account), `document` (a file), `passport`, `driver-license`, `membership`, `crypto` (a crypto wallet) and `id-document` (a social security number, national ID card and the like). User-defined types come later; keep the type an open identifier, not a closed enum on the wire.
- A type defines its known fields, each with a fixed field type, and which of them are required. Items may carry extra fields of any field type on top.
- Field types: `text`, `secret` (hidden unless asked), `url`, `email`, `otp` (TOTP secret: an `otpauth://totp/` URI or a bare base32 secret; shown as the current code), `month` (stored `YYYY-MM`), `date` (stored `YYYY-MM-DD`), `note` (multi-line), `file` (the file's name, a line break, then its contents in standard base64; at most 10 MiB). A known field may be marked multi-line (a secure note's body, a private key, notes) so forms and the detail pane give it lines.
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
| | billing | text (an identity's item id, its billing address) | |
| note | notes | secret, multi-line | |
| ssh | private-key | secret, multi-line | yes |
| | public-key | text | |
| | fingerprint | text | |
| | passphrase | secret | |
| | comment | text | |
| | notes | note | |
| identity | honorific | text | |
| | given-name | text | |
| | additional-name | text | |
| | family-name | text | |
| | nickname | text | |
| | organization | text | |
| | job-title | text | |
| | email | email | |
| | phone | text (one line; E.164, `+15550100`, when it reads as international) | |
| | address-line1, address-line2, address-line3 | text | |
| | city | text (`address-level2`) | |
| | region | text (state, province; `address-level1`) | |
| | postal-code | text | |
| | country | text (ISO 3166-1 alpha-2, upper case) | |
| | birthday | date | |
| | national-id | secret | |
| | passport | secret | |
| | license | secret | |
| | notes | note | |
| passkey | rp-id, credential-id, user-handle | text | yes |
| | private-key | secret | yes |
| | username, display-name | text | |
| | created | date | |
| | notes | note | |
| api | credential | secret | yes |
| | username (the key id or account), type (bearer, basic, aws-access-key, ...), host, environment | text | |
| | url | url | |
| | expires | date | |
| | notes | note | |
| database | type (postgres, mysql, ...), host, database, username | text | |
| | port | text (1–5 digits) | |
| | password, connection-string | secret | |
| | notes | note | |
| server | url, admin-console | url | |
| | username | text | |
| | password | secret | |
| | notes | note | |
| wifi | ssid, security | text | |
| | password | secret | |
| | notes | note | |
| license | product, version, licensed-to, order-number | text | |
| | license-key | secret, multi-line | |
| | email | email | |
| | purchased, expires | date | |
| | notes | note | |
| bank | bank, account-holder, routing-number, swift | text | |
| | account-number, iban, pin | secret | |
| | notes | note | |
| document | file | file | yes |
| | notes | note | |
| passport | full-name, type, issuing-country, issuing-authority, nationality, sex, birthplace | text | |
| | number | secret | |
| | birthday, issued, expires | date | |
| | notes | note | |
| driver-license | full-name, class, conditions, state, country, sex, height | text | |
| | number | secret | |
| | address | note | |
| | birthday | date | |
| | expires | month | |
| | notes | note | |
| membership | organization, member-name | text | |
| | member-id (loyalty and airline numbers take over accounts), pin | secret | |
| | url | url | |
| | phone | text (as identity's) | |
| | member-since, expires | month | |
| | notes | note | |
| crypto | recovery-phrase | secret, multi-line | |
| | password | secret | |
| | address, network | text | |
| | notes | note | |
| id-document | full-name, type, country | text | |
| | number | secret | |
| | issued, expires | date | |
| | notes | note | |

- Documents' countries are free text, as the documents print them, unlike an identity's ISO code; their numbers are secret. Dates follow what 1Password stores: a driver's license's and a membership's expiry are months, a passport's a day.
- **Files.** A `document` holds one file; any item can carry more as extra fields of type `file` (attachments). A file is encrypted like any other value (in the entry, under each device's local unlock key at rest, in iroh in transit) and travels in the item's entry, so it needs no blob store or chunking: an item's files hold at most 10 MiB together (`item::MAX_FILE`), whose base64 (13.3 MiB) leaves room under the 16 MiB entry and frame limit. Core holds every create to that everywhere and every change when it's written (`Vault::write`); applying a synced entry doesn't, so two devices' concurrent files can together go past it (each device still kept its own write under it). An import keeps an item's files to 10 MiB too, dropping and counting the rest. More would need chunking across entries, which isn't built. The cap is what keeps a vault from becoming a blob store, because **every version of a file stays**: replacing or removing a file leaves the old one in the item's history, on disk (encrypted) and in each device's memory while it's unlocked, since there's no compaction yet; ten edits of a 10 MiB document cost 100 MiB. Values are canonical base64 (one encoding per file) and names have no `/`, `\` or `:`. The agent lists a file field as its name alone; its contents leave only for `ItemGet` naming that field in `files` (`deadbolt get -f`, the app's Save…), one at a time. `deadbolt get -o` and Save… write to a new 0600 file beside the target and rename it over, so a symlink there is replaced, not followed, and an older file's mode doesn't carry over. In `deadbolt run`, `inject` and `read` (`deadbolt://` references) a file field goes only to `inject -o`, decoded, when the template is that one reference; `run` and `read` refuse it.

- An identity is a person's details as web forms ask for them (docs/autofill.md, "Forms"), named after the HTML autocomplete tokens, so the browser extension maps fields without guessing; people keep several (Home, Work), told apart by name. The agent writes an international phone number in E.164 form and a country code in upper case whatever was typed; core refuses `+1 555 0100` (store `+15550100`) and anything but an assigned alpha-2 code. Identities made before names and addresses had parts keep their one-line `name` and multi-line `address` as extra fields, shown and searched as before; an import or a sync from 1Password writes the parts.
- Card brand: the optional `brand` field, shown in the label when set. (Later: derive it from the number's prefix for major networks when the field is empty; a Luhn check as a CLI warning.)
- A login needs no password (a passkey-only or SSO account, an export's login without one); `new login` without one still generates one. No item may have neither a name nor a field (core rejects it at create), so a note or identity needs only one of them.
- Each type has one field ⏎ and `get` use by default: login, database, server and Wi-Fi password, card, passport, driver's license and ID number, note body, SSH private key, identity email, passkey username, API credential, license key, bank account number, document file (`get` writes it out; the app saves it), membership id, wallet recovery phrase.
- **Names are optional labels on every item** (alongside the type, not one of its fields), **not identifiers**, and need not be unique. Without a name, an item displays as a derived label (login: the URL's host without `www.`; card: brand + last four digits; ssh: the comment, else "SSH key"; identity: given and family name, else the nickname, else an old one-line `name`, else the email; API credential: the URL's host, else its host; database: "database on host"; server: its URL's host; Wi-Fi: the SSID; license: the product; bank account: the bank; document: the file's name; passport, driver's license, ID: the full name; membership: the organization; wallet: the network). Identity is the item id; the CLI shows a short id prefix.
- **Lookup is search**: query words are ANDed, case-insensitive, over name, URL host, username, for cards cardholder, brand and last four, for SSH keys the comment, for identities the name parts, organization, email and phone, for the other types their plain identifying fields (an API credential's type, host and environment, a database's type, host and database, a Wi-Fi network's SSID, a license's product, licensee and email, a bank, a holder, a full name, an organization, a wallet's address), and every file's name (never secret values, so never a note's body). An id prefix also matches. One match: use it. Several: fail listing the candidates (short id, label, username). Scripts that must be unambiguous use the id.
- After a single-item write the CLI computes its displayed short id from the nearest preceding and following live ids. It does not materialize the rest of the vault just to format that reply. A live edit, unset or deletion still searches the vault when given a query, but inspects one item at a time rather than keeping a copy of every secret; ambiguous queries retain just the rows in the error.
- Two Google accounts are just two logins with the same URL and different usernames; nobody has to invent a naming scheme.

## CLI
- Agent-first: every command works from flags, env (`DEADBOLT_PASSPHRASE`) and stdin (`field=-`, `--passphrase-stdin`) and never waits for a human without a TTY.
- On a TTY (stdin and stderr), it prompts only for what would otherwise be an error: passphrase, `field=-` values, missing required fields, and which vault `pair` adds to when the device holds several and `--vault` is missing.
- A background agent (`deadbolt agent`, auto-started) holds the unlocked store and the iroh node; commands talk to it over a user-only Unix socket.
- `deadbolt import [FILE] [--dry-run]` (stdin if omitted or `-`) imports another password manager's export into the vault: 1Password's `.1pux` or CSV, Apple Passwords' CSV, Bitwarden's unencrypted JSON, or any CSV with a password column. The client only turns the file into text, and from a `.1pux` also reads the files under `files/` that `export.data` names (documents and attachments, at most 10 MiB each, not icons or avatars) into the request beside it; the agent detects the format and maps it. 1Password's categories map to their types: logins and passwords, cards, secure notes, SSH keys, identities, API credentials, databases, servers, Wi-Fi routers (`wifi`), software licenses, bank accounts, documents, passports, driver's licenses, memberships, crypto wallets and social security numbers (`id-document`); an API credential without a credential, outdoor licenses, reward programs, email accounts and medical records become secure notes with their fields kept; a field a type doesn't know stays an extra field, a value that doesn't fit its field stays as an extra field with a warning, ID and account numbers are secret and dates become the nearest day. Attachments become file fields; a document or attachment missing from the export or over 10 MiB is skipped or dropped and counted. API credentials imported as logins before stay logins. Bitwarden's and CSV exports have no types beyond logins, cards, notes, identities and SSH keys and no attachments, so they map as before. Favorites and tags (including Bitwarden folders and collections, and `/` hierarchies) carry over; unsupported item types and password history are skipped and counted, and a value that isn't valid for its field is kept as an extra field with a warning. Items the vault already has (a login with the same URL host, username and password, or for a login without a password the same name and every field, a card with the same number, an SSH key with the same private key, or a note or identity with the same name and every field the same) or that the export repeats are skipped, so importing again changes nothing (a login's `sign-in-account` doesn't count as content here). 1Password's "Sign in with Google" logins keep their provider as `sign-in-with`, and their link to the provider's login becomes `sign-in-account` (see `docs/autofill.md`). All items are checked first, then created together in as few entries as fit (~1 MiB each); `--dry-run` writes nothing. Prints only a summary, never values.
- `deadbolt sync 1password [--account A] [--op-vault V]... [--dry-run] [--quiet]` mirrors 1Password into the vault one way, through the 1Password CLI run by the agent (`docs/sync-1password.md`). Items map as a `.1pux` import's do. A mirrored item records its source (`1password/<account>/<vault>/<item>`) and a version (1Password's `updated_at`, a digest of what was mirrored, and for an item taken over the fields 1Password wrote) in a hidden `source` register, set at create (`Create` wire tag 2) or by `Change::Source` (tag 4). A sync adds what's new, writes only the fields that differ (1Password wins), deletes only items it created, takes over an item imported from it, one with the same content or the one login with the same username and URL (keeping fields only deadbolt has), and never touches the user's other items. The app's Settings has "Sync from 1Password"; `ItemInfo.source` names the app an item is mirrored from. Protocol 8.
- `deadbolt code <query>` prints the item's current TOTP code. The agent computes it (`ItemCode`), so the secret never leaves the agent. `show` prints the current code with its time left in the otp field's place; the secret takes `show --reveal` or `get -f` naming a field of type otp (`-f otp` asks up front; another otp field comes back empty, so `get` asks again by id). Only then does `ItemGet` carry otp secrets (`otp: true`): otherwise every field of type otp comes back empty, so the app never receives one. An import's second otp becomes an extra secret field, since only one gives codes.
- Asking for a code doesn't count as use for the idle lock (`unlock_timeout`): the app asks once a period for as long as an item shows, which would otherwise keep the vault unlocked forever. Copying one, from the app or the CLI, is the same request, so it doesn't either; the other commands around it (opening the item, `show`) do.
- `deadbolt send` hands files, a secret or vault items to anyone through a one-time link that opens in a browser (`deadbolt.pw/r`), served live by the agent from an iroh endpoint of its own until picked up, expired (default 1h) or revoked; `deadbolt send ls`, `show` and `revoke` list, show and revoke them. Model, threat model and protocol: `docs/proposals/send.md`. Protocol 10.
- `deadbolt debug whoami` shows how the agent sees the calling process (its verified program, signature, terminal and parents, and what it claims), and `deadbolt activity [--since 1h]` lists what callers asked for and what the app showed or copied, never values. Entries are sealed in `store.redb` on this device for 90 days; those made while locked wait in memory until unlock. Nothing is refused on that basis yet (`docs/agent-control.md`). Protocol 11.
- The browser fills forms from identities and cards (`form-items`, `form-fill`; `docs/autofill.md`, "Forms"): metadata only in the list, only the fields asked in a fill, Touch ID for a card's number or code when it's on. Protocol 16.
- File fields take a path on the command line (`deadbolt new document file=./scan.pdf`, `deadbolt set github recovery:file=./codes.pdf`); the client reads the file (at most 10 MiB). `deadbolt get` writes a file field's contents to `-o FILE` (mode 0600), or to stdout when it isn't a terminal. `ItemGet` carries files' contents only with `files`; `Import` carries a `.1pux`'s attachments in `files`. Protocol 19.
- Items carry encrypted `favorite` (causal LWW register; `Create` tag 3, `Change::Favorite` tag 7) and nested `/` `tags` (add-wins OR-Set; `Change::TagAdd` tag 8, `Change::TagRemove` tag 9; `docs/favorites-tags.md`). Favorites sort first across CLI (`ls` / `items`), app, quick panel, autofill, forms and passkeys; `#work` matches `work` and `work/*`, `deadbolt tags` lists counts, and `⌘D` toggles favorite. Protocol 22.
- Basics only for now; convenience features (picker, history, generate, `run`, clipboard, JSON output) get decided together later.

## Pairing
One command per device and one code, typed once:

```
new$ deadbolt join
Code: violin-garden-tiger-lamp-zoo
On a device with your vault, run: deadbolt pair violin-garden-tiger-lamp-zoo
waiting…
✓ joined "personal" from laptop
Passphrase for this device: ••••   (Again: ••••)

laptop$ deadbolt pair violin-garden-tiger-lamp-zoo
✓ added "desktop" to personal
```

- **Code.** Five words from the BIP-39 English list (2048 words, `crates/net/src/words.txt`), drawn with the OS CSPRNG: 55 bits. Lowercase and hyphenated when shown; parsing ignores case and takes spaces or hyphens. It works once, for 5 minutes, and only while `deadbolt join` waits.
- **Rendezvous** (`crates/net/src/rendezvous.rs`). Both devices derive an Ed25519 key from the whole code with Argon2id (64 MiB, 6 passes, salt `deadbolt/pair/3 rendezvous` followed by the six-hour UTC bucket (`floor(Unix seconds / 21600)`, big-endian u64); about 0.1 s on a desktop, well under a second on a laptop). The new device signs a pkarr record under that key holding its endpoint id and addresses and publishes it to n0's pkarr relay, the same server iroh's own address lookup uses (`PkarrRelayClient`; a pkarr relay takes a signed packet for any key, not only an endpoint's). The listener freezes its bucket when the code starts, including across a boundary. The existing device tries the current, preceding and following bucket keys in that order, deriving each lazily and caching it for the attempt, and retains the matched key for PAKE. This tolerates crossing a boundary and clocks falling into adjacent buckets; record-age and five-minute code-expiry checks still apply, so large clock skew can still fail and code lifetime is not extended. There is no public nameplate: nothing published names the code, and only a holder of the code can compute the key. When the code is used, burnt or ends, the record is replaced with one saying `used` or `closed`, so a late existing device says so. The record names the new device's endpoint id and addresses to whoever resolves it, as the QR ticket did.
- **PAKE** (`crates/net/src/pair.rs`). Over the iroh connection (authenticated to both device keys by TLS), the existing device sends the rendezvous public key and its SPAKE2 message (RustCrypto `spake2`, Ed25519 group, identities A = dialer and B = listener endpoint ids); the new device answers with its own. Each side derives `K = HMAC-SHA256(SPAKE2 key, "deadbolt/pair/3" ‖ listener id ‖ dialer id ‖ TLS exporter)`, so K holds only on this connection between these two keys, and they confirm it (`HMAC(K, "dialer-confirm")`, then `HMAC(K, "listener-confirm")`) before anything else. Only then does the existing device send the offer (vault id and name, its name and addresses), the new device sign its consent ("join vault V, invited by this device"), and the existing device sign `Add` and send the membership log and data over the same connection, ending with the new device's receipt. A party without the code learns nothing about the vault or the inviter.
- **One guess, single use.** The first attempt to complete the PAKE ends the code: with a pairing if its confirmation holds; if not, the code is burnt and the new device fails loudly ("a device tried a wrong code… run `deadbolt join` again"). An attacker therefore gets one guess per code: 2^-55. Burning costs the legitimate user nothing, because a mistyped code derives another rendezvous key and finds no device at all ("no device is waiting for that code"); only someone who reached the new device without the code can fail the confirmation. A dialer naming an older code of the same device is turned away without spending the current one. Anyone arriving after the code was used hears "pairing failed: that code was already used. If it wasn't you, someone else may have used it". Codes expire after 5 minutes; dialers that never finish are bounded as before (16 running, 16 queued, 30 s each).
- **Offline guessing and precomputation.** Whoever sees a record (the relay operator, or anyone who learns the key) can test guesses offline, each costing one Argon2id evaluation with 64 MiB and 6 passes. The previous fixed salt allowed one table over the entire four-word space to be reused against every code indefinitely: the five-minute lifetime did not bound work done in advance. Six-hour salt buckets stop reuse across buckets, but are predictable, **not random per-code salts**: an attacker can precompute future buckets and amortize work across all codes within one bucket. We therefore also add a fifth word (55 bits), multiplying that work by 2,048 for one extra typed word. Covering half of 2^55 codes takes 1.8·10^16 evaluations. At the deliberately generous estimate of 5,000 evaluations/second/GPU (~2 TB/s over at least 384 MiB/evaluation), this is about 114,000 GPU-years per bucket, or 12 billion GPUs inside five minutes; even spreading it over six hours needs about 167 million GPUs. These are illustrative bandwidth-based estimates, not measured hardware guarantees. A table for salt bucket N does not derive keys salted with N−1 or N+1. However, resolvers in N−1, N and N+1 all try N, so the table has an **18-hour lookup window** (about 56 million GPUs if the illustrative computation is spread over that whole window). Record age and five-minute code expiry still apply: finding an expired code cannot admit a device, but can link an archived record to that code. Salt rotation does not provide forward secrecy or remove the need for PAKE and expiry.
- **Version mismatch.** Agent↔client protocol **23** replaces 21 and 22 (22 was used by favorites/tags before pairing v3) so a new CLI replaces a still-running old agent rather than displaying four-word codes or handing it five-word codes. Pairing ALPN, key-derivation domain and TLS exporter are version 3. Four-word codes fail locally with instructions to update both devices and generate a new code; old clients reject five-word codes. Raw version-2 QUIC attempts fail ALPN negotiation, rather than waiting for a PAKE. No fixed-salt fallback is published or resolved.
- **Welcome replay.** The joiner decodes directly into a private vault, verifying genesis and applying each signed entry as it arrives. Only `DONE` and final checks of the offered vault and both memberships permit adoption or a success receipt. A cut drops the prefix. The verified vault still occupies memory; when saved, one transaction encodes and seals one entry at a time.
- **Passphrase last.** A new device joins on a node of its own with a fresh device key and keeps the key and the received vault in memory only (`Fresh` in `crates/cli/src/agent/pairing.rs`). Once paired, the CLI asks for the device's passphrase (twice) and the agent creates the store with that key and stores the vault; `DEADBOLT_PASSPHRASE` or `--passphrase-stdin` given up front is used instead, and without either and without a terminal `join` fails before showing a code. Aborting at the prompt, or the client going away, discards everything; nothing unencrypted touches disk. The device name defaults to the hostname (`--device-name`). A device that is already set up joins with its own key and stores the vault as it arrives (unlocking inline first, as other commands do).
- **Half-finished joins.** The existing device commits `Add` before it sends the welcome, because an entry it signed but didn't keep could collide with its next one. So a new device that never stores the vault (the passphrase step abandoned, a crash) remains a member that was never seen; `devices` shows it as such and `devices remove` removes it. A set-up device whose earlier join was admitted but not stored can pair again: the existing device re-sends the welcome without a second `Add`. A removed device can't rejoin.
- **`pair` targets** the default vault, or `--vault`; with several vaults and no `--vault` it asks on a terminal and fails without one.
- **Residual risk.** The code is the only secret. Anyone who sees it while it is live (over a shoulder, in a screen share, in a shell history synced elsewhere) and uses it first can pose as the new device: they get the vault. The legitimate existing device then fails loudly as above, and the new device shows the vault and inviter it joined, which it reports before the passphrase prompt. Conversely, anyone who sees the code can pose as the inviter and pair the new device into a vault of theirs; the new device shows that vault's name and inviter. The `spake2` crate is a RustCrypto pre-release (0.5.0-pre.0, chosen because it shares this workspace's curve25519-dalek 5 / sha2 0.11 stack) and unaudited, as was 0.4. Pairing ALPN `deadbolt/pair/3`.

## Removing a device
Sign `Remove(B)`; it spreads to the other members as they sync. B is refused at connection time (and any open connection is closed) and can't get anything new; it keeps what it already had (inherent; prompt the user to rotate passwords it saw).

## Later (designed for, not built)
- Mailbox: add a shared vault key that encrypts entries, re-keyed on removal and wrapped to per-device X25519 keys so offline devices can pick it up from the mailbox. Entry format changes at that point.
- Recovery kit: a paper device with its own device key, added like any other device.
