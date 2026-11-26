# Deadbolt v2 — design

Deadbolt is a local-first password manager in Rust with signed `DBF2` frames, epoch-encrypted vault data, a `class = 0` 24-word recovery root, crash-safe append-only on-disk storage (`deadbolt-pack`), direct iroh sync plus optional blind HTTP remote sync (`deadbolt-remote`), process-level capability and taint isolation (`CapTable`, `TaintTable`, `deadbolt broker`, `deadbolt mcp`), and a zero-KDF read-only pack viewer (`deadbolt-viewer`) for mobile AutoFill extensions.

## Keys
1. **Device seed & derived device keys** (`crates/core/src/v2/crypto.rs`). Each device generates a 32-byte seed from which domain-separated BLAKE3 KDFs derive three distinct keys:
   - `D_sign` (Ed25519): signs `DBF2` frames and join/recovery consents.
   - `D_kem` (X25519): receives wrapped epoch keys (`X25519Wrap`) and sealed `outbox/` saves from mobile viewers.
   - `D_net` (Ed25519, distinct from `D_sign`): authenticates the device's iroh transport endpoint.
2. **Local device root & unlock slots** (`crates/cli/src/disk.rs`). A random 256-bit device root seals `device/local-<m>.sealed` (holding the device seed and per-vault rollback anchors), each vault's `v/<vault>/local-<m>.sealed`, and `device/activity-<k>.log`. The device root is wrapped under Argon2id(passphrase) in the local state header and optionally also in `device/biometric.slot` behind a macOS Secure Enclave key (`docs/touch-id.md`, device-only, never synced). While unlocked, the root and seed live in `deadbolt_os::mem::LockedSecret` pages locked in RAM and zeroized on drop.
3. **24-word recovery root (`class = 0`).** Each vault has a 256-bit BIP-39 recovery kit (`RecoverySecret`) whose derived Ed25519/X25519 keys sit at `class = 0`, outranking ordinary devices (`class = 1`). Every clean-tip epoch wraps its epoch key to the current recovery root so a user who loses every device can recover the vault and mint a fresh lineage, and `RotateRecovery` lets active devices rotate the recovery root with consent.

## Signed `DBF2` frames, `X25519Wrap` clean-tip epochs, and back-links
- Every vault event is a canonical, Ed25519-signed `DBF2` frame (`crates/core/src/v2/frame.rs`) split across two logs: plaintext-signed `Member` frames (`members.log`) and epoch-encrypted `Data` / `Checkpoint` frames (`wal-<n>.log`).
- **Epoch encryption & `X25519Wrap`:** `Data` bodies are Padmé-padded (`PADME_FLOOR = 256`) and XChaCha20-Poly1305-sealed under `K_data(e)`, derived from an `EpochKey` `K_e` (`SUITE_X25519_WRAP`, with `SUITE_XWING_RESERVED` reserved for future hybrid PQ). Each `Rotate` or `Create` mints a fresh epoch, commits to `K_e` via `commit = KDF("epoch commit", ...)`, and wraps `K_e` to every current member's `D_kem` and the recovery root.
- **Clean-tip epochs & back-links:** removing a device triggers a clean-tip epoch rotation so future writes are cryptographically unreadable to the removed device even over an untrusted store or relay. Each rotation seals encrypted back-links (`K_back(e)`) to predecessor epoch keys so authorized members and newly joined devices can decrypt historical frames without re-encrypting the log; `Rewrap` frames deliver keys to devices that need them.
- **Equivocation & causal ordering:** `FraudProof` detects a device signing two distinct frames at the same `(author, seq)`. Data frames carry delta clocks (`DeltaClock`) and fold deterministically (`crates/core/src/v2/fold.rs`) in any arrival order without wall-clock timestamps.

## Membership & recovery-lineage resolver
- Signed `Member` ops (`Create`, `Add` with join consent, `Remove`, `Rotate`, `Rewrap`, `RotateRecovery`) form a causal DAG resolved by `crates/core/src/v2/membership.rs`.
- The `class = 0` recovery root outranks ordinary devices in conflict resolution; among ordinary devices, seniority and recovery-lineage rules resolve mutual removals deterministically. Removed keys can never be re-added.
- `check_parking` parks local writes when the device detects unresolved epochs, missing keys (`Error::AwaitingKeys`), or verified fraud, preventing silent forks until reconciled.
- **Transport membership gate (`crates/net`):** one check ("is this peer's `D_net` a current member?") runs on accept and on dial. When a `Remove` arrives, open connections to that device close immediately. On startup, membership syncs with reachable peers before serving data.

## On-disk storage (`deadbolt-pack`, W1–W6)
Local persistence lives in `crates/pack` and `crates/cli/src/disk.rs` (no embedded SQL/B-tree database). Directories are `0700`, files `0600`:

```text
<data>/
  device/
    local-<m>.sealed          device seed + metadata + per-vault rollback anchors (passphrase slot in header)
    biometric.slot            device root wrapped under Secure Enclave key + opaque token
    activity-<k>.log          sealed Activity rows (90-day retention)
    LOCK                      single-writer lock
  v/<vault>/
    members.log               Member frames, append-only, never compacted
    gen-<n>.pack              immutable checkpoint pack (head/secret split, byte-identical to remote p/<pack_hash>)
    wal-<n>.log               Data and Checkpoint frames written or received after generation n
    blob/<hash>               content-addressed attachments
    local-<m>.sealed          vault-local state (parking memory, remote config/credentials)
    outbox/<rand>.wrap        offline saves sealed to the app's D_kem (e.g. from deadbolt-viewer)
    LOCK                      single-writer lock; readers never take it
```

Enforced crash rules:
- **W1** create-new, append, and delete only — never rename or overwrite (`Blocks`).
- **W2** the commit point is the fsync of an appended record.
- **W3** reopen from the newest verifying pack, then replay every WAL.
- **W4** a torn trailing record is truncated; corruption before a valid record fails with `CorruptLog`.
- **W5** compaction writes and syncs the new generation before deleting the old.
- **W6** readers (`VaultReader`, `PackReader`) take no lock.
Local state commits use alternating `local-<m>.sealed` files guarded by a two-phase rollback anchor.

## Sync: direct iroh & blind HTTP remote (`deadbolt-remote`)
- **Direct iroh sync (`crates/net`):** devices exchange heads and stream missing `DBF2` frames (membership before data) over authenticated QUIC connections with bounded handshakes (256, 5 s timeout, QUIC Retry), bounded authenticated sync slots (32 total, 2 per member, 60 s idle close), and one-frame sender scratch.
- **Blind HTTP remote sync (`crates/remote`):** optional four-verb `ObjStore` (create-only `PUT`, ranged `GET`, sorted `LIST`, idempotent `DELETE`) over S3/R2 (SigV4) or WebDAV. The remote sees only signed/sealed `DBF2` frames and immutable `gen-<n>.pack` checkpoints — never plaintext items, field names, or keys. `deadbolt-remote` includes a push/pull planner, rollback/withholding/self-rollback detection, and store-backed Deadbolt Send.
- **Checkpoints & GC (`crates/core/src/v2/{checkpoint,gc}`):** once WAL bytes or frame counts pass compaction thresholds, devices emit signed `Checkpoint` frames pointing to immutable `gen-<n>.pack` snapshots and reclaim superseded logs after a grace window.

## Zero-KDF mobile reader (`deadbolt-viewer`)
`crates/viewer` reads a single `gen-<n>.pack` directly inside memory-constrained mobile AutoFill extensions using pack-scoped keys (`K_pack`, `K_ix`, never `K_e` or `D_sign`), and seals offline saves to the host app's `D_kem` into `outbox/`. A lockfile test (`crates/viewer/src/tests/deps.rs`) enforces that `argon2`, `tokio`, `iroh`, `reqwest`, `hyper`, `redb`, `rune`, `wgpu`, and `deadbolt-net` never enter its dependency graph.

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
- New `otp` values must also be TOTP secrets (SHA-1/256/512, 6–8 digits; HOTP and Steam codes are refused). The daemon checks this on every write and an import keeps a value that fails it as an extra secret field; entries are not held to it, so values written before the check stay valid everywhere.

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
- **Files.** A `document` holds one file; any item can carry more as extra fields of type `file` (attachments). A file is encrypted like any other value (in the entry, under each device's local unlock key at rest, in iroh in transit) and travels in the item's entry, so it needs no blob store or chunking: an item's files hold at most 10 MiB together (`item::MAX_FILE`), whose base64 (13.3 MiB) leaves room under the 16 MiB entry and frame limit. Core holds every create to that everywhere and every change when it's written (`Vault::write`); applying a synced entry doesn't, so two devices' concurrent files can together go past it (each device still kept its own write under it). An import keeps an item's files to 10 MiB too, dropping and counting the rest. More would need chunking across entries, which isn't built. The cap is what keeps a vault from becoming a blob store, because **every version of a file stays**: replacing or removing a file leaves the old one in the item's history, on disk (encrypted) and in each device's memory while it's unlocked. A desktop keeps that full history locally; checkpoints (`gen-<n>.pack`) and remote GC only compact a remote store's old frames once a checkpoint covers them ("Checkpoints & GC" above). Ten edits of a 10 MiB document cost 100 MiB on each device. Values are canonical base64 (one encoding per file) and names have no `/`, `\` or `:`. The daemon lists a file field as its name alone; its contents leave only for `ItemGet` naming that field in `files` (`deadbolt get -f`, the app's Save…), one at a time. `deadbolt get -o` and Save… write to a new 0600 file beside the target and rename it over, so a symlink there is replaced, not followed, and an older file's mode doesn't carry over. In `deadbolt run`, `inject` and `read` (`deadbolt://` references) a file field goes only to `inject -o`, decoded, when the template is that one reference; `run` and `read` refuse it.

- An identity is a person's details as web forms ask for them (docs/autofill.md, "Forms"), named after the HTML autocomplete tokens, so the browser extension maps fields without guessing; people keep several (Home, Work), told apart by name. The daemon writes an international phone number in E.164 form and a country code in upper case whatever was typed; core refuses `+1 555 0100` (store `+15550100`) and anything but an assigned alpha-2 code. Identities made before names and addresses had parts keep their one-line `name` and multi-line `address` as extra fields, shown and searched as before; an import or a sync from 1Password writes the parts.
- Card brand: the optional `brand` field, shown in the label when set. (Later: derive it from the number's prefix for major networks when the field is empty; a Luhn check as a CLI warning.)
- A login needs no password (a passkey-only or SSO account, an export's login without one); `new login` without one still generates one. No item may have neither a name nor a field (core rejects it at create), so a note or identity needs only one of them.
- Each type has one field ⏎ and `get` use by default: login, database, server and Wi-Fi password, card, passport, driver's license and ID number, note body, SSH private key, identity email, passkey username, API credential, license key, bank account number, document file (`get` writes it out; the app saves it), membership id, wallet recovery phrase.
- **Names are optional labels on every item** (alongside the type, not one of its fields), **not identifiers**, and need not be unique. Without a name, an item displays as a derived label (login: the URL's host without `www.`; card: brand + last four digits; ssh: the comment, else "SSH key"; identity: given and family name, else the nickname, else an old one-line `name`, else the email; API credential: the URL's host, else its host; database: "database on host"; server: its URL's host; Wi-Fi: the SSID; license: the product; bank account: the bank; document: the file's name; passport, driver's license, ID: the full name; membership: the organization; wallet: the network). Identity is the item id; the CLI shows a short id prefix.
- **Lookup is search**: query words are ANDed, case-insensitive, over name, URL host, username, for cards cardholder, brand and last four, for SSH keys the comment, for identities the name parts, organization, email and phone, for the other types their plain identifying fields (an API credential's type, host and environment, a database's type, host and database, a Wi-Fi network's SSID, a license's product, licensee and email, a bank, a holder, a full name, an organization, a wallet's address), and every file's name (never secret values, so never a note's body). An id prefix also matches. One match: use it. Several: fail listing the candidates (short id, label, username). Scripts that must be unambiguous use the id.
- After a single-item write the CLI computes its displayed short id from the nearest preceding and following live ids. It does not materialize the rest of the vault just to format that reply. A live edit, unset or deletion still searches the vault when given a query, but inspects one item at a time rather than keeping a copy of every secret; ambiguous queries retain just the rows in the error.
- Two Google accounts are just two logins with the same URL and different usernames; nobody has to invent a naming scheme.

## CLI
- Agent-first: every command works from flags, env (`DEADBOLT_PASSPHRASE`) and stdin (`field=-`, `--passphrase-stdin`) and never waits for a human without a TTY.
- On a TTY (stdin and stderr), it prompts only for what would otherwise be an error: passphrase, `field=-` values, missing required fields, and which vault `approve` adds to when the device holds several and `--vault` is missing.
- A background daemon (`deadbolt daemon`, hidden, auto-started) holds the unlocked store and the iroh node; commands talk to it over a user-only Unix socket (`daemon.sock`). `deadbolt debug daemon` says whether it runs and is locked, `deadbolt debug daemon stop` stops it. It was called the agent until the rename: a new daemon stops one still on `agent.sock`, and `deadbolt agent` still runs the daemon, linking `agent.sock` to ours, for an older build's `deadbolt update` that restarts it under that name (`crates/cli/src/daemon/legacy.rs`).
- `deadbolt import [FILE] [--dry-run]` (stdin if omitted or `-`) imports another password manager's export into the vault: 1Password's `.1pux` or CSV, Apple Passwords' CSV, Bitwarden's unencrypted JSON, or any CSV with a password column. The client only turns the file into text, and from a `.1pux` also reads the files under `files/` that `export.data` names (documents and attachments, at most 10 MiB each, not icons or avatars) into the request beside it; the daemon detects the format and maps it. 1Password's categories map to their types: logins and passwords, cards, secure notes, SSH keys, identities, API credentials, databases, servers, Wi-Fi routers (`wifi`), software licenses, bank accounts, documents, passports, driver's licenses, memberships, crypto wallets and social security numbers (`id-document`); an API credential without a credential, outdoor licenses, reward programs, email accounts and medical records become secure notes with their fields kept; a field a type doesn't know stays an extra field, a value that doesn't fit its field stays as an extra field with a warning, ID and account numbers are secret and dates become the nearest day. Attachments become file fields; a document or attachment missing from the export or over 10 MiB is skipped or dropped and counted. API credentials imported as logins before stay logins. Bitwarden's and CSV exports have no types beyond logins, cards, notes, identities and SSH keys and no attachments, so they map as before. Favorites and tags (including Bitwarden folders and collections, and `/` hierarchies) carry over; unsupported item types and password history are skipped and counted, and a value that isn't valid for its field is kept as an extra field with a warning. Items the vault already has (a login with the same URL host, username and password, or for a login without a password the same name and every field, a card with the same number, an SSH key with the same private key, or a note or identity with the same name and every field the same) or that the export repeats are skipped, so importing again changes nothing (a login's `sign-in-account` doesn't count as content here). 1Password's "Sign in with Google" logins keep their provider as `sign-in-with`, and their link to the provider's login becomes `sign-in-account` (see `docs/autofill.md`). All items are checked first, then created together in as few entries as fit (~1 MiB each); `--dry-run` writes nothing. Prints only a summary, never values.
- 1Password comes in once, with `deadbolt import <export>.1pux` (`docs/sync-1password.md`). An imported item records its source (`1password/<account>/<vault>/<item>`) and a version in a hidden `source` register, set at create (`Create` wire tag 2) or by `Change::Source` (tag 4), so importing the same export again adds only what is new. The live `deadbolt sync 1password` mirror was retired (protocol 29).
- `deadbolt code <query>` prints the item's current TOTP code. The daemon computes it (`ItemCode`), so the secret never leaves the daemon. `show` prints the current code with its time left in the otp field's place; the secret takes `show --reveal` or `get -f` naming a field of type otp (`-f otp` asks up front; another otp field comes back empty, so `get` asks again by id). Only then does `ItemGet` carry otp secrets (`otp: true`): otherwise every field of type otp comes back empty, so the app never receives one. An import's second otp becomes an extra secret field, since only one gives codes.
- Asking for a code doesn't count as use for the idle lock (`unlock_timeout`): the app asks once a period for as long as an item shows, which would otherwise keep the vault unlocked forever. Copying one, from the app or the CLI, is the same request, so it doesn't either; the other commands around it (opening the item, `show`) do.
- `deadbolt send` hands files, a secret or vault items to anyone through a one-time link that opens in a browser (`deadbolt.pw/r`), served live by the daemon from an iroh endpoint of its own until picked up, expired (default 1h) or revoked; `deadbolt send ls`, `show` and `revoke` list, show and revoke them. Model, threat model and protocol: `docs/proposals/send.md`. Protocol 10.
- `deadbolt debug whoami` shows how the daemon sees the calling process (its class, verified program, signature, terminal and parents), and `deadbolt activity [--since 1h]` lists what callers asked for and what the app showed or copied, never values. Entries are sealed in `device/activity-<k>.log` on this device for 90 days; those made while locked wait in memory until unlock. See "Callers" below.
- `deadbolt run`, `inject` and `read` put values where a command needs them by reference (`deadbolt://vault/item/field`), masked in `run`'s output (`docs/secrets.md`). Protocol 18.
- The browser fills forms from identities and cards (`form-items`, `form-fill`; `docs/autofill.md`, "Forms"): metadata only in the list, only the fields asked in a fill, Touch ID for a card's number or code when it's on. Protocol 16.
- File fields take a path on the command line (`deadbolt new document file=./scan.pdf`, `deadbolt set github recovery:file=./codes.pdf`); the client reads the file (at most 10 MiB). `deadbolt get` writes a file field's contents to `-o FILE` (mode 0600), or to stdout when it isn't a terminal. `ItemGet` carries files' contents only with `files`; `Import` carries a `.1pux`'s attachments in `files`. Protocol 19.
- Items carry encrypted `favorite` (causal LWW register; `Create` tag 3, `Change::Favorite` tag 7) and nested `/` `tags` (add-wins OR-Set; `Change::TagAdd` tag 8, `Change::TagRemove` tag 9; `docs/favorites-tags.md`). Favorites sort first across CLI (`ls` / `items`), app, quick panel, autofill, forms and passkeys; `#work` matches `work` and `work/*`, `deadbolt tags` lists counts, and `⌘D` toggles favorite. Protocol 22.
- Basics only for now; convenience features (picker, history, generate, clipboard, JSON output) get decided together later.

## Callers (threat model)

**While unlocked, any process running as this user can read the vault. Lock it (or rely on the idle lock) when you're away.**

- The daemon's socket is user-only, and the daemon answers anything that connects as this user the same way: a person in a terminal, a script, an AI coding agent, a build tool. Nothing is gated on what a caller is, what runs it or what its environment says. This is the model of an unlocked `op` session, `pass` with gpg-agent, or a session-unlocked keychain; any finer gate would be a hint a same-user process can route around, at the cost of prompts for every honest use.
- What protects the vault: being locked (the store is encrypted at rest under the passphrase-derived key), OS user separation (another user's processes can't reach the socket, and the CLI and the app check the daemon is this build before sending a passphrase), the idle lock (`unlock_timeout`), locking on sleep and screen lock, and Touch ID unlock. Settings that ask for every caller stay: Touch ID for a card's number or code in the browser, for exporting an SSH private key, for deleting a saved passkey, and for passkey ceremonies that ask for verification.
- Caller identity (`crates/cli/src/daemon/caller.rs`) is for Activity labels and for the commands only Deadbolt's own pieces send: the app's Activity reports (macOS: by code signature, its team's `anomaly.deadbolt` wherever it runs for a Developer ID build, else the daemon's own bundle's app), the browser host's quiet page look-ups, and the macOS AutoFill extension's socket. Linux can't verify a peer's code, so every Linux caller is a plain caller, marked unverified.
- Activity records each caller request (item names and field names, never values), so you can see after the fact what was read, by what, and when.
- **Process taint & capabilities (`CapTable` / `TaintTable`):** `deadbolt run` registers itself with the daemon's `TaintTable` (`crates/cli/src/daemon/taint.rs`) before spawning the child command. On every control connection, the daemon walks caller ancestry by `(pid, start time)` (via `deadbolt-os`); descendants of a `deadbolt run` are pinned to that run's `CapTable` capability (`crates/engine`, none by default) and receive no ambient vault reads, secrets, unlocks, or prompts.
- **Secret brokering (`deadbolt run --broker`, `docs/broker.md`):** injects placeholder tokens and a loopback URL into the child's environment while a hardened `deadbolt broker` process (`RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`) holds the real credentials and swaps them into outgoing HTTP headers or AWS SigV4 signatures on allowed routes.
- **Metadata-only agent MCP (`deadbolt mcp`):** speaks JSON-RPC 2.0 over stdio for AI coding agents, exposing only value-free metadata tools (`status`, `vault-list`, `item-list`, `health`) and guiding agents to emit `deadbolt run --broker` commands when a task needs credentials.
- Plain `deadbolt run` (without `--broker`) masks injected values in its command's output, which keeps them out of logs and transcripts by accident, not from a command that means to show them.

## Pairing
One command per device and one code, typed once:

```
new$ deadbolt join
Code: violin-garden-tiger-lamp-zoo
On a device with your vault, run: deadbolt approve violin-garden-tiger-lamp-zoo
waiting…
✓ joined "personal" from laptop
Passphrase for this device: ••••   (Again: ••••)

laptop$ deadbolt approve violin-garden-tiger-lamp-zoo
✓ added "desktop" to personal
```

- **Code.** Five words from the BIP-39 English list (2048 words, `crates/net/src/words.txt`), drawn with the OS CSPRNG: 55 bits. Lowercase and hyphenated when shown; parsing ignores case and takes spaces or hyphens. It works once, for 5 minutes, and only while `deadbolt join` waits.
- **Rendezvous** (`crates/net/src/rendezvous.rs`). Both devices derive an Ed25519 key from the whole code with Argon2id (64 MiB, 6 passes, salt `deadbolt/pair/3 rendezvous` followed by the six-hour UTC bucket (`floor(Unix seconds / 21600)`, big-endian u64); about 0.1 s on a desktop, well under a second on a laptop). The new device signs a pkarr record under that key holding its endpoint id and addresses and publishes it to n0's pkarr relay, the same server iroh's own address lookup uses (`PkarrRelayClient`; a pkarr relay takes a signed packet for any key, not only an endpoint's). The listener freezes its bucket when the code starts, including across a boundary. The existing device tries the current, preceding and following bucket keys in that order, deriving each lazily and caching it for the attempt, and retains the matched key for PAKE. This tolerates crossing a boundary and clocks falling into adjacent buckets; record-age and five-minute code-expiry checks still apply, so large clock skew can still fail and code lifetime is not extended. There is no public nameplate: nothing published names the code, and only a holder of the code can compute the key. When the code is used, burnt or ends, the record is replaced with one saying `used` or `closed`, so a late existing device says so. The record names the new device's endpoint id and addresses to whoever resolves it, as the QR ticket did.
- **PAKE** (`crates/net/src/pair.rs`). Over the iroh connection (authenticated to both device keys by TLS), the existing device sends the rendezvous public key and its SPAKE2 message (RustCrypto `spake2`, Ed25519 group, identities A = dialer and B = listener endpoint ids); the new device answers with its own. Each side derives `K = HMAC-SHA256(SPAKE2 key, "deadbolt/pair/3" ‖ listener id ‖ dialer id ‖ TLS exporter)`, so K holds only on this connection between these two keys, and they confirm it (`HMAC(K, "dialer-confirm")`, then `HMAC(K, "listener-confirm")`) before anything else. Only then does the existing device send the offer (vault id and name, its name and addresses), the new device sign its consent ("join vault V, invited by this device"), and the existing device sign `Add` and send the membership log and data over the same connection, ending with the new device's receipt. A party without the code learns nothing about the vault or the inviter.
- **One guess, single use.** The first attempt to complete the PAKE ends the code: with a pairing if its confirmation holds; if not, the code is burnt and the new device fails loudly ("a device tried a wrong code… run `deadbolt join` again"). An attacker therefore gets one guess per code: 2-55. Burning costs the legitimate user nothing, because a mistyped code derives another rendezvous key and finds no device at all ("no device is waiting for that code"); only someone who reached the new device without the code can fail the confirmation. A dialer naming an older code of the same device is turned away without spending the current one. Anyone arriving after the code was used hears "pairing failed: that code was already used. If it wasn't you, someone else may have used it". Codes expire after 5 minutes; dialers that never finish are bounded as before (16 running, 16 queued, 30 s each).
- **Offline guessing and precomputation.** Whoever sees a record (the relay operator, or anyone who learns the key) can test guesses offline, each costing one Argon2id evaluation with 64 MiB and 6 passes. The previous fixed salt allowed one table over the entire four-word space to be reused against every code indefinitely: the five-minute lifetime did not bound work done in advance. Six-hour salt buckets stop reuse across buckets, but are predictable, **not random per-code salts**: an attacker can precompute future buckets and amortize work across all codes within one bucket. We therefore also add a fifth word (55 bits), multiplying that work by 2,048 for one extra typed word. Covering half of 2^55 codes takes 1.8·10^16 evaluations. At the deliberately generous estimate of 5,000 evaluations/second/GPU (~2 TB/s over at least 384 MiB/evaluation), this is about 114,000 GPU-years per bucket, or 12 billion GPUs inside five minutes; even spreading it over six hours needs about 167 million GPUs. These are illustrative bandwidth-based estimates, not measured hardware guarantees. A table for salt bucket N does not derive keys salted with N−1 or N+1. However, resolvers in N−1, N and N+1 all try N, so the table has an **18-hour lookup window** (about 56 million GPUs if the illustrative computation is spread over that whole window). Record age and five-minute code expiry still apply: finding an expired code cannot admit a device, but can link an archived record to that code. Salt rotation does not provide forward secrecy or remove the need for PAKE and expiry.
- **Version mismatch.** Daemon↔client protocol **23** replaces 21 and 22 (22 was used by favorites/tags before pairing v3) so a new CLI replaces a still-running old daemon rather than displaying four-word codes or handing it five-word codes. Pairing ALPN, key-derivation domain and TLS exporter are version 3. Four-word codes fail locally with instructions to update both devices and generate a new code; old clients reject five-word codes. Raw version-2 QUIC attempts fail ALPN negotiation, rather than waiting for a PAKE. No fixed-salt fallback is published or resolved.
- **Welcome replay.** The joiner decodes directly into a private vault, verifying genesis and applying each signed entry as it arrives. Only `DONE` and final checks of the offered vault and both memberships permit adoption or a success receipt. A cut drops the prefix. The verified vault still occupies memory; when saved, one transaction encodes and seals one entry at a time.
- **Passphrase last.** A new device joins on a node of its own with a fresh device key and keeps the key and the received vault in memory only (`Fresh` in `crates/cli/src/daemon/pairing.rs`). Once paired, the CLI asks for the device's passphrase (twice) and the daemon creates the store with that key and stores the vault; `DEADBOLT_PASSPHRASE` or `--passphrase-stdin` given up front is used instead, and without either and without a terminal `join` fails before showing a code. Aborting at the prompt, or the client going away, discards everything; nothing unencrypted touches disk. The device name defaults to the hostname (`--device-name`). A device that is already set up joins with its own key and stores the vault as it arrives (unlocking inline first, as other commands do).
- **Half-finished joins.** The existing device commits `Add` before it sends the welcome, because an entry it signed but didn't keep could collide with its next one. So a new device that never stores the vault (the passphrase step abandoned, a crash) remains a member that was never seen; `devices` shows it as such and `devices remove` removes it. A set-up device whose earlier join was admitted but not stored can pair again: the existing device re-sends the welcome without a second `Add`. A removed device can't rejoin.
- **`approve` targets** the default vault, or `--vault`; with several vaults and no `--vault` it asks on a terminal and fails without one.
- **Residual risk.** The code is the only secret. Anyone who sees it while it is live (over a shoulder, in a screen share, in a shell history synced elsewhere) and uses it first can pose as the new device: they get the vault. The legitimate existing device then fails loudly as above, and the new device shows the vault and inviter it joined, which it reports before the passphrase prompt. Conversely, anyone who sees the code can pose as the inviter and pair the new device into a vault of theirs; the new device shows that vault's name and inviter. The `spake2` crate is a RustCrypto pre-release (0.5.0-pre.0, chosen because it shares this workspace's curve25519-dalek 5 / sha2 0.11 stack) and unaudited, as was 0.4. Pairing ALPN `deadbolt/pair/3`.

## Removing a device
Sign `Remove(B)` and rotate to a fresh clean-tip epoch wrapped only to the remaining members and the recovery root. The removal spreads over iroh and blind remote storage; B is refused at connection time (any open connection closes immediately) and cannot decrypt any frame written in the new epoch. B still keeps whatever it already decrypted before removal (inherent; prompt the user to rotate passwords it saw).
