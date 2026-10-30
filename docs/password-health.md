# Password health

2026-10-30. Plan, not built yet. Open decisions are at the end.

Deadbolt audits saved credentials inside `deadbolt agent` and sends `Deadbolt.app` and the CLI only finding flags, counts, and item references, never secret values or password hashes. Five checks run offline by default using `zxcvbn` and ~292 KiB of bundled directory tables: **weak passwords**, **reused passwords**, **compromised websites**, **missing two-factor authentication**, and **passkeys available**. A sixth check, **breached passwords**, is strictly opt-in and queries Have I Been Pwned's k-anonymity range API (`5`-hex SHA-1 prefix with `Add-Padding: true`) directly from the agent, caching results encrypted in `store.redb`. Selecting a finding opens the item's edit form with a site-compatible generated password ready, keeps a one-click copy of the current password for the site's "Current password" prompt, and opens the site's change-password or 2FA setup page directly.

## Only password fields are scored, and weak ones use `zxcvbn`

Deadbolt's two existing strength functions solve different problems:

- `crates/core/src/password_rules.rs` (`strength`) counts the exact combinatorial space of a generator rule (`MIN_BITS = 60.0`), assuming uniform random choices from a known alphabet. It cannot score a human-chosen password.
- `crates/app/src/onboarding.rs` (`strength`) estimates character-class pool bits, which scores `"Password123!"` (~78 pool bits) as `Strong` even though cracking lists try it in milliseconds.

### Estimator and thresholds

Use `zxcvbn` (`3.1`, MIT, safe Rust, `default-features = false`) in `crates/core/src/health/strength.rs`, behind a `health` Cargo feature on `deadbolt-core` enabled by `deadbolt-cli` and `deadbolt-client`. Leaving the feature off on `deadbolt-ext-core` keeps `zxcvbn`'s ~500 KiB frequency tables and regex dependencies out of the standalone browser-worker WebAssembly build until the extension grows its own health view. Because `deadbolt-app` already links `deadbolt-core` through `deadbolt-client`, onboarding's vault passphrase meter (`crates/app/src/onboarding.rs`) can switch to the same `zxcvbn` wrapper and retire the character-pool estimate.

Pass item-specific context strings as `zxcvbn(password, &user_inputs)`:

- `username`, plus the local-part before `@` when `username` is an email address;
- the item's `name` (or derived label) split on non-alphanumeric boundaries;
- the primary label of `registrable_domain(url)` (`"github"` from `https://gist.github.com`).

That catches site-salted passwords such as `"github-alex-2026!"` that otherwise look varied.

| `zxcvbn` score | Guesses | Health result |
|---|---|---|
| `0`, `1` | `< 10^6` | **Weak** ("Very weak", sorts first) |
| `2` | `10^6 .. 10^8` | **Weak** ("Weak") |
| `3`, `4` | `>= 10^8` | Healthy |

Dropbox's `zxcvbn` model assigns brute-force characters a conservative cardinality of 10 (`10^len`) and marks scores `0..=2` (`< 10^8` guesses) as weak. Every password Deadbolt generates (`>= 60` combinatorial bits in `password_rules`, `>= 10^18` guesses; ~155 bits at the 24-character default) scores `4`, so replacing a weak password with Deadbolt's generator always clears the warning.

`zxcvbn::Entropy` holds `Match` values containing `String` slices of the input password and does not implement `Zeroize`. The wrapper in `strength.rs` extracts only `Copy` numbers and an enum (`{ score: u8, guesses_log10: f32, reason: WeakReason }`) and drops `Entropy` before returning, so matched substrings are never stored in the agent memo or serialized.

### Avoiding false nags on PINs and non-passwords

Deadbolt's typed item schemas (`crates/core/src/item.rs`) separate human passwords from PINs, keys, and numbers up front:

1. **Schema scoping.** Only `login.password`, `database.password`, `server.password`, `wifi.password`, `crypto.password`, and non-empty `ssh.passphrase` are audited for strength and breaches. `card.pin`, `bank.pin`, `membership.pin`, `card.number`, `card.cvv`, `api.credential`, `license.license-key`, `crypto.recovery-phrase`, `note.notes`, `*.otp`, `*.private-key`, government/account numbers, and extra user-added `secret` fields on a login (such as `pin:secret` or `security-answer:secret`) are never scored as passwords. Logins without a `password` field (passkey-only logins and `sign-in-with` SSO logins) are skipped.
2. **Site rule ceilings.** Deadbolt already embeds Apple's `quirks/password-rules.json` (`crates/core/src/site_password.rs`). Some banks and telecoms in that list cap logins at 4 to 8 digits or 8 characters, where `password_rules::strength(&rules, Field::default())` returns `Err(Refused::Weak)`. When a login's site has a quirk whose maximum strength cannot reach `Score::Three` and the saved password already uses the allowed length and classes, Deadbolt suppresses `Weak` rather than nagging the user to generate a password the site will refuse.
3. **Per-item ignore.** For a voicemail or router PIN stored in `login.password` without a known site quirk, one action (`Ignore warning`) silences `Weak` on that item until its `password` value changes.

## Reuse is detected in the agent with ephemeral keyed hashes

Neither `Deadbolt.app` nor the CLI receives secret values or hashes to find duplicates.

When `Loaded` opens (`crates/cli/src/agent/session.rs`), the agent draws a random 32-byte `reuse_key` in a `Zeroizing<[u8; 32]>` buffer, kept in memory only and wiped when the store locks. For every audited password across all unlocked vaults on the device (excluding `wifi.password`, since 2.4 GHz and 5 GHz SSIDs on one router commonly share a passphrase), the agent computes:

```text
digest = blake3::keyed_hash(&reuse_key, password.as_bytes())
```

Items with identical `digest` values form a candidate cluster without holding duplicate plaintext strings in secondary maps. Across the control socket, the agent reports only group counts and item references (`{ vault, id, short, label, detail }`), never `digest`. Cross-vault reuse (such as the same password in `personal` and `work`) is caught automatically.

### Same-account deduplication

Two items that represent the **same account** should not be flagged as password reuse across accounts:

- Two `login` items with the same password and the same non-empty ASCII-lowercased `username` whose URLs resolve to the same `registrable_domain` (`github.com` and `gist.github.com`) collapse to one logical account for reuse counting.
- Domains in the same backend group of Apple's `quirks/shared-credentials.json` (`amazon.com` and `amazon.co.uk`, `envato.com` and `themeforest.net`) count as the same site for that check.
- Different usernames on one site (`alex` and `deploy-bot` on `github.com`), logins with an empty username, and distinct `database` or `server` items without URLs (`prod-db` and `staging-db`) remain separate accounts and flag **Reused**.

### Near-duplicates

People who salt one base password per site (`BasePass-gh!`, `BasePass-aws!`, or `Summer2025!` and `Summer2026!`) lose every account once one leaks. Pairwise Levenshtein distance across 3,000 passwords requires ~4.5 million comparisons (~50 to 150 ms) and inspects raw plaintexts pairwise.

If Deadbolt flags near-duplicates, it can do so in $O(N)$ time (~0.5 ms for 3,000 items) with the same keyed-hash model:

1. Lowercase ASCII characters in the password.
2. Strip tokens of 3+ letters taken from the item's `registrable_domain` stem and `username`.
3. Trim leading and trailing ASCII digits and punctuation.
4. If at least 5 characters remain and the string differs from the raw password, compute `blake3::keyed_hash(&reuse_key, skeleton.as_bytes())`.

Generated passwords keep 20+ random interior characters and never collide; human-mutated base passwords (`Summer2025!` and `Summer2026?`, `alex-github!` and `alex-linear!`) collide in one pass. Ship exact reuse first so v1 has zero false positives, and treat skeleton `Similar` warnings as an explicit scope choice (Decision 2).

## Breach checks separate leaked passwords from breached websites

Following 1Password Watchtower's distinction, Deadbolt separates password-corpus matches from site-incident alerts:

- **Breached password:** the password's SHA-1 hash appears in Have I Been Pwned's Pwned Passwords corpus (~900M+ leaked passwords). When the password was set does not matter; it is in public credential-stuffing lists and must be replaced.
- **Compromised website:** the login's site appears in HIBP's verified password breaches (`haveibeenpwned.com/api/v3/breaches`), and the login's password has not been changed since `BreachDate`. Even a strong unique password should rotate once after the site itself was breached.

### HIBP k-anonymity range API vs an offline list

Use HIBP's k-anonymity range API (`GET https://api.pwnedpasswords.com/range/{5-hex}` with header `Add-Padding: true`) over TLS 1.3 via `reqwest` and `rustls` (`ring`, HTTPS-only, redirects disabled, already in `crates/cli/Cargo.toml` for `deadbolt update`).

Why not a bundled or downloaded offline password list:

- **Full offline corpus:** ~900M+ SHA-1 hashes take ~16 GB in packed binary (`20 B * 900M`) or ~1.5 GB in a low-false-positive Golomb/Fuse filter, roughly 100x the size of Deadbolt, and go stale between downloads while still requiring a large server fetch.
- **Bundled top-100k filter (~150 KiB):** catches only common passwords that `zxcvbn`'s built-in 30k dictionary already flags offline, while reporting "0 breached" on unique passwords leaked in real site dumps.
- **Optional local file (`deadbolt health --hibp-file <path>`):** trivial to add later for CLI users who keep a local HIBP dump, without making multi-gigabyte downloads part of the product.

### Privacy, opt-in, and Deadbolt's no-servers stance

Deadbolt runs no Anomaly server or proxy, and vault data only ever syncs device-to-device over iroh (`docs/design.md`). Like `deadbolt update`, HIBP range lookups are a direct client-to-public-API HTTPS fetch. To keep that boundary strict:

- **Off by default.** `breach_checks` in `config.toml` defaults to `false`. A fresh Deadbolt install makes zero background HTTP requests; weak, reused, compromised-site (from the bundled snapshot), 2FA, and passkey checks all work 100% offline.
- **Explicit opt-in.** Enabling Settings › Security › **Check for breached passwords** (or passing `--online` once on the CLI) states in one plain line: *"Sends the first 5 characters of each password's SHA-1 hash to Have I Been Pwned (`api.pwnedpasswords.com`) with response padding."*
- **Who learns what when enabled:**
  - **HIBP and Cloudflare** see the client IP address, TLS handshake, a minimal versionless `User-Agent: deadbolt`, request count and timing, and the 20-bit SHA-1 prefixes (`00000`–`FFFFF`) of unique passwords in the vault. They never see URLs, usernames, item titles, or full hashes.
  - **Passive network observers** see connections to `api.pwnedpasswords.com`, but `Add-Padding: true` pads every response to 800–1,000 lines (`:0` padding rows discarded locally), so response sizes do not reveal which prefix was queried.
  - **Weak-variant correlation risk:** a strong generated password ($\ge 60$ bits) shares its 20-bit bucket with $\ge 2^{40}$ valid passwords, giving an observer nothing to invert. If a user stores several related weak passwords (`MySecret1`, `MySecret2`, `MySecret3`), a malicious HIBP logging all prefixes from one IP could test candidate base words against those buckets. Deadbolt notes this at opt-in, deduplicates identical passwords before querying, and shuffles prefix order with random jitter on background refreshes.

### Caching and schedule

Cache HIBP range results locally in `store.redb` (`meta` key `"cli/hibp-cache"`), AEAD-sealed under `data_key`. Instead of indexing by raw SHA-1 (which would store an unsalted hash of every vault password inside `meta`), derive a store-bound key with BLAKE3 KDF from `store.device_secret()` and map:

```text
blake3::keyed_hash(hibp_cache_key, &sha1_bytes) -> { count: u64, checked_day: u32 }
```

- **Breached (`count > 0`):** cached permanently until that password changes (a password added to HIBP is never un-breached).
- **Clean (`count == 0`):** valid for **14 days**, plus 0–24 hours of deterministic per-entry jitter so a vault's prefixes do not all expire on the same day.
- **When lookups run (only while `breach_checks = true` and unlocked):**
  1. **Manual check** (`Check breaches` in Security or `deadbolt health --online`): queries uncached and expired prefixes at concurrency 8 over HTTP/2 connection reuse, streaming `checked / total` progress. A cold vault of 1,800 unique passwords takes ~225 RTT batches (~6–9 s once, ~25 MB compressed transfer) and 0 requests on subsequent opens.
  2. **Single-item write** (`ItemNew`, `ItemSet`, `SiteSave` changing `password`): checks that 1 prefix (~35 ms) in the background if uncached.
  3. **Background refresh:** at most once every 24 hours while unlocked, rechecking expired `count == 0` entries at concurrency 2 with jitter. Locking or stopping the agent aborts in-flight HTTP tasks immediately and drops results. Background health tasks never count as activity for `unlock_timeout`.

### Breach dates vs password change dates

Deadbolt's signed log entries intentionally carry no wall-clock timestamps (`docs/design.md`), so `Entry` cannot tell when a password was set. Recording a device-local `first_seen` timestamp in `store.redb` also fails: existing items and newly paired devices would appear "changed today" and silently miss older site breaches.

Instead, store an optional agent-managed `password_changed` (`YYYY-MM-DD`) stamp on `Item` via `Change::PasswordChanged(Option<String>)` (wire tag `8` in `crates/core/src/entry.rs`), kept apart from `Item::fields` just like `Change::Source`:

- **Day precision (`YYYY-MM-DD`)** matches `passkey.created` and HIBP's `BreachDate`, leaks no typing-time or timezone patterns across synced devices, keeps `data.rs` conflict resolution 100% causal (ties broken by entry hash), and powers the password age line on the item page (`"Login · Changed Mar 14, 2024"`).
- **Written automatically:** whenever the agent creates an item with an audited password or changes that password (`items::create`, `items::set`, `autofill::site_save`), it writes `Change::PasswordChanged(Some(today))` in the same signed entry.
- **Preserved on import and 1Password sync:** `.1pux` and `op` imports populate `password_changed` from the latest `passwordHistory` timestamp (falling back to `updatedAt`), and Bitwarden JSON imports populate it from `login.passwordRevisionDate` (falling back to `revisionDate`). Keeping `password_changed` off `Item::fields` preserves `item.fields` invariants and leaves `deadbolt sync 1password` `MirrorVersion` digests unchanged.

Site breaches come from `GET https://haveibeenpwned.com/api/v3/breaches` (CC-BY-4.0, unauthenticated), filtered to verified, non-retired, non-fabricated, non-spam breaches that have a `Domain` and include `"Passwords"` in `DataClasses` (622 domains, 48 KiB compact JSON). Downloading the full 622-domain list sends **zero** user domains over the network. A snapshot ships bundled for offline use and refreshes at most once every 7 days into `"cli/site-breaches"` when `breach_checks = true`.

| Item's `password-changed` | Site's `BreachDate` | Result |
|---|---|---|
| `< BreachDate` | `2020-05-01` | **Compromised site** ("`<Title>` was breached in May 2020, before this password was changed") |
| `>= BreachDate` | `2020-05-01` | Healthy |
| Missing (pre-existing item with no import timestamp) | `2020-05-01` | **Unverified site breach** ("`<Title>` was breached in May 2020 · password date not recorded"), cleared by rotating or ignoring |

## Bundled directories cover 2FA, passkeys, shared accounts, and fix links

Compile five compact snapshots into `crates/core/data/health/`, following the pattern already used for `crates/core/data/password-rules/password-rules.json`:

| Dataset | Source | License | Entries | Compact size |
|---|---|---|---|---|
| Software 2FA sites (`2fa.json`) | `api.2fa.directory/v3/tfa.json` | MIT | 1,710 domains (`totp`) | 137 KiB (with setup URLs) |
| Passkey sites (`passkeys.json`) | `passkeys-api.2fa.directory/v1/supported.json` | CC-BY-4.0 | 403 domains (`passwordless` / `mfa`) | 35 KiB (with setup URLs) |
| Breached sites (`breaches.json`) | `haveibeenpwned.com/api/v3/breaches` | CC-BY-4.0 | 622 password-breached domains | 48 KiB |
| Change-password links (`change-urls.json`) | `apple/password-manager-resources` `quirks/change-password-URLs.json` | MIT | ~550 domains | 50 KiB |
| Shared credentials (`shared.json`) | `apple/password-manager-resources` `quirks/shared-credentials.json` | MIT | ~190 domain groups | 22 KiB |

Together they add **~292 KiB uncompressed** (~70 KiB compressed in release archives), parsed lazily on first health check via `LazyLock`.

### Matching rules that avoid directory pitfalls

1. **Filter 2FA availability to `"totp"` (and WebAuthn passkeys).** Many banks in `2fa.directory` support only `"sms"` or `"email"` 2FA. Because Deadbolt holds no secret for SMS 2FA, flagging SMS-only sites would nag forever even when the user already has SMS 2FA turned on. `Missing2fa` triggers only when the site supports `"totp"` and:
   - the `login` has no `otp` field;
   - the `login` has no `sign-in-with` provider (an SSO login's 2FA lives on its `sign-in-account` login);
   - no `passkey` item in any unlocked vault matches the site (and `username`, when both items have one).
2. **Roll up login subdomains at compaction time.** `2fa.directory` lists Google under `mail.google.com` / `cloud.google.com` and Apple under `appleid.apple.com`, omitting bare `google.com`, `accounts.google.com`, and `apple.com`. The compaction script (`scripts/sync-health-data.ts`) indexes each entry's `domain`, its `additional-domains`, and its `registrable_domain` (excluding public suffixes via `psl`), and lookup walks from exact `url_host(url)` (without `www.`) up to `registrable_domain`, matching `site_password::quirk`.
3. **Passkey availability.** Flag `PasskeyAvailable` (recording whether `passwordless`, `mfa`, or both are supported, plus `documentation` URL) when `passkeys.json` matches a `login`'s site and no saved `passkey` item matches that site (and `username`, when both have one).

### Updating and attribution

A scheduled weekly GitHub Actions workflow runs `scripts/sync-health-data.ts`, verifies the PGP `.sig` files published by `2fa.directory` and `passkeys.2fa.directory`, and opens a PR against `dev` when entries change. Bundling keeps offline installs working, makes every directory change reviewable in git, and avoids client traffic hitting community Cloudflare endpoints (`2fa.directory` asks apps to cache rather than poll from clients). Only `breaches.json` also refreshes directly in the agent once a week when `breach_checks = true`.

Include upstream license files and commit/date stamps in `crates/core/data/health/` (`LICENSE.md`, `README.md`) and one attribution note under Settings › Security: *"Directory data from 2FA Directory, Passkeys Directory, Apple Password Manager Resources, and Have I Been Pwned."* (`cargo deny check` inspects Rust crate licenses in `Cargo.lock`, where `zxcvbn` is MIT.)

## Incremental agent caching keeps 3,000-item vaults fast

### Protocol and caller policy

Put health wire types in `crates/client/src/protocol/health.rs` (keeping `protocol.rs` below its 1,500-line ceiling, protocol v21):

- `Command::Health { vault: Option<String>, online: bool }` -> `Reply::Health { report: HealthReport }`.
- `Command::HealthIgnore { vault: Option<String>, query: Vec<String>, kind: FindingKind, ignored: bool }` -> `Reply::Health { report: HealthReport }`.
- `Command::BreachChecksSet { enabled: bool }` -> `Reply::Done` (writes `breach_checks` in `config.toml` and triggers an initial check when turned on).
- `Command::Generate { length, symbols, url: Option<String> }`: when `url` is supplied, honors `password-rules.json` site quirks with a 60-bit minimum floor (`site_password::generate_for_url`).
- `Change::Health` on the `watch` stream whenever the memo, breach cache, or ignore state changes.

Under `docs/agent-control.md`, `Health`, `HealthIgnore`, and `BreachChecksSet` are allowed for `Deadbolt.app` and human CLI callers, and **refused (`forbidden`) to AI callers**, so an AI session cannot ask Deadbolt which accounts have weak or reused passwords. None of them count toward `unlock_timeout` activity.

### Cost and incremental rerun on 3,000 items

For a vault of 3,000 items (2,400 passwords, 1,800 unique) on an Apple Silicon Mac:

| Operation | Work | Cost |
|---|---|---|
| Cold pass on unlock | `zxcvbn` x 2,400 (~50–150 us each) + `blake3::keyed_hash` x 2,400 (~0.2 ms) + domain lookups (~1.5 ms) | **~120–350 ms** on `spawn_blocking` |
| Single-item create or edit | `zxcvbn` x 1 (~0.1 ms) + regroup 2,400 cached 32-byte digests and passkey set | **`< 1 ms`** |
| 500-item import | `zxcvbn` x 500 new items + regroup | **~30–75 ms** |
| Memory held while unlocked | 3,000 memo entries (`ItemId`, 32-byte digest, flags, ~120 B each) | **~360 KiB** |

On unlock, `Agent` returns from `Unlock` / `UnlockBiometric` immediately and runs the cold pass on `tokio::task::spawn_blocking` over a `Zeroizing` snapshot of `(VaultId, ItemId, item_fingerprint, inputs)`. When it finishes, it populates `Session`'s health memo (skipping any item already edited in the meantime by comparing `item_fingerprint`) and sends `Change::Health`. Subsequent writes (`items::create`, `items::set`, `items::remove_id`, `import`, `mirror`, `autofill::site_save`, synced entries) recompute only items whose `item_fingerprint` changed. Locking drops `Session` and wipes the memo and `reuse_key`.

## UI: calm indicators, a keyboard Security view, and a one-step fix flow

All views follow `docs/app.md`: instant state transitions (`Tx::instant`), no hover fades, no focus rings, arrow cursor everywhere, no pill or tag clutter on rows, and zero layout reflow as async data lands.

### Where health shows up

1. **Sidebar count (`crates/app/src/vault/mod.rs`).** Place the active risk count inside the existing fixed-height `vault-head` row (`Personal` on the left, risk indicator + item count on the right). Because `vault-head` is always rendered, health arriving 150 ms after unlock causes **zero vertical shift** in the item list. Clicking it toggles the Security view. When risk count is 0, nothing nags in `vault-head`.
2. **Sidebar item rows.** Show a single 6 pt trailing dot on rows with an active **risk** (`k.c.danger.fg` for Breached, Compromised site, or Reused; `k.c.warning.fg` for Weak). Never badge rows in the main list for **upgrade opportunities** (`Missing2fa`, `PasskeyAvailable`), so a vault with 150 passkey-capable sites stays calm.
3. **`⌘K` palette and shortcut (`crates/app/src/palette.rs`, `crates/app/src/keys.rs`).** Add `Security` (`⇧⌘H`, avoiding macOS's reserved `⌘H` Hide) to `⌘K`'s window actions and `SHORTCUTS`.
4. **Security view (`crates/app/src/health.rs`, `crates/app/src/health/view.rs`).** Swaps into the detail pane's slot while the sidebar stays put, matching `Settings`:

```text
┌──────────────────────────┬──────────────────────────────────────────────────────────┐
│ 🔍 Search             ⌘F │ Security                           [Check breaches]      │
│ Personal       ● 6 · 243 │                                                          │
│ ──────────────────────── │ [1 Risks 6] [2 Breached 1] [3 Reused 3] [4 Weak 2]       │
│ 🔑 github.com            │ [5 2FA 8]   [6 Passkeys 14]                              │
│    alex                  │ ──────────────────────────────────────────────────────── │
│ 🔑 Linear              ● │ 🔑 Adobe                           Seen in 14,203 leaks  │
│    alex@example.com      │    alex@example.com                         [Fix ↵] [O]  │
│ 💳 Visa •••• 4242        │ 🔑 Linear                     Same as Staging DB, +1     │
│    08/29                 │    alex@example.com                                      │
│ 🔑 Staging DB          ● │ 🔑 Staging DB                 Same as Linear, +1         │
│    postgres              │    postgres                                              │
│                          │ 🔑 Router                     Common word with digits    │
│ ──────────────────────── │    admin                                                 │
│ ● laptop · 1 online ⚙ 🔒 │ ↑↓ move · 1–6 tab · ↵ fix · O open site · I ignore · esc │
└──────────────────────────┴──────────────────────────────────────────────────────────┘
```

   - Keys inside Security: `1`–`6` (and `[` / `]`) switch category tabs (`Ignored` appears as `7` when non-empty); `↑` / `↓` move between rows; `↵` starts the Fix flow for the selected row; `O` opens the site's change-password or 2FA/passkey setup URL; `I` ignores (or restores, on the `Ignored` tab); `Esc` returns to the vault.
5. **Item detail page (`crates/app/src/vault/page.rs`).** When the selected item has active findings, render one compact callout above its fields naming the highest-priority finding (`"Exposed in 14,203 breaches"`, `"Same password as Linear and 1 other"`, `"Supports authenticator codes"`) with the primary action (`Change password`, `Set up 2FA`, or `Open site`) and `Ignore`. When `password-changed` is present, show `"Changed Oct 30, 2026"` quietly in the item subtitle (`"Login · Changed Oct 30, 2026"`).

### The Fix flow (`App::fix_password`)

Today `App::edit_selected` (`crates/app/src/edit.rs`) opens `Form` with the old password untouched and hides the generator controls (`Length`, `Symbols`) until the user clicks regenerate. Also, changing a password on a real website almost always asks for **Current password** first, so overwriting the password in the form before copying the old one strands the user.

`App::fix_password` solves both:

1. Selects the item, opens its edit `Form`, focuses `password`, and immediately requests a generated password from the agent, passing the item's `url` so `password_rules.rs` honors site quirks (such as `163.com`'s 16-character cap) while keeping at least 60 bits of entropy.
2. Reveals the new candidate password in place (`set_revealed(true)`) with `Length` and `Symbols` controls shown (`form.generated = 1`), and copies the new candidate to the concealed clipboard (`Tx::copy_secret`).
3. Because `Form` already retains `base: Option<Snapshot>`, renders two helper actions right under the generator bar while fixing an existing password:
   - **Open `<site>`** (`O`): opens the direct URL from `change-urls.json` when known (`https://github.com/settings/security`), falling back to the item's `url`.
   - **Copy current password** (`⇧⌘C`): copies `base`'s saved password through `Tx::copy_secret` without losing the newly generated candidate in the input box.
4. Pressing `⌘S` saves the new password (stamping `password-changed` to today and keeping the old password in `Vault::history`); pressing `Esc` cancels cleanly if the website rejected the change.

For **Missing 2FA**, `Fix` (`↵`) opens the site's `2fa.directory` setup `documentation` URL (falling back to `url`) and opens the item's edit form with `otp` focused ready to paste an `otpauth://` URI or secret. For **Passkey available**, `Fix` opens the site's `passkeys.2fa.directory` setup URL so the paired browser extension can capture `navigator.credentials.create()`.

### CLI

```sh
deadbolt health                                # summary + flagged items across risk categories
deadbolt health --all                          # include 2FA and passkey upgrade opportunities
deadbolt health --only breached,reused --json  # machine-readable report (no values or hashes)
deadbolt health --online                       # run one HIBP range check even if config is off
deadbolt health ignore Linear weak             # silence until Linear's password changes
deadbolt health unignore Linear weak
```

## Sync: derived findings stay local, ignored warnings sync cleanly

- **Health findings and HIBP cache never sync.** Weak, Reused, Missing 2FA, and Passkeys are deterministic functions of the vault and bundled tables; each device computes them locally. `"cli/hibp-cache"` and `"cli/site-breaches"` stay in local `store.redb` so enabling `breach_checks` on one device never writes network-derived rows to the append-only signed log or reveals `breach_checks` activity to another device.
- **Ignored warnings (`Change::Ignore`).** Ignoring a voicemail PIN on a desktop should not leave the laptop nagging about the same item. Keep dismissals on `Item` **apart from `fields`**, just like `Source` (`Change::Source`, wire tag `4` in `crates/core/src/entry.rs`), via `Change::Ignore { kind: String, at: Option<Hash> }` (wire tag `7`, `None` clears the ignore):
  - Because `mirror::item_digest` hashes `&item.fields` only, ignoring a warning on a 1Password-mirrored item survives every future `deadbolt sync 1password`.
  - Dismissals never appear in `ItemGet`, edit forms, exports, or `deadbolt send`.
  - For password findings (`weak`, `reused`, `breached`, `site-breach`), `at` is the `Entry::hash()` of the winning write to `password` (`ItemState` in `crates/core/src/data.rs`). Every vault member already holds that `Entry` hash, so storing it leaks zero password-equality information while automatically expiring the ignore the instant any new `password` write wins. For item-level findings (`missing-2fa`, `passkey`), `at` is `Hash([0; 32])` and clears automatically once an `otp` or `passkey` exists.

## Code organization, testing, and PR plan

### Module layout

Follow Deadbolt's capability layout (no `mod.rs`, files well under 800 non-test lines, sibling `*_tests.rs` files):

- `crates/core/src/health.rs` + `crates/core/src/health/{strength,reuse,directory}.rs` + `crates/core/src/health_tests.rs`: pure scoring, schema scoping, keyed-hash reuse, directory matching, breach-date comparison.
- `crates/core/data/health/`: `2fa.json`, `passkeys.json`, `breaches.json`, `change-urls.json`, `shared.json`, `README.md`, `LICENSE.md`, refreshed by `scripts/sync-health-data.ts`.
- `crates/client/src/protocol/health.rs`: `HealthReport`, `ItemHealth`, `Finding`, `FindingKind`, `RiskLevel`, re-exported from `protocol.rs`.
- `crates/cli/src/agent/health.rs` + `crates/cli/src/agent/health/hibp.rs`: `Session` incremental memo, `spawn_blocking` cold scan, `"cli/hibp-cache"` and `"cli/site-breaches"` persistence, `reqwest` HIBP range client with `Add-Padding: true` and debug-only loopback override `DEADBOLT_HIBP_URL`.
- `crates/cli/src/health.rs`: `deadbolt health` subcommands and text/JSON formatting.
- `crates/app/src/health.rs` + `crates/app/src/health/view.rs`: Security view state, key handling, overview rendering, and inline item-page callout.

### Testing without a real vault

1. **Core unit, property, and scale tests (`crates/core/src/health_tests.rs`):**
   - Synthetic items across all 18 schemas asserting `card.pin`, `bank.pin`, `membership.pin`, `api.credential`, `ssh.private-key`, `crypto.recovery-phrase`, and extra `pin:secret` fields on `login` never flag weak, reused, or breached.
   - `zxcvbn` checks on common passwords, keyboard walks, `user_inputs` context tokens, site-quirk ceilings (`password-rules.json`), and 60-bit+ generated passwords.
   - Reuse checks across multiple vaults, `shared-credentials.json` equivalence (`amazon.com` + `amazon.co.uk`), same-domain + same-username collapse, and `sign-in-with` exemptions.
   - Subdomain rollup checks (`accounts.google.com` matching `mail.google.com` in `2fa.json`; `apple.com` matching `appleid.apple.com`), SMS-only 2FA exclusion, and `password-changed` vs `BreachDate` matrix.
   - Synthetic 3,000-item vault benchmark test verifying incremental 1-item update updates only 1 `zxcvbn` entry.
2. **Deterministic loopback HIBP tests (`crates/cli/tests/cli.rs`):**
   - Debug-only `DEADBOLT_HIBP_URL` (restricted to `127.0.0.1` and `[::1]` under `cfg!(debug_assertions)`, matching `DEADBOLT_RELEASE_URL` in `crates/cli/src/update.rs`).
   - Local `TcpListener` fixture serving padded `:0` and breached `:N` suffixes for public test vectors (`"password"` -> `5BAA6...`), verifying `Add-Padding: true`, prefix deduplication, permanent `count > 0` caching, 14-day TTL on `count == 0`, zero network traffic when `breach_checks = false`, and immediate cancellation on `deadbolt lock`.
3. **Headless Rune app tests and scenes (`crates/app/tests/app/health.rs`, wired in `tests/app/main.rs`):**
   - Loopback-agent fixtures (`scenes/fixtures.rs`) verifying `Security` opens from `⌘K` and `⇧⌘H` without fetching item secret values, `vault-head` does not shift row y-positions when health arrives, `Fix` opens the form with a revealed generated password and working `Copy current password`, and `snap.sh` captures `security`, `vault-risk`, and `fix-password` stills.

## Decisions

1. **Syncing "Ignore warning" across devices:** Synced via `Change::Ignore` on `Item` (wire tag `7` in `entry.rs`, apart from `fields` like `Source`, bound to `Item::password_entry` for password findings and `Hash([0; 32])` for item-wide findings).
2. **Near-duplicate ("similar") passwords in Reuse:** Exact password reuse only (`blake3::keyed_hash`), collapsing same-account logins across `shared-credentials.json` and excluding `wifi` and `ssh`.
3. **Sidebar warning number and row dots:** Count and dot only **risks** (`Breached`, `SiteBreach`, `Reused`, `Weak`) in the everyday vault sidebar; keep `MissingTwoFactor` and `PasskeyAvailable` as upgrade tabs inside `Security` (`⇧⌘H`, `⌘K`) and item-page callouts.
4. **Password change dates and site-level breach alerts:** Stamp `password_changed` (`YYYY-MM-DD`, `Change::PasswordChanged`, wire tag `8`) automatically on password writes and `.1pux` / `op` / Bitwarden imports, checking both opt-in HIBP Pwned Passwords ranges and bundled HIBP `/breaches` site dates.
