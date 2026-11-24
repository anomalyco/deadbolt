---
name: deadbolt
description: Use the Deadbolt local-first password manager CLI safely from scripts and AI agents — install, unlock non-interactively, inject secrets with deadbolt:// references, manage items, pair devices, share one-time Send links, audit password health, and update.
---

# Deadbolt CLI Reference

Deadbolt is a local-first, decentralized password manager written in Rust. Each device keeps its own encrypted store (`redb`, Argon2id + XChaCha20-Poly1305) and syncs directly with your other devices over [iroh](https://www.iroh.computer), end-to-end encrypted, with no accounts and no Deadbolt servers.

> Status: alpha. Every push to `dev` ships a build; stable releases are not yet published.

## Install

### macOS & Linux install script

Installs `deadbolt` to `~/.local/bin` (override with `DEADBOLT_INSTALL`) and verifies SHA-256 against the release manifest. On Linux with glibc 2.28+, it installs the binary with the built-in desktop app; on Alpine/musl or older glibc, it selects the static musl CLI build (override with `DEADBOLT_LIBC=gnu|musl`).

```sh
# Latest dev build (current alpha)
curl -fsSL https://deadbolt.pw/install | DEADBOLT_CHANNEL=dev sh

# Stable channel (default once stable releases start; pin with DEADBOLT_VERSION)
curl -fsSL https://deadbolt.pw/install | sh
```

### bun / npm (Node 18+)

On macOS this also brings `Deadbolt.app` (`deadbolt app` opens it and links it into `~/Applications`).

```sh
bun add -g @deadbolt/cli@dev
npm i -g @deadbolt/cli@dev
```

Use `@deadbolt/cli` once stable releases start.

### Homebrew (once stable releases start)

```sh
brew install anomalyco/tap/deadbolt          # CLI
brew install --cask anomalyco/tap/deadbolt   # Deadbolt.app + CLI (macOS)
```

## Agent & Non-Interactive Usage

Deadbolt is built to be driven non-interactively from flags, environment variables, and stdin. It prompts **only** when both `stdin` and `stderr` are terminals; otherwise it fails immediately instead of hanging.

### Global flags

- `--passphrase-stdin` — read the passphrase from the first line of stdin instead of `DEADBOLT_PASSPHRASE` (`init`, `join`, `unlock`, or any command that triggers an unlock).
- `-v, --vault <VAULT>` — vault to act on (default: this device's default vault). Rejected on commands where `--vault` does not apply (`init`, `join`, `unlock`, `lock`, `run`, `inject`, `read`, `vault`, `activity`, `receive`, `update`, `touchid`, `app`, `desktop`, `browser`, `debug`, and `send ls|show|revoke`).

### Environment variables

| Variable | Purpose |
| --- | --- |
| `DEADBOLT_PASSPHRASE` | Passphrase for non-interactive setup, join, or unlock (overridden by `--passphrase-stdin`). |
| `DEADBOLT_HOME` | Override the encrypted store directory (default: `$XDG_DATA_HOME/deadbolt`). Each `DEADBOLT_HOME` gets its own isolated daemon socket. |
| `DEADBOLT_NO_UI=1` | Prevent bare `deadbolt` outside a terminal from opening the desktop app. |
| `DEADBOLT_NO_UPDATE_CHECK=1` | Disable background update notices. |
| `DEADBOLT_SEND_URL` | Override the base URL printed in `deadbolt send` links (default: `https://deadbolt.pw/r`). |
| `DEADBOLT_CHANNEL` | Install script channel (`stable` default, or `dev`). |
| `DEADBOLT_VERSION` | Install script: pin a specific stable version from GitHub Releases. |
| `DEADBOLT_INSTALL` | Install script destination directory (default: `~/.local/bin`). |
| `DEADBOLT_LIBC` | Install script (Linux only): force `gnu` or `musl`. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `deadbolt run`, exits with the child command's exit code (or `128 + signal`). |
| `1` | General error (invalid arguments, item not found, offline peer, or `debug daemon status` when stopped). |
| `3` | Store is locked. Unlock first (`deadbolt unlock`) or pass `DEADBOLT_PASSPHRASE` / `--passphrase-stdin`. |
| `4` | Request refused by daemon (forbidden). For `deadbolt send --wait`, the link expired unopened. |
| `5` | For `deadbolt send --wait`, the link was revoked before pickup. |
| `10` | For `deadbolt update --check`, an update is available (`0` when already up to date). |

### Machine-readable output (`--json` and TSV)

`--json` is a per-command flag (not global) supported on:

- `deadbolt activity --json` — one JSON object per line
- `deadbolt send --yes --json` — `{"id", "link", "expires"}` (`--json` requires `--yes`)
- `deadbolt send ls --json`
- `deadbolt send show <id> --json`
- `deadbolt receive <link> --json` — `{"title", "note", "values", "files"}`
- `deadbolt health --json` — audit report (never includes secret values or hashes)
- `deadbolt debug whoami --json`

`deadbolt debug watch` always streams JSON lines of daemon state changes (never secret values). Listing commands (`ls`, `devices`, `vault ls`, `tags`, `touchid status`) print clean tab-separated lines; `get`, `read`, and `code` print raw values on stdout.

### Security rules for agents

- Prefer `deadbolt run` or `deadbolt inject` over `deadbolt get` / `deadbolt read` so secret values stay out of command-line arguments, transcripts, and scrollback.
- Never print, log, or commit resolved secrets.
- Every resolve and read is recorded in `deadbolt activity` (items and fields only, never values).

## Secret Reference Syntax

```text
deadbolt://[vault/]item/field
```

- **`vault`** (optional): vault name or id. A two-part reference (`deadbolt://item/field`) uses the default vault.
- **`item`**: item title (case-insensitive) or its id / unique prefix (4+ hex digits). Must match exactly one item; otherwise the error lists candidates by short id.
- **`field`**: exact field name (otherwise the error lists the item's field names).
- **Escaping**: write a literal `/` as `%2F` and a literal `%` as `%25` inside any segment.
- **Special fields**: an `otp` field resolves to the current TOTP code (never its seed); passkey private keys are never exposed as fields; a file field can only be written by `deadbolt inject` when the template consists solely of that one reference.

## Core Commands

### Setup, unlock & locking

```sh
# Create a new vault on first run (default vault name: personal)
printf '%s\n' "$PASS" | deadbolt --passphrase-stdin init personal --device-name work-laptop

# Unlock (optional idle lock timeout: 30s, 15m, 8h, 1d, never)
deadbolt unlock --timeout 8h

# Lock immediately
deadbolt lock

# macOS Touch ID unlock
deadbolt touchid [on | off | status]
```

### Pairing & device management

Pairing uses `join` on the new device and `approve` on a device already in the vault (there is no `pair` subcommand). Codes work once for 5 minutes.

```sh
# On the new device (non-interactive first run requires DEADBOLT_PASSPHRASE or --passphrase-stdin)
deadbolt join --device-name ci-box

# On an existing device in the vault
deadbolt approve violin-garden-tiger-lamp-zoo

# List or remove devices
deadbolt devices
deadbolt devices remove <name-or-id>

# Manage vaults
deadbolt vault ls
deadbolt vault rename <old> <new>
deadbolt vault default <name>

# Sync immediately with peers, or mirror 1Password via `op`
deadbolt sync
deadbolt sync 1password [--account <acct>] [--op-vault <name>] [--dry-run] [--quiet]
```

### Managing items

Listing uses `ls` (alias `items`) and editing uses `set` / `unset` (there are no `list` or `edit` subcommands).

```sh
# List items (TSV: short_id, label, detail)
deadbolt ls [query...] [--type <type>] [--tag <tag>] [--favorites] [--deleted]
deadbolt tags

# Create an item (prints short id; logins without password= get a generated password)
# Types: login, card, note, ssh, identity, api, database, server, wifi, license,
#        bank, document, passport, driver-license, membership, crypto, id-document
deadbolt new login username=alex url=github.com --name GitHub --tag work
printf '%s' "$API_KEY" | deadbolt new api credential=- username=deploy-bot type=bearer --name Deploy
deadbolt new document file=./cert.pem --name "TLS Cert"

# Read a single field (raw value; file fields write 0600 to --output)
deadbolt get github
deadbolt get github --field username
deadbolt get "TLS Cert" --output ./cert.pem

# Inspect fields (secrets masked unless --reveal) or get a TOTP code
deadbolt show github [--reveal]
deadbolt code github

# Edit fields, name, favorite state, or tags (args with '=' are assignments)
deadbolt set github password=- url=github.com --favorite --tag work/prod
deadbolt set github --untag old-tag
deadbolt unset github --field notes

# Soft-delete and restore
deadbolt rm github
deadbolt ls --deleted
deadbolt restore github
```

### Secrets for commands (`run`, `inject`, `read`)

```sh
# Run a command with secrets resolved into its environment and masked in stdout/stderr
deadbolt run --env GH_TOKEN=deadbolt://personal/GitHub/token -- gh release create v1
deadbolt run --env-file .env.tpl -- bun run dev

# Keep TTY (disables output masking; masking uses pipes)
deadbolt run --no-mask --env TOKEN=deadbolt://personal/API/credential -- ./interactive-cli

# Render {{ deadbolt://... }} placeholders to a mode-0600 file (or stdout if -o omitted)
deadbolt inject -i config.tpl -o config.json
deadbolt inject -i config.tpl -o config.json --force   # overwrite an externally modified file

# Print a single resolved value (prefer `run` or `inject`)
deadbolt read deadbolt://personal/GitHub/password [--no-newline]
```

`deadbolt run` resolves `--env`, `--env-file` (`NAME=VALUE`, `#` comments, `export`, quotes), and any inherited environment variable whose value starts with `deadbolt://`, then replaces each secret (plus URL-encoded and unpadded base64 forms, length >= 3) in stdout/stderr with `<concealed by deadbolt>`.

### One-time sharing (`send` & `receive`)

Serves files, folders, stdin (`-`), or vault items live from the local daemon over an encrypted one-time `deadbolt.pw/r#...` link. Nothing is uploaded to any server.

```sh
# Non-interactive scripts must pass --yes (required by --json and non-TTY)
deadbolt send ./report.pdf --note "quarterly numbers" --ttl 1h --opens 1 --yes --json
cat key.pem | deadbolt send - --sensitive --yes
deadbolt send --item Stripe --field secret --yes --wait

# Inspect or revoke active sends (send a literal file named 'ls' as ./ls)
deadbolt send ls [--json]
deadbolt send show <id> [--json]
deadbolt send revoke <id>

# Receive a Send link (needs no vault and no daemon; accepts full URL or #fragment)
deadbolt receive 'https://deadbolt.pw/r#...'
deadbolt receive 'https://deadbolt.pw/r#...' --output ./downloads [--force] [--json]
```

### Import, health, activity, updates & diagnostics

```sh
# Import from 1Password (.1pux/CSV), Apple Passwords CSV, Bitwarden (.json), or CSV
deadbolt import ./export.1pux --dry-run
deadbolt import ./export.1pux

# Audit saved passwords (offline by default; --online queries HIBP k-anonymity range API)
deadbolt health [--all] [--only weak,reused,breached,site-breach,2fa,passkeys,ignored] [--online] [--all-vaults] [--json]
deadbolt health ignore <item> <kind>
deadbolt health unignore <item> <kind>
deadbolt health breaches [on | off | status]

# Inspect daemon access history (never logs secret values)
deadbolt activity [--since 1h] [--limit 100] [--json]

# Check for or install updates (also updates registered unpacked browser extensions)
deadbolt update --check          # exits 10 if an update is available, 0 if current
deadbolt update [--channel dev|beta|stable] [--yes]

# Desktop app, browser extension registration, and daemon diagnostics
deadbolt app
deadbolt desktop [install | uninstall]
deadbolt browser install [--extension-dir <dir>] [--standalone]
deadbolt browser switch --standalone | --native [--channel dev|beta|stable] [--extension-dir <dir>]
deadbolt browser uninstall [--extension-dir <dir>]
deadbolt debug whoami [--json]
deadbolt debug watch
deadbolt debug daemon [status | stop]
```

## More Resources

- Website: <https://deadbolt.pw/>
- Architecture walkthrough: <https://deadbolt.pw/architecture/>
- LLM index: <https://deadbolt.pw/llms.txt>
- Source repository: <https://github.com/anomalyco/deadbolt>
