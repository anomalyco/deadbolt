# Browser autofill

Deadbolt fills and saves passwords in Chromium browsers (Chrome, Brave, Arc,
Edge, Chromium) through its own extension. The extension isn't written yet;
this doc covers the parts that are, the agent's side and the native messaging
host, and specifies the messages the extension will use.

```text
web page ─ content script ─ extension ══ native messaging ══ deadbolt browser-host ── agent socket ── agent
                                          (stdin/stdout)        (shape checks only)                   (decides)
```

- **The agent decides.** Matching a page to logins, refusing another site's
  login, computing one-time codes and comparing passwords all happen in the
  agent (`crates/cli/src/agent/autofill.rs`, rules in `crates/cli/src/site.rs`).
  Each agent command names the page's origin and the agent works out the site
  itself, so nothing upstream can widen what a page gets.
- **The host is a pipe.** `deadbolt browser-host` checks the shape of each
  message, turns it into one agent command (`site-logins`, `site-fill`,
  `site-check`, `site-save`) and passes the agent's watch stream back as
  `changed` messages. It never prompts for a passphrase or Touch ID.
- **The extension** finds login forms, asks the host, and fills. Saves need a
  click in the extension's own UI.

## Install

```sh
deadbolt browser install                      # browsers found on this computer
deadbolt browser install --browser brave      # or name them: chrome brave arc edge chromium all
deadbolt browser uninstall                    # every browser, or --browser
```

`install` writes `pw.deadbolt.browser.json` to each browser's
`NativeMessagingHosts` directory:

| Browser  | macOS (`~/Library/Application Support/…`) | Linux (`$XDG_CONFIG_HOME` or `~/.config/…`) |
| -------- | ----------------------------------------- | ------------------------------------------- |
| Chrome   | `Google/Chrome`                           | `google-chrome`                             |
| Brave    | `BraveSoftware/Brave-Browser`             | `BraveSoftware/Brave-Browser`               |
| Arc      | `Arc/User Data`                           | (none)                                      |
| Edge     | `Microsoft Edge`                          | `microsoft-edge`                            |
| Chromium | `Chromium`                                | `chromium`                                  |

```json
{
  "name": "pw.deadbolt.browser",
  "description": "Deadbolt password manager",
  "path": "/absolute/path/to/deadbolt",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://jhocodkhpifjndffenppfmdkmiolngal/"]
}
```

Without `--browser`, a browser counts as installed when its directory exists.
Run `install` again after moving the binary.

**`path` is the `deadbolt` binary itself.** A browser runs a host with one
argument, the caller's origin (`chrome-extension://<id>/`), and a manifest
can't add others. So when `deadbolt` gets exactly one argument starting with
`chrome-extension://`, it runs `deadbolt browser-host <origin>`. A launcher
script would also work, but it's a second file that has to point at the
binary and can drift from it.

**The extension id is fixed by a key.** `extension/manifest-key.txt` holds the
base64 DER SubjectPublicKeyInfo of an RSA-2048 key, which goes in the extension
manifest's `key` field. Chrome derives the id from it: SHA-256 of the DER, the
first 16 bytes in hex, each digit `0`–`f` written as a letter `a`–`p`. That
gives `jhocodkhpifjndffenppfmdkmiolngal`, which a unit test checks against
`EXTENSION_ID`. Only the public key is committed. Loading the extension
unpacked doesn't need the private key, and it was discarded. Packing a `.crx`
ourselves would need a new key, so a new id. The Chrome Web Store signs with
its own key, so a store listing gets another id, and that id would go into
`allowed_origins` too.

The host refuses to start for any origin other than the extension's, and
`allowed_origins` already stops the browser from connecting any other
extension.

## Which logins a page gets

These rules follow Foyer's (see Prior art), so the two behave alike:

- **Pages:** https only, or http on `localhost`, `127.0.0.1`, `*.localhost`
  and `*.test` (a trailing dot allowed). Anything else (http sites, `file:`,
  `data:`, extension pages) gets `bad_request`.
- **A page's site** is the registrable domain of its host under the full
  Public Suffix List, private section included (the `psl` crate, compiled in,
  updated by bumping it). `gist.github.com` is on `github.com`, while
  `alice.github.io` and `bob.github.io` are two sites. An IPv4 address,
  `localhost` and a single label are their own sites. A page whose host is a
  public suffix itself (`github.io`, `co.uk`) has no site and gets nothing.
- **A saved URL is on the site** when its host is the site, under it, or has
  it as its registrable domain. A URL without `://` is read as `https://`.
  Hosts are parsed as browsers parse them (WHATWG URL rules via the `url`
  crate): lowercase, IDNs in punycode, port and path ignored. Lookalikes
  don't match: `github.com.evil.com`, `evilgithub.com`, a punycode `gíthub.com`
  or `https://github.com@evil.com` aren't on `github.com`.
- **Labels agree:** a login's title when it has no name, and search, use
  the same host parsing, so `https://evil.com\@github.com` is labelled
  `evil.com`, where it would fill.
- **A login's URLs** are all its fields of type url: `url`, plus `url-2`,
  `url-3`… that imports keep. Any one matching is enough. A list shows only
  the URLs that match.
- **Every vault** is searched. A `ref` is `<vault id>:<item id>` (64 and 32
  lowercase hex digits), so it names one login without ambiguity. New logins
  go to the default vault.

## Threat model

- **Same-user processes are trusted, as they are for the CLI.** Any program
  running as you can run `deadbolt get`, talk to the agent socket, or run
  `deadbolt browser-host` with the extension's origin as its argument. The
  origin check only confirms which browser extension connected; it doesn't
  stop local programs. Protection against them would need the OS, such as
  code signing checks on the socket peer.
- **Web pages are not trusted.** A page can't reach the host: only the
  extension can, and the extension passes the frame origin the browser
  reports, never anything the page said. The agent refuses another site's
  login even if the extension asks for it (`domain_mismatch`), so a bug or a
  compromise in the extension's matching can't leak logins across sites.
- **What leaves the agent:** a list carries titles, usernames, vault names
  and matching URLs, never passwords or one-time password secrets. A fill
  carries only what it asked for, and a one-time password only as its current
  code. A check returns new, update or same and which logins matched. It
  compares passwords by BLAKE3 hash, in constant time, and never reveals
  them.
- **Secrets in transit** go only over stdin/stdout and the agent socket, never
  argv. They are held in `Zeroizing` buffers, and Debug output prints
  `<redacted>` in their place. Neither the host nor the agent logs them.
- **Check results stay in the extension.** A check is a password oracle
  for the page's site. The extension must never hand its result (or a
  fill's values before filling) to page scripts, nor run a check a page
  asked for. The host rate-limits checks and fills as well, so a runaway or
  compromised caller can't guess quickly.
- **The idle lock:** fill and save count as use. Hello, list and check don't,
  because a browser asks for those on every page and would otherwise hold the
  vault open.
- **Locked means locked.** While the store is locked, every request but hello
  gets `locked`. Hello starts the agent if it isn't running but never unlocks
  it.

## Host messages

Every message is a frame: a 32-bit length in native byte order, then that
many bytes of UTF-8 JSON. The extension connects with
`chrome.runtime.connectNative("pw.deadbolt.browser")` and keeps the port open.
Requests are answered in order. `changed` messages can arrive between replies.
The host exits when the port closes.

- **Limits:** requests are capped at 64 KiB. A bigger one is skipped whole and
  answered with `bad_request` and `"id": null`, and the connection stays open.
  Replies stay under the browser's 1 MB limit. A list too large to fit becomes
  a `failed` error.
- **Rate limits:** per connection, `check` allows a burst of 20 then one a
  second, and `fill` a burst of 60 then four a second. Past that a request
  gets `rate_limited`; nothing else is limited.
- **Requests** carry an `id`, a string of up to 200 characters or a number. The
  reply echoes it. A message without a usable id, or one that isn't JSON, gets
  `bad_request` with `"id": null`.
- **`origin`** is the origin of the frame the form is in, such as
  `https://gist.github.com` or `http://localhost:3000`.
- **Unknown fields** are ignored. Values are strings unless noted otherwise.

### hello

```json
{ "id": "1", "type": "hello" }
{ "id": "1", "type": "hello", "protocol": 1, "version": "0.1.0+abc123",
  "status": "ready", "capabilities": ["list", "fill", "check", "save"] }
```

`status` is one of:

- `ready`: unlocked.
- `locked`: `detail` says "Unlock Deadbolt to fill passwords".
- `not-set-up`: no device yet.
- `unavailable`: the agent couldn't be reached or started; `detail` says why.

Hello starts the agent if needed. It's the only message that does.

### list: the logins for a page

```json
{ "id": "2", "type": "list", "origin": "https://github.com" }
{ "id": "2", "type": "list", "site": "github.com", "accounts": [
  { "ref": "<64 hex>:<32 hex>", "vault": "personal", "title": "GitHub",
    "username": "octocat", "hasPassword": true, "hasTotp": true,
    "urls": ["https://github.com"] } ] }
```

`username` is left out when the login has none. `title` is the login's name,
else its URL's host. Accounts are sorted by title.

### fill: values of one login

```json
{ "id": "3", "type": "fill", "origin": "https://github.com", "ref": "…",
  "want": ["username", "password", "totp"] }
{ "id": "3", "type": "fill", "username": "octocat", "password": "…", "totp": "123456" }
```

`want` holds one to three of `username`, `password` and `totp`. The reply has
only those the login has. `totp` is the current code, computed by the agent.
A login that isn't on the page's site gets `domain_mismatch`, and an unknown
`ref` gets `not_found`.

### check: was what was typed saved?

```json
{ "id": "4", "type": "check", "origin": "https://github.com",
  "username": "octocat", "password": "…" }
{ "id": "4", "type": "check", "status": "update", "matches": ["<ref>"] }
```

Among the site's logins with the same username (compared trimmed and
case-insensitively; a blank username matches logins that have none):

- `same`: some have that password. `matches` lists them.
- `update`: none do. `matches` lists those with that username.
- `new`: no login has that username. `matches` is empty.

The password is 1 to 4096 characters and the username at most 500.

### save

```json
{ "id": "5", "type": "save", "origin": "https://github.com",
  "entry": { "title": "github.com", "url": "https://github.com/login",
             "username": "octocat", "password": "…" } }
{ "id": "5", "type": "save", "ref": "<ref>", "created": true }
```

- **Without `ref`:** creates a login in the default vault with `url`,
  `username` (when not blank) and `password`, named `title` unless that is
  just the site. Runs of spaces and control characters in `title` become one
  space.
- **With `ref`:** changes only that login's password (`created: false`), and
  only if one of its URLs is on the page's site, else `domain_mismatch`.
- **Validation:** `entry.url` is trimmed, then must be a whole URL of a page
  Deadbolt fills, by the rule for origins (https, or http on local hosts), with
  no spaces, at most 2048 bytes (`bad_request`), and on the page's site
  (`domain_mismatch`). `title` is 1 to 128 characters.

### changed (pushed)

```json
{ "type": "changed", "change": "locked" }
```

`change` is one of:

- `locked` or `unlocked`.
- `items`: logins or vaults changed, here or by sync.
- `stopped`: the agent stopped, which locks it.
- `started`: an agent is running again after the one watched went away, or
  after a hello found none, so ask hello. The agent a hello starts isn't
  announced.

Pushes carry no id and no values. Refetch what's on screen.

### error

```json
{ "id": "3", "type": "error", "code": "domain_mismatch", "message": "github.com isn't saved for gitlab.com" }
```

`code` is one of:

- `locked`: the store is locked, not set up, or no agent runs.
- `not_found`: no such login.
- `domain_mismatch`: the login or URL isn't on the page's site.
- `bad_request`: a malformed message, a page that gets no logins, or a value
  out of range.
- `rate_limited`: too many checks or fills; try again in a moment.
- `failed`: anything else.

`message` is for people and never holds a secret.

## Not supported yet

- **Passkeys:** no storage or WebAuthn yet. They'd be matched by relying party
  id rather than URL.
- **"Sign in with…" (SSO):** remembering which identity provider a site uses
  isn't supported.
- **Firefox and Safari:** Firefox passes different host arguments and uses a
  different manifest. Safari needs an app extension.
- **Touch ID on fill:** an unlocked vault fills without asking again.
- **Unlocking from the browser:** the extension can say Deadbolt is locked but
  can't unlock it. Use the app or `deadbolt unlock`.
- **Choosing the vault for a new login:** new logins go to the default vault.

## Prior art

[Foyer](https://github.com/R44VC0RP/foyer), by Ryan Vogel, is an autofill
extension that learns sign-in flows and asks pluggable password managers for
credentials through its own native host. Its protocol and safety rules shaped
this design: an extension-only native host, matching by host or registrable
domain with the private suffixes, https-only filling, secret-free lists, and
check-then-save. Deadbolt's extension and host are written from scratch, and
no Foyer code is copied (Foyer has no license).
