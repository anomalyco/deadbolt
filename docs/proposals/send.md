# Deadbolt Send

2026-10-27. One-time links that hand files, secrets or vault items to someone who doesn't use Deadbolt. Built in `crates/send` (protocol and crypto, native and WebAssembly), `crates/send-web` (the browser wrapper), the agent (`crates/cli/src/agent/send.rs`), the CLI (`crates/cli/src/send.rs`) and the site's receive page (`site/r.html`, `site/src/receive/`).

## Model

- **The recipient needs only a browser.** They open `https://deadbolt.pw/r#<ticket>`. The page fetches the share straight from the sender's computer and decrypts it locally.
- **Live, peer to peer, nothing stored.** The sender's agent serves the share over iroh on ALPN `deadbolt/send/1` until it is picked up, expires or is revoked. The browser runs iroh compiled to WebAssembly, which can only use relays, so it reaches the sender through the n0 relay named in the link. No server of ours, or anyone's, keeps a copy; the relay only forwards end-to-end encrypted QUIC.
- **The link is the key.** The ticket (`SendTicket`, unpadded base64url after `#`):
  `version(1) || sender endpoint id(32) || access secret(32) || content key(32) || relay_len(1) || relay url || addr_count(1) || addrs`.
  Browsers never send a fragment to a server. Direct addresses go in only when there is no relay (local networks and tests); with one, they'd only lengthen the link and tell its holder the sender's network addresses.
- **A send endpoint of its own.** The agent serves sends from a second iroh endpoint with a random key per agent run, not the device key: a link doesn't identify the device, and it stops working when the agent stops. Sends need no vault and no unlock (the agent holds only sealed bytes), so they keep working while the store is locked and on a device that isn't set up.
- **The agent never sees the content key.** The CLI builds the bundle, seals it, and sends the agent only the sealed bytes and the access secret (`send-create`); the key goes straight from the CLI into the link. So `deadbolt sends` can't show a link again.
- **Bundle.** Minimal and general: `Bundle { title?, note?, entries: [Entry | Group] }`, `Entry { name, data, mime?, sensitive }`, `Group { name?, entries }`. Names and types are inside the encryption. Files are entries, folders groups, a vault item a group of its fields (secret and otp fields sensitive). At most 32 MiB sealed.
- **Sealing.** Chunked XChaCha20-Poly1305 (STREAM): 64 KiB chunks, nonce `prefix(15) || last(1) || index(8)`, key `BLAKE3 derive_key("deadbolt send 2026-10 bundle", content key)`. Truncation, reordering and extension fail.

### Protocol (`deadbolt/send/1`)

```text
receiver -> sender   PROOF  HMAC-SHA256(secret, "receiver-proof" || 0 || transcript)
sender -> receiver   STATUS 0 ok | 1 expired | 2 used | 3 revoked
                     then, if ok: len (u64 BE) || sealed bundle
receiver -> sender   ACK    1
transcript = "deadbolt/send/1" || sender id || receiver id || TLS exporter("EXPORTER-deadbolt-send-v1")
```

The secret is proved, never sent, and the proof is bound to the connection, so it can't be replayed. The sender checks the proof against each share it serves (constant time); a proof that matches none closes the connection with code 1 ("unknown link"). The sender's identity is the endpoint id in the ticket, which iroh's TLS authenticates.

### Policy

- Single use by default (`--opens N` for more, up to 100); expires after **1 hour** by default (`--ttl`, up to 7 days).
- An open is reserved when a receiver proves the secret, and counted once the whole sealed bundle has been written to the connection, acknowledged or not (the receiver may have it). A receiver that fails before then gives its open back. While one is downloading, a second receiver of a single-use link is refused as "used": first opener wins.
- Revoking stops further opens; one already under way may finish. Once a share can't be opened again the agent drops its bundle from memory; finished shares stay listed until a day after they would have expired.
- Shares live in the agent's memory. **They end when the agent stops** (a `send --wait` then fails); the CLI says so when it prints a link.

## Threat model

- **Whoever holds the link is the recipient.** Anyone who sees it (a chat log, a shoulder, a link scanner) can open it instead. Single use plus "picked up" make that visible: if the intended recipient finds the link already used, the sender's `deadbolt sends show` says when it was opened, and they should treat the contents as exposed.
- **The sender must be online.** Their computer must be awake with the agent running until the link is opened. Nothing waits on a server.
- **Link scanners.** The receive page only connects when the recipient presses "Receive", so a mail or chat scanner that runs scripts doesn't spend a one-time link. Previews that don't run scripts never see the fragment at all.
- **The page.** It reads the fragment once, removes it from the address bar and history (`history.replaceState`), keeps it only in memory, and never logs or sends it. It sets `Referrer-Policy: no-referrer` (also as a meta tag), loads nothing from third parties (CSP allows connections only to the site, and to https/wss for the relays), has no analytics and can't be framed. Trust in the page is trust in deadbolt.pw serving honest code, as with any web client; the page is static and built from this repository.
- **The relay** sees that a browser connected to an endpoint id, when, and how many bytes went through; not the content, the secret or the key.
- **The agent** holds the sealed bundle and the access secret in memory until the share ends, never the content key. A process that can read the agent's memory can already read the unlocked vault.
- **Not in scope:** a recipient keeping what they received, a compromised recipient browser, metadata (sizes, timing) visible to the relay.

## CLI

```text
deadbolt send [PATH|ITEM]... [--item QUERY]... [--field NAME] [--title T] [--note N]
              [--sensitive] [--opens N] [--ttl 1h] [--qr] [--json] [--wait]
deadbolt sends [ls [--json] | show <id> [--json] | revoke <id>]
```

- `deadbolt send ./file ./folder/` sends files (media type sniffed) and folders (as groups).
- `deadbolt send` with no arguments asks for a secret with hidden input; with stdin piped and no terminal, it reads stdin.
- `deadbolt send -` reads stdin. Short UTF-8 is a sensitive value named `secret`, without the trailing newline `echo` adds; anything else a file.
- `deadbolt send "github work"` sends a vault item as a group of its fields, keeping secret and otp fields hidden; `--field password` sends only that field.
- **Paths vs items:** an argument that names an existing file or folder is sent as one; anything else is a vault search (words ANDed, or an id prefix, like `get`). `--item QUERY` forces an item when a file of the same name exists. A search that matches nothing fails with "no file or vault item matches".
- Inputs mix freely in one send. `--title` and `--note` are shown to the recipient (the note is never hidden). `--sensitive` hides files and stdin behind "reveal" too.
- Prints the link on stdout (`--json`: `{"id", "link", "expires"}`), a summary on stderr, and with `--qr` a QR code on stderr.
- `--wait` blocks until the link is picked up (exit 0), expires (exit 4) or is revoked (exit 5); other failures exit 1. Waiting doesn't hold the vault unlocked.
- `DEADBOLT_SEND_URL` points links at another copy of the receive page (a local `bun run dev`, or a self-hosted site).
- Control protocol 9: `send-create`, `send-list`, `send-show`, `send-revoke`, `send-wait` (`crates/client/src/protocol.rs`).

## Receive page

`/r` (`site/r.html`): states for no link, ready, connecting, proving, downloading (with progress), decrypting, done, and failures: sender offline (retry; the link wasn't used), expired, already used, revoked, unknown, corrupt. Done shows the title and note; sensitive values hidden with reveal and copy; other text shown; files with name, size and download; groups as a tree; and "copy as .env" for a group (or the whole bundle) of short single-line values with usable names.

### Building it

`site/scripts/wasm.sh` (run by the site's `build` and `typecheck`) builds `crates/send-web` for `wasm32-unknown-unknown` in release and runs `wasm-bindgen --target web` into `site/src/receive/wasm/` (not committed); Vite bundles the result. It needs `rustup target add wasm32-unknown-unknown` and `cargo install wasm-bindgen-cli --version <the version crates/send-web pins> --locked`. The iroh browser build uses `default-features = false` with `tls-ring` (ring compiles to wasm32 with clang) and getrandom's `wasm_js` backend. `bun run check` and CI clippy both crates for wasm32.

## Later

- Shares that survive an agent restart (persist the sealed bundle and the endpoint key, encrypted at rest).
- Sending from the desktop app; receiving into a vault with Deadbolt.
- An offline mailbox for when the sender can't stay online, which changes the "nothing stored" model and would be a separate decision.
