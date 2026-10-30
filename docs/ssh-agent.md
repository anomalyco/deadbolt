# SSH agent

2026-10-30. Built (`crates/cli/src/agent/ssh.rs`, `crates/cli/src/ssh.rs`,
`crates/app/src/ssh.rs`). An SSH agent and Git commit signer inside
Deadbolt's background agent, matching 1Password's SSH agent while keeping
Deadbolt's Touch ID and caller-verification rules (`docs/agent-control.md`,
`docs/touch-id.md`).

## Summary

- **Runs in `deadbolt agent` on a second socket (`ssh.sock`).** The background
  agent already holds the unlocked `store.redb` handle, the caller identity
  cache (`caller.rs`), the Activity ledger, and the Secure Enclave Touch ID
  helper (`deadbolt-enclave`). Listening on a separate `0600` socket keeps the
  JSON control socket (`agent.sock`) unreachable when an SSH session forwards
  `SSH_AUTH_SOCK`. A stable symlink at `~/.deadbolt/ssh.sock` gives
  `~/.ssh/config` and GUI apps one short path that survives reboots and stays
  under macOS's 104-byte `sun_path` limit.
- **Private keys stay in the agent.** `ssh.sock` speaks only public-key
  listings, `session-bind@openssh.com`, and single-message signatures.
  `deadbolt ssh-sign` returns only armored `SSHSIG` signatures. Pressing `⏎` on
  an `ssh` item copies its public key instead of its private key, and `ItemGet`
  omits `private-key` and `passphrase` unless explicitly asked for with a
  Touch ID tap (`Tier::Read`), the same way `otp` secrets stay out of the app.
- **A finger approves each signature.** Every `SIGN_REQUEST` identifies the
  socket peer by kernel audit token (`LOCAL_PEERTOKEN` on macOS, `SO_PEERCRED`
  on Linux), parses what is being signed (an SSH login packet, an `SSHSIG`
  message such as a Git commit, or raw bytes), and raises Touch ID through the
  hash-pinned `deadbolt-enclave` helper with an agent-written sentence naming
  the verified caller, the key, and the target. Optional 15-minute grants tie
  to `(tty, session_started)` and drop on lock; AI callers, TTY-less processes,
  and forwarded connections always ask per use.
- **Host-aware key order avoids `MaxAuthTries` failures.** OpenSSH 8.9+ sends
  `session-bind@openssh.com` with the server's verified host key *before*
  `REQUEST_IDENTITIES`. Deadbolt remembers which key last signed for each
  server host key (`cli/ssh-used` in `store.redb`) and reads optional
  `$XDG_CONFIG_HOME/deadbolt/ssh.toml` rules plus `~/.ssh/known_hosts`, so the
  matching key is offered first even when a vault holds dozens of SSH keys.
- **One binary signs Git commits too.** Git passes `gpg.ssh.program` directly
  as `argv[0]` without splitting spaces (`gpg-interface.c`), starting its
  arguments with `-Y`. `deadbolt` detects a leading `-Y` or `-U` before `clap`
  parses flags (the same trick `browser-host` uses for `chrome-extension://`)
  and routes to `deadbolt ssh-sign`, so `.gitconfig` sets
  `gpg.ssh.program = deadbolt`.

```text
ssh / git ──▶ ~/.deadbolt/ssh.sock ──▶ deadbolt agent (ssh.rs)
                                         ├─ caller.rs: LOCAL_PEERTOKEN + code signature + tty
                                         ├─ bind.rs:   verify session-bind@openssh.com hostkey
                                         ├─ select.rs: ssh.toml + known_hosts + last-used rank
                                         ├─ policy.rs: Touch ID via deadbolt-enclave (or tty grant)
                                         └─ keys.rs:   sign in Zeroizing memory, log to Activity
```

## Protocol coverage

Deadbolt implements the wire framing and v2 client messages of
`draft-ietf-sshm-ssh-agent` (formerly `draft-miller-ssh-agent`) and OpenSSH's
`PROTOCOL.agent` in `crates/cli/src/agent/ssh/wire.rs`. Each frame is a
big-endian `u32` length (`1..=262_144`, matching OpenSSH's 256 KiB cap; `0` or
larger closes the stream before allocating) followed by a `u8` message type and
SSH `string` / `uint32` / `boolean` fields. One connection handles requests
sequentially until EOF, because `ssh` sends `session-bind`,
`REQUEST_IDENTITIES`, and `SIGN_REQUEST` on a single stream.

| Message | Code | Reply | Behaviour |
| --- | --- | --- | --- |
| `SSH_AGENTC_REQUEST_IDENTITIES` | `11` | `12` (`IDENTITIES_ANSWER`) | Lists eligible `(key_blob, comment)` pairs in host-matched order. `Tier::Look`, no tap while unlocked. |
| `SSH_AGENTC_SIGN_REQUEST` | `13` | `14` (`SIGN_RESPONSE`) or `5` | Checks policy, prompts Touch ID (unless covered by a live TTY grant), signs `data`, logs to Activity. |
| `SSH_AGENTC_EXTENSION` `"query"` | `27` | `29` (`EXTENSION_RESPONSE`) | Returns `["query", "session-bind@openssh.com"]`. |
| `SSH_AGENTC_EXTENSION` `"session-bind@openssh.com"` | `27` | `6` (`SUCCESS`) or `28` (`EXTENSION_FAILURE`) | Verifies the server host key's KEX signature over `session_id` and records `(hostkey, session_id, is_forwarding)` on this connection, even while locked. |
| `SSH_AGENTC_EXTENSION` (any other name) | `27` | `5` (`FAILURE`) | Per `draft-ietf-sshm-ssh-agent`, unknown extensions return `FAILURE` (`5`), whereas a known extension whose check fails returns `EXTENSION_FAILURE` (`28`). |
| `ADD_IDENTITY`, `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`, `ADD_ID_CONSTRAINED`, `ADD_SMARTCARD_KEY*`, `REMOVE_SMARTCARD_KEY`, `LOCK`, `UNLOCK`, SSHv1 (`1..=9`) | `17..=26`, `1..=9` | `5` (`FAILURE`) | Always refused (below). |

### Key types and signature flags

- **Ed25519 (`ssh-ed25519`):** `flags` must be `0`; non-zero flags return
  `SSH_AGENT_FAILURE`.
- **ECDSA (`ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`):**
  `flags` must be `0`. Signatures encode `(mpint r, mpint s)` per RFC 5656
  §3.1.2, not ASN.1 DER.
- **RSA (`ssh-rsa` key blobs with RFC 8332 SHA-2 flags):**
  - `SSH_AGENT_RSA_SHA2_256` (`0x02`) signs with `rsa-sha2-256`.
  - `SSH_AGENT_RSA_SHA2_512` (`0x04`) signs with `rsa-sha2-512` (preferred when
    both `0x02` and `0x04` are set).
  - **`flags == 0` (legacy SHA-1 `ssh-rsa`) and keys under 2048 bits are
    refused** with `SSH_AGENT_FAILURE`. OpenSSH 8.8 disabled `ssh-rsa` SHA-1
    signatures by default, and `PROTOCOL.sshsig` forbids SHA-1.
- **Not supported:** `ssh-dss` (DSA, removed in OpenSSH 9.8) and `sk-*` FIDO
  hardware-token keys (which talk directly to a YubiKey or Secretive rather
  than living in a synced vault). SSH user certificates (`*-cert-v01@openssh.com`)
  are out of v1 and can be added later as an optional `certificate` field on
  `ssh` items.

### Why `session-bind@openssh.com` is supported and `restrict-destination` is not on the wire

When OpenSSH 8.9+ connects to a server, `get_agent_identities` (`sshconnect2.c`)
sends `session-bind@openssh.com` (`hostkey`, `session_id`, `signature`,
`is_forwarding`) as the **first** message on the agent socket, before
`REQUEST_IDENTITIES` and before `SIGN_REQUEST`. On `ssh -A`, `clientloop.c`
does the same with `is_forwarding = true` before opening the remote channel.

Verifying `session-bind@openssh.com` gives Deadbolt three concrete properties:

1. **Works while locked.** Checking the server's KEX signature uses only the
   public `hostkey` in the message, never vault state. Accepting bindings while
   locked avoids the OpenSSH 9.8 lock-interaction bug where a `ssh -A` session
   started while the agent was locked bypassed forwarding detection once
   unlocked.
2. **Detects agent forwarding.** Any connection with `is_forwarding = true` in
   its binding chain, or whose earlier `session-bind` failed (`bind_failed =
   true`), is known to be forwarded or untrusted. Deadbolt refuses forwarded
   `SIGN_REQUEST`s by default (`ssh_allow_forwarding = false`), and when
   forwarding is turned on, never grants a time window and labels the Touch ID
   prompt `(forwarded via …)`.
3. **Verifies what `SIGN_REQUEST` is signing.** Standard SSH public-key
   authentication signs `string session_id || byte 50 (USERAUTH_REQUEST) ||
   string username || string "ssh-connection" || string method || ...`, where
   `method` is `"publickey"` (RFC 4252) or
   `"publickey-hostbound-v00@openssh.com"` (which embeds the server `hostkey`
   inside the signed packet too). When the connection was bound via
   `session-bind`, Deadbolt checks that the packet's `session_id` (and, for
   hostbound requests, its `hostkey`) matches the last bound hop; a mismatch
   returns `SSH_AGENT_FAILURE`.

By contrast, `restrict-destination-v00@openssh.com` (`0xff`) is a constraint
attached to `SSH2_AGENTC_ADD_ID_CONSTRAINED` (`25`) when `ssh-add -h` loads an
external key into OpenSSH's `ssh-agent`. Because Deadbolt refuses `ssh-add`, it
never receives `0xff` constraints on the wire; instead, per-host restrictions
live in `ssh.toml` (`hosts = [...]`, below) and are enforced against the same
`session-bind` state.

### Why `add`, `remove`, and `lock` are refused

`ssh-add` with no arguments loads every `~/.ssh/id_*` file on disk, and
`ssh-add -D` deletes every key in the agent. Silently importing local disk keys
into a synced vault on `ssh-add`, or deleting synced vault items on
`ssh-add -D`, would break muscle memory with destructive side effects. Holding
temporary un-synced keys in RAM beside vault keys would split the security
model in two. `SSH_AGENTC_LOCK` and `SSH_AGENTC_UNLOCK` carry a plain byte
password over a socket that may be forwarded over `ssh -A`; Deadbolt locks and
unlocks only on its verified control socket. Importing a disk key is an
explicit command (`deadbolt ssh import ~/.ssh/id_ed25519`).

### Rust dependencies (why `ssh-key` + `ring`, not `ssh-agent-lib` or `rsa`)

- **`ssh-agent-lib` is not used.** `ssh-agent-lib 0.6` depends on `ssh-key 0.6`
  (`ed25519-dalek 2`, `p256 0.13`, `sha2 0.10`, `signature 2`) and `secrecy`,
  which would duplicate Deadbolt's RustCrypto tree (`ed25519-dalek 3.0`,
  `p256 0.14`, `sha2 0.11`, `signature 3.0`, triggering `multiple-versions` in
  `deny.toml`) and hide each accepted `UnixStream`'s `LOCAL_PEERTOKEN` behind
  its listener loop. The binary framing is ~200 lines of bounds-checked code in
  `ssh/wire.rs` with zero `unsafe`.
- **`rsa` crate is not used.** Both `rsa 0.9` and `rsa 0.10.0-rc` carry an
  unpatched RustSec advisory (`RUSTSEC-2023-0071`, Marvin timing side-channel,
  `patched = []`), which fails `cargo deny check`. `ring 0.17` is already in
  `Cargo.lock` (via `iroh` and `rustls`, `crates/cli/Cargo.toml`) and provides
  constant-time RSA PKCS#1 v1.5 SHA-256/SHA-512 signing (`RsaKeyPair`) and
  verification (`UnparsedPublicKey`) for 2048–8192-bit keys.
- **`ssh-key 0.7.0-rc.11` lives in `deadbolt-cli` only** (`features = ["std",
  "ed25519", "p256", "p384", "p521", "encryption"]`, no `rsa` feature), sharing
  the workspace's exact `ed25519-dalek 3`, `p256 0.14`, `sha2 0.11`,
  `signature 3`, and `zeroize 1.9` crates. Keeping SSH dependencies in
  `deadbolt-cli` rather than `deadbolt-core` adds zero bytes to the standalone
  extension's `wasm32` build (`deadbolt-ext-core`).

## Where it runs and how users configure it

### Listener and socket path

The SSH agent runs inside `deadbolt agent` (`crates/cli/src/agent/mod.rs`
`serve`), sharing the Tokio runtime, `Session`, `Callers`, `Watchers`, and
`biometric` locks with `agent.sock`:

```text
$XDG_RUNTIME_DIR/deadbolt<suffix>/ssh.sock    real listener (0600, dir 0700 via secure_dir)
~/.deadbolt/ssh.sock                          symlink -> real listener (default store only)
```

- **Why two paths:** `$XDG_RUNTIME_DIR` is unset for macOS GUI apps (Tower,
  Fork, Zed, VS Code) and `~/.ssh/config` `IdentityAgent` cannot evaluate
  `$TMPDIR` or `<uid>`. Putting a `0700` directory `~/.deadbolt` with a
  symlink `ssh.sock -> <paths.ssh_socket>` gives `~/.ssh/config` one portable
  path (`~/.deadbolt/ssh.sock`, ~32 bytes, well under the 104-byte `sun_path`
  limit on macOS and safe even when `$HOME` is on a network filesystem).
- **Test isolation:** When `DEADBOLT_HOME` is set (`<suffix>` is non-empty),
  the agent binds only `paths.ssh_socket` inside the test's runtime directory
  and never touches `~/.deadbolt`.
- **Opt-in toggle:** Controlled by `ssh_agent = true` in `config.toml` (default
  `false`) and `Command::SshAgentSet { enabled: bool }` (`Status.ssh_agent:
  bool`, `Status.ssh_socket: Option<String>`). Turning it on binds `ssh.sock`
  immediately without restarting `deadbolt agent`; turning it off drops the
  listener, drains open SSH connections, and unlinks `ssh.sock` and
  `~/.deadbolt/ssh.sock`.
- **Cold boot (`ssh` does not auto-start `deadbolt agent`):** Unlike
  `deadbolt` CLI commands, `/usr/bin/ssh` connects directly to `ssh.sock` and
  fails if no process is listening. Turning `ssh_agent` on installs a user
  login unit (`~/Library/LaunchAgents/pw.deadbolt.agent.plist` with
  `RunAtLoad = true` on macOS; `~/.config/systemd/user/deadbolt-agent.service`
  on Linux) that starts `deadbolt agent` (locked) at login; turning `ssh_agent`
  off removes it (Decision 5).

### Pointing `ssh` and tools at it

In `~/.ssh/config` (recommended, because it works in terminals and GUI apps
alike while keeping forwarded `SSH_AUTH_SOCK` working on remote hosts):

```sshconfig
# Use Deadbolt locally; keep forwarded SSH_AUTH_SOCK when logged in over ssh -A.
Match host * exec "test -z $SSH_CONNECTION"
    IdentityAgent ~/.deadbolt/ssh.sock
```

CLI helpers (`crates/cli/src/ssh.rs`):

```sh
deadbolt ssh on                        # enable SSH agent (and login auto-start), print snippet
deadbolt ssh off                       # disable SSH agent and remove socket
deadbolt ssh status                    # socket path, enabled state, eligible key count
deadbolt ssh sock                      # print socket path (/Users/…/.deadbolt/ssh.sock)
eval "$(deadbolt ssh env)"             # export SSH_AUTH_SOCK=… for tools ignoring IdentityAgent
```

In `Deadbolt.app`, Settings › Security gains an **SSH agent** switch under
**Unlock with Touch ID** (`crates/app/src/ssh.rs`), with a **Copy `~/.ssh/config`
snippet** button when on.

## Approval model

### Identifying the caller

When a client connects to `ssh.sock`, `Agent::handle_ssh` checks `uid(&stream)
== getuid()`, captures `Peer::of(&stream)` (`LOCAL_PEERTOKEN` on macOS: `pid` +
`pid_version`; `SO_PEERCRED` + `/proc` `start_ticks` on Linux), and resolves
`CallerInfo` via `self.callers.identify(peer, None)` (`caller.rs`):

- **macOS:** `deadbolt-enclave identify` verifies the peer's code signature
  against the kernel audit token before and after reading its `tty`,
  `session_started`, and process ancestry (`Ghostty › zsh › git › ssh`,
  `OpenCode › zsh › ssh`, `Fork › git › ssh`). PID reuse fails the second
  audit-token check with exit 15.
- **Linux:** labelled `"… · unverified (Linux)"` from `/proc`, as in
  `caller.rs:281`.
- **AI detection:** `ssh` speaks binary SSH agent frames and carries no
  `Request.claimed`, so `caller::is_ai` relies on ancestry (`opencode`,
  `opencode-cli`, `claude`, `codex`, `cursor-agent`, `gemini`, `aider`). For
  Git commits via `deadbolt ssh-sign`, the CLI speaks Deadbolt's control
  protocol and forwards `DEADBOLT_CALLER` and `OPENCODE_SESSION_ID` in
  `Request.claimed` as usual.

### Touch ID per use vs 15-minute grants

SSH signing belongs to `Tier::Use` (`docs/agent-control.md`): the caller gets
one signature, never the private key.

- **Default (`ssh_approval = "each"` in `config.toml`):** Every `SIGN_REQUEST`
  and `Command::SshSign` raises Touch ID via `deadbolt-enclave unseal` with an
  agent-built reason string derived from verified facts:
  - Bound SSH login: `sign in as "git" to github.com (SHA256:+DiY…) with
    personal › GitHub (Ghostty › zsh › ssh)` (hostname shown only when
    `~/.ssh/known_hosts` matches the verified `session-bind` host key;
    otherwise the host key's `SHA256:…` fingerprint alone).
  - Unbound SSH login (older SSH client without `session-bind`): `sign in as
    "git" (unverified host) with personal › GitHub (Ghostty › zsh › ssh)`.
  - `SSHSIG` (`ssh-keygen -Y sign` or `deadbolt ssh-sign`): `sign a "git"
    message with personal › GitHub (Ghostty › zsh › git)`.
  - Anything else (arbitrary challenge bytes): `sign raw data with personal ›
    GitHub (Ghostty › zsh › ssh)`.
- **Optional 15-minute grant (`ssh_approval = "15m"`, or `[Allow 15 min]` once
  the `Deadbolt.app` approval panel of `agent-control.md` build order 2
  ships):**
  - Stored in agent memory (never persisted across restarts), keyed by
    `(anchor, vault_id, item_id)` with `15 min` idle expiry and `1 hour` hard
    cap, revocable in `deadbolt grants` / Settings › Activity, and **wiped on
    every lock**.
  - **Anchor:** `(tty, session_started)` only.
  - **Always `Once` (never granted a window):** callers with `tty == None`,
    callers where `caller::is_ai(&caller)` is true, forwarded connections
    (`is_forwarding == true`), and raw non-SSH / non-`SSHSIG` payloads.
- **Concurrency, limits, and idle lock:**
  - At most **one** Touch ID prompt on screen across the whole agent, with up
    to **3** requests queued per anchor (60 s deadline each; closing the client
    socket or locking cancels the in-flight `CancelHandle` immediately). This
    lets parallel `git fetch` jobs (submodules, Cargo git deps) wait in line
    instead of failing while a finger is moving to the sensor.
  - **3 cancelled or timed-out prompts in 10 minutes** put that anchor in a
    10-minute denial cooldown (`Outcome::Refused`), matching
    `docs/agent-control.md`.
  - SSH requests do not extend `unlock_timeout` (so a background `git fetch`
    loop or AI cannot hold the vault open), while an active Touch ID prompt
    holds `self.busy()` until settled.
  - Every `SIGN_REQUEST` and `Command::SshSign` writes an Activity entry
    (`tier: Use`, `command: "ssh-sign"`, item vault/id/title, target summary in
    `fields`, outcome); `REQUEST_IDENTITIES` is unrecorded like `passkey-list`
    so `ssh-add -l` and connection preflights do not flood Activity.

### Behaviour when the vault is locked

While locked, `store.redb` is closed and encrypted, so neither private keys nor
public keys are in memory:

1. **With `deadbolt ssh-sign` (Git commit signing):** Git passes `-f <pubkey>`
   and `-n git`, so `deadbolt ssh-sign` sends `Command::SshSign` naming the
   public key up front. When `touch_id_ready` is true, one Touch ID tap
   (`"unlock Deadbolt and sign a \"git\" message with SSH key SHA256:…"`)
   unseals the store, checks the key exists, signs, and leaves the store
   unlocked under its configured `unlock_timeout`.
2. **On `ssh.sock` when `touch_id_ready` is true:** `ssh` sends
   `session-bind@openssh.com` first, then `REQUEST_IDENTITIES`. `REQUEST_IDENTITIES`
   runs `unlock_biometric` (coalesced on `biometric_flight`, rate-limited per
   anchor). When the connection has a verified local (`is_forwarding == false`)
   `session-bind` host key, the prompt says `"unlock Deadbolt and sign in to
   <host/fingerprint> (<caller>)"` and permits **one** matching `SIGN_REQUEST`
   on that same connection and `session_id` within 15 seconds without a second
   tap (Decision 4). An unbound `REQUEST_IDENTITIES` (`ssh-add -l`) unlocks
   with `"unlock your Deadbolt vaults"` and still asks on any later
   `SIGN_REQUEST`.
3. **When `touch_id_ready` is false** (Touch ID off, 14-day passphrase reset,
   lid closed without Touch ID keyboard, or Linux): `ssh.sock` never raises a
   passphrase prompt; `REQUEST_IDENTITIES` returns 0 keys (`[0,0,0,5, 12,
   0,0,0,0]`) and `SIGN_REQUEST` returns `SSH_AGENT_FAILURE`, recording a held
   `Outcome::Locked` Activity entry. On an interactive TTY, `deadbolt ssh-sign`
   falls back to the terminal passphrase prompt unless `caller::is_ai` is true.

## Key selection (avoiding `Too many authentication failures`)

OpenSSH `sshd` defaults to `MaxAuthTries 6`. Each public key `ssh` tests counts
toward those six tries, so offering seven unrelated keys disconnects before the
seventh key or password auth runs. Deadbolt avoids this in three layers
(`crates/cli/src/agent/ssh/select.rs`):

1. **Remembered host-key pairing (`cli/ssh-used` in `store.redb`, device-local):**
   Whenever a `SIGN_REQUEST` succeeds on a connection bound via
   `session-bind@openssh.com`, Deadbolt records `server_hostkey_sha256 ->
   (vault_id, item_id, last_used)` (capped at 1,000 entries, oldest evicted,
   just like `cli/autofill-filled` in `session.rs`). On the next connection to
   that server, `session-bind` arrives before `REQUEST_IDENTITIES`, so Deadbolt
   puts that server's last-used key **first** in `IDENTITIES_ANSWER`. The
   server accepts on try 1 with zero config files.
2. **Optional `$XDG_CONFIG_HOME/deadbolt/ssh.toml` (live-reloaded, matching
   1Password's `agent.toml` plus `hosts`):**
   Without `ssh.toml`, Deadbolt offers active `ssh` items from the **default
   vault** only (ordered by `cli/ssh-used` for the bound server, then stable
   item order). Creating `ssh.toml` overrides which vaults and items are
   offered, in rule order, and optionally scopes rules to hosts:

   ```toml
   # Offer only to github.com (matched against session-bind via ~/.ssh/known_hosts)
   [[ssh-keys]]
   item = "GitHub"
   vault = "personal"
   hosts = ["github.com", "gist.github.com"]

   # Offer all keys from the work vault next
   [[ssh-keys]]
   vault = "work"
   ```

   When `session-bind` provides a server `hostkey` and `~/.ssh/known_hosts`
   (both plain hostnames and `|1|<salt>|<hash>` HMAC-SHA1 entries, checked with
   `hmac` + `sha1` already in the workspace) matches a rule's `hosts`, keys
   scoped to *other* hosts are omitted from `IDENTITIES_ANSWER` AND refused at
   `SIGN_REQUEST` for any non-matching bound server. For clients that do not
   send `session-bind`, keys with `hosts` still appear in `IDENTITIES_ANSWER`
   only if `unverified_hosts = true` is not required (default: omitted for
   host-pinned keys so destination pinning fails closed).
3. **Multiple keys on the same host (e.g. two GitHub accounts sharing GitHub's
   host key):** Because both accounts see the same server `hostkey`, host-key
   matching cannot tell them apart. Users distinguish them in `~/.ssh/config`
   with `IdentityFile ~/.ssh/github-work.pub` and `IdentitiesOnly yes`;
   `deadbolt get "GitHub Work" -f public-key -o ~/.ssh/github-work.pub` writes
   the `.pub` stub cleanly.

## Git commit and tag signing

Git 2.34+ signs commits and tags when `gpg.format = ssh` by invoking
`gpg.ssh.program` directly as `argv[0]` (`gpg-interface.c`, no shell word
splitting):

- **Sign:** `<program> -Y sign -n git -f <key_file> [-U] [buffer_file]`
- **Verify (`git log --show-signature`, `git verify-commit`, `git verify-tag`):**
  - `<program> -Y find-principals -f <allowed_signers> -s <sig_file> [-Overify-time=…]`
  - `<program> -Y verify -n git -f <allowed_signers> -I <principal> -s <sig_file> [-r <revocation>] [-Overify-time=…]`
  - `<program> -Y check-novalidate -n git -s <sig_file> [-Overify-time=…]`

### How `deadbolt` handles `gpg.ssh.program`

1. **`argv` dispatch in `crates/cli/src/main.rs`:** Right beside the
   `chrome-extension://` check (`main.rs:394`), if `args[1]` is `-Y` or `-U`,
   `main` inserts `"ssh-sign"` at `args[1]` before `Cli::parse_from`. Users set
   `gpg.ssh.program` to `deadbolt` (or
   `/Applications/Deadbolt.app/Contents/Helpers/deadbolt`), with no wrapper
   binary to ship, sign, or keep in sync.
2. **Signing (`-Y sign`):**
   - Reads the public key from `-f <key_file>` (Git writes a temporary `.pub`
     file when `user.signingkey` is `ssh-ed25519 …` or `key::ssh-ed25519 …`) and
     reads the raw bytes from `[buffer_file]` or `stdin` into `Vec<u8>` without
     decoding as UTF-8, avoiding `op-ssh-sign`'s failure on binary `patatt` and
     `ssh-keygen -Y sign -n file` inputs.
   - If `$SSH_CONNECTION` (or `$SSH_TTY`) and `$SSH_AUTH_SOCK` are both set and
     `$SSH_AUTH_SOCK` is not Deadbolt's own local socket, delegates to the
     forwarded `SSH_AUTH_SOCK` so commit signing on a remote dev box prompts
     Touch ID on the user's local Mac.
   - Otherwise calls `ensure_running` and sends `Command::SshSign { public_key,
     namespace, data }` over `agent.sock` (carrying `Request.claimed` and
     verifying the agent binary with `set_agent_check`). The agent constructs
     the `SSHSIG` signed-data structure (`"SSHSIG" || namespace || reserved ||
     "sha512" || SHA512(data)` per OpenSSH `PROTOCOL.sshsig`), approves via
     Touch ID, signs, and returns the `-----BEGIN SSH SIGNATURE-----` block to
     write to `<buffer_file>.sig` or `stdout`.
3. **Verification (`-Y find-principals`, `-Y verify`, `-Y check-novalidate`):**
   Verification uses only public keys and `allowed_signers`, never the agent or
   vault. `deadbolt ssh-sign` delegates these subcommands straight to `ssh-keygen`
   on `PATH` (falling back to `/usr/bin/ssh-keygen`), preserving exact exit
   codes and `Good "git" signature …` output that `gpg-interface.c` parses.
4. **Setup helper and `allowed_signers`:**
   `deadbolt ssh git-config <query> [--global] [--write]` prints (or applies
   with `--write`) the Git config and idempotently adds
   `<git user.email> namespaces="git" <public-key>` to
   `~/.ssh/allowed_signers` (creating `~/.ssh` `0700` and `allowed_signers`
   `0644`, UTF-8 without BOM) and sets `gpg.ssh.allowedSignersFile`, so local
   `git verify-commit HEAD` works immediately alongside GitHub/GitLab commit
   verification.

## Generating, importing, and copying keys

### Canonical `ssh` items and 1Password compatibility

`crates/core/src/item.rs` already defines `ssh` with `private-key` (required,
secret, multiline), `public-key`, `fingerprint`, `passphrase`, `comment`, and
`notes`. Checking `crates/cli/src/import/onepassword.rs` (`lines 291–295`,
`658–685`) and `op.rs` (`line 288`) shows three real-world formats already in
Deadbolt vaults:

1. **1Password `.1pux` and `deadbolt sync 1password` (`op`):** store PKCS#8 PEM
   (`-----BEGIN PRIVATE KEY-----`) from `sshKey.metadata.privateKey`, plus an
   extra `key-type` text field on 1Password 8 exports.
2. **Bitwarden exports (`bitwarden.rs:331`) and `~/.ssh/id_*` files:** store
   OpenSSH PEM (`-----BEGIN OPENSSH PRIVATE KEY-----`, plain or `bcrypt`
   encrypted) or legacy PKCS#1 / SEC1 PEM (`BEGIN RSA/EC PRIVATE KEY`).
3. **Encrypted keys with a separate `passphrase` field:** imported items may
   carry an encrypted `private-key` alongside `passphrase`.

To make every `ssh` item work without manual repair:

- `ssh/keys.rs` parses **PKCS#8 PEM, OpenSSH PEM, PKCS#1 RSA PEM, and SEC1 EC
  PEM**, unlocking encrypted keys with the item's `passphrase` field when
  present.
- On every `ItemNew` and `ItemSet` touching an `ssh` item's `private-key`,
  `passphrase`, or `comment`, the agent validates that the key parses as a
  supported type (Ed25519, ECDSA P-256/P-384/P-521, RSA ≥ 2048 bits) and
  **derives canonical `public-key` (`<alg> <base64>[ <comment>]`) and
  `fingerprint` (`SHA256:<unpadded-base64>`)** from the private key itself, so
  `public-key` and `fingerprint` can never drift from `private-key`. (Imports
  fill missing `public-key` and `fingerprint` the same way, while keeping
  unsupported keys such as legacy DSA as a warning rather than dropping data;
  `op` sync preserves 1Password's `MirrorVersion` digest calculation.)

### CLI and desktop app flows

- **CLI:**
  - `deadbolt new ssh --name "GitHub" [comment=alice@laptop]` (when
    `private-key` is omitted) and `deadbolt ssh new [NAME] [--type
    ed25519|p256] [--comment TEXT]` generate a fresh Ed25519 (default) or
    ECDSA P-256 key inside the agent.
  - `deadbolt ssh import ~/.ssh/id_ed25519 [--name NAME]`: reads the private key
    file (prompting on TTY for its file passphrase if encrypted), strips the
    file passphrase into an unencrypted OpenSSH PEM stored inside the encrypted
    vault so signing needs only Touch ID, derives `public-key`, `fingerprint`,
    and `comment`, and creates the `ssh` item.
- **Desktop app (`crates/app`):**
  - **New / Edit Item › SSH key:** adds an `Ed25519` / `ECDSA P-256` segmented
    control, **Generate key** button (`Command::SshGenerate { kind, comment }`),
    and **Import file…** button (`Command::SshInspect`) under `private-key`,
    filling `public-key`, `fingerprint`, and `comment` while keeping the private
    key masked.
  - **Copy & actions (`model.rs`, `listing.rs`):** `primary_field("ssh")`
    becomes `"public-key"` (`copy_label("ssh")` → `"Copy public key"`), so `⏎`
    in the main window and Quick Panel copies the public key instead of the
    private key.
  - **Withholding `private-key` by default:** `Listing::info_with` leaves `ssh`
    `private-key` and `passphrase` empty on default `ItemGet` (`ssh_private =
    false`, including background cache `Peek`s, `deadbolt show`, `deadbolt run`,
    and `deadbolt inject`). Exporting `private-key` from the CLI (`deadbolt get
    <item> -f private-key` or `deadbolt show --reveal`) requires Touch ID.

## Security argument

### Invariant: private keys never leave the agent

1. `ssh.sock` speaks only `IDENTITIES_ANSWER` (public key blobs and comments),
   `EXTENSION_RESPONSE` (`"query"`), and `SIGN_RESPONSE` (a signature over one
   caller-supplied message). There is no message in the protocol that exports a
   private key.
2. `Command::SshSign` returns only an armored `SSHSIG` signature.
3. During signing, `ssh/keys.rs` decodes the key from the in-memory `Vault`
   into `Zeroizing` buffers, signs synchronously, and drops and zeroizes the
   parsed key material before sending the reply.
4. With `private-key` omitted from default `ItemGet` (`Decision 3`),
   `Deadbolt.app`, its 32-item page cache (`crates/app/src/cache.rs`), the Quick
   Panel, `deadbolt show`, `deadbolt run`, and `deadbolt inject` never receive
   SSH private keys either. Exporting a private key (`deadbolt get <item> -f
   private-key`) requires an explicit `Tier::Read` Touch ID tap naming the export.

### What a same-UID attacker cannot do

- **Cannot read an SSH private key** over `ssh.sock`, `deadbolt ssh-sign`, or
  any unapproved control-socket request.
- **Cannot silently sign an SSH login or Git commit** under `each` (or outside
  an approved TTY tab under `15m`): every signature requires a physical finger
  on the Touch ID sensor via the SHA-256-pinned `deadbolt-enclave` helper, with
  `localizedFallbackTitle = ""` (no macOS login password fallback).
- **Cannot click "Allow" programmatically:** an AI or malware with macOS
  Accessibility (`cua-driver`, `CGEventPost`, AppleScript) can click any window
  button, which 1Password documents as an accepted risk of its click-to-approve
  dialog, whereas `CryptoKit.SecureEnclave` in SEP hardware refuses ECDH
  without a live fingerprint match from `coreauthd`.
- **Cannot forge caller identity on macOS:** `LOCAL_PEERTOKEN` binds the
  connection to `(pid, pid_version)` in the kernel, and `identify.swift`
  re-checks the audit token after reading process metadata.
- **Cannot forge a server host key in `session-bind@openssh.com`** without that
  server's private host key, and **cannot reach `agent.sock` commands** over a
  forwarded `ssh -A` channel because `ssh.sock` is a separate listener that
  parses only SSH agent messages.
- **Cannot spam Touch ID prompts:** at most one prompt shows at a time, 3 queue
  per anchor, and 3 cancellations/timeouts lock out that anchor for 10 minutes.

### What a same-UID attacker can do (residual risks)

- **List active public keys while unlocked:** `REQUEST_IDENTITIES` returns
  configured public keys and comments without a tap, equivalent to reading
  `~/.ssh/*.pub` on disk.
- **Race a Touch ID tap:** a local process can send a `SIGN_REQUEST` hoping the
  user taps without reading the sheet. The sheet counters this by naming the
  verified caller chain, the item title, and the parsed action (`sign in as
  "git" to github.com` vs `sign a "git" message` vs `sign raw data`), serialized
  one prompt at a time.
- **Share a 15-minute TTY grant (if enabled):** if the user opts into `15m`
  grants, another process running on the same `(tty, session_started)` can sign
  with that specific key until the 15-minute idle timer or lock fires. Keeping
  `each` as the default eliminates this window.
- **Same-UID memory or binary tampering without Hardened Runtime (and on
  Linux):** as documented in `docs/agent-control.md`, Developer ID signing with
  Hardened Runtime blocks code injection and `task_for_pid` on macOS release
  builds; ad-hoc local builds and Linux (`ptrace`, `/proc` races, no OS code
  signing) cannot stop a same-UID attacker who modifies binaries or attaches a
  debugger.

## Testing without real vaults or keys

All tests run against throwaway temp directories (`DEADBOLT_HOME`,
`XDG_RUNTIME_DIR`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME` under `tempfile` with a
short `db` prefix so `ssh.sock` stays well under 104 bytes on macOS) and debug
switches (`DEADBOLT_NET=local`, `DEADBOLT_KDF=fast`), never touching
`~/.local/share/deadbolt`, `~/.config/deadbolt`, or `~/.deadbolt`, and never
waking a display or asking for a real fingerprint:

1. **Unit & property tests (`crates/cli/src/agent/ssh/*_tests.rs`):**
   - Key fixtures generated in tests (or static RFC/OpenSSH test keys) covering
     Ed25519, ECDSA P-256/P-384/P-521, and RSA 2048/4096 in OpenSSH PEM (plain
     and `bcrypt`-encrypted), PKCS#8 PEM (1Password `.1pux`/`op` shape), PKCS#1,
     and SEC1; verify RSA SHA-1 (`flags == 0`), <2048-bit RSA, and DSA are
     rejected.
   - `proptest` framing and parser tests on `wire.rs` and `bind.rs`: oversized
     lengths, truncated strings, unknown extensions (`5`) vs bad
     `session-bind` signatures (`28`), duplicate `session_id`, binding while
     locked, and `USERAUTH_REQUEST` `session_id` mismatches.
   - Policy and Activity tests driving `Agent`'s existing `biometric_hook`
     (`crates/cli/src/agent/mod.rs:124`): approve, user cancel, client socket
     EOF cancelling an in-flight prompt, 3-strikes cooldown, lock clearing
     grants, AI and `is_forwarding` callers forced to `Once`, and Activity
     verifying no private key or signed payload bytes ever appear in
     `store.redb`.
2. **Real OpenSSH & Git integration tests (`crates/cli/tests/cli/ssh.rs`, a
   submodule of `crates/cli/tests/cli.rs` so Cargo builds one test binary):**
   - Uses a debug-only `DEADBOLT_TEST_SSH_APPROVE=allow|deny` switch (gated by
     `config::test_env`, compiled out of `--release` builds just like
     `DEADBOLT_KDF=fast`) so child `deadbolt agent` processes approve or deny
     deterministically in headless CI on macOS and Linux.
   - **`ssh-add`:** runs real `ssh-add -l` and `ssh-add -L` against
     `SSH_AUTH_SOCK=$(deadbolt ssh sock)` to check fingerprints, key blobs, and
     `ssh.toml` ordering; verifies `ssh-add <file>` and `ssh-add -D` fail
     cleanly.
   - **`ssh-keygen -Y`:** signs text and random non-UTF-8 binary blobs via
     `ssh-keygen -Y sign` over `ssh.sock` (for Ed25519, P-256, and RSA-4096) and
     verifies them with `ssh-keygen -Y verify` against a temp `allowed_signers`.
   - **Real `git commit -S` and `git tag -s`:** initializes a temp Git repo with
     `gpg.format = ssh`, `gpg.ssh.program = env!("CARGO_BIN_EXE_deadbolt")`,
     `user.signingkey`, and `gpg.ssh.allowedSignersFile`, then asserts
     `git verify-commit HEAD` and `git verify-tag` succeed (and fail when
     `DEADBOLT_TEST_SSH_APPROVE=deny` or when locked without Touch ID).
   - **Real `ssh` against a local unprivileged `sshd`:** when `/usr/sbin/sshd`
     is present, spawns `sshd -D -e -f <tmp>/sshd_config` on `127.0.0.1:0` as
     the current user (`UsePAM no`, `StrictModes no`, `MaxAuthTries 6`, temp
     host key in `<tmp>/known_hosts` and public key in `<tmp>/authorized_keys`),
     runs `ssh -F <tmp>/ssh_config 127.0.0.1 true` to exercise real OpenSSH
     `session-bind@openssh.com` + `publickey-hostbound-v00@openssh.com`, and
     verifies a 7-key vault succeeds without `Too many authentication failures`.

## Code organization

Following `code-organization` (capability folder, no new `mod.rs`, every file
well under 800 non-test lines, SSH dependencies isolated to `deadbolt-cli` so
`deadbolt-core` and `deadbolt-ext-core` wasm stay untouched):

| Path | Responsibility | Est. lines |
| --- | --- | --- |
| `crates/cli/src/ssh.rs` | `deadbolt ssh` subcommands (`on`, `off`, `status`, `sock`, `env`, `new`, `import`, `git-config`) and `deadbolt ssh-sign` (`-Y` sign & `ssh-keygen` verify delegation) | ~320 |
| `crates/cli/src/agent/ssh.rs` | `ssh.sock` listener + `~/.deadbolt/ssh.sock` symlink lifecycle, per-connection loop, `Command::Ssh*` handlers, Activity wiring | ~300 |
| `crates/cli/src/agent/ssh/wire.rs` | SSH agent binary framing (`256 KiB` cap), message codecs, `USERAUTH_REQUEST` and `SSHSIG` payload parsers | ~220 |
| `crates/cli/src/agent/ssh/keys.rs` | OpenSSH / PKCS#8 / PKCS#1 / SEC1 key parsing (with `passphrase`), Ed25519 & P-256 generation, `public-key` & `fingerprint` derivation, `ring` RSA-SHA2 + `ssh-key` signing, `SSHSIG` armoring | ~350 |
| `crates/cli/src/agent/ssh/bind.rs` | `session-bind@openssh.com` KEX signature verification (unlocked or locked), hop chain, forwarding & `session_id` checks | ~180 |
| `crates/cli/src/agent/ssh/select.rs` | `ssh.toml` (`[[ssh-keys]]`) loader, `cli/ssh-used` hostkey MRU ranking, `~/.ssh/known_hosts` plain & HMAC-SHA1 matching | ~220 |
| `crates/cli/src/agent/ssh/policy.rs` | Caller checks, serialized Touch ID prompt queue (1 active, 3 queued/anchor, 3-strikes cooldown), optional 15m TTY grants | ~220 |
| `crates/cli/src/agent/ssh/*_tests.rs` | Sibling unit & `proptest` suites per submodule | <500 each |
| `crates/cli/tests/cli/ssh.rs` | End-to-end `ssh-add`, `ssh-keygen -Y`, `git commit -S`, and unprivileged `sshd` integration tests (`mod ssh;` in `tests/cli.rs`) | ~380 |
| `crates/app/src/ssh.rs` | Settings › SSH agent switch + snippet copy, New Item › SSH key generation & file import wiring, `⌘K` actions | ~220 |

## PR-sized steps and risks

1. **PR 1: SSH key parsing, derivation, generation, and `ssh import` (`ssh/keys.rs`, `items.rs`, `import/`)**
   - *Scope:* Parse PKCS#8 (1Password), OpenSSH, PKCS#1, and SEC1 keys; sign
     Ed25519, ECDSA, and RSA-SHA2 (`ring`); auto-derive `public-key` and
     `fingerprint` on create/edit/import; generate Ed25519 on `deadbolt new ssh`
     without `private-key`; add `deadbolt ssh import`; withhold `private-key` /
     `passphrase` from default `ItemGet` (if Decision 3 is approved).
   - *Risk:* `deadbolt sync 1password` compares `MirrorVersion::digest` against
     stored fields (`import/mod.rs:126`). *Mitigation:* preserve 1Password's
     exact `publicKey` / `fingerprint` strings when they already match the key,
     filling them only when missing, and test against `op.rs`'s existing
     `EXPORT` / `ITEMS` fixtures.
2. **PR 2: `ssh.sock` listener, `session-bind`, and Touch ID per-use signing (`agent/ssh.rs`, `ssh/{wire,bind,policy}.rs`, `cli/src/ssh.rs`)**
   - *Scope:* `ssh_agent` config & `Command::SshAgentSet`, `ssh.sock` +
     `~/.deadbolt/ssh.sock` symlink, `REQUEST_IDENTITIES`, `SIGN_REQUEST`,
     `session-bind@openssh.com`, caller + payload Touch ID prompts, Activity
     entries, `deadbolt ssh on|off|status|sock|env`, and `tests/cli/ssh.rs`
     against `ssh-add`, `ssh-keygen -Y`, and local `sshd`.
   - *Risk:* Overlapping Touch ID prompts between `unlock_biometric`,
     `passkey_prompt`, and `ssh`. *Mitigation:* unify `passkey_prompt` and SSH
     prompts behind one agent-wide prompt mutex/queue so two `deadbolt-enclave`
     Touch ID sheets never compete on screen.
3. **PR 3: Host-aware key selection (`ssh/select.rs`)**
   - *Scope:* `cli/ssh-used` hostkey MRU ranking, `$XDG_CONFIG_HOME/deadbolt/ssh.toml`
     (`[[ssh-keys]]` with `vault`, `item`, `hosts`), `~/.ssh/known_hosts`
     matching, and the >6-key `MaxAuthTries` `sshd` integration test.
   - *Risk:* Hashed `known_hosts` entries (`|1|salt|hash`) or non-standard ports
     (`[host]:2222`). *Mitigation:* test both `host` and `[host]:port` forms
     against real `ssh-keygen -H -F` output.
4. **PR 4: Git commit & tag signing (`deadbolt ssh-sign`, `deadbolt ssh git-config`)**
   - *Scope:* `main.rs` `-Y`/`-U` dispatch, `Command::SshSign` single-tap
     unlock+sign with raw binary support and remote `$SSH_AUTH_SOCK` forwarding
     passthrough, `ssh-keygen` verification passthrough, `deadbolt ssh git-config`
     + `allowed_signers`, and `git commit -S` / `git verify-commit` tests.
   - *Risk:* Git installations where `ssh-keygen` is not in a GUI app's minimal
     `PATH`. *Mitigation:* check `PATH`, `/usr/bin/ssh-keygen`, and
     `/opt/homebrew/bin/ssh-keygen`, matching how `app.md` locates helpers.
5. **PR 5: Desktop app SSH settings, key generation, and public-key copy (`crates/app/src/ssh.rs`)**
   - *Scope:* Bump Rune `rev` first (`AGENTS.md`); add Settings › SSH agent
     switch + `~/.ssh/config` snippet copy + login LaunchAgent/systemd unit;
     New Item › SSH key generator and file import; `⏎` copies public key; update
     `crates/app/scripts/snap.sh` stills.
   - *Risk:* Stale LaunchAgent path if `Deadbolt.app` moves. *Mitigation:* point
     the LaunchAgent at the installed CLI symlink or rewrite it on app launch
     when `ssh_agent` is enabled, as `browser install` notes.
6. **PR 6 (after `agent-control.md` build order 2): Approval panel & Linux passphrase fallback**
   - *Scope:* Route SSH prompts through `Deadbolt.app`'s approval panel (`[Deny]
     [Allow once] [Allow 15 min]`) with verified caller details, host key, and
     secure passphrase fallback when Touch ID is unavailable.

## Decisions

1. **Touch ID per signature (`each`) by default, with optional `15m` per terminal tab:**
   Default is **`each`** (one Touch ID tap per SSH login or Git commit), with
   `ssh_approval = "15m"` in `config.toml` tied to `(tty, session_started)`,
   while always keeping AI callers (`caller::is_ai`), TTY-less callers, and
   forwarded connections at `Once`.
2. **SSH agent forwarding (`ssh -A`) refused by default:**
   `ssh_allow_forwarding = false` by default, with a `config.toml` / per-key
   `ssh.toml` (`allow-forwarding = true`) opt-in that always requires a
   per-signature Touch ID tap labelled `(forwarded via SHA256:…)`.
3. **`⏎` copies `public-key`, and `private-key` is withheld from default `ItemGet`:**
   `primary_field("ssh") = "public-key"`, and default `ItemGet` omits
   `private-key` and `passphrase` (like `otp`), returning them to CLI callers
   only on explicit `ssh_private = true` with a Touch ID tap.
4. **Single-tap Touch ID unlock + sign on `ssh.sock` when locked:**
   When `touch_id_ready` is true and `session-bind@openssh.com` already bound
   the connection to a local server host key, one Touch ID tap unlocks Deadbolt
   and issues a 15-second single-use ticket for that connection's matching
   `SIGN_REQUEST`; unbound `ssh-add -l` unlocks only and still prompts before
   signing.
5. **Login auto-start unit installed when turning the SSH agent on:**
   Enabling the SSH agent on the default store writes
   `~/Library/LaunchAgents/pw.deadbolt.agent.plist` (macOS) or
   `~/.config/systemd/user/deadbolt-agent.service` (Linux) and removes it when
   disabled.
