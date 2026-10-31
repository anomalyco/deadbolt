# AI agents using Deadbolt

2026-10-27. Design, mostly not built yet: build order 1 (caller identity
and Activity), standing grants for agent sign-ins and secrets for
commands (`deadbolt run`, `inject`, `read`, with standing grants for AIs;
both below) are. How AI agents (OpenCode sessions and the like) may use
Deadbolt, carefully. Questions for Kit are at the end.

**What is enforced today** (until `policy::decide`, build order 3; #111).
The socket admits only this user. Beyond that, a caller that looks like an
AI (an AI host among its parents, or a claimed `OPENCODE_SESSION_ID`; a
hint, so it only ever refuses):

- sees a value (`item-get`, so `get` and `show`, and `item-code`) only with
  Touch ID raised by the agent each time, as `deadbolt read`; without Touch
  ID, or with it cancelled or denied, it is `forbidden` (exit 4, "refused"
  in Activity);
- is refused the Never tier outright: `setup`, `unlock`,
  `unlock-biometric`, `touch-id-set`, `vault-create`, `vault-rename`,
  `vault-default`, `device-remove`, `join`, `pair`, `item-remove`, `import`
  and `sync-one-password`;
- is refused the browser's fills and saves: `site-fill`, `site-save` with a
  login (a new password for a saved one), `form-fill`, `passkey-get` and
  `passkey-create`;
- gets values from `resolve` and agent sign-ins (`agent-logins`,
  `agent-fill`, `agent-passkey-get`, proved by the client's token) only as
  their sections below say.

A refusal names the AI host it saw ("This shell runs under OpenCode
(OpenCode › zsh › deadbolt)") and points to a terminal outside it, the app,
and `deadbolt whoami`. On Linux the app has no signature to check, so
Deadbolt.app started from inside an AI's tree is a caller like any other
there and is refused the same; start it from the desktop instead.

Not yet:

- Everyone else, Kit's terminal and an AI that started a terminal outside
  its own tree included, gets everything while unlocked.
- The browser's commands, `site-fill` and the rest, are open to any
  same-user process on the socket that isn't taken for an AI, not only
  `deadbolt browser-host`, until browser pairing.
- Write-tier commands aren't gated for AIs yet: `item-set`, `item-unset`
  and `item-restore` (`site-save` with a login and `passkey-create` are, as
  above).

Words: **the agent** is Deadbolt's background agent (`deadbolt agent`), as
everywhere else in these docs. **An AI** is an AI agent calling Deadbolt.
**A caller** is any process on the control socket that isn't Deadbolt.app or
the browser host.

## Summary

- **The agent decides, per caller.** Today any process running as Kit can
  read every secret once the vault is unlocked (`docs/autofill.md`, threat
  model). An AI's shell runs as Kit, so it can too. This design makes the
  agent look at who is asking and what for, the way it already checks a
  page's site before a fill.
- **Use, don't read.** An AI gets secrets into a command's environment or a
  file (`deadbolt run`, `deadbolt inject`), not into its transcript.
  Printing a value is possible, costs a Touch ID tap every time, and says so.
- **A finger approves, not a click.** Approvals are a Deadbolt panel plus a
  Touch ID sheet raised by the agent itself. Kit's AIs have Accessibility
  (cua-driver, computer use) and can click anything; they can't touch the
  sensor.
- **Grants live in the agent.** The caller holds nothing it could copy or
  stretch. Locking drops every grant.
- **Everything is logged** in an Activity list in the app, without values.

## Tiers

| Tier | What | Asks? |
| --- | --- | --- |
| Look | List and search: titles, usernames, URLs, field names. Never values | No. Logged, rate-limited |
| Use | Put values in a command's env or a 0600 file | Yes. Once, or 15 min |
| Read | Print one field to the caller | Yes. Once, every time |
| Add | Create an item, add a field, edit a plain field (not a secret or URL) | No. Logged, rate-limited, marked "added by" |
| Write | Change or remove a secret, change an item's URLs, add a URL that another item already has | Yes. Once each |
| Never | See below | AIs: refused. Other callers: a tap every time, no grant |

How today's protocol (`crates/client/src/protocol.rs`) maps:

- **Look:** `status`, `vault-list`, `item-list`, `devices`, `watch`, and
  `item-get` asking for no values (a new `fields: Some([])`, below).
- **Use:** the new `resolve` with a `run` or `inject` purpose.
- **Read:** `item-get` with values (`deadbolt get`, `show --reveal`),
  `item-code`, and `resolve` with a `read` purpose.
- **Add:** `item-new`, and `item-set` that adds a field or edits a plain
  one. Nothing is overwritten or revealed, so a stray add costs a cleanup,
  not a secret. The app marks what an AI added ("added by OpenCode, Oct 27")
  in the item pane, and an AI-added login carries that mark in the browser
  menu too, so a decoy login for a real site stands out.
- **Write:** `item-set` and `item-unset` on a secret field (overwriting a
  password locks Kit out until he restores it) and any change to an
  existing item's URLs. URLs decide where the browser extension fills, so
  adding `evil.example` to the GitHub login would hand the GitHub password
  to that site. Values come from stdin or the agent's generator, never
  argv. Old values stay in the item's history (`Vault::history`), so a bad
  write can be undone. `item-restore` too: a restored login fills on its
  sites again.
- **Never:** `item-remove`, `import`, `join`, `pair`, `device-remove`,
  `vault-create`, `vault-rename`, `vault-default`, `touch-id-set`,
  `sync-one-password`, and answering approvals. There is no export command,
  and no grant covers more than the items it names, so there is no bulk read
  either. `setup`, `unlock` and `unlock-biometric` carry their own proof (the
  passphrase or a finger), so they don't ask again, but AIs are refused them
  too.
- **Always allowed:** `status` and `stop` (version handover depends on
  them, `docs/app.md`), `lock` (makes things safer), `generate` (no vault
  needed), `sync`, `app-activate` (brings the desktop app forward).
- **Browser only:** `site-logins`, `site-fill`, `site-check`, `site-save`
  and `site-generate` with its check, keep and drop, from a caller the agent
  sees as the browser host (next section).

`policy::decide(&Caller, &Command, &Grants) -> Allow | Ask | Deny` is one
pure function with an exhaustive match and no fallback arm, so a new
`Command` doesn't compile until someone puts it in a tier. Table tests cover
every command for every kind of caller.

## Who is asking

The agent reads the socket's peer, not anything the caller says:

- **The process:** macOS gives the peer's audit token (`LOCAL_PEERTOKEN`):
  pid plus pid version, so a reused pid can't pass. Linux gives
  `SO_PEERCRED`: pid and uid, with no pid version. The agent remembers
  each peer it identified by pid, uid and pid version; on Linux the last is
  the process's start time (clock ticks), read from `/proc` after the
  connection, so it is missing if the process has already exited, and a
  process that `exec`s another program keeps its start time and so the
  entry made for the first. One more reason a Linux peer is labels only
  (below). The workspace forbids `unsafe`, so this comes from a dependency
  (`nix`, in `deadbolt-client`'s `peer` module, shared by the agent, the
  CLI and the app).
- **Its code signature:** checked against the audit token
  (`SecCodeCopyGuestWithAttributes`) in the hash-pinned Swift helper that
  already does Touch ID (`docs/touch-id.md`), as `deadbolt-enclave
  identify`. It reads the process's facts by pid, then confirms the token
  still names that process, so a reused pid can't lend its facts. A team ID
  counts only when the signature chains to Apple for that team.
- **Its terminal:** the controlling tty and when its session started.
- **Its ancestry:** parents up to launchd, for the label ("OpenCode › zsh",
  "Ghostty › zsh").
- **What it says it is:** the CLI sends `DEADBOLT_CALLER` or
  `OPENCODE_SESSION_ID` if set. It's shown as claimed, never trusted.

That sorts every connection into one of three:

- **Deadbolt.app:** a process running the `MacOS/Deadbolt` of the agent's
  own bundle, by real path, that is that code: for a Developer ID build,
  signed by the team compiled into the agent (`DEADBOLT_APPLE_TEAM_ID`, or
  the team in `DEADBOLT_APPLE_SIGNING_IDENTITY`, at build time) as
  `pw.deadbolt.app`; for an ad-hoc build, matching that file's cdhash, since
  two ad-hoc builds with one identifier aren't the same code. A copy of the
  app run from anywhere else, byte for byte, is a caller. The path counts
  for Developer ID builds too because `MacOS/Deadbolt` is the whole
  `deadbolt` binary: run from its bundle it is only ever the app
  (`docs/app.md`, One command), but a copy elsewhere would run CLI commands
  under the app's signature. Outside a bundle there's no app: `deadbolt ui`
  is the agent's own code under its own identity, a caller. Everything, as
  today.
  - **Ad-hoc is only as strong as the bundle's directory.** Something that
    can write into `Deadbolt.app` can swap `MacOS/Deadbolt` and be the app.
    Developer ID builds close this: the team and identifier come from
    Apple's chain, not from a path.
- **The browser host:** the `deadbolt` binary launched by a browser Kit
  paired, speaking for an extension install Kit paired. Site commands only.
  Today any process can run `deadbolt browser-host chrome-extension://…`,
  name any origin and get that site's password; this closes it.
  - **Until pairing lands** (build order 3), the agent calls a peer the
    browser host when it runs the agent's own code with `browser-host`
    arguments. Arguments are read by pid and a process can rewrite its own,
    so that label is for Activity only and never grants anything.
  - **Why not a vendor list or the extension id:** the id's manifest key is
    public (`extension/manifest-key.txt`), so anyone can load an unpacked
    copy with the same id into a real, vendor-signed browser (a throwaway
    profile, or "Load unpacked" clicked through Accessibility) and send any
    origin. And a fixed vendor list misses real browsers: Helium is signed by
    Imput (`S4Q33XPHB4`), Chromium and Chrome for Testing are ad-hoc.
  - **Pair once per install, with a tap.** On first connect the extension
    makes a key pair (WebCrypto, non-extractable) and asks to pair; Deadbolt
    shows the browser (its signing identity: team ID, or cdhash when
    ad-hoc) and the profile, and Kit taps. The agent pins that browser
    identity and the extension's public key together. Later connects answer
    a challenge with the key and must come from the pinned browser. A new
    browser, a new profile or a reinstalled extension pairs again; an
    ad-hoc browser re-pairs when it updates.
  - **What pairing doesn't stop:** a process running as Kit can read the
    browser profile on disk, key included, and something that can drive Kit's
    screen could approve a pairing it started. Pairing turns "anyone can
    claim a site" into "steal a profile or win a tap Kit can see", and
    Activity lists every pairing. A Chrome Web Store build, whose signing key
    isn't public, makes the extension id itself mean something for
    releases.
- **A caller:** everything else, Kit's own terminal included. An AI's
  shell and Kit's look the same here: same binary, same user. Ancestry tells
  them apart only as a hint, since an AI can `open -a Terminal` its way out
  of its tree. So ancestry labels prompts and refuses the Never tier to AIs
  outright, and never grants anything.

**Linux is labels only.** There are no code signatures, and `/proc/<pid>/exe`
is read after the connection, so a process can race it. A Linux peer is
always a caller, its check `unverified`, and its label ends "unverified
(Linux)" in `whoami`, Activity and the app. Nothing a Linux peer sends is
taken on its word: the agent refuses every `ActivityReport`, so the app's
reveals and copies aren't entries there. Its requests for the values it
shows are, as an unverified caller's.

**What a grant is tied to (its anchor):**

- **With a tty:** the tty and its session's start time, as 1Password does.
  It covers subshells in that tab, not other tabs.
- **No tty, under a known AI host** (OpenCode's tool shells): the host
  process, its start time and the claimed session. The panel says
  "OpenCode session ses_… (claimed)". Another session on the same server
  could claim that id; that's a known limit (see Later).
- **Neither:** Once only.

**Why a compromised caller can't widen its own scope:**

- The grant (items, fields, tier, anchor, expiry) is a row in the agent,
  fixed from what Kit saw when he approved. The caller holds no token to
  edit or replay. Anything outside the row asks again.
- It can't approve itself: approvals are answered only by Deadbolt.app's
  verified connection, and an Allow still needs a finger.
- It can't borrow the app or the browser's standing: those are checked by
  code signature, not by name or by what they ask for.
- It can't loosen the rules: no env var or `config.toml` key weakens the
  gate. Anything that would (later: standing grants) lives in `store.redb`
  and changes in the app with a tap. Restarting the agent leaves it locked,
  with no grants.
- It can't fake the agent: on every connection, before sending anything
  (a passphrase, a request, a watch), the app and the CLI
  check that the socket's owner runs from the exact `deadbolt` they expect
  (the CLI's own binary, the app's bundled helper), by real path, and is
  that code: by team and the `deadbolt` identifier for a Developer ID build,
  by the cdhash of that file for an ad-hoc one. A copy elsewhere is refused.
  A process that stops the agent and binds the socket gets nothing. The
  check is `deadbolt_client::set_agent_check`, run once per agent process
  (known by its audit token); a client that sets none can't send `setup` or
  `unlock` at all, and checks only the owner's user for the rest. `stop`
  goes to whatever holds the socket, so a stale or foreign one can be
  stopped. The CLI runs its hash-pinned helper; the app runs the
  `deadbolt-enclave` in its own bundle, which the bundle's signature covers.
  - So after rebuilding an ad-hoc build, the new binary won't talk to the
    agent the old one started until `deadbolt agent stop`, as it already
    wouldn't unlock it.
  - Every macOS distribution ships `deadbolt-enclave` beside `deadbolt`
    (the release tarballs, Homebrew, `deadbolt.pw/install`). Without it,
    `setup` and `unlock` fail and name the missing file; there is no
    unchecked fallback.
  - On Linux the check is only that the socket's owner runs as this user.
    The socket's 0700 directory keeps other users out; that isn't
    authentication, and any process of Kit's could stand in for the agent.
  - The agent, for its part, takes its runtime directory only if it's a
    real directory of this user's (not a symlink), makes it 0700 before
    binding, and drops any connection from another user.
- What it can still do: use what was granted, from inside the anchor,
  until it expires. And an approved command can send the value anywhere.
  That is why the panel shows the command.
- Out of scope, as today: something that can rewrite Deadbolt's own
  binaries or inject into them. Developer ID signing with the hardened
  runtime (`docs/app.md`, release work) blocks the injection; ad-hoc
  development bundles don't.

**Tokens considered:** a token handed out at approval would be a bearer
secret. It would land in env vars and transcripts and outlive the process it
was meant for. Anchored grants give the same reuse without one. A real
per-session key held by OpenCode is under Later.

## Approving

```text
caller ── resolve ──▶ agent: decide → ask
agent ── watch: approvals ──▶ Deadbolt.app (opened if not running)
panel: who · what · scope        [Deny]  [Allow once]  [Allow 15 min]
Allow ──▶ agent runs deadbolt-enclave confirm "<reason the agent wrote>"
Touch ID ──▶ grant row in agent ──▶ caller gets the values
```

**The panel shows:**

- **Who:** the verified program and path ("OpenCode › zsh"), pid, working
  directory and tty, then what it claims, in grey.
- **What for:** the exact command for `run`, the output path for `inject`,
  "shown to the caller" for `read`.
- **Each secret:** vault › title (short id) › field. If an AI created the
  item, it says so, with the date ("created by OpenCode, Oct 27").

One prompt per command: `run` asks for all its references at once. Deny has
focus. Esc, closing the panel and 60 s without an answer all deny.

**The Touch ID sheet** carries the agent's own sentence, built from
verified facts: `Allow OpenCode to run "wrangler deploy" with Cloudflare ›
token, once`. The helper checks the finger with `LAContext`. That's a yes or
no, which `docs/touch-id.md` calls weak for protecting a key at rest. It's
fine here: the agent already holds the keys and only needs to know a finger
touched, from a helper it hash-checks before running.

**Scopes:**

- **Once:** one request, or one `deadbolt run` and its child for as long as
  the child runs.
- **15 min:** the same anchor, items, fields and tier, the same working
  directory, and the same program: the approved command's resolved
  executable and its team ID. It expires after 15 minutes without use, an
  hour at most. Use tier only.
  - **Only for programs Kit has trusted by name.** Same program doesn't mean
    same behaviour: `wrangler`, `npm run`, `make` run whatever the project's
    files say, `docker run`, `terraform` (`local-exec`), `go run`,
    `kubectl` plugins and `aws` (`credential_process`) run arbitrary code
    while signed by real vendors, and an AI can edit the project between two
    runs. No list of "code runners" is ever complete, so Deadbolt ships with
    no trusted programs at all. An unknown program, signed or not, gets Once.
  - **Trusting a program** is its own tap, from the panel ("Allow 15-minute
    grants for `/opt/homebrew/bin/flyctl`, signed by …") or in Settings. It
    pins the path and team ID; ad-hoc binaries, scripts and shebang files
    can't be trusted. The panel says plainly that a trusted program can
    leak the secret if it runs project code. Settings lists and removes
    them, and Activity records each change. AIs can't add to the list.
- Read and Write are always Once. Add needs no grant. Never has no scope.

**What can't spoof a prompt:**

- **A fake window:** only the agent grants, and only after a tap through its
  own helper. A window someone else draws grants nothing.
- **Synthetic clicks and keys:** a click never approves on its own.
  1Password lists Accessibility-enabled apps getting past its prompt as an
  accepted risk; requiring a finger is the answer to that. The sheet has no
  Mac-password fallback (`localizedFallbackTitle = ""`, as for unlock).
- **A fake Touch ID sheet:** a tap on it unlocks the faker's own
  `LAContext`, nothing in Deadbolt.
- **Misleading text:** item titles (an AI may have written "GitHub
  (harmless)"), process names and claimed ids are quoted and set apart
  from the verified facts beside them: signature, vault, short id.
- **No Touch ID** (Linux, no sensor, over SSH): the vault passphrase, typed
  into the app's secure field or the CLI's no-echo tty prompt. Never read
  from stdin, a pipe or `DEADBOLT_PASSPHRASE`.

## Lock, limits, activity

- **Lock:** any lock (⌘L, idle, sleep, screen lock, `deadbolt lock`, agent
  stop) drops every grant and pending prompt. While locked, callers get
  `locked` (see Decision 3).
- **Idle lock:** caller requests don't count as use, as `site-logins`
  doesn't, so a looping AI can't hold the vault open.
- **Limits, per anchor:**
  - One prompt on screen at a time across the agent, and at most 3 queued
    per anchor. More get `rate_limited`.
  - 3 denials or timeouts in 10 minutes and that anchor's prompts deny
    themselves for 10 minutes, shown in Activity. A runaway AI can't wear
    Kit down with prompts.
  - Under a grant, 60 resolves a minute.
  - Look, a burst of 20 then one a second, like the extension's checks.
- **Activity:** every caller request, and the app's own reveals and copies,
  gets an entry with the time, caller (verified and claimed), tier,
  command, items (vault, id, title), fields, and outcome (allowed by grant,
  approved, denied, timed out, locked, rate limited). Never values.
  - Kept encrypted in `store.redb`, on this device only, for 90 days.
    Entries made while locked wait in memory until unlock.
  - The app's Settings › Activity lists them, with live grants and Revoke.
    The CLI has `deadbolt activity`, and `watch` sends an `activity` change.
  - The app reports its own reveals and copies (`ActivityReport`), which
    the agent can't see; every copy in the app, the editor's ⌘C included,
    goes through one function that reports it. The app's own requests, a
    caller's `status`, `watch` and `app-activate`, the browser host's lookups
    (`site-logins`, `site-check`, `passkey-list`, and `site-generate-check`
    and `site-generate-drop`, asked before anyone picked a password) and
    `ActivityList` itself aren't entries: they come with every command or
    page, and a client that reads Activity on every change mustn't feed
    itself. `site-generate` and `site-generate-keep` are entries naming the
    page, never the password or its id.
  - An entry is written before its reply goes, so a client that never reads
    the reply, or the agent stopping, can't lose it.
  - **Bounded.** Each string in an entry (the claim, labels, paths, titles,
    field names) keeps at most 256 bytes, marked "…(cut)", and each list 16
    items. Past 60 entries a minute from one anchor (the tty and its
    session, else the label and claimed session), or 300 a minute from all
    anchors together (so making up a claimed session per request doesn't
    help), the rest fold into one `more-past-limit` entry saying how many.
    Reads, writes and removals (the Read, Write and Never tiers) never fold
    into it: past a limit, the first of each kind is still its own entry,
    and only exact repeats of it (same caller, command, items, fields and
    outcome) fold, into one entry naming them too. While locked, at most 1,000
    entries or 1 MiB wait; past that they fold into one `more-while-locked`
    entry naming who made them. The store keeps at most 100,000 entries or
    64 MiB; past that the oldest go, and the listing ends with one
    `more-past-budget` entry counting them. An `ActivityList` returns at
    most 1,000 entries; older ones page back by id (`before`).

## Keeping secrets out of transcripts

- **Use over read.** `run` and `inject` are the documented paths. `read`
  exists, costs a tap every time, and its prompt says the value will be shown
  to the caller.
- **Masking:** `run` replaces the values in the child's stdout and stderr
  with `<concealed by deadbolt>`, as `op run` does. `--no-mask` is shown on
  the prompt. This stops accidents, not a determined command, which is why
  the prompt shows the command.
- **Never in argv, logs, errors or Activity**, as today. Writes take values
  on stdin or generate them in the agent.
- **A `deadbolt` OpenCode skill** with 2password's rules, so AIs learn the
  safe path first.

## CLI

```sh
deadbolt ls github --json                  # Look: refs and field names, no values
deadbolt run --env GH_TOKEN=deadbolt://personal/GitHub/token -- gh release create v1
deadbolt run --env-file .env.tpl -- bun run dev       # KEY=deadbolt://… lines
deadbolt inject -i config.tpl -o config.json          # {{ deadbolt://… }}; written 0600
deadbolt read deadbolt://personal/GitHub/password     # a tap every time
echo -n "$NEW_KEY" | deadbolt new note --name "OpenAI API Key" credential:secret=-
deadbolt set deadbolt://personal/Stripe password=-    # value on stdin
deadbolt whoami                            # how Deadbolt sees this caller
deadbolt grants                            # live grants; grants revoke <id> | --all
deadbolt activity --since 1h
```

- **References:** `deadbolt://<vault>/<item>/<field>`. The item is a title
  or short id and must match exactly one. Without a field, it's the item's
  primary one (`primary_field`).
- **`--no-prompt`** fails with `needs-approval` instead of waiting.
- **Exit codes:** denied exits 4, beside today's 3 for locked.

## Protocol

Version 11 (build order 1):

- `Status.caller: CallerInfo`, for `whoami`.
- `Request.claimed`: what the client claims (`DEADBOLT_CALLER`,
  `OPENCODE_SESSION_ID`), on every request.
- `ActivityList { since, limit, before }`, newest first, at most 1,000 a
  page, and `Change::Activity`. `ActivityEntry.more` counts the requests a
  folded entry stands for.
  Until enforcement, `deadbolt activity` uses it too; build order 3 decides
  whether the CLI keeps it.
- `ActivityReport { action, vault, item, title, field }`: the app's
  reveals and copies. Only from Deadbolt.app, so never on Linux.
- `deadbolt-enclave identify`: `{"token", "files"}` on stdin, the running
  code's signature, the process (args, tty, start times, ancestry) and each
  file's signature out; exit 15 when the token's process is gone.
- Outcomes so far are `allowed`, `locked` and `failed`; approvals bring the
  rest.

Later:

- `Command::Resolve { refs, purpose, prompt }`, where `purpose` is
  `Run { argv, cwd, mask }`, `Inject { output }` or `Read`. It may send
  `Event::Waiting { approval, summary }` (the CLI prints "Waiting for
  approval in Deadbolt…"), then replies `Secrets { values }` in reference
  order. When the peer is a genuine `deadbolt`, the agent checks `argv`
  against the peer's real arguments; otherwise the panel says "unknown
  program".
- `ItemGet` gains `fields: Option<Vec<String>>`. `Some([])` is Look; named
  fields are Read. `show` without `--reveal` sends `Some([])`, so masked
  display stops receiving values at all.
- App only: `ApprovalList`, `ApprovalAnswer { id, allow: Option<Scope> }`,
  `GrantList`, `ActivityList { since, limit, before }`.
- Anyone: `GrantRevoke { id: Option<String> }`. Narrowing is always safe.
- `Change::Approvals`.
- `ErrorCode::Denied`, `NeedsApproval` and `RateLimited`.
- `deadbolt-enclave` gains `confirm <reason>`.

## Build order

1. **Caller identity and Activity, observe only.** Peer token, signature
   check, tty, ancestry, `whoami`, `activity`, the app's Activity list. The
   app and CLI check the agent they talk to. Nothing is refused yet.
2. **Approvals.** The agent's queue, the app's panel, `confirm`, the
   passphrase fallback, grants and anchors, lock dropping them, limits.
3. **Enforce.** `policy::decide`. Read asks (`get`, `show --reveal`,
   `code`), Never refuses AIs, site commands only from a paired browser
   and extension (pairing tap, challenge on connect; the extension side
   ships in the same PR), `ItemGet.fields`. Kit's terminal starts asking here (Decision 1).
4. **`deadbolt run`.** `resolve`, references, env files, masking. Built,
   with standing grants in place of approvals (see "Secrets for commands").
5. **`deadbolt inject` and `read`** on references. Built, the same way.
6. **Writes from callers.** Add without asking, with "added by" in the
   app and the browser menu; ask on secret and URL changes, showing the
   title and field names.
7. **The OpenCode skill**, and the threat model in `docs/autofill.md`
   updated to match.

## Secrets for commands (built)

2026-10-29. Build orders 4 and 5, without the approval panel of build
order 2: until approvals exist, standing grants stand in for "Allow 15
min", and Touch ID raised by the agent for each read.

```sh
deadbolt run --env GH_TOKEN=deadbolt://personal/GitHub/token -- gh release create v1
deadbolt run --env-file .env.tpl -- bun run dev       # KEY=deadbolt://… lines
deadbolt inject -i config.tpl -o config.json          # {{ deadbolt://… }}; written 0600
deadbolt read deadbolt://personal/GitHub/password
deadbolt agents allow-secrets GitHub --fields token --purpose run --expires 8h
```

**References.** `deadbolt://[vault/]item/field`. The vault is a name or id
(default: the default vault); the item is its title (any case) or its id
or a unique prefix of it (4+ hex digits), and must match exactly one item,
else the error lists the candidates by short id; the field is its exact
name, else the error lists the item's field names. A `/` or `%` in a name
is `%2F` or `%25`. A one-time password field gives its current code, never
its secret; a passkey's private key is never a field. The field is always
named: a two-part reference is item and field.

**`deadbolt run`.** Resolves `--env NAME=REF`, `--env-file` lines
(`NAME=VALUE`, `#` comments, `export`, quotes; values that aren't
references are set as they are) and inherited variables whose value is a
reference, later ones winning, in one request. Then it starts the command
(after `--`) with them in its environment and its stdin, and passes on
SIGTERM, SIGHUP, SIGUSR1 and SIGUSR2, and SIGINT and SIGQUIT unless stdin is
a terminal (the terminal already sent those to the command, which shares
its process group). It exits with the command's code, or 128 + the signal
that ended it. Its stdout and stderr have each value, its URL encoding and
its base64 (unpadded) replaced with `<concealed by deadbolt>` as they
stream: output whose tail could begin a value is held until the next read
says, or until 100 ms pass with no output (so a prompt doesn't stall), so
values split across writes are concealed and everything else flows at
once. A value written in pieces more than 100 ms apart may show. Values
shorter than 3 characters aren't masked. Masking makes the command's
stdout and stderr pipes, so it sees no terminal: no colors, no full-screen
UIs, and a pager may behave differently. `--no-mask` turns masking off and
leaves them on the terminal. Masking stops accidents, not a command that
means to leak.

**`deadbolt inject`.** Replaces each `{{ deadbolt://… }}` in the template
(`-i`, default stdin; other `{{ … }}` are left alone) and writes the result
to `-o` through a 0600 temporary file renamed into place. Written to
stdout (no `-o`, or `-o -`), the values go to whoever ran it, so it resolves
as a `read`: an AI needs Touch ID for it, whatever it was granted.
An existing output is replaced only if `inject` wrote it and it hasn't
changed since (same device, inode, size and modification time, recorded in
`injected.json` in the data directory, no values), or with `--force`.

**`deadbolt read`.** Prints one value, the Read tier.

**Who gets values.** The agent's `resolve {refs, purpose}` (`run`,
`inject` or `read`) decides from the caller:

- Not an AI (no AI host among its parents, no claimed OpenCode session):
  allowed while unlocked, as `deadbolt get` is (build order 3 will ask).
- An AI, for `run` or `inject`: only what live grants cover, each item,
  field and purpose; otherwise `not-granted`, naming what is missing and
  the `deadbolt agents allow-secrets` line that would allow it.
- An AI, for `read` (and `inject` to stdout): Touch ID raised by the agent
  every time, with its own sentence ("show personal › GitHub › password to
  an AI agent"). No grant skips that prompt, but a run or inject grant
  lets the AI learn the value another way (below). Without Touch ID
  (Linux, no sensor, off) it is `forbidden`.
- The browser host: `forbidden`.

Refused, the CLI exits 4 (`not-granted` or `forbidden`), beside 3 for
locked. An AI's resolves are rate-limited: a burst of 20, then one a
second, per anchor (its terminal, else its label and claimed session), and
60 then two a second for all AIs together (`rate-limited`). That bounds what
trying names teaches it and how often a read raises Touch ID. Resolves
don't count as use for the idle lock, but one waiting on Touch ID holds it
off until answered, as does a grant waiting on the user's proof.

**Granting.** `deadbolt agents allow-secrets ITEM… [--vault V] [--fields
a,b] [--purpose run|inject]… [--expires 8h]` makes one grant per item
(default: every field, both purposes, no expiry), replacing an item's
earlier grant. It needs the user's proof and refuses AIs exactly as the
sign-in grants do (below): Touch ID or the passphrase, never
`DEADBOLT_PASSPHRASE`. `deadbolt agents grants` lists them beside the
sign-in grants ("AI agents › vault › title"), and `deadbolt agents revoke
<id>` removes either kind at once. Grants name items by id (a rename keeps
them), live in this device's store (`cli/secret-grants`) and never sync.

**What a grant gives.** Using a value means being able to learn it: the AI
picks the command (`sh -c 'echo $T | base64'`), or reads the file it
injected. Masking guards against accidents, not against an AI that wants
the value. So a run or inject grant is, in practice, a grant to know those
fields; what it spares is the value landing in a transcript by mistake.
Allow only what you would hand that agent, and change a value it no longer
should have.

**Activity.** Every resolve is an entry, from anyone: `resolve-run` and
`resolve-inject` (tier Use) or `resolve-read` (Read), the caller (verified
and claimed), the items found (vault, id, title) or as named when nothing
was found, the fields, and allowed, refused, locked or failed. Never a
value. Granting is a `secret-grant-set` entry.

**Trust model, honestly.**

- A grant is for "callers that look like an AI", not for one session: there
  is no anchor yet (build order 2). Any AI on this computer can use what is
  granted. Keep grants to the fields a task needs, with an expiry.
- Telling an AI from Kit is ancestry, a hint. An AI that starts a terminal
  outside its own tree is "not an AI" and gets values like Kit does, until
  build order 3 makes every caller ask.
- A command run with a value can send it anywhere, including back to the
  AI; masking only keeps it out of the transcript by accident (see "What a
  grant gives").

**Protocol (18).** `resolve {refs, purpose}` → `secrets {secrets: [{vault,
item, title, field, value}]}` in reference order; `secret-grant-set {vault,
items, fields, purposes, expires_at, passphrase?}` → `secret-grants
{grants}`; `secret-grant-list` → `secret-grants`; `agent-grant-remove`
removes either kind. Not yet: `Event::Waiting`, `argv`/`cwd`/`mask` in the
purpose (the panel's facts), `--no-prompt`, `needs-approval`.

## Standing grants: agent sign-ins (built)

2026-10-28. Built, and scoped to one kind of client: a browser relay, such
as Browse's, that signs an AI's browser in to sites without a person at the
Mac, and never shows the AI a value. This is the "AI-driven browser fills"
and "standing grants" items of Later, made unattended. Browse's side of the
contract is in Browse's repo; this is Deadbolt's.

```text
AI ── secrets.signIn ──▶ Browse relay ── agent-fill {client, origin, login, want} ──▶ agent
                         (reads the frame's origin over CDP,      checks token, grant, site
                          types the values, forgets them)  ◀────  values (never to the AI)
```

**Pairing a client.** `deadbolt agents add-client browse` (Browse's
`opencode-browser deadbolt connect` runs it) asks the agent for a new client.
The agent makes an id and a token of 32 random bytes (64 hex digits), keeps
only the token's SHA-256, and returns the token once. The client stores it
(Browse: 0600 under its data root) and sends `client: {id, token}` with every
request; the agent finds the id and compares the hashes in constant time.
An unknown id, a wrong token or a removed client is `forbidden`.

**Granting.** Allowing everything is meant to be easy.
`deadbolt agents allow github.com` lets the client fill the username,
password and one-time code of the logins saved for a site and sign in with
its passkeys; `--login kit` narrows it to one login, `--fields
username,password` to some fields, `--no-passkeys` leaves passkeys out,
`--expires 30d` ends it (default: never). `deadbolt agents allow --all` is
one grant for every login on every site. Neither loosens where a login
fills: at fill time the login must still have a URL on the frame's site, so
under `--all` the GitHub login fills on github.com and nowhere else. A site
is a registrable domain (`www.github.com` is kept as `github.com`) or an
exact origin with its scheme (`https://app.example.com`, that origin only).
Setting the same client, site and login again replaces the grant. `deadbolt agents grants`, `revoke <id>`, `clients` and
`remove-client <id>` list and narrow; Settings › Agents in the app lists
clients and grants with Revoke.

**Proof that the user is there.** Pairing and granting need the vault
unlocked and one of the following. The Touch ID sheet says plainly what is
allowed, with the caller-chosen client name in quotes: "pair a NEW agent
client "browse" with Deadbolt", "let agent client "browse" use logins for
github.com without asking".

- Touch ID, raised by the agent itself with its own sentence ("let browse
  sign in to sites for AI agents"), when Touch ID unlock is on and set up;
- the vault passphrase, typed on the CLI's terminal (no echo) or given with
  `--passphrase-stdin`. Never `DEADBOLT_PASSPHRASE`: an AI's shell inherits
  Kit's environment. The CLI checks the agent's identity before it sends the
  passphrase, as for `unlock`. The agent checks it on a copy of the wrapped
  key set, off the session's lock, so fills and the app carry on during the
  KDF; one check runs at a time, and after 5 wrong ones every check waits 30
  seconds, doubling up to 10 minutes, until a right one (`rate-limited`).
  The backoff is one for every passphrase the agent checks: `unlock`
  (locked, or unlocked asking for a longer idle timeout) and this proof
  share it, so none of them is a faster way to guess the passphrase. The
  app's unlock screen says "Too many wrong passphrases. Try again in N s.".

And the caller must not look like an AI: an AI host among its parents
(OpenCode, Claude Code, Codex, Cursor, Gemini CLI, Aider) or a claimed
`OPENCODE_SESSION_ID` is refused (`forbidden`), passphrase or not. That is
ancestry, a hint (see "Who is asking"), so it only ever refuses.

**Using a grant.** `agent-logins` lists a site's logins without values and
what the client's live grants cover of each (nothing, with `granted: false`,
when no grant covers the site). `agent-fill` gives the values asked for only
if live grants cover the client, the site of the frame's origin, the login
and every field; the login must also be saved for that site, by the same
rules as the extension's fills (`domain-mismatch` otherwise). A one-time
code is computed now; the secret never leaves. Anything uncovered is
`not-granted`, naming the site and (once the site is granted) the login, so
the client can tell the user exactly what to allow. `agent-passkey-get`
signs with a passkey for the frame's relying party under a grant with
`passkeys` (see `docs/autofill.md`, "Passkeys"). `agent-logins` lists those
passkeys with their account (WebAuthn user name, display name if saved,
credential id) and ref; the client passes the ref it chose. Without one, the
only covered passkey among `allowCredentials` (all of the site's when
empty) signs; with several the reply is `choose-passkey`, listing them
without secrets, and the client asks again with one.

**Limits and lock.** Each client gets a burst of 30 requests, then one a
second (`rate-limited`). Agent requests don't count as use for the idle
lock, so a looping AI can't hold the vault open. Locked, every agent request
is `locked`: nothing unlocks without a person, and no grant can change that.

**Activity.** Every agent request, and every pairing, grant and removal, is
an entry: the client's name, the caller, the page, the login, the fields
asked for, and whether it was allowed, refused or locked. Never a value. The
client's name is proved by its token, unlike a claim, but that only means
"whoever holds that client's token file": any process that can read the file
appears as that client.

**Kept on this device, not synced.** Clients and grants are rows in this
device's encrypted store (`cli/agent-clients`, `cli/agent-grants`), not vault
entries. The token is a credential for one computer's relay; synced, it
would be one more place to steal it from, and a grant made on the laptop
would let a relay on another device in without that device's user ever
being asked. Each device pairs and grants for itself.

**Trust model, honestly.**

- The relay is the only client. It types values into fields over CDP after
  checking the field's real frame origin, and never returns them to the AI.
  Deadbolt can't see that; it trusts the relay to keep its promise.
- The token is a bearer secret on disk. Any process running as Kit that can
  read Browse's data root can use what was granted, without asking. That is
  the price of unattended use: keep grants small (one login, the fields it
  needs, an expiry), and revoke what you don't use.
- A grant covers only fills and passkey sign-ins for its site. No item-get,
  no listing beyond the granted site's logins, no export, no writes.
- An AI that gets a terminal outside its own process tree passes the
  ancestry check; it still needs Kit's finger or passphrase to pair or grant.
- What Browse promises, and what it can't. Values never pass through the
  AI's results, Browse's logs or its HAR recordings, and they aren't exposed
  by accident or to a prompt-injected page that asks for them. But a
  deliberately hostile agent driving Browse, with page scripts or network
  hooks in a page it controls, could capture what is typed into that page.
  So a grant should cover only what you would let that agent use anyway.
  A value that leaked outlives revoking the grant and locking the vault:
  change the password.
- Passkeys sign with user presence (the grant is Kit's standing consent) and
  never user verification: no finger touched anything. Sites that require
  verification fail, which is correct.

**Protocol (15).** `agent-client-add {name, passphrase?}` → `agent-client-added
{client, token}`; `agent-client-list` → `agent-clients`; `agent-client-remove
{id}`; `agent-grant-set {client_id, site (null: every site), login?, fields,
passkeys, expires_at?, passphrase?}` → `agent-grant`; `agent-grant-list` →
`agent-grants`; `agent-grant-remove {id}`; `agent-logins {client, origin}` →
`agent-logins {site, granted, logins, passkeys}`; `agent-fill {client, origin, login,
want}` → `site-fill {values}`; `agent-passkey-get {client, origin, rp_id?, login?,
challenge, allow_credentials, user_verification}` → `passkey-assertion` with
`verified: false`. New error codes `forbidden`, `not-granted` (with
`grant: {site, login}` beside the message), `choose-passkey` (with
`passkeys: [...]`) and `rate-limited`; a new tier
`agent` and outcome `refused` in Activity, which also gains `client`.

## Prior art

- **1Password CLI with the app**
  ([security model](https://developer.1password.com/docs/cli/app-integration-security/)).
  - A biometric prompt names the process.
  - Authorization is tied to one terminal (tty plus start time), lasts 10
    minutes idle and 12 hours at most, and ends when the app locks.
  - Accepted risk: apps with Accessibility may get past the prompt.
  - Taken: the tty anchor and lock revoking. Changed: a finger, never a
    click.
- **`op run` and `op inject`**
  ([run](https://developer.1password.com/docs/cli/reference/commands/run/)).
  References, injecting into env, and masking stdout and stderr by default.
  Taken almost as is.
- **1Password service accounts.** Scoped to vaults, no prompts. Later, as
  standing grants.
- **1Password for Agents and Secure Agentic Autofill**
  ([blog](https://1password.com/blog/closing-the-credential-risk-gap-for-browser-use-ai-agents),
  [principles](https://1password.com/blog/security-principles-guiding-1passwords-approach-to-ai)).
  A person approves on their own device and the fill goes into the form, so
  the AI never sees the password. "Users should see a deterministic auth
  prompt… by a trusted party, as opposed to in-chat." Taken: the
  Deadbolt-owned prompt. AI-driven browser fills are Later.
- **Bitwarden.** `bw unlock` hands out a `BW_SESSION` key that reads
  everything ([CLI](https://bitwarden.com/help/cli/)), and its MCP server
  gives AIs the whole vault. The
  [Agent Access SDK](https://github.com/bitwarden/agent-access) (alpha,
  March 2026) approves each credential and injects with `aac run`. Taken:
  inject. Avoided: session keys.
- **macOS keychain ACLs**
  ([Apple](https://developer.apple.com/documentation/security/access-control-lists)).
  Each item lists trusted apps by code signature; others get Allow, Always
  Allow or Deny. Taken: identity by signature. Avoided: approving with a
  click.
- **`ssh-add -c`** ([man](https://man.openbsd.org/ssh-add)). Confirms each
  use of a key through `ssh-askpass`. The dialog is one any same-user
  process can click. Taken: confirm per use, with a finger instead.
- **2password**, which Kit's AIs use today
  (`~/.config/opencode/skills/2password`).
  - `find` returns references, never values.
  - `run` and `env run` come first, `read` is the last resort.
  - Batch everything into one prompt.
  - New keys come from stdin or the clipboard, never argv, and nothing is
    overwritten.
  - The prompts are 1Password's.
  - Taken: its rules and its command shape, so the skill carries over.

## Later

- AI-driven browser fills approved per use, with a tap, as in 1Password for
  Agents. Unattended fills under a standing grant are built (above); per-use
  approval is not. Shape (from Ryan's Foyer, which already fills this way):
  - **By reference.** The AI sees metadata and an opaque ref, picks the ref
    and the step, and gets back only "submitted" or "failed". Values go
    agent → extension → field, never to the AI.
  - **Approval bound to the browser's facts.** The tap shows and checks the
    frame origin the browser reports and delivers to that exact
    `documentId`, so a page that navigates during the wait gets nothing.
  - **Fill and submit in one step.** An AI driving the tab over CDP can read
    `input.value` right after a fill, so pass-through only holds if the
    submit happens before control returns, and only for tools that can't
    read the field. Say so in the prompt; it is a narrower promise than
    `deadbolt run`.
  - **Passkeys fit best**: the AI never sees anything usable, and the tap is
    honest user verification.
  - Approving from the phone is a second way to give the tap.
- An SSH agent that confirms each use of a key.
- Approving from the iPhone.
- Standing grants for scripts, by code signature and item list, set in the
  app with a tap. (Standing grants for a browser relay are built, above.)
- A per-session key held by OpenCode's server that signs requests, to tell
  sessions on one server apart for real.

## Decisions (Kit, Oct 27)

1. **Kit's own terminal asks too:** one tap per tab per 15 minutes idle.
   Deadbolt can't reliably tell his shell from an AI's.
2. **AIs list and search without asking**, logged and rate-limited. Titles,
   usernames, URLs and field names, never values.
3. **An AI's request may unlock a locked vault** with the same tap. One
   Touch ID sheet that says it both unlocks and approves. Never a
   passphrase prompt started by an AI.
4. **Use grants:** 15 minutes idle, an hour at most, ending at lock. Reads
   stay Once.
5. **Adding needs no tap** (new items, new fields, edits to plain fields),
   marked "added by". Changing or removing a secret, or changing an item's
   URLs, needs a tap each. No deletes; delete in the app.
