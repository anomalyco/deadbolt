# AI agents using Deadbolt

2026-10-27. Design, not built yet. How AI agents (OpenCode sessions and the
like) may use Deadbolt, carefully. Questions for Kit are at the end.

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
  write can be undone.
- **Never:** `item-remove`, `import`, `join`, `pair`, `device-remove`,
  `vault-create`, `vault-rename`, `vault-default`, `touch-id-set`,
  `sync-one-password`, and answering approvals. There is no export command,
  and no grant covers more than the items it names, so there is no bulk read
  either. `setup`, `unlock` and `unlock-biometric` carry their own proof (the
  passphrase or a finger), so they don't ask again, but AIs are refused them
  too.
- **Always allowed:** `status` and `stop` (version handover depends on
  them, `docs/app.md`), `lock` (makes things safer), `generate` (no vault
  needed), `sync`.
- **Browser only:** `site-logins`, `site-fill`, `site-check`, `site-save`,
  from a caller the agent sees as the browser host (next section).

`policy::decide(&Caller, &Command, &Grants) -> Allow | Ask | Deny` is one
pure function with an exhaustive match and no fallback arm, so a new
`Command` doesn't compile until someone puts it in a tier. Table tests cover
every command for every kind of caller.

## Who is asking

The agent reads the socket's peer, not anything the caller says:

- **The process:** macOS gives the peer's audit token (`LOCAL_PEERTOKEN`):
  pid plus pid version, so a reused pid can't pass. Linux gives
  `SO_PEERCRED`. The workspace forbids `unsafe`, so this comes from a
  dependency.
- **Its code signature:** checked against the audit token
  (`SecCodeCopyGuestWithAttributes`) in the hash-pinned Swift helper that
  already does Touch ID (`docs/touch-id.md`).
- **Its terminal:** the controlling tty and when its session started.
- **Its ancestry:** parents up to launchd, for the label ("OpenCode › zsh",
  "Ghostty › zsh").
- **What it says it is:** the CLI sends `DEADBOLT_CALLER` or
  `OPENCODE_SESSION_ID` if set. It's shown as claimed, never trusted.

That sorts every connection into one of three:

- **Deadbolt.app:** signed by the same identity as the agent's own bundle
  (the team ID for Developer ID builds; for ad-hoc builds, the cdhash of the
  `MacOS/Deadbolt` beside the agent's own helper). Everything, as today.
- **The browser host:** the `deadbolt` binary whose parent is a browser
  signed by its vendor (Google, Brave, Microsoft, The Browser Company). Site
  commands only. Today any process can run `deadbolt browser-host
  chrome-extension://…`, name any origin and get that site's password; this
  closes it.
- **A caller:** everything else, Kit's own terminal included. An AI's
  shell and Kit's look the same here: same binary, same user. Ancestry tells
  them apart only as a hint, since an AI can `open -a Terminal` its way out
  of its tree. So ancestry labels prompts and refuses the Never tier to AIs
  outright, and never grants anything.

Linux has no code signatures to check, so the app and the browser are
recognised by executable path. That's weaker, and the Activity list says
which check was used.

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
- It can't fake the agent: the app and the CLI check that the socket's
  owner is the bundled `deadbolt`, by the same signature check, before
  sending a passphrase. A process that stops the agent and binds the socket
  gets nothing.
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
- **15 min:** the same anchor, items, fields and tier, any command. It
  expires after 15 minutes without use, an hour at most. Use tier only.
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

## Protocol (version 9)

- `Status.caller: CallerInfo`, for `whoami`.
- `Command::Resolve { refs, purpose, claimed, prompt }`, where `purpose` is
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
  `GrantList`, `ActivityList { since, limit }`.
- Anyone: `GrantRevoke { id: Option<String> }`. Narrowing is always safe.
- `Change::Approvals` and `Change::Activity`.
- `ErrorCode::Denied`, `NeedsApproval` and `RateLimited`.
- `deadbolt-enclave` gains `confirm <reason>` and `identify` (an audit
  token in, a signature verdict out).

## Build order

1. **Caller identity and Activity, observe only.** Peer token, signature
   check, tty, ancestry, `whoami`, `activity`, the app's Activity list. The
   app and CLI check the agent they talk to. Nothing is refused yet.
2. **Approvals.** The agent's queue, the app's panel, `confirm`, the
   passphrase fallback, grants and anchors, lock dropping them, limits.
3. **Enforce.** `policy::decide`. Read asks (`get`, `show --reveal`,
   `code`), Never refuses AIs, site commands only from the browser host,
   `ItemGet.fields`. Kit's terminal starts asking here (Decision 1).
4. **`deadbolt run`.** `resolve`, references, env files, masking.
5. **`deadbolt inject` and `read`** on references.
6. **Writes from callers.** Add without asking, with "added by" in the
   app and the browser menu; ask on secret and URL changes, showing the
   title and field names.
7. **The OpenCode skill**, and the threat model in `docs/autofill.md`
   updated to match.

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

- AI-driven browser fills: `site-fill` for a page an AI's browser has
  open, approved per login, as in 1Password for Agents.
- An SSH agent that confirms each use of a key.
- Approving from the iPhone.
- Standing grants for scripts, by code signature and item list, set in the
  app with a tap.
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
