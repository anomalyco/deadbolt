# Syncing from 1Password

`deadbolt sync 1password` mirrors 1Password into a Deadbolt vault, one way.
1Password stays the source of truth; Deadbolt keeps a copy that a sync brings
up to date. It reads 1Password through the 1Password CLI (`op`), so nothing is
ever exported to disk.

```sh
deadbolt sync 1password                       # every vault of the one account
deadbolt sync 1password --dry-run             # say what it would do, write nothing
deadbolt sync op --account my.1password.com --op-vault Private --op-vault Work
deadbolt sync 1password --quiet               # print only if something changed
```

`--vault` picks the Deadbolt vault to write to, as everywhere else.
`--op-vault` (repeatable, by name or id) limits the 1Password vaults read.
`--account` picks the account by sign-in address, email, shorthand or id. It
is needed only when `op` knows more than one and the Deadbolt vault doesn't
already mirror exactly one of them (or, mirroring none, hold `.1pux`
imports from exactly one).

In the app it's Settings › 1Password › **Sync from 1Password**, which shows
what the sync did ("12 updated, 3 added"). Items a sync added or took over
say "From 1Password" under their title. Items from a one-time `.1pux` import
don't: they're yours to edit until a sync takes them over.

## Setup

1. `brew install 1password-cli` (or put `op` anywhere and set `DEADBOLT_OP`
   to its path).
2. In the 1Password app: Settings › Developer › **Integrate with 1Password
   CLI**.
3. Run `deadbolt sync 1password --dry-run` and approve 1Password's prompt.
   Read the plan, then run it without `--dry-run`.

The sync runs in Deadbolt's background agent, which finds `op` on its `PATH`
or in Homebrew's `bin`. `DEADBOLT_OP` is read by the agent, so set it before
the agent starts (or `deadbolt agent stop` first).

## How it works

A sync makes at most four `op` calls, all with `--format json`:

1. `op account list`, to pick the account.
2. `op vault list`, only with `--op-vault`.
3. `op item list`: ids, titles, categories, URLs and `updated_at` of every
   active item. No values.
4. `op item get -`, once, for just the items that need it, with their ids on
   stdin. Skipped entirely when nothing changed.

Each item a sync wrote keeps hidden metadata: where it's from
(`1password/<account>/<vault>/<item>`) and a version (1Password's
`updated_at`, a digest of the values as mirrored, and whether the sync added
it or took it over). The digest is what lets a sync skip `op item get` for an
item that hasn't changed on either side: 1Password's time is the same and
the Deadbolt item still matches what was mirrored. A mirror is found by
account and 1Password item id, so an item moved to another 1Password vault
is updated in place.

A `.1pux` import records where each item came from too, but only as
provenance: the item isn't a mirror, isn't labelled, and nothing changes it
until a sync takes it over. The export names your user rather than the
account; a sync knows both.

Then, under the agent's lock:

| In 1Password | In Deadbolt | The sync |
|---|---|---|
| new | nothing like it | adds it |
| new | imported from a `.1pux` export of that item | takes it over |
| new | an item with the same content | takes it over |
| new (a login) | one login with the same username and URL | takes it over, saying which fields change |
| new | an item that only shares its name | adds it beside, saying so; yours is untouched |
| changed | mirrored | updates it, writing only the fields that differ |
| unchanged | edited here | puts 1Password's values back (1Password wins) |
| any | edited or deleted here while `op` was asked | skips it; the next sync settles it |
| deleted or archived | added by a sync | deletes it |
| deleted or archived | taken over | releases it: keeps it, drops the source |
| any | your own item | never touches it |

Taking over writes 1Password's values and keeps fields only Deadbolt has
(a PIN you added, say). The item then records which fields 1Password wrote:
later syncs keep 1Password's values winning, remove a field once 1Password
deletes it, and keep fields added here, before or since. (An item with so
many fields that their names don't fit in its version records none, and
then no field is ever removed from it.)

A username and URL count only when exactly one login in the Deadbolt vault
and exactly one in the 1Password vaults synced have them, counting items
already mirrored too. Otherwise the content decides, and the rest are added
beside, with a reason saying which side was ambiguous. An import is only
ever taken over by the item it was exported from: one from another account,
or whose item is gone, stays as it is.

An item whose 1Password type changed is deleted and added again if a sync
added it, and skipped if it was taken over. Two Deadbolt copies of one
1Password item (say, after two devices synced at once) are settled to one:
the extra copy is deleted if a sync added it, released if it was taken over.
That happens only when every copy is in the 1Password vaults being synced.
If `op item list` returns nothing while the vault holds mirrored items, the
sync stops rather than delete them.

One sync runs at a time; a second is refused until the first finishes. Each
`op` call has two minutes (plus a little per item fetched) before it's
killed. Locking Deadbolt, stopping its agent, or cancelling the command
also kills `op`, and nothing is written. A sync waiting on `op` doesn't keep
Deadbolt unlocked: the idle timeout still locks it.

Each sync writes in as few entries as it can, and other devices get the
changes through normal sync.

## Mapping

Items map exactly as a `.1pux` import does (the same code: `op` JSON becomes
1PUX JSON first):

| 1Password | Deadbolt |
|---|---|
| Login, Password, Database, Wireless Router, Server, API Credential | login |
| Credit Card | card |
| Identity | identity |
| SSH Key | ssh |
| Secure Note, and every other category (Software License, Bank Account, Driver License, Passport, Membership, ...) | note, its fields kept, account and ID numbers secret |

Values that aren't valid for their Deadbolt field (an otp that isn't TOTP, a
card number with letters) become extra fields with a warning, as on import.

A `.1pux` login that signs in with Google, Apple, GitHub and so on keeps its
provider as `sign-in-with`, and the import links it to the provider's login
as `sign-in-account` (see `docs/autofill.md`). A sync doesn't read these from
`op` yet; it keeps the two fields on an item it takes over, as it keeps any
field only Deadbolt has.

## Not mirrored

- **Passkeys.** Deadbolt has nowhere to put them; the login is mirrored
  without it.
- **Attachments and Documents.** A Document item is skipped; files attached
  to other items are counted and left out. `op item get` never downloads
  them.
- **SSH keys without a private key**, and item types this build doesn't know:
  skipped and listed.
- **Tags, favorites, password history.** Counted, not kept.

## Approval prompts

1Password asks for approval (Touch ID or your Mac password) the first time
`op` is used in a session, then keeps it for 10 minutes after each use, up to
12 hours, and drops it whenever the 1Password app locks. A sync's calls run
back to back, so a sync prompts at most once, and not at all within 10
minutes of the last one.

If the prompt is dismissed or times out, the sync fails with "1Password did
not allow access" and changes nothing. If 1Password is locked, or the CLI
integration is off, it says that instead.

## Running it on a schedule

The sync is safe to run unattended: it exits cleanly with a message when
something's in the way, and writes nothing then.

| Exit | Meaning |
|---|---|
| 0 | synced (or nothing to do) |
| 3 | Deadbolt is locked (`op` was not asked anything), or locked during the sync (nothing written) |
| 1 | anything else: `op` missing, 1Password locked or not signed in, the prompt dismissed, `op` timed out |

A LaunchAgent that runs it hourly (not installed for you; save it as
`~/Library/LaunchAgents/dev.deadbolt.sync-1password.plist` and
`launchctl load` it):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.deadbolt.sync-1password</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/deadbolt</string>
    <string>sync</string>
    <string>1password</string>
    <string>--quiet</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>StandardErrorPath</key><string>/tmp/deadbolt-sync-1password.log</string>
</dict>
</plist>
```

Expect a 1Password prompt on most runs: an hour apart, the 10-minute
approval has lapsed. A schedule suits a Mac you're at; run it by hand
otherwise.

## Why `op`

- **Not exports.** A `.1pux` is every secret in one unencrypted file on disk,
  and it's a snapshot: keeping a mirror current would mean exporting again
  and again. `op` hands items over a pipe, and only the ones that changed.
- **Not UI scripting.** Driving the 1Password app through Accessibility is
  slow, breaks with every redesign, and needs a permission that can bypass
  1Password's own prompts. `op` is 1Password's supported interface, gated by
  its own approval.
- **Secrets stay off disk and out of argv.** Item ids go to `op` on stdin;
  values come back on a pipe into the agent and nowhere else. Reports hold
  titles and field names only, never values.
