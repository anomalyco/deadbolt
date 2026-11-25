# Secrets for commands

`deadbolt run`, `inject` and `read` put vault values where a command needs
them, by reference, without the value going through argv, shell history or
a file you have to remember to delete.

```sh
deadbolt run --env GH_TOKEN=deadbolt://personal/GitHub/token -- gh release create v1
deadbolt run --env-file .env.tpl -- bun run dev       # KEY=deadbolt://… lines
deadbolt inject -i config.tpl -o config.json          # {{ deadbolt://… }}; written 0600
deadbolt read deadbolt://personal/GitHub/password
```

**Who gets values.** Anyone who can run commands as you, while the vault is
unlocked, exactly as with `deadbolt get`, except what `deadbolt run`
starts (below). See the threat model in `docs/design.md`. Locked, every resolve fails `locked`
(exit 3). The browser host and macOS AutoFill never resolve references
(`forbidden`, exit 4).

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
leaves them on the terminal. Masking stops accidents, such as a value
landing in a log or a transcript, not a command that means to show it.

**A run's command gets nothing more.** Once its values are resolved,
`deadbolt run` registers its own process with the daemon (`run-taint`)
and only then starts the command, so the command never has a moment
outside the run. While the run lasts, the daemon walks the ancestry of
every caller by pid and start time (`proc_pidinfo`/`sysctl` on macOS,
`/proc/<pid>/stat` on Linux): the command, a shell it starts, and
anything below them are refused every request but `status` (`forbidden`,
"process is running inside deadbolt run and cannot access daemon
secrets"): no item, no reference, no list, no lock or unlock. A start time
that doesn't match ends the walk, so a reused pid neither inherits a run
nor escapes one. When the command exits, `deadbolt run` ends the run with
its id, which the command never sees; a run whose process has died is
dropped as the daemon finds it. A process that outlives the run, or
detaches from it with a double fork, is no longer anyone's descendant and
is served as any other caller. The daemon's code is
`crates/cli/src/daemon/taint.rs`; capabilities a run may carry are
`crates/engine/src/cap.rs`.

**`deadbolt inject`.** Replaces each `{{ deadbolt://… }}` in the template
(`-i`, default stdin; other `{{ … }}` are left alone) and writes the result
to `-o` through a 0600 temporary file renamed into place. Written to
stdout (no `-o`, or `-o -`), it resolves as a `read`. An existing output is
replaced only if `inject` wrote it and it hasn't changed since (same
device, inode, size and modification time, recorded in `injected.json` in
the data directory, no values), or with `--force`.

**`deadbolt read`.** Prints one value. Prefer `run` or `inject`, which keep
values out of your terminal and scrollback.

**Activity.** Every resolve is an entry: `resolve-run` and
`resolve-inject` (tier Use) or `resolve-read` (Read), the caller, the items
found (vault, id, title) or as named when nothing was found, the fields,
and the outcome. Never a value. Resolves don't count as use for the idle
lock.

**Protocol.** `resolve {refs, purpose}` → `secrets {secrets: [{vault,
item, title, field, value, file}]}` in reference order. A file field goes
only into a file `inject` writes from a template that is that one
reference. `run-taint` → `run-tainted {run}` registers the caller;
`run-untaint {run}` → `done` ends it (protocol 30).
