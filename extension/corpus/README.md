# Detection corpus

Crawls real sites' sign-in pages and runs the extension's form detector
(`src/content/detect.ts`) on them, to see how login forms look in the wild and
where detection disagrees with what the pages declare. Not part of
`bun run check`.

```sh
bun corpus/crawl.ts --top 50            # shake-out run
bun corpus/crawl.ts --top 1000          # resumable: rerun to continue
bun corpus/report.ts                    # report.md, report.json, contact.html
bun corpus/compare.ts                   # engine vs detect.ts: compare.md, compare.json
```

`corpus/frame-logins.txt` lists sign-ins whose form is in a frame of the
page's own site (Schwab, account.apple.com, App Store Connect; issue #88).
Crawl them with `bun corpus/crawl.ts --urls corpus/frame-logins.txt --out <dir>`,
then `bun corpus/frames.ts --out <dir>` prints every frame of each page (host,
size, same site as the top page all the way up, `sandbox` on the way, the
detector's kind and roles) and fails unless each has a frame login the
inline menu serves. `--all` lists the frames of every crawled page instead.

`bun corpus/sweep.ts` is the real-site sweep: the extension itself (an e2e
build, native with `e2e/fake-host.py` or `--standalone` with a throwaway
vault) on the pages in `corpus/sweep-sites.txt` (about 330 sign-ins: banks,
email, dev tools, shopping, SaaS, streaming, government, the crawl's reached
pages and its hard list). On each page it checks what a person gets: whether
a frame reports a login form, whether clicking the field opens the menu with
logins (top page or a same-site frame), whether picking the made-up login
fills the right fields and nothing else, and on identifier-first sign-ins,
step 2: it presses Continue with the reserved address `step2.ts` uses and
checks the password box is filled by the sign-in session or a second pick.
It never submits a password. `--report` writes `sweep.md` (rates, failures
ranked by pattern, every failing page with a screenshot); add `--against
<earlier out dir>` for before and after. Other flags: `--urls`, `--dist`
(an existing e2e build), `--out`, `--concurrency 6`, `--timeout`, `--only
<substring>`, `--retry`, `--no-step2`.

`bun corpus/learned.ts` reports on "Learn this site" logs instead
(`--dir`, default `~/.local/state/deadbolt/learn`; `--out file.md`): every
field the user typed into while signing in by hand, with the role their typing
shows next to the detector's, so its labels are ground truth rather than the
crawl's weak ones (see docs/autofill.md, "Learning a site").

Flags for `crawl.ts`: `--top N` (Tranco top N, default 1000), `--sites file.txt`
(one domain per line instead), `--urls file.txt` (open each listed page
directly, one hop to a clear "Sign in" control if it has no fields),
`--step2` (see below), `--concurrency 6`, `--timeout 30` (45 with `--step2`;
seconds per site), `--out <dir>`, `--retry` (redo sites that ended in an error
or timeout). Pages of the same site are never visited at the same time.
Both scripts default to `$TMPDIR/opencode/deadbolt-corpus/`, never the repo.
Needs Playwright's Chromium (`bunx playwright-core install chromium`).

## What it does

- `sites.ts`: the latest Tranco list (top 100k cached as `tranco.csv`). Skips
  obvious CDN/DNS/telemetry hosts and adult or gambling sites by name.
- `crawl.ts`: one fresh browser context per site, one site per worker. Opens
  the homepage, then at most two candidate sign-in pages: a "Sign in" link
  (same site or a known identity provider) or button, else `/login` and
  `/signin`. It never types, submits or dismisses anything, and stops at bot
  challenges. On the page it ends on it saves a screenshot (`shots/`), the HTML
  (`html/`) and a line in `results.jsonl`.
- `probe.ts`: bundled to an IIFE and evaluated in every reachable frame
  (`crawl.ts` adds each subframe's size, its parent and its frame element's
  `sandbox` attribute). It
  records every input (type, name, id, autocomplete, label, visibility, shadow
  root, form action host, position), runs `scanPage()`, and notes each field's
  role, the page kind and the submit control. Runs in the page's main world,
  not an isolated one as the extension does.
- `labels.ts`: weak labels from the page's own markup (autocomplete tokens,
  then `type=password`/`email`, then name/id hints) and how they compare with
  the detector's roles. They are hints, not ground truth.
- `snapshot.ts`: collects the autofill engine's value-free Snapshot
  (`crates/autofill`) in each frame; `crawl.ts` saves one per page as
  `snapshots/<page>.json`, and each probed input carries its snapshot `fid`.
- `compare.ts`: replays `snapshots/` with
  `cargo run -p deadbolt-autofill --bin replay` and compares the engine with
  the recorded `scanPage()` result and the weak labels: page kind, field
  roles, and on each disagreement which one matches the markup.
- `step2.ts` (`--step2`): on identifier-first pages, types the reserved,
  undeliverable `deadbolt.corpus@example.com` (RFC 2606) into the identifier
  field and presses the detected submit control once per site, then records
  what step 2 shows (password, code, magic link, sign-up, error, SSO redirect,
  passkey, challenge, nothing), whether it's the same document, which origin,
  and where the address is carried. Never types a password and never submits
  step 2.
- `report.ts`: reach and detection rates, field agreement and confusion,
  failure patterns with example sites, the worst pages, and `contact.html`, a
  sheet of screenshots with each field boxed and tagged `label→role`. With
  step-2 results it adds their tables and `step2.html` (step 1 and 2 side by side).
