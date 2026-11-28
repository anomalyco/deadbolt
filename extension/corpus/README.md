# Detection corpus

Crawls real sites' sign-in pages and runs the extension's form detector
(`src/content/detect.ts`) on them, to see how login forms look in the wild and
where detection disagrees with what the pages declare. The crawl is not part
of `bun run check`; the frozen corpus gate below is.

```sh
bun corpus/crawl.ts --top 50            # shake-out run
bun corpus/crawl.ts --top 1000          # resumable: rerun to continue
bun corpus/report.ts                    # report.md, report.json, contact.html
```

`corpus/frame-logins.txt` lists sign-ins whose form is in a frame of the
page's own site (Schwab, account.apple.com, App Store Connect; issue #88).
Crawl them with `bun corpus/crawl.ts --urls corpus/frame-logins.txt --out <dir>`,
then `bun corpus/frames.ts --out <dir>` prints every frame of each page (host,
size, same site as the top page all the way up, `sandbox` on the way, the
detector's kind and roles) and fails unless each has a frame login the
inline menu serves. `--all` lists the frames of every crawled page instead.

`bun corpus/sweep.ts` is the real-site sweep: the extension itself (an e2e
build, talking to `e2e/fake-host.py`) on the pages in `corpus/sweep-sites.txt` (about 330 sign-ins: banks,
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

`bun corpus/learned.ts` reports on Record's logs instead
(`--dir`, default `~/.local/state/deadbolt/learn`; `--out file.md`): every
field the user typed into while signing in by hand, with the role their typing
shows next to the detector's, so its labels are ground truth rather than the
crawl's weak ones (see docs/autofill.md, "Recording a site").

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

## The detection gate (frozen corpus)

`bun run test:corpus` (in `bun run check`) scores the detector on a frozen
corpus with no network and no browser, in under two seconds:

```sh
bun corpus/score.ts --gate            # what CI runs
bun corpus/score.ts --verbose         # every miss, field by field
bun corpus/score.ts --only github     # some pages
bun corpus/score.ts --update-gate     # after an improvement: raise the floors
```

- `frozen/`: one script-free HTML file per page, with the layout Chromium gave
  every control (`data-db-box="x,y,w,h,vis"`) and its shadow roots as
  `<template shadowrootmode>`. 133 pages. The first 77: 49 modeled on
  the structure of real sign-in, sign-up, code, change-password and
  checkout pages (GitHub, Google's email-first step with its
  `hiddenPassword`, Microsoft's off-screen boxes, Apple, Amazon, Stripe's
  React sign-in, Okta, Auth0, Clerk, Shopify, PayPal, Coinbase, banks, open
  and closed shadow roots, six-box codes) and 28 decoys (searches, promo and
  gift cards, newsletters, an `author.` host, invites, admin and settings
  forms, comments, support, a transfer PIN, two sent-code groups, a
  delete-account confirmation). Then 56 more, all on reserved `.example`
  hosts: sign-ins, sign-ups, code steps, a reset and a change of password
  in German, French, Spanish, Portuguese, Japanese, Italian and Dutch; SSO
  with a workspace and region, a bank's customer ID with date of birth and
  postcode, a passkey-first box, a magic link, a masked 2FA box with no
  maxlength, a two-step sign-up, a `<my-button>` submit, hashed React
  classes, a login dialog over a search, card expiry in selects, split
  billing and shipping; and 28 decoys (a hotel confirmation code, a flight
  booking reference, a badge PIN, a masked SSN, a national ID, a direct
  deposit account, recovery codes, a webhook secret, an environment
  variable, a seed phrase, a Wi-Fi password, a link password, a PDF
  password, a strength meter, a profile PIN, an alarm code, contact-sales,
  an RSVP, a filter-by-key box, a delete-workspace box…). Every address in
  them is reserved (`example.com`, `.example`); none holds a value.
- `frozen.lock.json`: each page's URL and SHA-256. `score.ts` refuses a page
  that doesn't match.
- `gold-labels.jsonl`: per page, the kind the login detector should give it
  and the role of each control it should claim (`login`), and the identity
  and payment fields (`forms`), by `controlKey` (`replay.ts`: `#id`,
  `tag[name=…]`, `host >> #id` in a shadow root). `decoy: true` marks a page
  on which no login menu should open. `split` is `train` or `holdout`, by
  site (registrable domain): every page of a site is in the same split, and
  `score.ts` fails if one isn't. A new site's split is a hash of its name
  (`splitFor`, 35% holdout); `freeze.ts` proposes it.
- `gate.json`: the baseline the gate holds, written by `--update-gate`:
  per-role precision and recall floors, the page-kind floor, the decoy
  false-trigger ceilings (each 0.5 points past what was measured), and the
  pages that scored exactly, each of which must stay exact. `--update-gate`
  only ratchets; `--allow-regress` is for a deliberate trade, said so in the
  PR. The target is 98% precision, 95% recall and at most 2% decoy false
  triggers. `holdout` holds the same floors for the holdout pages alone.

## The cluster model (`train-weights.ts`)

The rules in `clues.ts` give each field a role; then every cluster (a form
or container, `graph.ts`) holding a login role is judged as a whole by a
sparse linear model in `src/content/weights.gen.ts`. `clusterFeatures`
(`rationalize.ts`) lists the cluster's value-free facts: the roles the
rules gave it and their shape, its autocomplete tokens, how many boxes it
has and how many no role claims, the form kinds its words and buttons name
(in every language `clues.ts` knows), wording groups (secrets, bookings,
identity numbers, wallets, networks, sharing, deletion, sent codes,
offers…), the page's path and title, and `signal:none` when nothing says
sign-in. Never a site's name: `test/weights.test.ts` checks. The summed
weights are the log-odds that it's a login form; under the threshold it's
set aside, as a gift card form is.

```sh
bun corpus/train-weights.ts            # fit on the train split, print train and holdout scores, write weights.gen.ts
bun corpus/train-weights.ts --check    # fail unless weights.gen.ts is what training writes (test/weights.test.ts runs it)
bun corpus/train-weights.ts --dry-run  # fit and print only
```

It fits L1- and L2-regularised logistic regression on the train pages'
clusters only (a cluster is a login when it holds a gold login field, or
it's the code or reset step of a page with nothing to fill), deterministic
from zero, drops weights under 0.05 and features seen on fewer than two
clusters, and puts the threshold under every train login, halfway to the
highest non-login below it. Retrain after changing `clusterFeatures` or
the corpus, and commit the diff with the gate.

`score.ts` reports precision, recall and F1 for username/email, password,
new password, one-time code, card and address; how often the page's kind is
right; the decoy false-trigger rate (decoys on which the login detector
claims a field, so a menu would open) and decoys offered a card or address.
It scores the corpus twice and fails if the two runs' predictions differ.

New pages come from `freeze.ts`, which opens each page once in headless
Chromium, measures it, strips scripts, styles, frame sources, images, event
handlers, query strings and every value, and updates the lock:

```sh
bun corpus/freeze.ts --in $TMPDIR/opencode/deadbolt-corpus   # what crawl.ts saved
bun corpus/freeze.ts --urls corpus/decoy-urls.txt --decoy    # live pages (network, once)
bun corpus/freeze.ts --html <dir>                            # pages written by hand (<meta name="db-url">)
bun corpus/freeze.ts --relock                                # after editing a frozen page by hand
```

A page without a gold label gets a proposed one in
`gold-labels.proposed.jsonl` (from its autocomplete tokens and input types);
check it, set its kind and move it into `gold-labels.jsonl`. Keep the corpus
small: under 500 KB in all.
