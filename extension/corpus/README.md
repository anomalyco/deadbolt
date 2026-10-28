# Detection corpus

Crawls real sites' sign-in pages and runs the extension's form detector
(`src/content/detect.ts`) on them, to see how login forms look in the wild and
where detection disagrees with what the pages declare. Not part of
`bun run check`.

```sh
bun corpus/crawl.ts --top 50            # shake-out run
bun corpus/crawl.ts --top 1000          # resumable: rerun to continue
bun corpus/report.ts                    # report.md, report.json, contact.html
```

Flags for `crawl.ts`: `--top N` (Tranco top N, default 1000), `--sites file.txt`
(one domain per line instead), `--concurrency 6`, `--timeout 30` (seconds per
site), `--out <dir>`, `--retry` (redo sites that ended in an error or timeout).
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
- `probe.ts`: bundled to an IIFE and evaluated in every reachable frame. It
  records every input (type, name, id, autocomplete, label, visibility, shadow
  root, form action host, position), runs `scanPage()`, and notes each field's
  role, the page kind and the submit control. Runs in the page's main world,
  not an isolated one as the extension does.
- `labels.ts`: weak labels from the page's own markup (autocomplete tokens,
  then `type=password`/`email`, then name/id hints) and how they compare with
  the detector's roles. They are hints, not ground truth.
- `report.ts`: reach and detection rates, field agreement and confusion,
  failure patterns with example sites, the worst pages, and `contact.html`, a
  sheet of screenshots with each field boxed and tagged `label→role`.
