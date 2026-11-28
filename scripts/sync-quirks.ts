#!/usr/bin/env bun
// Syncs the quirks Deadbolt bundles from Apple's password-manager-resources
// (MIT) at one pinned commit:
//
//   quirks/password-rules.json       -> crates/core/data/password-rules/password-rules.json
//   quirks/shared-credentials.json   -> crates/core/data/health/shared.json
//   quirks/change-password-URLs.json -> crates/core/data/health/change-urls.json
//
// Usage:
//   bun scripts/sync-quirks.ts            re-sync from the pinned commit
//   bun scripts/sync-quirks.ts --sha SHA  pin SHA and sync from it
//   bun scripts/sync-quirks.ts --latest   pin the head of Apple's main and sync
//   bun scripts/sync-quirks.ts --check    fail if the bundled files differ from the pin
//
// Pinning a new commit rewrites PINNED below and the commit in both data
// READMEs, so a plain re-run reproduces the same files.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const PINNED = "6c0cedf7b5664cfc41bcc0a0d9e59325d0468271";
const REPO = "apple/password-manager-resources";
const DATA = join(import.meta.dir, "../crates/core/data");
const RULES_DIR = join(DATA, "password-rules");
const HEALTH_DIR = join(DATA, "health");
const HEADERS = { "User-Agent": "deadbolt-quirks-sync" };

type Rules = Record<string, { "password-rules": string }>;
type SharedEntry =
  | { shared: string[] }
  | { from: string[]; to: string[]; fromDomainsAreObsoleted?: boolean };

function args(): { sha?: string; latest: boolean; check: boolean } {
  const argv = process.argv.slice(2);
  const at = argv.indexOf("--sha");
  const sha = at >= 0 ? argv[at + 1] : undefined;
  if (at >= 0 && !/^[0-9a-f]{40}$/.test(sha ?? "")) {
    throw new Error("--sha takes a full 40-character commit SHA");
  }
  return {
    sha,
    latest: argv.includes("--latest"),
    check: argv.includes("--check"),
  };
}

async function get(url: string): Promise<string> {
  const res = await fetch(url, { headers: HEADERS });
  if (!res.ok) throw new Error(`GET ${url} failed: ${res.status}`);
  return res.text();
}

async function commit(ref: string): Promise<{ sha: string; date: string }> {
  const body = JSON.parse(
    await get(`https://api.github.com/repos/${REPO}/commits/${ref}`),
  );
  return { sha: body.sha, date: body.commit.committer.date.slice(0, 10) };
}

function domain(value: unknown, where: string): string {
  if (typeof value !== "string" || !/^[a-z0-9.-]+$/.test(value)) {
    throw new Error(
      `${where}: ${JSON.stringify(value)} is not a lowercase domain`,
    );
  }
  return value;
}

function domains(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${where}: expected a non-empty list of domains`);
  }
  return value.map((d, i) => domain(d, `${where}[${i}]`));
}

// Apple's CONTRIBUTING.md allows exactly `shared`, or `from` and `to` with an
// optional boolean `fromDomainsAreObsoleted`.
function checkShared(raw: unknown): SharedEntry[] {
  if (!Array.isArray(raw)) {
    throw new Error("shared-credentials.json is not a list");
  }
  raw.forEach((entry, i) => {
    const keys = Object.keys(entry).sort().join(",");
    if (keys === "shared") {
      domains(entry.shared, `shared #${i}`);
    } else if (
      keys === "from,to" ||
      keys === "from,fromDomainsAreObsoleted,to"
    ) {
      domains(entry.from, `from #${i}`);
      domains(entry.to, `to #${i}`);
      if (
        "fromDomainsAreObsoleted" in entry &&
        typeof entry.fromDomainsAreObsoleted !== "boolean"
      ) {
        throw new Error(
          `entry #${i}: fromDomainsAreObsoleted is not a boolean`,
        );
      }
    } else {
      throw new Error(`entry #${i} has unknown keys: ${keys}`);
    }
  });
  return raw;
}

function checkRules(raw: unknown): Rules {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("password-rules.json is not an object");
  }
  for (const [host, entry] of Object.entries(raw)) {
    domain(host, "password-rules key");
    if (typeof (entry as Rules[string])["password-rules"] !== "string") {
      throw new Error(`${host} has no password-rules string`);
    }
  }
  return raw as Rules;
}

// Lowercase hosts, https targets only, sorted by host.
function changeUrls(raw: Record<string, string>): Record<string, string> {
  const out = new Map<string, string>();
  for (const [host, url] of Object.entries(raw)) {
    const clean = host.trim().toLowerCase().replace(/\.$/, "");
    const target = url.trim();
    if (clean && target.startsWith("https://")) out.set(clean, target);
  }
  return Object.fromEntries(
    [...out].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

async function main() {
  const opts = args();
  const ref = opts.sha ?? (opts.latest ? "main" : PINNED);
  const { sha, date } = await commit(ref);
  const raw = (path: string) =>
    get(`https://raw.githubusercontent.com/${REPO}/${sha}/${path}`);

  const [rulesText, sharedText, changeText, license] = await Promise.all([
    raw("quirks/password-rules.json"),
    raw("quirks/shared-credentials.json"),
    raw("quirks/change-password-URLs.json"),
    raw("LICENSE.md"),
  ]);
  const rules = checkRules(JSON.parse(rulesText));
  const shared = checkShared(JSON.parse(sharedText));
  const change = changeUrls(JSON.parse(changeText));

  // password-rules.json stays byte for byte Apple's; shared.json keeps every
  // field of every entry, minified.
  const files: Record<string, string> = {
    [join(RULES_DIR, "password-rules.json")]: rulesText,
    [join(RULES_DIR, "LICENSE.md")]: license,
    [join(HEALTH_DIR, "shared.json")]: JSON.stringify(shared) + "\n",
    [join(HEALTH_DIR, "change-urls.json")]: JSON.stringify(change) + "\n",
  };
  const pin = (text: string) =>
    text.replace(
      /commit `[0-9a-f]{40}`( \(\d{4}-\d{2}-\d{2}\))?/g,
      `commit \`${sha}\` (${date})`,
    );
  for (const readme of [
    join(RULES_DIR, "README.md"),
    join(HEALTH_DIR, "README.md"),
  ]) {
    files[readme] = pin(await readFile(readme, "utf8"));
  }

  const counts = [
    `password-rules=${Object.keys(rules).length}`,
    `shared=${shared.length}`,
    `change-urls=${Object.keys(change).length}`,
  ].join(", ");
  if (opts.check) {
    const stale: string[] = [];
    for (const [path, text] of Object.entries(files)) {
      const now = await readFile(path, "utf8").catch(() => "");
      if (now !== text) stale.push(path);
    }
    if (stale.length) {
      console.error(`out of date with ${REPO}@${sha}:`);
      for (const path of stale) console.error(`  ${path}`);
      process.exit(1);
    }
    console.log(`quirks match ${REPO}@${sha} (${counts})`);
    return;
  }

  await Promise.all(
    Object.entries(files).map(([path, text]) => writeFile(path, text)),
  );
  if (sha !== PINNED) {
    const self = import.meta.path;
    const source = await readFile(self, "utf8");
    const pinned = (s: string) => `const PINNED = "${s}"`;
    await writeFile(self, source.replace(pinned(PINNED), pinned(sha)));
  }
  console.log(`synced ${REPO}@${sha} (${date}): ${counts}`);
}

await main();
