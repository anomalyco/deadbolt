#!/usr/bin/env bun
// Refreshes the bundled offline health directories in `crates/core/data/health/`
// from 2FA Directory, Passkeys Directory, Apple password-manager-resources, and
// Have I Been Pwned's public breaches list.

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const APPLE_COMMIT = "d158201a3c67899494b1beea0a6c016a44d835d5";
const OUT_DIR = join(import.meta.dir, "../crates/core/data/health");

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { "User-Agent": "deadbolt-health-sync" },
  });
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status}`);
  }
  return (await res.json()) as T;
}

type TfaV3Entry = [
  string,
  {
    domain: string;
    "additional-domains"?: string[];
    tfa?: string[];
    documentation?: string;
  },
];

type PasskeysV1 = Record<
  string,
  {
    passwordless?: "allowed" | "required";
    mfa?: "allowed" | "required";
    "additional-domains"?: string[];
    documentation?: string;
  }
>;

type HibpBreach = {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
};

function cleanHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

function sortedObject<T>(entries: Iterable<[string, T]>): Record<string, T> {
  return Object.fromEntries(
    Array.from(entries).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const [tfaRaw, passkeysRaw, breachesRaw, changeUrlsRaw, sharedRaw] =
    await Promise.all([
      fetchJson<TfaV3Entry[]>("https://api.2fa.directory/v3/tfa.json"),
      fetchJson<PasskeysV1>(
        "https://passkeys-api.2fa.directory/v1/supported.json",
      ),
      fetchJson<HibpBreach[]>("https://haveibeenpwned.com/api/v3/breaches"),
      fetchJson<Record<string, string>>(
        `https://raw.githubusercontent.com/apple/password-manager-resources/${APPLE_COMMIT}/quirks/change-password-URLs.json`,
      ),
      fetchJson<unknown[]>(
        `https://raw.githubusercontent.com/apple/password-manager-resources/${APPLE_COMMIT}/quirks/shared-credentials.json`,
      ),
    ]);

  const tfaMap = new Map<string, string>();
  for (const [, info] of tfaRaw) {
    if (!info.tfa?.includes("totp")) continue;
    const doc = info.documentation?.trim() ?? "";
    const primary = cleanHost(info.domain);
    if (primary) tfaMap.set(primary, doc);
    for (const extra of info["additional-domains"] ?? []) {
      const domain = cleanHost(extra);
      if (domain && !tfaMap.has(domain)) tfaMap.set(domain, doc);
    }
  }

  type CompactPasskey = { p?: true; m?: true; d?: string };
  const passkeyMap = new Map<string, CompactPasskey>();
  for (const [rawDomain, info] of Object.entries(passkeysRaw)) {
    const p =
      info.passwordless === "allowed" || info.passwordless === "required";
    const m = info.mfa === "allowed" || info.mfa === "required";
    if (!p && !m) continue;
    const entry: CompactPasskey = {};
    if (p) entry.p = true;
    if (m) entry.m = true;
    if (info.documentation?.trim()) entry.d = info.documentation.trim();
    const primary = cleanHost(rawDomain);
    if (primary) passkeyMap.set(primary, entry);
    for (const extra of info["additional-domains"] ?? []) {
      const domain = cleanHost(extra);
      if (domain && !passkeyMap.has(domain)) passkeyMap.set(domain, entry);
    }
  }

  type CompactBreach = { t: string; d: string; a: string };
  const breachMap = new Map<string, CompactBreach>();
  for (const breach of breachesRaw) {
    const domain = cleanHost(breach.Domain ?? "");
    if (
      !domain ||
      !breach.IsVerified ||
      breach.IsFabricated ||
      breach.IsRetired ||
      breach.IsSpamList ||
      !breach.DataClasses?.includes("Passwords")
    ) {
      continue;
    }
    const date = breach.BreachDate.slice(0, 10);
    const added = breach.AddedDate.slice(0, 10);
    const prev = breachMap.get(domain);
    if (!prev || date > prev.d) {
      breachMap.set(domain, { t: breach.Title, d: date, a: added });
    }
  }

  const changeMap = new Map<string, string>();
  for (const [rawDomain, url] of Object.entries(changeUrlsRaw)) {
    const domain = cleanHost(rawDomain);
    const target = url.trim();
    if (domain && target.startsWith("https://")) {
      changeMap.set(domain, target);
    }
  }

  await Promise.all([
    writeFile(
      join(OUT_DIR, "2fa.json"),
      JSON.stringify(sortedObject(tfaMap)) + "\n",
    ),
    writeFile(
      join(OUT_DIR, "passkeys.json"),
      JSON.stringify(sortedObject(passkeyMap)) + "\n",
    ),
    writeFile(
      join(OUT_DIR, "breaches.json"),
      JSON.stringify(sortedObject(breachMap)) + "\n",
    ),
    writeFile(
      join(OUT_DIR, "change-urls.json"),
      JSON.stringify(sortedObject(changeMap)) + "\n",
    ),
    writeFile(join(OUT_DIR, "shared.json"), JSON.stringify(sharedRaw) + "\n"),
  ]);

  console.log(
    `wrote health data: 2fa=${tfaMap.size}, passkeys=${passkeyMap.size}, breaches=${breachMap.size}, change-urls=${changeMap.size}, shared=${sharedRaw.length}`,
  );
}

await main();
