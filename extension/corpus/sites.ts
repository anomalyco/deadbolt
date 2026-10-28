// The sites to crawl: the top N of the latest Tranco list (cached in the
// output dir), or a file of domains, one per line.

import { existsSync } from "node:fs"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"

/** Adult and gambling sites, when the name says so. Not a real classifier. */
const UNWANTED = /porn|xxx|xvideo|xnxx|xhamster|redtube|youporn|onlyfans|chaturbate|stripchat|bongacams|livejasmin|camsoda|hentai|sex|casino|1xbet|bet365|betway|poker|gambl|slot/i
/**
 * Infrastructure domains (CDNs, DNS, telemetry, APIs) that have no page to
 * sign in on. Only the obvious ones; anything else just ends as unreachable.
 */
const INFRA =
  /(^|\.)(gstatic|googleapis|googleusercontent|googlevideo|googlesyndication|googleadservices|googletagmanager|google-analytics|doubleclick|ggpht|gvt\d|fbcdn|akamai\w*|akadns|edgekey|edgesuite|cloudfront|amazonaws|awsdns\w*|azureedge|azurefd|trafficmanager|msedge|windowsupdate|digicert|sectigo|letsencrypt|ocsp\w*|fastly\w*|cdn\w*|\w*cdn|root-servers|nic|in-addr|ntp|pool|tiktokcdn\w*|tiktokv|ttlivecdn|byteoversea|ibyteimg|sc-cdn|scdn|aaplimg|mzstatic|icloud-content|apple-dns|cloudflare-dns|one\.one|demdex|omtrdc|scorecardresearch|adnxs|rubiconproject|pubmatic|casalemedia|openx|appsflyer\w*|branch|adjust|onesignal|crashlytics|app-measurement|firebaseio|gvt1|hicloud\w*|ezviz\w*|dbankcloud|samsungcloudsolution|tplinkcloud|wbx2|teams|live\.net|office\.net|msftncsi|msftconnecttest|data\.microsoft|events\.data|mozgcp|spotifycdn|nr-data)\./i

/** Never inside the repo. */
export const DEFAULT_OUT = join(process.env.TMPDIR ?? "/tmp", "opencode", "deadbolt-corpus")

export interface SiteOptions {
  top: number
  sitesFile?: string
  out: string
}

async function tranco(out: string): Promise<string[]> {
  const cache = join(out, "tranco.csv")
  if (existsSync(cache)) return parse(await readFile(cache, "utf8"))
  const latest = (await (await fetch("https://tranco-list.eu/api/lists/date/latest")).json()) as { list_id: string }
  // The first 100k is plenty and much smaller than the full million.
  const res = await fetch(`https://tranco-list.eu/download/${latest.list_id}/100000`)
  if (!res.ok) throw new Error(`Tranco download failed: ${res.status}`)
  const text = await res.text()
  await writeFile(cache, text)
  await writeFile(join(out, "tranco-id.txt"), latest.list_id + "\n")
  return parse(text)
}

const parse = (csv: string) =>
  csv
    .split(/\r?\n/)
    .map((l) => l.split(",")[1]?.trim())
    .filter((d): d is string => !!d)

export interface Site {
  rank: number
  domain: string
  /** A page to open directly (crawl.ts --urls), instead of the homepage. */
  target?: string
  skip?: "unwanted" | "infra"
}

export async function loadSites({ top, sitesFile, out }: SiteOptions): Promise<Site[]> {
  await mkdir(out, { recursive: true })
  const domains = sitesFile
    ? (await readFile(sitesFile, "utf8"))
        .split(/\r?\n/)
        .map((l) => l.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, ""))
        .filter((l) => l && !l.startsWith("#"))
    : (await tranco(out)).slice(0, top)
  return domains.map((domain, i) => ({
    rank: i + 1,
    domain,
    skip: UNWANTED.test(domain) ? "unwanted" : INFRA.test(domain) ? "infra" : undefined,
  }))
}

if (import.meta.main) {
  const arg = (n: string) => {
    const i = process.argv.indexOf(n)
    return i > 0 ? process.argv[i + 1] : undefined
  }
  const out = arg("--out") ?? DEFAULT_OUT
  const sites = await loadSites({ top: Number(arg("--top") ?? 1000), sitesFile: arg("--sites"), out })
  for (const s of sites) console.log(`${s.rank}\t${s.domain}${s.skip ? `\t(skip: ${s.skip})` : ""}`)
}
