// Generates static/site-icons/simple-icons.json: brand marks from Simple
// Icons (simpleicons.org, CC0 data, a pinned devDependency) for the most
// visited domains, so the vault and the menu can show a well-known site's
// mark without any request. Run by hand when bumping simple-icons:
//
//   bun scripts/simple-icons.ts [path to a Tranco top-1m.csv]
//
// The full set is about 4.6 MB of path data (2 MB gzipped), too much to ship
// in every install for a tile 28 px wide, so this keeps the brands whose own
// domain ranks highest on a pinned Tranco list (tranco-list.eu, list
// TRANCO_LIST below), and a hand map for big sites whose Simple Icons source
// URL isn't their own domain. Without a CSV it downloads that pinned list.

import { mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { parse } from "tldts"

const root = join(import.meta.dir, "..")
const out = join(root, "static", "site-icons", "simple-icons.json")
/** The Tranco list the ranking comes from (generated 2026-10; tranco-list.eu/list/<id>). */
const TRANCO_LIST = "PYK6J"
/** How many domains to keep. */
const KEEP = 500

/**
 * Big sites whose Simple Icons `source` names some other domain (a brand
 * portal, a CDN, a press page), and second domains of a brand. Domain → slug.
 */
const HAND: Record<string, string> = {
  "google.com": "google",
  "gmail.com": "gmail",
  "youtube.com": "youtube",
  "facebook.com": "facebook",
  "instagram.com": "instagram",
  "whatsapp.com": "whatsapp",
  "meta.com": "meta",
  "threads.net": "threads",
  "twitter.com": "x",
  "reddit.com": "reddit",
  "steampowered.com": "steam",
  "steamcommunity.com": "steam",
  "wikipedia.org": "wikipedia",
  "supabase.com": "supabase",
  "godaddy.com": "godaddy",
  "atlassian.com": "atlassian",
  "atlassian.net": "atlassian",
  "bitbucket.org": "bitbucket",
  "icloud.com": "icloud",
  "protonmail.com": "protonmail",
  "proton.me": "proton",
  "npmjs.com": "npm",
  "notion.so": "notion",
  "notion.com": "notion",
  "spotify.com": "spotify",
  "twitch.tv": "twitch",
  "ebay.com": "ebay",
  "planetscale.com": "planetscale",
  "fly.io": "flydotio",
  "hetzner.com": "hetzner",
  "tiktok.com": "tiktok",
  "pinterest.com": "pinterest",
  "tumblr.com": "tumblr",
  "medium.com": "medium",
  "duckduckgo.com": "duckduckgo",
  "mozilla.org": "mozilla",
  "firefox.com": "firefox",
  "telegram.org": "telegram",
  "signal.org": "signal",
  "bsky.app": "bluesky",
  "mastodon.social": "mastodon",
  "ycombinator.com": "ycombinator",
  "stackoverflow.com": "stackoverflow",
  "airbnb.com": "airbnb",
  "uber.com": "uber",
  "booking.com": "bookingdotcom",
  "kickstarter.com": "kickstarter",
  "patreon.com": "patreon",
  "trello.com": "trello",
  "asana.com": "asana",
  "miro.com": "miro",
  "nvidia.com": "nvidia",
  "intel.com": "intel",
  "samsung.com": "samsung",
  "playstation.com": "playstation",
  "epicgames.com": "epicgames",
  "ea.com": "ea",
  "ubisoft.com": "ubisoft",
  "battle.net": "battledotnet",
  "claude.ai": "claude",
  "anthropic.com": "anthropic",
  "huggingface.co": "huggingface",
  "codeberg.org": "codeberg",
  "sourcehut.org": "sourcehut",
  "sr.ht": "sourcehut",
  "railway.com": "railway",
  "render.com": "render",
  "deno.com": "deno",
  "bun.sh": "bun",
  "linear.app": "linear",
  "figma.com": "figma",
  "tailscale.com": "tailscale",
  "1password.com": "1password",
  "bitwarden.com": "bitwarden",
  "netlify.com": "netlify",
  "posthog.com": "posthog",
  "digitalocean.com": "digitalocean",
  "coinbase.com": "coinbase",
  "binance.com": "binance",
  "docker.com": "docker",
  "gitlab.com": "gitlab",
  "vercel.com": "vercel",
  "github.com": "github",
}

type Brand = { title: string; slug: string; hex: string; source?: string }

const pkg = join(root, "node_modules", "simple-icons")
const version = JSON.parse(await readFile(join(pkg, "package.json"), "utf8")).version as string
const brands = JSON.parse(await readFile(join(pkg, "data", "simple-icons.json"), "utf8")) as Brand[]
const bySlug = new Map(brands.map((b) => [b.slug, b]))

const csvArg = process.argv[2]
const csv = csvArg
  ? await readFile(csvArg, "utf8")
  : await (async () => {
      const r = await fetch(`https://tranco-list.eu/download/${TRANCO_LIST}/1000000`)
      if (!r.ok) throw new Error(`Tranco list ${TRANCO_LIST}: HTTP ${r.status}`)
      return r.text()
    })()
const rank = new Map<string, number>()
for (const line of csv.split("\n")) {
  const [r, d] = line.trim().split(",")
  if (d && !rank.has(d)) rank.set(d, Number(r))
}

/** Domain → slug: a brand whose source URL is on its own domain (its label is the slug), then the hand map. */
const domains = new Map<string, string>()
for (const b of brands) {
  let host = ""
  try {
    host = b.source ? new URL(b.source).hostname : ""
  } catch {}
  // Private suffixes count (github.io, vercel.app): a site under one is its owner's, not the brand's.
  const p = parse(host, { allowPrivateDomains: true })
  if (p.domain && p.domainWithoutSuffix && p.domainWithoutSuffix.replace(/[-.]/g, "") === b.slug && !domains.has(p.domain)) domains.set(p.domain, b.slug)
}
for (const [d, slug] of Object.entries(HAND)) {
  if (!bySlug.has(slug)) throw new Error(`hand map: no Simple Icon ${slug} (for ${d})`)
  if (parse(d, { allowPrivateDomains: true }).domain !== d) throw new Error(`hand map: ${d} isn't a registrable domain`)
  domains.set(d, slug)
}

// The most visited first; hand-mapped domains always stay.
const ranked = [...domains.entries()]
  .filter(([d]) => rank.has(d) || d in HAND)
  .sort(([a], [b]) => (rank.get(a) ?? Infinity) - (rank.get(b) ?? Infinity))
const kept = ranked.filter(([d], i) => i < KEEP || d in HAND)

const paths: Record<string, [string, string, string]> = {}
const map: Record<string, string> = {}
for (const [d, slug] of kept) {
  const b = bySlug.get(slug)!
  const svg = await readFile(join(pkg, "icons", `${slug}.svg`), "utf8")
  const path = / d="([^"]+)"/.exec(svg)?.[1]
  if (!path || !/^[\d\s.,+\-eMmLlHhVvCcSsQqTtAaZz]+$/.test(path)) throw new Error(`${slug}: unexpected path`)
  paths[slug] = [b.title, b.hex, path]
  map[d] = slug
}

const json = JSON.stringify({ version, tranco: TRANCO_LIST, domains: map, brands: paths })
await mkdir(join(root, "static", "site-icons"), { recursive: true })
await writeFile(out, json + "\n")
const gz = Bun.gzipSync(new TextEncoder().encode(json)).length
console.log(`simple-icons ${version}: ${Object.keys(map).length} domains, ${Object.keys(paths).length} brands, ${(json.length / 1024).toFixed(0)} KB (${(gz / 1024).toFixed(0)} KB gzipped) -> static/site-icons/simple-icons.json`)
