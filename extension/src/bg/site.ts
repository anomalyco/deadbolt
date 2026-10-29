// Which frames may ask for logins, decided from the browser's record of the
// sender. senderOrigin and fillableOrigin are ported from Foyer
// (github.com/R44VC0RP/foyer, src/autofill/origin.ts, by Ryan Vogel).
//
// The agent makes the real decision: it works out the page's site from the
// origin and refuses another site's login. The extension's job is to pass the
// right origin, and to give a frame nothing unless it is on the same site as
// the page around it.

import { getDomain } from "tldts"

/**
 * The sender's real origin. Sandboxed frames report the site's URL but have an
 * opaque origin ("null"); sites sandbox exactly the content they don't trust,
 * so those get nothing.
 */
export function senderOrigin(sender: Pick<chrome.runtime.MessageSender, "url" | "origin">): URL | null {
  if (!sender.url || !sender.origin || sender.origin === "null") return null
  let url: URL
  try {
    url = new URL(sender.url)
  } catch {
    return null
  }
  return url.origin === sender.origin ? url : null
}

function isLocalHost(hostname: string): boolean {
  const h = hostname.replace(/\.$/, "")
  return h === "localhost" || h === "127.0.0.1" || h.endsWith(".localhost") || h.endsWith(".test")
}

/** Only https pages, and http on local development hosts, get logins (docs/autofill.md). */
export function fillableOrigin(url: URL): boolean {
  if (url.protocol === "https:") return true
  return url.protocol === "http:" && isLocalHost(url.hostname)
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/**
 * The registrable domain of a host under the full Public Suffix List, private
 * section included, as the agent computes it. An IP address, localhost and a
 * single label are their own site; a public suffix itself has none.
 */
export function siteOf(hostname: string): string | null {
  const host = hostname.toLowerCase().replace(/\.$/, "")
  if (!host) return null
  if (IPV4.test(host) || host.startsWith("[") || !host.includes(".")) return host
  return getDomain(host, { allowPrivateDomains: true }) ?? null
}

/** A subframe gets logins only when it's on the same site as the top page. */
export function sameSite(frame: URL, top: URL): boolean {
  const site = siteOf(frame.hostname)
  return site !== null && site === siteOf(top.hostname)
}

/**
 * Whether a login field in a frame may open the inline menu: `chain` is the
 * frame, then each frame above it, ending with the top page. Every one has
 * to be on the frame's site and https (http only on local development hosts,
 * see fillableOrigin): a cross-site page anywhere on the way could place,
 * size and cover the frame to steer the user's pick (docs/autofill.md,
 * Frames).
 */
export function sameSiteChain(chain: URL[]): boolean {
  if (chain.length < 2) return false
  const site = siteOf(chain[0].hostname)
  return site !== null && chain.every((url) => fillableOrigin(url) && siteOf(url.hostname) === site)
}

const MAX_TITLE = 128
const MAX_URL_BYTES = 2048

/**
 * A new login's name: the page title with runs of spaces and control
 * characters made one space, trimmed and capped at 128 characters, as the
 * agent wants it. Without one, the site.
 */
export function saveTitle(raw: unknown, site: string): string {
  const clean = typeof raw === "string" ? raw.replace(/[\s\p{Cc}]+/gu, " ").trim() : ""
  const title = Array.from(clean).slice(0, MAX_TITLE).join("").trim()
  return title || site
}

/** A new login's URL: the sign-in page without its query or fragment, or just the origin. */
export function saveUrl(page: URL): string {
  const url = `${page.origin}${page.pathname}`
  return new TextEncoder().encode(url).length <= MAX_URL_BYTES ? url : page.origin
}
