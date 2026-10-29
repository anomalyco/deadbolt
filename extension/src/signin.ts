// "Sign in with Google" and the like: the providers Deadbolt knows by id
// (crates/client `sign_in_provider`), their names, the hosts their own
// sign-in pages are on, and the words a site's button for them uses. A
// provider Deadbolt doesn't know is its own name, with no hosts.

declare const DEADBOLT_E2E: boolean | undefined


export interface Provider {
  id: string
  name: string
  /** Hosts of the provider's own sign-in pages: the menu there narrows to the linked login. */
  hosts: string[]
  /**
   * The provider's account chooser has a reliable pattern (tiles carrying the
   * account in an attribute), on hosts that are only its own sign-in pages:
   * only then is the linked account sent to its page, to ring the tile.
   */
  chooser: boolean
  /**
   * The account the provider's own password step shows (its account chip,
   * or the hidden username its form carries) may narrow the menu there, on
   * hosts that are only its own sign-in pages (see isAccountPage).
   */
  pageAccount?: boolean
  /** How a site's button names it, lowercased. */
  words: string[]
}

const KNOWN: Record<string, Omit<Provider, "id">> = {
  google: { name: "Google", hosts: ["accounts.google.com"], words: ["google"], chooser: true, pageAccount: true },
  apple: { name: "Apple", hosts: ["appleid.apple.com"], words: ["apple", "apple id"], chooser: false },
  github: { name: "GitHub", hosts: ["github.com"], words: ["github"], chooser: false },
  microsoft: { name: "Microsoft", hosts: ["login.microsoftonline.com", "login.live.com"], words: ["microsoft", "outlook"], chooser: false },
  facebook: { name: "Facebook", hosts: ["www.facebook.com", "m.facebook.com"], words: ["facebook"], chooser: false },
  x: { name: "X", hosts: ["x.com", "twitter.com", "api.twitter.com"], words: ["x", "twitter"], chooser: false },
  amazon: { name: "Amazon", hosts: ["www.amazon.com"], words: ["amazon"], chooser: false },
  discord: { name: "Discord", hosts: ["discord.com"], words: ["discord"], chooser: false },
  slack: { name: "Slack", hosts: ["slack.com"], words: ["slack"], chooser: false },
  okta: { name: "Okta", hosts: [], words: ["okta"], chooser: false },
  linkedin: { name: "LinkedIn", hosts: ["www.linkedin.com"], words: ["linkedin"], chooser: false },
  gitlab: { name: "GitLab", hosts: ["gitlab.com"], words: ["gitlab"], chooser: false },
}

export function provider(id: string): Provider {
  const known = KNOWN[id.toLowerCase()]
  return known ? { id: id.toLowerCase(), ...known } : { id, name: id, hosts: [], words: [id.toLowerCase()], chooser: false }
}

/**
 * Whether `url` is one of the provider's own sign-in pages: on one of its
 * hosts, over https. An e2e build also takes a `.test` host for the same
 * `.com` one, over http (e2e/run.ts maps them to its own server).
 */
export function isProviderPage(p: Provider, url: string): boolean {
  let u: URL
  try {
    u = new URL(url)
  } catch {
    return false
  }
  const host = u.hostname.toLowerCase()
  if (u.protocol === "https:" && p.hosts.includes(host)) return true
  // DEADBOLT_E2E is true only in an e2e build (scripts/build.ts --e2e); every
  // other build defines it false, and this branch drops out of its code.
  if (typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true)
    return (u.protocol === "https:" || u.protocol === "http:") && host.endsWith(".test") && p.hosts.includes(`${host.slice(0, -5)}.com`)
  return false
}

/** Whether the linked account may be sent to `url` to ring its tile: the provider's own page, with a reliable chooser. */
export const isChooserPage = (p: Provider, url: string) => p.chooser && isProviderPage(p, url)

/**
 * Whether `url` is the sign-in page of a provider whose page-set account may
 * narrow the menu (Provider.pageAccount): one of its exact hosts, over https.
 * Anywhere else, a username the page put there itself is ignored.
 */
export const isAccountPage = (url: string) => Object.entries(KNOWN).some(([id, p]) => p.pageAccount === true && isProviderPage(provider(id), url))

/** The account a provider's page names, if it looks like one: an email address or a plain username, at most 500 characters. */
export function pageAccountOf(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length > 500) return undefined
  const v = raw.trim()
  return /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(v) || /^[\w.+-]{1,64}$/.test(v) ? v : undefined
}
