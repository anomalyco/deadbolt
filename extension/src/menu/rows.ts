// Row formatting, provider marks, and text-matching helpers for the inline menu.

import type { MenuPasskey } from "../messages"
import type { Account, FormCard, FormIdentity } from "../protocol"
import { provider as providerOf } from "../signin"
import { avatar, h } from "../ui/dom"
import { brandBySlug } from "../ui/site-icon"

/** A row: a login to fill, a passkey the page's sign-in is waiting for, a "Sign in with …" login, or a generated password. */
export type Row =
  | { passkey: MenuPasskey }
  | { account: Account }
  | { provider: Account }
  | { generate: true }
  | { identity: FormIdentity }
  | { card: FormCard }
  /** "Unlock Deadbolt": Touch ID when it's ready, else Deadbolt's window (see bg/unlock.ts). */
  | { unlock: { touchId: boolean } }

export const CHEVRON = `<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`

/** "Visa ••4242 · 08/28": the brand (or the card's name), its last digits, and when it expires. */
export function cardLine(card: FormCard): string {
  const expiry = card.expiry ? ` · ${card.expiry.slice(5, 7)}/${card.expiry.slice(2, 4)}` : ""
  return `${card.brand || card.title} ••${card.last4}${expiry}`
}

/**
 * Brand colours of the providers Simple Icons doesn't carry (their owners
 * asked it not to): their initial in that colour. Microsoft's four squares
 * are drawn, being plain geometry.
 */
const UNBUNDLED: Record<string, string> = { amazon: "FF9900", slack: "4A154B", linkedin: "0A66C2", microsoft: "737373" }
const MICROSOFT = [["F25022", 0, 0], ["7FBA00", 13, 0], ["00A4EF", 0, 13], ["FFB900", 13, 13]] as const

/** Near-black (Apple, GitHub, X): drawn in the tile's own ink, so it reads in dark mode too. */
function brandInk(hex: string): string {
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.12 ? "currentColor" : `#${hex}`
}

const SVG_NS = "http://www.w3.org/2000/svg"
function markSvg(paint: (svg: SVGSVGElement) => void, box = "0 0 24 24"): SVGSVGElement {
  const el = document.createElementNS(SVG_NS, "svg")
  el.setAttribute("viewBox", box)
  el.setAttribute("aria-hidden", "true")
  paint(el)
  return el
}

/**
 * A provider's mark, its logo in its brand colour from the bundled Simple
 * Icons subset (no request), whatever the site icons setting: it says who
 * the row signs in with. Its initial until that loads, or for a provider
 * the subset lacks.
 */
export function providerMark(id: string): HTMLElement {
  const p = providerOf(id)
  const el = avatar(p.name)
  el.classList.add("provider")
  const show = (mark: SVGSVGElement) => {
    el.replaceChildren(mark)
    el.classList.add("mark")
  }
  if (p.id === "microsoft")
    show(markSvg((s) => MICROSOFT.forEach(([fill, x, y]) => {
      const r = document.createElementNS(SVG_NS, "rect")
      for (const [k, v] of Object.entries({ x, y, width: 11, height: 11, fill: `#${fill}` })) r.setAttribute(k, String(v))
      s.append(r)
    })))
  else if (UNBUNDLED[p.id]) el.style.color = brandInk(UNBUNDLED[p.id])
  else if (p.hosts.length)
    void brandBySlug(p.id).then((brand) => {
      if (!brand || !/^[0-9a-f]{6}$/i.test(brand[1])) return
      show(markSvg((s) => {
        const path = document.createElementNS(SVG_NS, "path")
        path.setAttribute("d", brand[2])
        path.setAttribute("fill", brandInk(brand[1]))
        s.append(path)
      }))
    })
  return el
}

export function notice(glyph: Element, title: string, sub: string): HTMLElement {
  return h("div", { class: "row notice" }, avatar("", glyph), h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)))
}

export function matches(item: Row, q: string): boolean {
  if (!q) return true
  // A generated password matches nothing typed: typing a password of one's own puts it away.
  if ("generate" in item) return false
  // Unlocking is what the list is for while it's locked, whatever's typed.
  if ("unlock" in item) return true
  const hay =
    "identity" in item
      ? [item.identity.title, item.identity.summary]
      : "card" in item
      ? [item.card.title, item.card.brand ?? "", item.card.cardholder ?? ""]
      : "passkey" in item
      ? [item.passkey.username ?? ""]
      : "provider" in item
        ? [item.provider.title, item.provider.signIn?.account ?? "", providerOf(item.provider.signIn?.provider ?? "").name]
        : [item.account.title, item.account.username ?? ""]
  return hay.some((s) => s.toLowerCase().includes(q))
}

/** What a pick's pill calls it: the login's username, or the item's name. */
export function pillName(a: Row): string {
  if ("identity" in a) return a.identity.title
  if ("card" in a) return cardLine(a.card)
  if ("generate" in a) return "Strong password"
  if ("passkey" in a) return a.passkey.username || "Passkey"
  if ("account" in a) return a.account.username || a.account.title
  return ""
}
