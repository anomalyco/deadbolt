// Small DOM helpers for the extension's own pages. h and svg are ported from
// Foyer (github.com/R44VC0RP/foyer, src/ui.ts, by Ryan Vogel).

type Child = Node | string | null | undefined | false

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, string>> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) if (v !== undefined) el.setAttribute(k, v)
  for (const c of children) if (c) el.append(c)
  return el
}

/** Static, trusted SVG markup (never built from page or vault data). */
export function svg(markup: string): Element {
  const t = document.createElement("template")
  t.innerHTML = markup.trim()
  return t.content.firstElementChild!
}

export const ICONS = {
  /** The app icon: the site's keyhole, red on black (crates/app/scripts/icon.swift). */
  deadbolt: `<svg viewBox="0 0 1024 1024" aria-hidden="true"><rect x="60" y="60" width="904" height="904" rx="200" fill="#090909"/><circle cx="512" cy="382" r="160" fill="#f02e29"/><path d="M451 490h122l59 290H392Z" fill="#f02e29"/></svg>`,
  keyhole: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8.6" r="4.1" fill="currentColor"/><path d="M10.4 11.4h3.2l1.5 7.5H8.9Z" fill="currentColor"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><rect x="5" y="10.5" width="14" height="9.5" rx="2.2"/><path d="M8.2 10.5V8a3.8 3.8 0 0 1 7.6 0v2.5"/></svg>`,
  plug: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 3v4M15 3v4M6.5 7h11v3.5a5.5 5.5 0 0 1-11 0Z"/><path d="M12 16v5"/></svg>`,
  copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8.5" y="8.5" width="11" height="11" rx="2.2"/><path d="M15.5 8.5V6.7a2.2 2.2 0 0 0-2.2-2.2H6.7a2.2 2.2 0 0 0-2.2 2.2v6.6a2.2 2.2 0 0 0 2.2 2.2h1.8"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>`,
  clock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 7.5V12l3 2"/></svg>`,
  arrow: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 17 17 7M9 7h8v8"/></svg>`,
  passkey: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="8" r="3.6"/><path d="M3.5 19.5v-1.2A4.8 4.8 0 0 1 8.3 13.5h1.9"/><circle cx="16.5" cy="13.5" r="2.3"/><path d="M16.5 15.8v4.7l1.3-1.2M16.5 18.2l1.3 1"/></svg>`,
  key: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15.5" r="3.8"/><path d="m10.7 12.8 8.3-8.3M15.8 7.7l2.6 2.6M13.6 9.9l1.9 1.9"/></svg>`,
  card: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="6" width="17" height="12" rx="2.2"/><path d="M3.5 10h17M7 14.5h3"/></svg>`,
  close: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17"/></svg>`,
} as const

export const icon = (name: keyof typeof ICONS) => svg(ICONS[name])

/** A hue for `text`, the same every time, so a login keeps its colour. */
export function hueOf(text: string): number {
  let hash = 0
  for (const c of text.toLowerCase()) hash = (hash * 31 + c.codePointAt(0)!) >>> 0
  return hash % 360
}

/**
 * A login's avatar: the first letter of its title on a soft tint of its own
 * hue. With `glyph` (a passkey, a lock), the glyph on a neutral tint.
 */
export function avatar(title: string, glyph?: Element): HTMLElement {
  if (glyph) return h("span", { class: "avatar neutral", "aria-hidden": "true" }, glyph)
  const letter = [...(title.trim() || "?")][0].toUpperCase()
  return h("span", { class: "avatar", style: `--hue:${hueOf(title.trim() || "?")}`, "aria-hidden": "true" }, letter)
}

/** The letter avatar for a login (see avatar). */
export const monogram = (title: string) => avatar(title)

/**
 * Whether the menu had been fully visible, and still, for long enough before
 * a press. A fresh reading after the press isn't enough on its own: a page
 * can keep the menu see-through over a decoy and show it the moment the
 * press lands. Every visibility reading (the observer reports only changes)
 * and every move starts the wait again.
 */
export class Dwell {
  private since: number | null = null
  private movedAt = -Infinity
  private changes = 0

  constructor(readonly ms = 500) {}

  /** An observer reading taken at `at` (a performance.now() time). */
  seen(visible: boolean, at: number) {
    this.since = visible ? Math.max(at, this.movedAt) : null
    this.changes++
  }

  /** The menu's frame moved or changed size at `at`. */
  moved(at: number) {
    this.movedAt = Math.max(this.movedAt, at)
    if (this.since !== null) this.since = Math.max(this.since, at)
    this.changes++
  }

  get visible(): boolean {
    return this.since !== null
  }

  /** Bumped by every reading and move, to tell that nothing changed across an await. */
  get version(): number {
    return this.changes
  }

  /** Visible and still from at least `ms` before `at` until now. */
  settled(at: number): boolean {
    return this.since !== null && at - this.since >= this.ms
  }
}

/**
 * Whether the keyboard may pick in this menu. A page can focus the menu's
 * frame from script and catch the user's next Enter, so focus counts only
 * when Deadbolt put it there: the content script's handler for the user's own
 * ↓ in the field says so (`offered`) over a channel only it holds, just as it
 * moves focus in. A real press inside the menu counts too, but only once it
 * has passed the same checks a pick by pointer does (`pressed`, then
 * `confirmed`): a press the menu refused, or any press still being checked,
 * lets nothing through. Losing focus ends it, as does a newer press; getting
 * focus back any other way doesn't restore it.
 */
export class Entry {
  private offeredAt = -Infinity
  private granted = false
  private press = 0

  constructor(readonly windowMs = 1000) {}

  /** The content script is moving focus in for the user's ↓. `hasFocus`: it already arrived. */
  offered(now: number, hasFocus: boolean) {
    if (hasFocus) this.granted = true
    else this.offeredAt = now
  }

  /** This frame got focus at `now`. */
  focused(now: number) {
    if (now - this.offeredAt <= this.windowMs) this.granted = true
  }

  /** A trusted pointer press inside the menu, to be checked: what `confirmed` takes. */
  pressed(): number {
    this.granted = false
    return ++this.press
  }

  /** The press passed the checks, and it's still the latest one with focus held since. */
  confirmed(press: number) {
    if (press === this.press) this.granted = true
  }

  blurred() {
    this.granted = false
    this.offeredAt = -Infinity
    this.press++
  }

  get entered(): boolean {
    return this.granted
  }
}

/** How long after a press the menu waits before it trusts what it sees: see confirmPick. */
export const CONFIRM_AFTER_MS = 400

/**
 * Whether a press at `pressedAt` may pick: the menu had been fully visible
 * and still for the dwell before it, and stays so until a fresh reading taken
 * at least CONFIRM_AFTER_MS after it. A frame learns how the page around it
 * shows it only some time after the page changes it, so a reading taken right
 * at the press can predate a page that hid the menu as the press began.
 */
export async function confirmPick(
  dwell: Dwell,
  pressedAt: number,
  { now = () => performance.now(), sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms)), fresh = () => visibleNow() } = {},
): Promise<boolean> {
  if (!dwell.settled(pressedAt)) return false
  const version = dwell.version
  const wait = pressedAt + CONFIRM_AFTER_MS - now()
  if (wait > 0) await sleep(wait)
  // Any reading or move since, even one taken before the press, means no.
  return (await fresh()) && dwell.version === version
}

/** Feeds `dwell` Intersection Observer v2 readings of this page for as long as it's open. Without v2, it never settles. */
export function watchVisibility(dwell: Dwell) {
  try {
    new IntersectionObserver(
      (entries) => {
        for (const e of entries) dwell.seen(fullyVisible(e), e.time)
      },
      { threshold: [0, 0.5, 0.9, 1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
    ).observe(document.body)
  } catch {}
}

// Sub-pixel heights mean a strict 100% can be unreachable.
const fullyVisible = (e: IntersectionObserverEntry) => (e as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true && e.intersectionRatio >= 0.9
/**
 * Unobscured (not faded, transformed or covered), though maybe only partly on
 * screen: for a frame element taller than the viewport, whose fields'
 * boxes are cut to what shows separately (see placeBoxes).
 */
const partlyVisible = (e: IntersectionObserverEntry) => (e as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true && e.intersectionRatio > 0

/**
 * Whether `target` is fully on screen and unobscured, through every frame
 * above it: not faded, clipped, transformed or covered, even by something
 * that lets clicks through. With `partly`, on screen at all is enough. One fresh Intersection Observer v2 reading; fails
 * closed: no v2 visibility, an error or no answer means no. Adapted from
 * Foyer's menu and dialog.
 */
export function visibleNow(timeoutMs = 1000, target: Element = document.body, partly = false): Promise<boolean> {
  return new Promise((resolve) => {
    let observer: IntersectionObserver | undefined
    const finish = (visible: boolean) => {
      observer?.disconnect()
      clearTimeout(timer)
      resolve(visible)
    }
    const timer = setTimeout(() => finish(false), timeoutMs)
    try {
      observer = new IntersectionObserver(
        (entries) => {
          finish((partly ? partlyVisible : fullyVisible)(entries[entries.length - 1]))
        },
        { threshold: [0, 0.5, 0.9, 1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
      )
      observer.observe(target)
    } catch {
      finish(false)
    }
  })
}

/** Tells the background how tall the page's content is, whenever it changes. */
export function reportHeight(send: (height: number) => void) {
  new ResizeObserver(() => send(Math.ceil(document.body.getBoundingClientRect().height))).observe(document.body)
}
