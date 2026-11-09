// Deadbolt's surface in the page: the account list under a login field, the
// pill a pick folds into while it fills, and the save offer after a
// confirmed sign-in. It runs as an extension page inside an iframe on the
// page, so the page can neither read nor click it. The account list is
// ported from Foyer (github.com/R44VC0RP/foyer, src/menu.ts, by Ryan Vogel).
//
// One object: the frame never swaps for another. Its parent (content/inline.ts)
// springs the frame to the size each mode asks for; inside, only the
// surface's clip and radius change, what stays travels, what goes fades, and
// labels roll. Every pick and button waits for the visibility guard and the
// dwell (see ui/dom.ts) before it does anything.

import type { ChooseReply, FieldRole, MenuLoadReply, MenuPasskey, OfferChoice, PickReply, SignInReply, Status, StatusChanged, SurfaceMode, ToBackground } from "./messages"
import { provider as providerOf } from "./signin"
import type { Account, FormCard, FormIdentity } from "./protocol"
import { avatar, confirmPick, Dwell, Entry, h, icon, ICONS, svg, watchVisibility } from "./ui/dom"
import { animateTo, devicePx, inFrame, MENU_MOTION, reducedMotion, REDUCED_FADE, rollLabel, ROLL_CSS, SHRINK_WAITS_MS, spring, Spring, timing, type SpringState } from "./ui/motion"
import { iconKey, onIconSettings, type StoredIcon } from "./ui/icon-store"
import { ring } from "./ui/ring"
import { offerTitle } from "./ui/offer"
import { brandBySlug, siteTile } from "./ui/site-icon"

/** A row: a login to fill, a passkey the page's sign-in is waiting for, a "Sign in with …" login, or a generated password. */
type Row = { passkey: MenuPasskey } | { account: Account } | { provider: Account } | { generate: true } | { identity: FormIdentity } | { card: FormCard }

// Set once the background accepts a token from the parent window.
let token = ""
let parentOrigin = ""
/** The content script's channel: ↓ into the menu one way, "done" the other. */
let port: MessagePort | undefined
const surface = document.getElementById("surface")!
const rowsEl = document.getElementById("rows")!
const highlightEl = document.getElementById("highlight")!
/** A quiet line under the list, only when there's something to say ("Pick again in a moment."). */
const foot = document.getElementById("foot")!
/** The site, small, over a list of two or more. */
const caption = document.getElementById("caption")!
/**
 * What a screen reader says as it happens: "Filled", "Saved", why a pick
 * didn't go ahead. Inside this frame like the rest, so the page hears none of it.
 */
const live = document.getElementById("live")!
let accounts: Row[] = []
/**
 * The logins' site icons, with "Site icons in the fill menu" on (see
 * MenuLoadReply); null with it off, and the logins' rows show only their
 * title and username (every login here is the page's own site's).
 */
let siteIcons: Record<string, StoredIcon | null> | null = null
/** Whether this list's rows go without a tile: a login list with icons off. */
let bare = false
/** A site icon resolving after this long since the list showed just appears: the user may be about to pick. */
const REVEAL_WITHIN_MS = 250
let focused: FieldRole = "username"
/** The site signs in username first and has one login: its row says "Continue as …". */
let continueAs = false
let active = 0
let busy = false
let mode: SurfaceMode = "accounts"
let universal = false
/** The logins whose pick here signs in (MenuLoadReply `signsIn`), not only fills. */
let signsIn = new Set<string>()
let universalExpanded = false
/** When the user last pressed a key or pointer in the menu: what a pick is judged at. */
let pressedAt = -Infinity
const dwell = new Dwell(500)
watchVisibility(dwell)
/** The intended viewport and the parent's post-layout scale verdict, over its private channel. */
let geometry: { width: number; height: number; dpr: number; visible: boolean; version: number } | null = null
let pressedScale = false

// A page's ResizeObserver on a deeper element can change the host after
// its observer ran; the browser defers the shallower observation. Our own
// document is outside that loop. Its physical/CSS ratio changes as Chromium
// syncs the restored layout and the scaled paint, even when IO v2 stays true.
let paintedScale = 0
let paintedPixels = 0
let scaleChangedAt = -Infinity
const readScale: ResizeObserverCallback = (entries) => {
  // Each observer watches only documentElement, so its batch has at most this one entry.
  const e = entries[0]
  const css = e?.contentBoxSize[0]?.inlineSize
  const pixels = e?.devicePixelContentBoxSize[0]?.inlineSize
  if (!css || !pixels) return
  paintedPixels = pixels
  const scale = pixels / css
  // One physical pixel of rounding isn't a change in rendered scale.
  if (paintedScale && Math.abs(scale - paintedScale) > 1 / css) {
    scaleChangedAt = performance.now()
    dwell.moved(scaleChangedAt)
  }
  paintedScale = scale
}
// Separate observers: observing the same target twice on one replaces the
// first box. Compensating zoom with width/height can keep device pixels
// unchanged, but then its CSS size changes instead.
for (const box of ["content-box", "device-pixel-content-box"] as const)
  new ResizeObserver(readScale).observe(document.documentElement, { box })

function scaleMatches(): boolean {
  // innerWidth/Height round to integral CSS px. Never replace the parent's
  // painted verdict with click-time layout, which a page can have restored.
  // The absolute physical width also refuses a steady scaled paint: it
  // doesn't depend on the child seeing the restored/scaled alternation.
  // Two device pixels allow for the measured physical box snapping to pixels.
  // Keep a scale change a "covered" refusal, not an invitation to pick again.
  return !!geometry?.visible && paintedScale > 0 && performance.now() - scaleChangedAt >= dwell.ms &&
    Math.abs(innerWidth - geometry.width) <= 2 && Math.abs(innerHeight - geometry.height) <= 2 &&
    Math.abs(paintedPixels - geometry.width * geometry.dpr) <= 2
}

let placementCheck = 0
const placementChecks = new Map<number, (ok: boolean) => void>()

/** A fresh answer from the parent, without letting it restore layout first. */
function confirmPlacement(version: number): Promise<boolean> {
  if (!port) return Promise.resolve(false)
  const check = ++placementCheck
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish(false), 1000)
    const finish = (ok: boolean) => {
      clearTimeout(timer)
      placementChecks.delete(check)
      resolve(ok)
    }
    placementChecks.set(check, finish)
    port!.postMessage({ type: "db:menu-check", check, version })
  })
}

async function confirmScale(at: number): Promise<boolean> {
  const version = geometry?.version
  if (version === undefined || !pressedScale || !scaleMatches()) return false
  for (const a of surface.getAnimations()) a.cancel()
  if (!(await confirmPick(dwell, at))) return false
  return (await confirmPlacement(version)) && geometry?.version === version && scaleMatches() && dwell.settled(at)
}

/** Whether the keyboard may pick: see Entry. */
const entry = new Entry()
const COVERED = "This menu is covered. Nothing was filled."
/** How long the save offer stays in the page before it leaves the offer to the toolbar. */
const OFFER_STAYS_MS = 12_000
/** After a save that failed once the offer's time was up, it stays this much longer. */
const OFFER_REARM_MS = 6000
/** The dot the offer shrinks to stays this long before leaving the offer to the toolbar. */
const DOT_STAYS_MS = 20_000
/** Reopened from the dot, the pill stays this long. */
const OFFER_REOPENED_MS = 8000
/** The offer's compact pill is this tall; its dot this wide. */
const ROW = 36
const DOT = 28
/** The pointer resting on the pill this long opens it. */
const OPEN_AFTER_MS = 350
/** Leaving the open offer closes it after this grace. */
const COLLAPSE_GRACE_MS = 300
/** Reopened from the dot under the pointer, it waits this long before opening further. */
const REOPEN_SETTLES_MS = 500
/** Pointer events this soon after the frame changed size may be the browser replaying an old position. */
const REPLAY_MS = 150
/** The pill and the dot cross-fade over this long (menu.css). */
const CROSSFADE_MS = 260
/** The pointer moving onto the corner offer's top account this long lists the others: passing over it doesn't. */
const EXPAND_AFTER_MS = 150
/** How long a pill says how it went before it goes. */
const FILLED_STAYS_MS = 900
const FAILED_STAYS_MS = 1800
/** A pill's flash as its fill lands, or fails: up quickly, then cooling. */
const PILL_FLASH_MS = 1100
/** How far the frame's width leads a pill's label roll. */
const WIDTH_LEAD_MS = 80
/** How long narrowing's row animations run: the dwell starts again after. */
const NARROW_SETTLES_MS = 480
/** "Saving…" stays in the Save button at least this long, so it can be read. */
const SAVING_READS_MS = 520

document.head.append(h("style", {}, ROLL_CSS))

declare const DEADBOLT_NATIVE: boolean | undefined
/** A `--native` build unlocks in the Deadbolt app; the default unlocks on device.html. */
const native = typeof DEADBOLT_NATIVE !== "undefined" && DEADBOLT_NATIVE === true

function send<T>(message: ToBackground): Promise<T | null> {
  return chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>
}

/** The surface is done: the content script fades it out (or, `travel`, sends it to the toolbar button). */
const done = (travel = false) => port?.postMessage({ type: "db:surface-done", travel })
/**
 * The save offer leaves the way a saved login does, toward the toolbar
 * button, whether it was saved, put away, turned off or timed out: the page
 * sees the same exit. (A save folds into its pill first; see the threat model.)
 */
const leaveLikeSave = () => done(true)

// ---- Size --------------------------------------------------------------------

let reported = ""
let ready = false
/** Tells the parent the size this mode needs, whenever it changes. */
function report(grow = 0) {
  if (!token || !ready) return
  const height = Math.ceil(mode === "pill" ? 32 : mode === "save" ? offerSize().height : surface.offsetHeight || surface.getBoundingClientRect().height)
  const pill = document.querySelector<HTMLElement>(".pill")
  // The pill hugs its content: it is the whole pill, padding included.
  const offer = mode === "save" ? offerSize() : null
  const width = mode === "pill" && pill ? Math.ceil(pill.getBoundingClientRect().width + grow) : offer ? offer.width : universal ? 320 : undefined
  const key = `${mode}:${height}:${width}`
  if (key === reported) return
  reported = key
  void send({ type: "db:menu-resize", token, height, ...(width ? { width } : {}), ...(mode === "pill" ? { mode } : {}) })
}
// A pill's size is said once per change (fold, settle), from where it will
// end up: the frame resizing around it mustn't report it mid-animation and
// pull the frame back.
new ResizeObserver(() => mode !== "pill" && report()).observe(surface)

// ---- The account list ----------------------------------------------------------

/** "Visa ••4242 · 08/28": the brand (or the card's name), its last digits, and when it expires. */
export function cardLine(card: FormCard): string {
  const expiry = card.expiry ? ` · ${card.expiry.slice(5, 7)}/${card.expiry.slice(2, 4)}` : ""
  return `${card.brand || card.title} ••${card.last4}${expiry}`
}

function row(item: Row, i: number): HTMLElement {
  const [tile, title, sub] =
    "identity" in item
      ? [avatar(item.identity.title), item.identity.title, [fills[item.identity.ref]?.length ? `Fills ${fills[item.identity.ref].join(", ")}` : "", item.identity.summary].filter(Boolean).join(" · ") || "Fill this address"]
      : "card" in item
      ? [avatar(item.card.brand || item.card.title, icon("card")), cardLine(item.card), item.card.brand && item.card.title !== item.card.brand ? item.card.title : item.card.cardholder || item.card.title]
      : "generate" in item
      ? [avatar("", icon("key")), "Use a strong password", "Saved only if you sign up with it"]
      : "passkey" in item
      ? [avatar("", icon("passkey")), item.passkey.username || "Passkey", `Passkey · ${item.passkey.vault}`]
      : "provider" in item
        ? // "Sign in with Google · kit@gmail.com": the provider's mark and name, then the account it uses.
          [providerMark(item.provider.signIn!.provider), `Sign in with ${providerOf(item.provider.signIn!.provider).name}`, item.provider.signIn!.account || item.provider.title]
        : universal
        ? [loginTile(item.account, i), `Sign in${item.account.username ? ` as ${item.account.username}` : ` to ${item.account.title}`}`, "Fills and submits this sign-in"]
        : continueAs && item.account.username
        ? [loginTile(item.account, i), `Continue as ${item.account.username}`, item.account.title]
        : [loginTile(item.account, i), item.account.title, focused === "otp" ? "Fill the current code" : item.account.username || "No username"]
  const r = h(
    "button",
    // Rows aren't tab stops: the list is, and says which row is active (see listbox).
    { class: `row${i === active ? " active" : ""}`, type: "button", role: "option", id: `row-${i}`, tabindex: "-1", "aria-selected": String(i === active) },
    // A provider's mark shows even in a bare list: it says who the row signs in with.
    bare && !("provider" in item) ? null : tile,
    h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)),
  )
  // A pointer's click only: Enter or Space on a focused row clicks it too (detail 0).
  r.addEventListener("click", (e) => e.isTrusted && e.detail > 0 && void pick(i))
  // The press shows at once, inside the frame (which doesn't move, so the
  // dwell isn't disturbed); the pick itself waits for its checks.
  r.addEventListener("pointerdown", (e) => {
    if (!e.isTrusted || e.button !== 0 || busy || mode !== "accounts") return
    active = i
    highlight()
    press(r)
  })
  r.addEventListener("pointermove", () => {
    if (active === i && !highlightEl.hidden) return
    active = i
    // The pointer is the user's own hand: the highlight lands under it at once.
    highlight()
  })
  return r
}

/** When the list last showed, and which sites' icons may still reveal in it (see revealable). */
let listedAt = 0
let revealable = new Set<string>()

/**
 * A login's tile with its site's icon (see ui/site-icon.ts). The icon
 * dithers in only the first time this browser session a menu shows it, and
 * only if it's ready within moments of the list showing; it never moves
 * anything, and a press stops it at once: nothing in the frame may animate
 * while a press is checked (see press).
 */
function loginTile(account: Account, i: number): HTMLElement {
  const url = account.urls.find(Boolean) ?? ""
  let key = ""
  try {
    key = url ? iconKey(new URL(url.includes("://") ? url : `https://${url}`).hostname) : ""
  } catch {}
  const reveal = revealable.has(key)
  return siteTile(account.title, url, {
    reveal,
    once: key,
    delay: Math.min(i, 6) * 30,
    stored: siteIcons?.[key] ?? null,
    revealBy: listedAt + REVEAL_WITHIN_MS,
    stop: () => document.body.classList.contains("held") || busy,
  })
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
function providerMark(id: string): HTMLElement {
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

function notice(glyph: Element, title: string, sub: string): HTMLElement {
  return h("div", { class: "row notice" }, avatar("", glyph), h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)))
}

/**
 * The browser-only Deadbolt unlocks on its own page (device.html), never in
 * the page or this frame: the row opens that page in a new tab. Like a pick,
 * it waits for the menu to have been visible and still (see pick).
 */
function unlockRow(): HTMLElement {
  const r = h(
    "button",
    { class: "row", type: "button" },
    avatar("", icon("lock")),
    h("span", { class: "text" }, h("span", { class: "title" }, "Unlock Deadbolt"), h("span", { class: "sub" }, "Opens Deadbolt in a new tab")),
  )
  // A pointer's click; Enter goes through the keydown handler, which checks Entry first.
  r.addEventListener("click", (e) => e.isTrusted && e.detail > 0 && void unlock())
  return r
}

/** The unlock row, pressed: it waits for the menu to have been visible and still, as a pick does. */
async function unlock() {
  if (busy) return
  if (!pressedScale || !dwell.settled(pressedAt)) return say(pressedScale && dwell.visible ? "Click again in a moment." : "This menu is covered.")
  busy = true
  try {
    if (!(await confirmScale(pressedAt))) return say("This menu is covered.")
    await send<boolean>({ type: "db:menu-unlock", token })
  } finally {
    busy = false
  }
}

/** Says `text` to a screen reader, once, politely. */
function announce(text: string) {
  live.textContent = ""
  if (text) setTimeout(() => (live.textContent = text), 50)
}

/**
 * The rows as a listbox named `label` (null: not a list, a notice or the
 * unlock row). The list itself takes focus, so Tab lands on it, and points
 * at the active row (aria-activedescendant), as the highlight shows it.
 */
function listbox(label: string | null) {
  if (label) {
    rowsEl.setAttribute("role", "listbox")
    rowsEl.setAttribute("aria-label", label)
    rowsEl.tabIndex = 0
  } else {
    for (const a of ["role", "aria-label", "aria-activedescendant", "tabindex"]) rowsEl.removeAttribute(a)
  }
}

/** Says something under the list, or (empty) nothing at all. */
function say(text: string) {
  foot.textContent = text
  foot.hidden = !text
  announce(text)
}

function setCaption(site: string) {
  caption.textContent = site
  caption.hidden = !site
}

/**
 * The one highlight. A key or the pointer puts it on the active row at once,
 * in the same frame as the row's own colour; as the list narrows it rides on
 * its row, on the rows' spring, retargeting mid-flight.
 */
const hl = { y: new Spring(0), height: new Spring(0), raf: 0, shown: false }

function stepHighlight() {
  highlightEl.style.transform = `translateY(${hl.y.value}px)`
  highlightEl.style.height = `${hl.height.value}px`
  hl.raf = hl.y.done && hl.height.done ? 0 : requestAnimationFrame(stepHighlight)
}

/** Puts the highlight on the active row: at once, or riding along as rows reflow with `slide`. */
function highlight(slide = false) {
  const rows = Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row"))
  rows.forEach((el, i) => {
    el.classList.toggle("active", i === active)
    el.setAttribute("aria-selected", String(i === active))
  })
  const el = rows[active]
  highlightEl.hidden = !el
  if (el && rowsEl.getAttribute("role") === "listbox") rowsEl.setAttribute("aria-activedescendant", el.id)
  else rowsEl.removeAttribute("aria-activedescendant")
  if (!el) return
  // Layout positions, not what's on screen: rows may be sliding.
  const y = rowsEl.offsetTop + el.offsetTop
  const height = el.offsetHeight
  if (slide && hl.shown) {
    hl.y.to(y, MENU_MOTION.reflow)
    hl.height.to(height, MENU_MOTION.reflow)
    if (!hl.raf) hl.raf = requestAnimationFrame(stepHighlight)
  } else {
    hl.y.jump(y)
    hl.height.jump(height)
    cancelAnimationFrame(hl.raf)
    stepHighlight()
  }
  hl.shown = true
  el.scrollIntoView({ block: "nearest" })
}

/** The row (or button) being pressed: a darker highlight, until the pick goes ahead or doesn't. */
function press(el: HTMLElement) {
  relax()
  // Nothing in the frame animates while the press is checked: running
  // animations pause the visibility readings the check relies on.
  for (const a of surface.getAnimations()) a.cancel()
  document.body.classList.add("held")
  el.classList.add("pressed")
  if (el.classList.contains("row")) highlightEl.classList.add("pressing")
}

function relax() {
  document.body.classList.remove("held")
  highlightEl.classList.remove("pressing")
  for (const el of Array.from(document.querySelectorAll(".pressed"))) el.classList.remove("pressed")
}

// A press that didn't become a click (dragged off, or refused) lets go.
addEventListener("pointerup", () => requestAnimationFrame(() => !busy && relax()), true)
addEventListener("pointercancel", () => !busy && relax(), true)

// ---- Narrowing as the user types ----------------------------------------------------

/** What the user has typed in the field, lowercased; the list shows the rows it matches. */
let query = ""

function matches(item: Row, q: string): boolean {
  if (!q) return true
  // A generated password matches nothing typed: typing a password of one's own puts it away.
  if ("generate" in item) return false
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

const visible = () => accounts.flatMap((a, i) => (matches(a, query) ? [i] : []))

/**
 * Narrows the list to the rows that match `text`, typed in the field below
 * (it comes from the content script over the private channel and goes no
 * further). Rows that stop matching fade where they are while their
 * neighbours slide into the gap; rows that match again come back. The
 * frame's height follows (see report), and the content script hears how
 * many still match: none puts the menu away.
 */
function narrow(text: string) {
  query = text.trim().toLowerCase().slice(0, 200)
  if (mode !== "accounts" || !accounts.length) return
  const rows = Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row"))
  const shown = (r: HTMLElement) => !r.hidden && !r.classList.contains("leaving")
  const before = new Map(rows.filter(shown).map((r) => [r, r.getBoundingClientRect().top]))
  const reduced = reducedMotion()
  rows.forEach((r, i) => {
    const want = matches(accounts[i], query)
    if (shown(r) && !want) {
      // Out of the flow at once, so the rest slide up, while it fades where it was.
      const top = r.offsetTop
      r.classList.add("leaving")
      r.style.cssText = `position:absolute;top:${top}px;left:0;right:0;pointer-events:none`
      const finish = () => {
        if (!r.classList.contains("leaving")) return
        r.classList.remove("leaving")
        r.hidden = true
        r.style.cssText = ""
      }
      const anim = animateTo(r, reduced ? { opacity: "0" } : { opacity: "0", filter: "blur(3px)", transform: "scale(0.96)" }, MENU_MOTION.rowOut, { fill: false })
      if (anim) anim.finished.then(finish, finish)
      else finish()
    } else if (!shown(r) && want) {
      for (const a of r.getAnimations()) a.cancel()
      r.classList.remove("leaving")
      r.hidden = false
      r.style.cssText = ""
      if (typeof r.animate === "function")
        r.animate(reduced ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, filter: "blur(3px)", transform: "scale(0.96)" }, { opacity: 1, filter: "blur(0px)", transform: "none" }], timing(MENU_MOTION.rowIn))
    }
  })
  const slid = new Map<HTMLElement, number>()
  if (!reduced)
    for (const [r, top] of before) {
      if (!shown(r)) continue
      const dy = top - r.getBoundingClientRect().top
      if (Math.abs(dy) > 0.5) r.animate([{ transform: `translateY(${dy}px)` }, { transform: "none" }], spring(MENU_MOTION.reflow))
      slid.set(r, dy)
    }
  const left = visible()
  const was = active
  if (left.length && !left.includes(active)) active = left[0]
  // The highlight stays on its row: a row it moves to (its own went) it
  // takes from where that row is on screen, then rides along with it.
  const to = rows[active]
  if (left.length && active !== was && to) {
    const dy = slid.get(to)
    if (dy !== undefined) hl.y.jump(rowsEl.offsetTop + to.offsetTop + dy)
    hl.height.jump(to.offsetHeight)
    highlight(dy !== undefined)
  } else if (left.length) highlight(true)
  else highlightEl.hidden = true
  // The rows' own animations pause the frame's visibility readings, so the
  // dwell counts from when they're over, as if the menu had moved.
  dwell.moved(performance.now())
  setTimeout(() => dwell.moved(performance.now()), NARROW_SETTLES_MS)
  port?.postMessage({ type: "db:matches", count: left.length })
}

function showStatus(status: Status) {
  accounts = []
  listbox(null)
  highlightEl.hidden = true
  if (status.state === "locked" && !native) {
    rowsEl.replaceChildren(unlockRow())
    say("")
  } else if (status.state === "locked") {
    rowsEl.replaceChildren(notice(icon("lock"), "Deadbolt is locked", "Unlock it in the app, then come back"))
    say("")
  } else {
    rowsEl.replaceChildren(notice(icon("plug"), "Deadbolt isn't available", "Open the toolbar button to see why"))
    say("")
  }
  setCaption("")
}

/**
 * A pick counts only if the menu had been fully visible and still for half a
 * second when the key or pointer went down, and stays so for a moment after
 * (see confirmPick). Mouse and keyboard alike. Enter counts only once the
 * user entered the menu themselves (see Entry). Only then does the list fold
 * into a pill on the field: moving the frame before that would itself break
 * the check.
 */
async function pick(i: number) {
  const a = accounts[i]
  if (!a || busy || mode !== "accounts" || !matches(a, query)) return
  if (!pressedScale || !dwell.settled(pressedAt)) {
    relax()
    return say(pressedScale && dwell.visible ? "Pick again in a moment." : COVERED)
  }
  busy = true
  if (!(await confirmScale(pressedAt))) {
    busy = false
    relax()
    return say(COVERED)
  }
  // "Sign in with …" fills nothing: the page's own button for it gets a ring, and the user clicks it.
  if ("provider" in a) return signInWith(i, a.provider)
  // Checked: now it may move. A ring turns round the avatar while the fill is on its way.
  document.body.classList.remove("held")
  highlightEl.classList.remove("pressing")
  const passkey = "passkey" in a
  const signing = passkey || universal || ("account" in a && signsIn.has(a.account.ref))
  // A row without a tile (no site icons) gets a bare one in the pill, for the ring to turn round.
  const tile = rowsEl.querySelectorAll<HTMLElement>("button.row")[i]?.querySelector<HTMLElement>(".avatar") ?? h("span", { class: "avatar bare", "aria-hidden": "true" })
  // The pill names what was picked and keeps that name: the ring says how it's going.
  const name = pillName(a)
  const label = fold(tile, name)
  const turning = ring(tile)
  announce(signing ? "Signing in…" : "Filling…")
  const ref = "identity" in a ? a.identity.ref : "card" in a ? a.card.ref : passkey ? a.passkey.ref : "account" in a ? a.account.ref : ""
  const reply = await send<PickReply>("generate" in a ? { type: "db:menu-generate", token } : { type: "db:menu-pick", token, ref })
  busy = false
  if (reply?.ok) {
    // A passkey's sign-in closes the surface from the background once it's through.
    if (passkey) return
    const going = universal || reply.submitted === true
    const pill = label.parentElement
    turning.close(() => {
      if (!pill) return
      land(true)
      // The check opens as the ring closes, the frame widening for it first.
      settle(label, name, true)
    })
    relax()
    announce(going ? "Continuing sign-in" : "Filled")
    return void setTimeout(() => (label.parentElement ? toCircle(label.parentElement) : done()), FILLED_STAYS_MS + 450)
  }
  // The corner offer gone under the pick (its page no longer qualifies): it leaves without a word.
  if (universal && !reply?.message) return done()
  const message = reply?.message || "Couldn't fill. Try again."
  say(message)
  announce(`Couldn't fill. ${message}`)
  label.title = message
  turning.stop(() => land(false))
  settle(label, "Couldn't fill", false)
  setTimeout(() => done(), FAILED_STAYS_MS)
}

/** The pill's own answer as its ring closes, or goes: its whole ground flashes green, or red, and cools. */
function land(ok: boolean) {
  // A tinted layer under the pill's content, up fast, then cooling slowly: a light, not a fade.
  const glow = h("span", { class: `pill-glow${ok ? "" : " failed"}`, "aria-hidden": "true" })
  surface.append(glow)
  glow
    .animate([{ opacity: 0, easing: "ease-out" }, { opacity: 1, offset: 0.15, easing: "cubic-bezier(.2,.7,.3,1)" }, { opacity: 0 }], PILL_FLASH_MS)
    .finished.then(() => glow.remove(), () => glow.remove())
}

/**
 * A filled pill going: its words fade where they are and its green goes,
 * then the frame shrinks into the circle at its right end, the pill
 * narrowing with it frame by frame so the tile rides its left edge there
 * (placePill), and the circle fades as it arrives.
 */
function toCircle(pill: HTMLElement) {
  if (reducedMotion()) return done()
  for (const el of pill.querySelectorAll<HTMLElement>(".pill-label, .pill-mark"))
    el.animate([{ opacity: 1, filter: "blur(0px)" }, { opacity: 0, filter: "blur(2px)" }], { duration: 160, easing: "ease-out", fill: "forwards" })
  const tile = pill.querySelector<HTMLElement>(".avatar, .offer-mark")
  if (tile) tile.style.flexShrink = "0"
  const shrink = spring(MENU_MOTION.frameSize).duration
  setTimeout(() => {
    if (!pill.isConnected) return
    closingUp = pill
    // The ring goes back to its plain track, the rim's light out.
    for (const el of pill.querySelectorAll<HTMLElement>(".ring-comet, .pill-glow"))
      el.animate([{ opacity: getComputedStyle(el).opacity }, { opacity: 0 }], { duration: shrink * 0.5, easing: "ease-out", fill: "forwards" })
    report(PILL_HEIGHT - pill.getBoundingClientRect().width)
    pill.style.boxSizing = "border-box"
    pill.style.overflow = "clip"
    whenWide(PILL_HEIGHT, placePill)
    // It starts to fade while it's still closing.
    setTimeout(() => done(), shrink * 0.55)
  }, 120)
}

/** What a pick's pill calls it: the login's username, or the item's name. */
function pillName(a: (typeof accounts)[number]): string {
  if ("identity" in a) return a.identity.title
  if ("card" in a) return cardLine(a.card)
  if ("generate" in a) return "Strong password"
  if ("passkey" in a) return a.passkey.username || "Passkey"
  if ("account" in a) return a.account.username || a.account.title
  return ""
}

/**
 * A "Sign in with …" row picked: the page's content script rings the site's
 * own button for the provider and the menu goes; with no such button, the
 * row says what to look for, and the menu stays.
 */
async function signInWith(i: number, account: Account) {
  const reply = await send<SignInReply>({ type: "db:menu-signin", token, ref: account.ref })
  busy = false
  relax()
  if (!reply?.ok) return say(reply?.message || "Couldn't do that. Try again.")
  if (reply.found) return
  const name = providerOf(reply.provider).name
  const sub = rowsEl.querySelectorAll<HTMLElement>("button.row")[i]?.querySelector<HTMLElement>(".sub")
  if (sub) sub.textContent = `Look for “Continue with ${name}”`
  say(`Deadbolt couldn't find the page's ${name} button.`)
}

// ---- Folding into a pill ---------------------------------------------------------

/**
 * The host's springs as the content script last handed them over (see
 * db:fold): how far the frame still is from the pill's place on the page.
 * The pill is laid out at that place from the first frame and stays there
 * while the frame contracts onto it, so it never rides along with the frame.
 */
type Edge = "left" | "top" | "width" | "height"
const host = { springs: null as Record<Edge, Spring> | null, width: 0, raf: 0, waiters: [] as Array<{ width: number | null; go: () => void }> }

/**
 * What the fold moves on the host's springs, so it keeps one clock with the
 * frame. What fades stays where it was across the page while the frame closes
 * over it, riding only its rise; what travels into the pill
 * goes the same share of its way as the frame has, so the frame's edge never
 * passes it; and the label fades in once the frame's edges are clear of it.
 */
const folding = {
  fading: [] as HTMLElement[],
  travellers: [] as Array<{ el: HTMLElement; dx: number; dy: number; scale: number }>,
  label: null as HTMLElement | null,
  /** The frame's offsets when what fades was last pinned, and how far it had been moved back by then (across: up, it rides the frame). */
  pin: null as { left: number; x: number } | null,
  /** The frame's longest way still to go when the travel last began. */
  edge: "left" as Edge,
  from: 0,
}

/** How much of the way the frame has come since the travel last began, 0 to 1. */
function foldProgress(s: Record<Edge, Spring>): number {
  if (Math.abs(folding.from) < 1) return 1
  return Math.min(1, Math.max(0, 1 - s[folding.edge].value / folding.from))
}

function stepFold(s: Record<Edge, Spring>, moving: boolean) {
  const pin = folding.pin
  if (pin) {
    // Across, it stays put (riding the frame's left edge would slide it sideways);
    // up, it rides the frame's top as it goes.
    const x = pin.x + pin.left - s.left.value
    for (const el of folding.fading) el.style.translate = `${x}px 0`
  }
  const rest = moving ? 1 - foldProgress(s) : 0
  for (const t of folding.travellers) t.el.style.transform = rest > 0 ? `translate(${t.dx * rest}px, ${t.dy * rest}px) scale(${1 + (t.scale - 1) * rest})` : ""
  if (!moving) folding.travellers = []
  // Fit before fading: the label comes in once the frame's edges are clear of it.
  const label = folding.label
  if (!label) return
  const r = label.getBoundingClientRect()
  const fits = r.left >= -1 && r.top >= -1 && r.right <= innerWidth + 1 && r.bottom <= innerHeight + 1
  if (moving && !fits) return void (label.style.opacity = "0")
  folding.label = null
  label.style.opacity = ""
  label.animate([{ opacity: 0, filter: "blur(3px)", transform: "scale(0.96)" }, { opacity: 1, filter: "none", transform: "none" }], timing(MENU_MOTION.pillLabel))
}

/** The pill's frame at rest (inline.ts targetRect), and the pill itself (menu.css .pill). */
const PILL_HEIGHT = 32
/** The check (menu.css .pill-mark): its width, its pull-in while closed, and the room it takes open (its 14px, the gap, less its pull-in). */
const MARK_WIDTH = 14
const MARK_PULL = -8
const MARK_ROOM = 20
/** The check opening with the frame (placePill), till the frame stops. */
let opening: HTMLElement | null = null
/** A pill shrinking into its circle with the frame (placePill, toCircle). */
let closingUp: HTMLElement | null = null

function placePill() {
  const pill = document.querySelector<HTMLElement>(".pill")
  const s = host.springs
  if (!pill) return
  // The frame is the pill's place plus these offsets: undo them, anchored at the right
  // (pills grow leftward from the end of the field, and from the top right of the page).
  // On the pixel grid, as the host's box is (inline.ts position), so the two cancel exactly.
  // The middle is the pill's own (32 px tall at rest), not innerHeight's, which the browser rounds.
  const ox = s ? devicePx(s.left.value) : 0
  const oy = s ? devicePx(s.top.value) : 0
  const ow = s ? devicePx(s.width.value) : 0
  pill.style.right = `${ox + ow}px`
  pill.style.top = `${PILL_HEIGHT / 2 - oy}px`
  const moving = !!s && !(s.left.done && s.top.done && s.width.done && s.height.done)
  // A check opening takes exactly the room the frame has gained so far, so the
  // tile stays at the frame's left edge, on the frame's own clock.
  if (opening) {
    const k = Math.min(1, Math.max(0, 1 + ow / MARK_ROOM))
    opening.style.width = `${MARK_WIDTH * k}px`
    opening.style.marginLeft = `${MARK_PULL + (MARK_ROOM - MARK_WIDTH) * k}px`
    if (!moving) {
      opening.style.width = ""
      opening.style.marginLeft = ""
      opening = null
    }
  }
  // Shrinking into its circle, the pill is exactly as wide as the frame is now.
  if (closingUp?.isConnected) closingUp.style.width = `${PILL_HEIGHT + Math.max(0, ow)}px`

  if (s) stepFold(s, moving)
  // One loop, however often this is called directly.
  if (moving && !host.raf)
    host.raf = requestAnimationFrame((time) => {
      host.raf = 0
      inFrame(time, placePill)
    })
}

/** The content script's springs for the frame, as it starts or changes the fold. */
function onFold(data: { width?: unknown; at?: unknown; springs?: Record<string, SpringState> }) {
  if (mode !== "pill" || typeof data.at !== "number" || !data.springs) return
  const resume = (k: Edge) => Spring.resume(data.springs![k], data.at as number)
  const old = host.springs
  const next = { left: resume("left"), top: resume("top"), width: resume("width"), height: resume("height") }
  // Carry on from where everything is now: what travels keeps what it has
  // left of its way, and what fades keeps its place on the page.
  if (old) {
    const rest = 1 - foldProgress(old)
    for (const t of folding.travellers) Object.assign(t, { dx: t.dx * rest, dy: t.dy * rest, scale: 1 + (t.scale - 1) * rest })
  }
  const pin = folding.pin
  folding.pin = {
    left: next.left.value,
    x: pin && old ? pin.x + pin.left - old.left.value : 0,
  }
  folding.edge = (["left", "top", "width", "height"] as const).reduce((a, k) => (Math.abs(next[k].value) > Math.abs(next[a].value) ? k : a))
  folding.from = next[folding.edge].value
  host.springs = next
  host.width = typeof data.width === "number" ? data.width : host.width
  placePill()
  // Whatever waited for the frame to take this width goes now (see whenWide).
  const ready = host.waiters.filter((w) => w.width === null || Math.abs(w.width - host.width) < 2)
  host.waiters = host.waiters.filter((w) => !ready.includes(w))
  for (const w of ready) w.go()
}

/**
 * Runs `go` once the content script has started the frame toward `width`
 * (null: toward the pill at all), or after a moment, whatever happens.
 */
function whenWide(width: number | null, go: () => void) {
  let ran = false
  const once = () => {
    if (ran) return
    ran = true
    go()
  }
  host.waiters.push({ width, go: once })
  setTimeout(once, 150)
}

/**
 * Folds the surface into a pill at its place on the page (the end of the
 * field the menu belongs to, or the top right for the save offer):
 * `persist` (the picked row's avatar, or the Save button's label) and `lead`
 * travel into it, everything else fades and blurs where it is, and the frame
 * contracts from where it is onto the pill, which is laid out at its final
 * size and place from the start. Returns the pill's label. Without `check`,
 * the pill has no check of its own to open when it's done (a pick's ring says so).
 */
function fold(persist: HTMLElement | null, text: string, { persistIsLabel = false, lead, check = true }: { persistIsLabel?: boolean; lead?: HTMLElement; check?: boolean } = {}): HTMLElement {
  mode = "pill"
  const pill = h("div", { class: "pill waiting" })
  const label = persistIsLabel && persist ? h("span", { class: "pill-label" }) : h("span", { class: "pill-label" }, text)
  label.dataset.text = persistIsLabel && persist ? (persist.dataset.text ?? text) : text
  const slots = { lead: h("span", { class: "pill-slot" }), persist: h("span", { class: "pill-slot" }) }
  // A `persist` that isn't on the menu has nowhere to travel from: it's in the pill from the start.
  const inPlace = !!persist && !persistIsLabel && !persist.isConnected
  if (lead) pill.append(slots.lead)
  if (inPlace) pill.append(persist)
  else if (persist && !persistIsLabel) pill.append(slots.persist)
  pill.append(label)
  if (check) pill.append(h("span", { class: "pill-mark", "aria-hidden": "true" }, icon("check")))
  // Whatever goes fades where it is; the pill is the main change. It keeps
  // its size too, so the narrowing frame closes over it instead of reflowing it.
  const fading = Array.from(surface.children) as HTMLElement[]
  for (const el of fading) el.style.width = `${el.getBoundingClientRect().width}px`
  Object.assign(folding, { fading, travellers: [], label: null, pin: null })
  surface.classList.add("folded")
  document.body.append(pill)
  for (const el of fading) {
    el.setAttribute("aria-hidden", "true")
    el.style.pointerEvents = "none"
    animateTo(el, reducedMotion() ? { opacity: "0" } : { opacity: "0", filter: "blur(3px)", transform: "scale(0.96)" }, MENU_MOTION.foldOut)
  }
  // The pill's size, before anything moves into it: the label's text and the slots' sizes.
  if (persistIsLabel && persist) label.append(...Array.from(persist.cloneNode(true).childNodes))
  const size = (slot: HTMLElement, el: HTMLElement | null | undefined, w: number) => {
    if (!el) return
    slot.style.cssText = `display:inline-block;flex-shrink:0;width:${w}px;height:${w}px`
  }
  size(slots.lead, lead, 22)
  size(slots.persist, persist && !persistIsLabel && !inPlace ? persist : null, 22)
  report()

  // Once the content script says where the frame is going, the pill takes
  // its place and what stays moves in, each from where it was.
  whenWide(null, () => {
    pill.classList.remove("waiting")
    placePill()
    const moveIn = (el: HTMLElement | null | undefined, slot: HTMLElement, asLabel = false) => {
      if (!el?.isConnected) return
      const from = el.getBoundingClientRect()
      // A gap of its size stays behind, so what fades out doesn't shift into the hole.
      const gap = h("span", { "aria-hidden": "true" })
      gap.style.cssText = `display:inline-block;flex-shrink:0;width:${from.width}px;height:${from.height}px`
      el.replaceWith(gap)
      const target = asLabel ? label : slot
      if (asLabel) {
        // The label itself travels; the pill's own copy of its text takes over where it lands.
        label.replaceChildren(...Array.from(el.childNodes))
        el.remove()
      } else slot.replaceWith(el)
      // Reduced motion: it fades in where it lands.
      if (reducedMotion()) return void (asLabel ? label : el).animate([{ opacity: 0 }, { opacity: 1 }], REDUCED_FADE)
      const to = (asLabel ? target : el).getBoundingClientRect()
      const dx = from.left + from.width / 2 - (to.left + to.width / 2)
      const dy = from.top + from.height / 2 - (to.top + to.height / 2)
      const scale = to.width && !asLabel ? from.width / to.width : 1
      // On the frame's springs it goes as far as the frame has (see stepFold); without them, on its own.
      if (host.springs) folding.travellers.push({ el: asLabel ? label : el, dx, dy, scale })
      else (asLabel ? label : el).animate([{ transform: `translate(${dx}px, ${dy}px) scale(${scale})` }, { transform: "none" }], spring(MENU_MOTION.foldIn))
    }
    moveIn(lead, slots.lead)
    if (persistIsLabel) moveIn(persist, slots.persist, true)
    else if (!inPlace) moveIn(persist, slots.persist)
    if (!persistIsLabel) {
      if (host.springs && !reducedMotion()) folding.label = label
      else label.animate([{ opacity: 0 }, { opacity: 1 }], timing(MENU_MOTION.pillLabel))
    }
    placePill()
  })
  return label
}

/** The label's width with `text` in it, measured off to the side. */
function widthOf(label: HTMLElement, text: string): number {
  const probe = h("span", { class: label.className, "aria-hidden": "true" }, text)
  probe.style.cssText = "position:absolute;visibility:hidden;left:0;top:0"
  label.parentElement?.append(probe)
  const w = probe.getBoundingClientRect().width
  probe.remove()
  return w
}

/**
 * The pill says how it went. The frame always holds the pill: growing, its
 * width leads (the new width goes to the content script first, and the label
 * rolls, and the check comes in, once the frame has started toward it);
 * shrinking, the label goes first and the frame follows on the same spring.
 */
function settle(label: HTMLElement, text: string, ok: boolean) {
  const pill = label.parentElement
  if (!pill) return
  const mark = ok ? pill.querySelector<HTMLElement>(".pill-mark") : null
  const grow = widthOf(label, text) - label.getBoundingClientRect().width + (mark ? MARK_ROOM : 0)
  const width = Math.ceil(pill.getBoundingClientRect().width + grow)
  // Only the check comes, the words staying: it opens with the frame itself, from the moment the frame starts toward it.
  if (mark && (label.dataset.text ?? label.textContent) === text && grow > 0) {
    report(grow)
    return whenWide(width, () => {
      mark.style.transition = "opacity 200ms ease-out 120ms"
      if (!reducedMotion()) opening = mark
      relax()
      pill.classList.remove("failed")
      pill.classList.add("ok")
      placePill()
    })
  }
  const say = () => {
    const mark = pill.querySelector<HTMLElement>(".pill-mark")
    if (mark && !reducedMotion()) {
      const { easing, duration } = spring(0.45)
      mark.style.transition = `width ${duration}ms ${easing}, margin-left ${duration}ms ${easing}, opacity 200ms ease-out 120ms`
    }
    rollLabel(label, text)
    relax()
    pill.classList.toggle("ok", ok)
    pill.classList.toggle("failed", !ok)
  }
  if (grow < 0) {
    say()
    return void setTimeout(() => report(grow), SHRINK_WAITS_MS)
  }
  report(grow)
  // The frame's width springs over .37 s from when the content script hears of
  // it; the label rolls over .45 s, a beat later, so the width stays ahead.
  whenWide(width, () => setTimeout(say, WIDTH_LEAD_MS))
}

// ---- Keys and presses ----------------------------------------------------------

addEventListener("pointerdown", (e) => {
  if (!e.isTrusted) return
  // Any press ends what the keyboard was allowed; only the main button's can earn it back.
  const press = entry.pressed()
  if ((e as PointerEvent).button !== 0) return
  pressedAt = e.timeStamp
  pressedScale = scaleMatches()
  // The keyboard may pick after a press only if the press itself would have,
  // and only with focus still in the menu: a press takes none (see below), so
  // one that ended in no pick (dragged off its row, on the caption) leaves
  // nothing for a later Tab in to pick with.
  if (pressedScale && dwell.settled(e.timeStamp)) void confirmScale(e.timeStamp).then((ok) => ok && document.hasFocus() && entry.confirmed(press))
}, true)
// A press leaves focus where it was, in the page's field. Taking it would
// tell the page the moment of the press (its field blurs), and many fields
// redraw on blur (a floating label drops back, an outlined border thins, the
// box changes width): the field moves at the very press, the menu with it,
// and the move cancels the pick (see Dwell). Tab and the user's ↓ in the
// field still bring focus in.
addEventListener("mousedown", (e) => void (e.isTrusted && e.preventDefault()), true)
addEventListener("focus", (e) => {
  if (e.target !== window) return
  if (e.isTrusted) entry.focused(performance.now())
  // Focus that came in with the keyboard (↓ in the field, or Tab) goes to the
  // list, so a screen reader reads it and its active row. A click brings no
  // focus in (see the mousedown handler above).
  setTimeout(() => {
    if (document.hasFocus() && document.activeElement === document.body && rowsEl.getAttribute("role") === "listbox" && mode === "accounts") rowsEl.focus({ preventScroll: true })
  }, 0)
})
addEventListener("blur", (e) => void (e.target === window && entry.blurred()))

document.addEventListener("keydown", (e) => {
  if (e.isTrusted) {
    pressedAt = e.timeStamp
    pressedScale = scaleMatches()
  }
  if (e.key === "Escape") return void send({ type: "db:menu-dismiss", token })
  if (mode === "save") return
  // Tab leaves the list as Escape does: focus goes back to the field, never on into the end of the page.
  if (e.key === "Tab" && mode === "accounts") {
    e.preventDefault()
    return void send({ type: "db:menu-dismiss", token })
  }
  if (e.key === "Enter" || e.key === " ") e.preventDefault()
  // The locked menu's one row: Enter opens Deadbolt to unlock, once the user came in with ↓.
  if (e.key === "Enter" && mode === "accounts" && !accounts.length && rowsEl.querySelector("button.row")) {
    if (!entry.entered) return say("Press ↓ in the field to choose.")
    return void unlock()
  }
  const rows = visible()
  if (!rows.length || mode !== "accounts") return
  // ↓ or ↑ on the corner offer's top account lists the others; the next ↓ moves in them.
  if (universal && !universalExpanded && accounts.length > 1 && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
    e.preventDefault()
    return expandUniversal()
  }
  const at = Math.max(0, rows.indexOf(active))
  if (e.key === "ArrowDown") active = rows[Math.min(at + 1, rows.length - 1)]
  else if (e.key === "ArrowUp") active = rows[Math.max(at - 1, 0)]
  else if (e.key === "Enter") {
    if (!entry.entered) return say("Press ↓ in the field to choose.")
    const el = rowsEl.querySelectorAll<HTMLElement>("button.row")[active]
    if (el && !busy) press(el)
    return void pick(active)
  } else return
  e.preventDefault()
  highlight()
})

function show(reply: MenuLoadReply) {
  if (reply.kind === "offer") return showOffer(reply)
  if (reply.kind === "notice") return showNotice(reply)
  if (mode !== "accounts") return
  if (reply.kind === "status") return showStatus(reply.status)
  if (reply.kind === "forms") return showForms(reply)
  universal = reply.kind === "accounts" && reply.universal === true
  signsIn = new Set(reply.kind === "accounts" ? (reply.signsIn ?? []) : [])
  surface.classList.toggle("universal", universal)
  // A new-password box offers one row, a generated password; otherwise the logins.
  // A "Sign in with …" login shows as that; one with a password too gets its fill row first.
  accounts =
    reply.kind === "generate"
      ? [{ generate: true }]
      : [
          ...(reply.passkeys ?? []).map((passkey) => ({ passkey })),
          ...reply.accounts.flatMap((account): Row[] =>
            account.signIn ? [...(account.hasPassword && reply.focused !== "otp" ? [{ account }] : []), { provider: account }] : [{ account }],
          ),
        ]
  focused = reply.kind === "generate" ? "new-password" : reply.focused
  continueAs = reply.kind === "accounts" && reply.continueAs === true && !reply.passkeys?.length
  active = Math.min(active, Math.max(accounts.length - 1, 0))
  if (!accounts.length) {
    listbox(null)
    highlightEl.hidden = true
    rowsEl.replaceChildren(notice(icon("keyhole"), "No logins here", `Nothing saved for ${reply.site}`))
    setCaption("")
    return say("")
  }
  listbox(reply.kind === "generate" ? "Passwords" : "Logins")
  siteIcons = reply.kind === "accounts" ? (reply.icons ?? null) : null
  // The corner offer always shows each account's mark: the provider's, or the site's tile.
  bare = reply.kind === "accounts" && !siteIcons && !universal
  rowsEl.classList.toggle("bare", bare)
  revealable = new Set(reply.kind === "accounts" ? (reply.reveal ?? []) : [])
  listedAt = performance.now()
  rowsEl.replaceChildren(...accounts.map(row))
  // No site over logins: they're only ever the page's own site's (or a same-site frame's), which the page shows.
  setCaption("")
  say("")
  // The list is already at rest when it opens: no slide on the first paint.
  if (query) for (const [i, r] of Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row")).entries()) r.hidden = !matches(accounts[i], query)
  const left = visible()
  if (left.length && !left.includes(active)) active = left[0]
  highlight()
  if (universal) showUniversal()
  if (query) port?.postMessage({ type: "db:matches", count: left.length })
}

/**
 * The corner offer's other accounts, listed from its top one. Listing picks
 * nothing, and the surface grows: as after any move, a pick waits out the
 * dwell again (see pick). The list is one fixed height, scrolling inside,
 * so the frame's size doesn't tell the page how many accounts there are.
 */
function expandUniversal() {
  if (universalExpanded || mode !== "accounts" || accounts.length < 2) return
  universalExpanded = true
  surface.classList.add("expanded")
  rowsEl.replaceChildren(...accounts.map(row))
  highlight()
  dwell.moved(performance.now())
  report()
}

/** Back to the top account alone: the pointer left the list and nothing was picked. */
function collapseUniversal() {
  if (!universalExpanded || busy || mode !== "accounts" || surface.matches(":hover, :focus-within")) return
  universalExpanded = false
  surface.classList.remove("expanded")
  showUniversal()
  dwell.moved(performance.now())
  report()
}

let collapsing: ReturnType<typeof setTimeout> | undefined
// Leaving the listed accounts folds them back after a moment's grace; coming back keeps them.
surface.addEventListener("pointerleave", (e) => {
  if (!e.isTrusted || !universal || !universalExpanded) return
  clearTimeout(collapsing)
  collapsing = setTimeout(collapseUniversal, COLLAPSE_GRACE_MS)
})
surface.addEventListener("pointerenter", () => clearTimeout(collapsing))
// Keyboard focus coming into the list (Tab) lists the accounts too; a press takes none (see the mousedown handler).
rowsEl.addEventListener("focus", (e) => e.isTrusted && universal && expandUniversal())

/**
 * The person's own pointer moving, not the browser replaying where it was
 * after the frame changed size, nor a pointer resting where the offer came
 * in (see the save offer's real()).
 */
const moving = (e: PointerEvent) => e.isTrusted && (e.movementX !== 0 || e.movementY !== 0) && e.timeStamp - resizedAt > REPLAY_MS

const CHEVRON = `<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`

/**
 * The corner offer, collapsed: its top account's own row (the site's first
 * login, else the first provider account), which one click picks with every
 * check a pick has. With more accounts a quiet chevron says so, and the
 * pointer moving onto the row for a moment, focus or ↓ lists them.
 */
function showUniversal() {
  if (!universalExpanded && accounts.length) {
    active = 0
    const top = row(accounts[0], 0)
    if (accounts.length > 1) {
      const more = h("span", { class: "more", "aria-hidden": "true" })
      more.innerHTML = CHEVRON
      top.append(more)
      top.setAttribute("aria-description", "More accounts: press ↓")
      let resting: ReturnType<typeof setTimeout> | undefined
      let inside = false
      top.addEventListener("pointermove", (e) => {
        if (!moving(e)) return
        inside = true
        if (resting === undefined) resting = setTimeout(() => {
          resting = undefined
          if (inside && !busy) expandUniversal()
        }, EXPAND_AFTER_MS)
      })
      top.addEventListener("pointerleave", () => {
        inside = false
        clearTimeout(resting)
        resting = undefined
      })
    }
    rowsEl.replaceChildren(top)
    // Quiet until the pointer is on it (the row's own pointermove lights it).
    highlightEl.hidden = true
  }
  surface.querySelector(".signin-dismiss")?.remove()
  const dismiss = h("button", { class: "signin-dismiss", type: "button", title: "Not now for this site (30 minutes)", "aria-label": "Not now for this site" }, "×")
  dismiss.addEventListener("click", async (e) => {
    if (!e.isTrusted || (e.detail === 0 && !entry.entered) || busy || !pressedScale || !dwell.settled(pressedAt)) return
    if (await confirmScale(pressedAt)) await send({ type: "db:menu-dismiss", token })
  })
  surface.append(dismiss)
}

// ---- Addresses and cards ------------------------------------------------------------

/**
 * An identity or card field's menu: the identities ("Home · 123 Main St")
 * or cards ("Visa ••4242 · 08/28") to fill the whole section with. A card
 * says where it goes when that's a payment provider's frame ("Into Stripe
 * on shop.com"), and that Deadbolt may ask for Touch ID first (or, in the
 * browser-only Deadbolt under Strict, for the passphrase).
 */
/** For each identity listed, what of the section it fills (see fillsWords). */
let fills: Record<string, string[]> = {}

function showForms(reply: Extract<MenuLoadReply, { kind: "forms" }>) {
  fills = reply.fills ?? {}
  accounts = reply.form === "card" ? reply.cards.map((card) => ({ card })) : reply.identities.map((identity) => ({ identity }))
  continueAs = false
  active = Math.min(active, Math.max(accounts.length - 1, 0))
  if (!accounts.length) {
    listbox(null)
    highlightEl.hidden = true
    rowsEl.replaceChildren(notice(icon(reply.form === "card" ? "card" : "keyhole"), reply.form === "card" ? "No cards saved" : "No addresses saved", "Add one in Deadbolt"))
    setCaption("")
    return say("")
  }
  listbox(reply.form === "card" ? "Cards" : "Addresses")
  bare = false
  rowsEl.classList.remove("bare")
  rowsEl.replaceChildren(...accounts.map(row))
  // Where a pick goes, always: a payment provider's frames on the site, or the site itself.
  setCaption(reply.into ? `Into ${reply.into} on ${reply.site}` : `On ${reply.site}`)
  say(reply.passphrase ? "Deadbolt asks for your passphrase first." : reply.verify ? "Deadbolt may ask for Touch ID." : "")
  if (query) for (const [i, r] of Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row")).entries()) r.hidden = !matches(accounts[i], query)
  const left = visible()
  if (left.length && !left.includes(active)) active = left[0]
  highlight()
}

// ---- A step filled without a pick -----------------------------------------------------

/**
 * "Password filled", "Code filled": a sign-in session filled the next step
 * (see bg/autofill.ts Session), and this pill on the field says so, then goes.
 */
function showNotice(notice: Extract<MenuLoadReply, { kind: "notice" }>) {
  mode = "pill"
  surface.classList.add("folded")
  for (const el of Array.from(surface.children) as HTMLElement[]) el.hidden = true
  const label = h("span", { class: "pill-label" }, notice.label)
  label.dataset.text = notice.label
  const pill = h("div", { class: "pill ok" }, avatar(notice.title), label, h("span", { class: "pill-mark", "aria-hidden": "true" }, icon("check")))
  document.body.append(pill)
  announce(notice.label)
  report()
  setTimeout(() => done(), FILLED_STAYS_MS + 600)
}

// ---- The save offer --------------------------------------------------------------

/**
 * The save offer's shape: a small pill in the corner ("compact"), opened on
 * approach to show who and the other choices ("open"), or just Deadbolt's
 * mark ("dot") once it's not wanted for now.
 */
type OfferState = "compact" | "open" | "dot"
let offerState: OfferState = "compact"
/** Re-measures the offer and tells the parent its size (see report). */
let offerSize: () => { width: number; height: number } = () => ({ width: 0, height: 0 })

/**
 * "Save login?" after a confirmed sign-in, in the top right corner of the
 * page. It shows the username and site only; the password stays in the
 * background.
 *
 * The whole card is laid out once, at its open size, anchored to the top
 * right corner; the frame shows only as much of it as the shape needs, so
 * opening and closing are the frame's clip and radius moving, with nothing
 * inside reflowing. The parent moving the frame restarts the dwell, so a
 * button that just came into view takes no press until it has sat still.
 */
function showOffer(offer: Extract<MenuLoadReply, { kind: "offer" }>) {
  mode = "save"
  const title = offerTitle(offer)
  document.body.classList.add("save")
  document.body.dataset.offer = offerState
  const status = h("p", { class: "offer-status" })
  // An update says so on its button.
  const primary = offer.update ? "Update" : "Save"
  const saveLabel = h("span", { class: "roll-label" }, primary)
  saveLabel.dataset.text = primary
  const save = h("button", { class: "btn primary", type: "button" }, saveLabel)
  const later = h("button", { class: "btn", type: "button" }, "Not now")
  const never = h("button", { class: "link never", type: "button" }, "Never for this site")
  // An update of a card or identity may be kept as a new one instead.
  const asNew = offer.saveNew ? h("button", { class: "btn new", type: "button" }, "Save as new") : null
  const bar = h("span", { class: "bar", "aria-hidden": "true" })
  const mark = h("span", { class: "offer-mark", "aria-hidden": "true" }, svg(ICONS.deadbolt))
  const row = h("div", { class: "offer-row" }, mark, h("h1", { class: "offer-title" }, title), save)
  const section = h(
    "section",
    { class: "offer", "aria-label": title.slice(0, -1) },
    row,
    h(
      "div",
      { class: "offer-more" },
      h("p", { class: "offer-user" }, h("span", { class: "value" }, offer.username), h("span", { class: "site" }, ` · ${offer.site}`)),
      // What an update changes, for a card: "Expires 08/28 → 09/30".
      offer.change ? h("p", { class: "offer-change" }, offer.change) : null,
      status,
      h("div", { class: "offer-actions" }, never, asNew, later),
    ),
    bar,
  )
  const dot = h("button", { class: "dot", type: "button", "aria-label": title }, svg(ICONS.deadbolt))
  surface.replaceChildren(section, dot)
  section.inert = offerState === "dot"
  dot.inert = offerState !== "dot"

  // The compact pill: the top row, from the mark (with the row's padding) to the corner.
  const compactWidth = () => Math.ceil(section.getBoundingClientRect().right - mark.getBoundingClientRect().left + 12)
  offerSize = () => {
    if (offerState === "dot") return { width: DOT, height: DOT }
    const box = section.getBoundingClientRect()
    if (offerState === "open") return { width: Math.ceil(box.width), height: Math.ceil(box.height) }
    const width = compactWidth()
    bar.style.width = `${width}px`
    return { width, height: ROW }
  }
  // The bar runs along the compact pill's bottom edge.
  bar.style.width = `${compactWidth()}px`

  // ---- Shape ----
  let grace: ReturnType<typeof setTimeout> | undefined
  let reopenedAt = -Infinity
  const shape = (next: OfferState) => {
    clearTimeout(grace)
    if (next === offerState || mode !== "save") return
    for (const a of surface.getAnimations()) a.cancel()
    const fromDot = offerState === "dot"
    offerState = next
    document.body.dataset.offer = next
    if (fromDot) reopenedAt = performance.now()
    // Only what shows takes focus: the dot alone, or the pill alone.
    section.inert = next === "dot"
    dot.inert = next !== "dot"
    port?.postMessage({ type: "db:radius", radius: next === "open" ? 12 : next === "dot" ? DOT / 2 : ROW / 2 })
    // The pill and the dot cross-fade (inside the frame): the dwell counts
    // from when that's over, as after a move.
    if (fromDot || next === "dot") {
      dwell.moved(performance.now())
      setTimeout(() => dwell.moved(performance.now()), CROSSFADE_MS)
    }
    report()
  }
  // Where the pointer is, by real movement only. The browser's own idea
  // (:hover) goes stale once the pointer leaves for the page, and after the
  // frame changes size it replays the last position here as if the pointer
  // had moved; the content script says when the pointer is in the page
  // (db:away), and only movement after that counts.
  const pointer = { inside: false }
  const real = (e: PointerEvent) => e.isTrusted && (!pointerAway || e.movementX !== 0 || e.movementY !== 0 || e.timeStamp - resizedAt > REPLAY_MS)
  const wanted = () => pointer.inside || section.matches(":focus-within")
  // Approach opens it; leaving closes it again after a moment's grace.
  // Opening waits a moment under the pointer: a quick Save from the pill
  // goes ahead without the card opening (which, being a move, would make
  // the press wait out the dwell again).
  let opening: ReturnType<typeof setTimeout> | undefined
  const approach = (e: PointerEvent) => {
    if (!real(e)) return
    pointerAway = false
    pointer.inside = true
    if (offerState === "dot") return shape("compact")
    // Just reopened from the dot under the pointer: stay compact until the pointer moves on it.
    if (offerState !== "compact" || opening !== undefined || performance.now() - reopenedAt < REOPEN_SETTLES_MS) return
    opening = setTimeout(() => {
      opening = undefined
      if (pointer.inside && offerState === "compact" && !busy && !document.body.classList.contains("held")) shape("open")
    }, OPEN_AFTER_MS)
  }
  const depart = () => {
    pointer.inside = false
    clearTimeout(opening)
    opening = undefined
    clearTimeout(grace)
    grace = setTimeout(() => offerState === "open" && !wanted() && !busy && shape("compact"), COLLAPSE_GRACE_MS)
  }
  section.addEventListener("pointerenter", approach)
  section.addEventListener("pointermove", approach)
  section.addEventListener("pointerleave", depart)
  // Keyboard focus opens it; the focus a click gives a button doesn't (that
  // would move the frame under the press, and the press would be refused).
  section.addEventListener("focusin", (e) => offerState !== "dot" && e.target instanceof Element && e.target.matches(":focus-visible") && shape("open"))
  section.addEventListener("focusout", () => !pointer.inside && depart())
  dot.addEventListener("pointerenter", approach)
  dot.addEventListener("pointermove", approach)
  dot.addEventListener("pointerleave", () => (pointer.inside = false))
  dot.addEventListener("click", (e) => e.isTrusted && shape("compact"))
  // Tabbed onto, the dot is the pill again, and focus moves onto its Save (the dot leaves the tab order).
  dot.addEventListener("focus", () => {
    shape("compact")
    save.focus({ preventScroll: true })
  })
  away = () => {
    pointerAway = true
    if (pointer.inside || offerState === "open") depart()
  }

  // ---- Time ----
  // The pill's bar empties over twelve seconds, then it shrinks to the dot,
  // which stays twenty more before leaving the offer to the toolbar. Stepped
  // frame by frame, never animated (see menu.css), and paused while the offer
  // is open, under the pointer or focus, approached, or a press is checked.
  let barEnded = false
  const time = { total: OFFER_STAYS_MS, left: OFFER_STAYS_MS, last: performance.now(), shape: offerState }
  const tick = (now: number) => {
    if (!section.isConnected || mode !== "save") return
    if (time.shape !== offerState) {
      // The dot has its own time, and so does the pill reopened from it;
      // opening and closing the pill keeps the time it had.
      const from = time.shape
      time.shape = offerState
      if (offerState === "dot") Object.assign(time, { total: DOT_STAYS_MS, left: DOT_STAYS_MS })
      else if (from === "dot") Object.assign(time, { total: OFFER_REOPENED_MS, left: OFFER_REOPENED_MS })
    }
    const paused = offerState === "open" || wanted() || dot.matches(":focus") || document.body.matches(".near, .held, .busy")
    if (!paused) time.left = Math.max(0, time.left - (now - time.last))
    time.last = now
    if (offerState !== "dot") bar.style.transform = `scaleX(${time.left / time.total})`
    if (time.left > 0) return void requestAnimationFrame(tick)
    if (offerState === "dot") return leaveLikeSave()
    barEnded = true
    if (!busy) shape("dot")
    requestAnimationFrame(tick)
  }
  requestAnimationFrame(tick)
  /** After a save that failed once the time was up: the pill stays a while longer. */
  const rearm = () => {
    if (!barEnded) return
    barEnded = false
    Object.assign(time, { total: OFFER_REARM_MS, left: OFFER_REARM_MS, last: performance.now(), shape: offerState })
  }
  // A click elsewhere in the page (the content script says so): the dot.
  tuck = () => !busy && shape("dot")

  const say = (text: string) => {
    status.hidden = !text
    if (text) rollLabel(status, text)
    announce(text)
  }
  say("")
  // It shows in the corner, away from where the user is: a screen reader hears it came.
  // An update names what it changes: "Update phone for Kit Langton?".
  announce(`${title.slice(0, -1)} for ${offer.what && offer.update ? offer.username : offer.site}? Deadbolt's offer is at the end of the page, and in the toolbar button.`)
  const answer = async (choice: OfferChoice, e: MouseEvent) => {
    // Real presses only.
    if (!e.isTrusted || busy || offerState === "dot") return
    // Enter or Space count only once the user came into the surface themselves (see Entry): say where else to answer.
    if (e.detail === 0 && !entry.entered) return say("Click to answer here, or answer in Deadbolt's toolbar button.")
    if (!pressedScale || !dwell.settled(pressedAt)) {
      relax()
      shape("open")
      return say(pressedScale && dwell.visible ? "Press again in a moment." : "This offer is covered. Nothing was saved.")
    }
    busy = true
    if (e.currentTarget instanceof HTMLElement) press(e.currentTarget)
    if (!(await confirmScale(pressedAt))) {
      busy = false
      relax()
      shape("open")
      return say("This offer is covered. Nothing was saved.")
    }
    document.body.classList.remove("held")
    // "Saving…" rolls in the button itself, and stays long enough to read.
    const shownAt = performance.now()
    const saving = choice === "save" || choice === "new"
    if (saving) {
      document.body.classList.add("busy")
      rollLabel(saveLabel, "Saving…")
    }
    const reply = await send<ChooseReply>({ type: "db:surface-choose", token, choice })
    if (!saving) return leaveLikeSave()
    if (reply?.ok) {
      await new Promise((r) => setTimeout(r, Math.max(0, SAVING_READS_MS - (performance.now() - shownAt))))
      const label = fold(saveLabel, "Saving…", { persistIsLabel: true, lead: mark })
      // Once the pill has its place, its label rolls on to the result: "Saved"
      // for a new login and an update alike, so the pill is the same either way.
      return void setTimeout(() => {
        settle(label, "Saved", true)
        announce("Saved")
        setTimeout(() => done(true), FILLED_STAYS_MS + 450)
      }, 380)
    }
    if (!reply || ("gone" in reply && reply.gone)) return leaveLikeSave()
    // Locked or busy: open, say so in place, and let Save be pressed again, for a while.
    busy = false
    relax()
    document.body.classList.remove("busy")
    rollLabel(saveLabel, primary)
    shape("open")
    say(reply.message)
    rearm()
  }
  // The press shows at once; what it does waits for the checks.
  for (const b of [save, later, never, ...(asNew ? [asNew] : [])]) b.addEventListener("pointerdown", (e) => e.isTrusted && e.button === 0 && !busy && press(b))
  save.addEventListener("click", (e) => void answer("save", e))
  asNew?.addEventListener("click", (e) => void answer("new", e))
  later.addEventListener("click", (e) => void answer("later", e))
  never.addEventListener("click", (e) => void answer("never", e))
  report()
}

/** The offer's answer to a click elsewhere in the page, once it's showing. */
let tuck = () => {}
/** The offer's answer to the pointer moving in the page (see db:away). */
let away = () => {}
/** Whether the pointer was last seen in the page, not here (see showOffer). */
let pointerAway = true
/** When the frame last changed size: the browser replays the last pointer position just after. */
let resizedAt = -Infinity
addEventListener("resize", (e) => (resizedAt = e.timeStamp))

// ---- The token ---------------------------------------------------------------------

async function load() {
  const reply = token && mode === "accounts" ? await send<MenuLoadReply>({ type: "db:menu-load", token, parent: parentOrigin }) : null
  if (reply) show(reply)
}

/**
 * The content script that opened this surface posts its token from the parent
 * window. The page is that window too and can post first, so every offer is
 * tried and the first the background accepts wins.
 */
async function claim(offered: string, origin: string, channel: MessagePort | undefined) {
  const reply = await send<MenuLoadReply>({ type: "db:menu-load", token: offered, parent: origin })
  if (token) return
  if (!reply) return say("This menu has expired.")
  token = offered
  parentOrigin = origin
  show(reply)
  // Mounting the offer's text starts its font load; measure once it's ready so
  // the compact pill lands at its real width instead of springing from fallback.
  if (reply.kind === "offer" && document.fonts) await Promise.race([document.fonts.ready, new Promise((r) => setTimeout(r, 50))])
  // Came with the token, so it's the content script's: the page never sees it.
  if (channel) {
    port = channel
    channel.onmessage = (e: MessageEvent<{ type?: unknown }>) => {
      const data = e.data as { type?: unknown; query?: unknown; near?: unknown; origin?: unknown; corner?: unknown; geometry?: typeof geometry; check?: number; ok?: boolean }
      if (data?.type === "db:menu-checked" && typeof data.check === "number") placementChecks.get(data.check)?.(data.ok === true)
      else if (data?.type === "db:menu-enter") entry.offered(performance.now(), document.hasFocus())
      else if (data?.type === "db:reveal") {
        const corner = data.corner === true
        const origin = typeof data.origin === "string" ? data.origin : "top left"
        for (const el of [surface, ...Array.from(document.querySelectorAll<HTMLElement>(".pill"))]) {
          if (!corner) el.style.transformOrigin = origin
          if (corner && mode === "save" && offerState === "compact") el.style.borderRadius = `${ROW / 2}px`
          const anim = el.animate(
            reducedMotion()
              ? [{ opacity: 0 }, { opacity: 1 }]
              : corner
                ? [
                    { opacity: 0, transform: "translate(17px, -17px)" },
                    { opacity: 1, transform: "none" },
                  ]
                : [
                    { opacity: 0, transform: "scale(0.96)" },
                    { opacity: 1, transform: "none" },
                  ],
            timing(corner ? MENU_MOTION.openCorner : MENU_MOTION.open),
          )
          if (corner && mode === "save") {
            const clear = () => { el.style.borderRadius = "" }
            anim.finished.then(clear, clear)
          }
        }
        watchVisibility(dwell, performance.now() + 60)
      } else if (data?.type === "db:menu-geometry" && data.geometry) {
        const was = geometry
        const now = data.geometry
        geometry = now
        // Only "visible" coming back isn't a move: the parent restarted the
        // wait (a new version) when it changed, not again on recovery.
        const back = !!was && now.visible && !was.visible && was.width === now.width && was.height === now.height && was.dpr === now.dpr && was.version === now.version
        if (!back) dwell.moved(performance.now())
      } else if (data?.type === "db:fold") onFold(e.data as Parameters<typeof onFold>[0])
      else if (data?.type === "db:filter" && typeof data.query === "string") narrow(data.query)
      // The pointer near the offer pauses its bar, as being on it does.
      else if (data?.type === "db:near") document.body.classList.toggle("near", data.near === true)
      else if (data?.type === "db:tuck") tuck()
      else if (data?.type === "db:away") away()
    }
  }
  // Keep the frame exactly as big as the content (fonts load late and change
  // sizes): the visibility guard only trusts a fully visible surface.
  ready = true
  report()
}

addEventListener("message", (e: MessageEvent<{ type?: unknown; token?: unknown }>) => {
  if (window.parent === window || e.source !== window.parent) return
  // The page can send this too, but it only ever makes the menu wait longer.
  if (e.data?.type === "db:menu-moved") return dwell.moved(performance.now())
  if (!token && e.data?.type === "db:menu-token" && typeof e.data.token === "string") void claim(e.data.token, e.origin, e.ports[0])
})
if (window.parent !== window) window.parent.postMessage({ type: "db:menu-ready" }, "*")

// Turning site icons on or off shows in the open menu at once.
onIconSettings(() => void load())

// Unlocking in the app, or a sync, updates the open menu in place.
chrome.runtime.onMessage.addListener((message: StatusChanged) => {
  if (message?.type === "db:status") void load()
})
