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


import type { FieldRole, MenuLoadReply, MenuRefresh, PickReply, SignInReply, Status, StatusChanged, SurfaceMode, ToBackground, UnlockReply } from "./messages"
import { provider as providerOf } from "./signin"
import type { Account } from "./protocol"
import { avatar, confirmPick, Dwell, Entry, h, icon, watchVisibility } from "./ui/dom"
import { animateTo, MENU_MOTION, reducedMotion, ROLL_CSS, spring, Spring, timing } from "./ui/motion"
import { iconKey, onIconSettings, type StoredIcon } from "./ui/icon-store"
import { onFold } from "./ui/pill-frame"
import { ring } from "./ui/ring"
import { siteTile } from "./ui/site-icon"
import { COLLAPSE_GRACE_MS, FILLED_STAYS_MS, renderOffer, REPLAY_MS, ROW, type OfferState } from "./menu/offer"
import { createPillController } from "./menu/pill"
import { cardLine, CHEVRON, matches, notice, pillName, providerMark, type Row } from "./menu/rows"

export { cardLine }

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
/** The pointer moving onto the corner offer's top account this long lists the others: passing over it doesn't. */
const EXPAND_AFTER_MS = 150
const FAILED_STAYS_MS = 1800
/** How long narrowing's row animations run: the dwell starts again after. */
const NARROW_SETTLES_MS = 480

document.head.append(h("style", {}, ROLL_CSS))

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

const { land, toCircle, fold, settle } = createPillController({
  surface,
  setMode: (next) => { mode = next },
  report,
  done,
  relax,
})

function row(item: Row, i: number): HTMLElement {
  const [tile, title, sub] =
    "identity" in item
      ? [avatar(item.identity.title), item.identity.title, [fills[item.identity.ref]?.length ? `Fills ${fills[item.identity.ref].join(", ")}` : "", item.identity.summary].filter(Boolean).join(" · ") || "Fill this address"]
      : "card" in item
      ? [avatar(item.card.brand || item.card.title, icon("card")), cardLine(item.card), item.card.brand && item.card.title !== item.card.brand ? item.card.title : item.card.cardholder || item.card.title]
      : "generate" in item
      ? [avatar("", icon("key")), "Use a strong password", "Saved only if you sign up with it"]
      : "unlock" in item
      ? [avatar("", icon("lock")), item.unlock.touchId ? "Unlock Deadbolt · Touch ID" : "Unlock Deadbolt", item.unlock.touchId ? "Then pick a login here" : "Opens Deadbolt to type your passphrase"]
      : "passkey" in item
      ? [avatar("", icon("passkey")), item.passkey.username || "Passkey", `Passkey · ${item.passkey.vault}`]
      : "provider" in item
        ? // "Sign in with Google · alex@gmail.com": the provider's mark and name, then the account it uses.
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

function showStatus(status: Status, unlock = false) {
  // Locked, with a host that unlocks from here: one row that does it, a pick like any other.
  if (status.state === "locked" && unlock) {
    accounts = [{ unlock: { touchId: status.touchId === true } }]
    active = 0
    listbox("Deadbolt")
    rowsEl.classList.remove("bare")
    rowsEl.replaceChildren(...accounts.map(row))
    setCaption("")
    say("")
    return highlight()
  }
  accounts = []
  listbox(null)
  highlightEl.hidden = true
  if (status.state === "locked") {
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
  if ("unlock" in a) return unlock(i, a.unlock.touchId)
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


/**
 * "Unlock Deadbolt" picked: Touch ID comes up, or Deadbolt's window, and the
 * row says which to answer. The menu stays; once the vault is ready, it
 * lists the site's logins in place (db:menu-refresh).
 */
async function unlock(i: number, touchId: boolean) {
  const sub = rowsEl.querySelectorAll<HTMLElement>("button.row")[i]?.querySelector<HTMLElement>(".sub")
  if (sub) sub.textContent = touchId ? "Waiting for Touch ID…" : "Opening Deadbolt…"
  const reply = await send<UnlockReply>({ type: "db:menu-unlock", token })
  busy = false
  relax()
  if (!reply?.ok) {
    if (sub) sub.textContent = touchId ? "Then pick a login here" : "Opens Deadbolt to type your passphrase"
    return say(reply?.message || "Couldn't unlock. Try again.")
  }
  if (reply.app && sub) sub.textContent = "Type your passphrase in Deadbolt"
  announce(reply.app ? "Type your passphrase in Deadbolt" : "Unlocked")
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
  if (reply.kind === "status") return showStatus(reply.status, reply.unlock === true)
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

let getOfferState: () => OfferState = () => "compact"
/** Re-measures the offer and tells the parent its size (see report). */
let offerSize: () => { width: number; height: number } = () => ({ width: 0, height: 0 })

function showOffer(offer: Extract<MenuLoadReply, { kind: "offer" }>) {
  const handles = renderOffer(
    {
      surface,
      dwell,
      entry,
      send,
      token: () => token,
      port: () => port,
      report,
      done,
      leaveLikeSave,
      fold,
      settle,
      press,
      relax,
      announce,
      confirmScale,
      isBusy: () => busy,
      setBusy: (value) => { busy = value },
      getMode: () => mode,
      setMode: (next) => { mode = next },
      isPressedScale: () => pressedScale,
      getPressedAt: () => pressedAt,
      isPointerAway: () => pointerAway,
      setPointerAway: (value) => { pointerAway = value },
      getResizedAt: () => resizedAt,
    },
    offer,
  )
  getOfferState = handles.state
  offerSize = handles.size
  tuck = handles.tuck
  away = handles.away
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
          if (corner && mode === "save" && getOfferState() === "compact") el.style.borderRadius = `${ROW / 2}px`
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
      } else if (data?.type === "db:fold" && mode === "pill") onFold(e.data as Parameters<typeof onFold>[0])
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

// Unlocking in the app, or a sync, updates the open menu in place; so does
// the unlock this menu asked for, once its site's logins are in hand.
chrome.runtime.onMessage.addListener((message: StatusChanged | MenuRefresh) => {
  if (message?.type === "db:status" || (message?.type === "db:menu-refresh" && !!token && message.token === token)) void load()
})

