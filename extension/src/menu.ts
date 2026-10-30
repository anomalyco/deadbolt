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
import { animateTo, reducedMotion, rollLabel, ROLL_CSS, spring, Spring, timing, type SpringState } from "./ui/motion"

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
let accounts: Row[] = []
let focused: FieldRole = "username"
/** The site signs in username first and has one login: its row says "Continue as …". */
let continueAs = false
let active = 0
let busy = false
let mode: SurfaceMode = "accounts"
/** When the user last pressed a key or pointer in the menu: what a pick is judged at. */
let pressedAt = -Infinity
const dwell = new Dwell(500)
watchVisibility(dwell)
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
/** How long a pill says how it went before it goes. */
const FILLED_STAYS_MS = 900
const FAILED_STAYS_MS = 1800
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
/** Tells the parent the size this mode needs, whenever it changes. */
function report(grow = 0) {
  if (!token) return
  const height = Math.ceil(mode === "pill" ? 32 : mode === "save" ? offerSize().height : surface.getBoundingClientRect().height)
  const pill = document.querySelector<HTMLElement>(".pill")
  // The pill hugs its content: it is the whole pill, padding included.
  const offer = mode === "save" ? offerSize() : null
  const width = mode === "pill" && pill ? Math.ceil(pill.getBoundingClientRect().width + grow) : offer ? offer.width : undefined
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
        : continueAs && item.account.username
        ? [avatar(item.account.title), `Continue as ${item.account.username}`, item.account.title]
        : [avatar(item.account.title), item.account.title, focused === "otp" ? "Fill the current code" : item.account.username || "No username"]
  const r = h(
    "button",
    { class: `row${i === active ? " active" : ""}`, type: "button", role: "option", "aria-selected": String(i === active) },
    tile,
    h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)),
  )
  // A pointer's click only: Enter or Space on a focused row clicks it too (detail 0).
  r.addEventListener("click", (e) => e.isTrusted && e.detail > 0 && void pick(i))
  // The press shows at once, inside the frame (which doesn't move, so the
  // dwell isn't disturbed); the pick itself waits for its checks.
  r.addEventListener("pointerdown", (e) => {
    if (!e.isTrusted || e.button !== 0 || busy || mode !== "accounts") return
    active = i
    highlight(false)
    press(r)
  })
  r.addEventListener("pointermove", () => {
    if (active === i) return
    active = i
    // The pointer is the user's own hand: the highlight lands under it at once.
    highlight(false)
  })
  return r
}

/** A provider's mark: its initial on its own tint (Deadbolt draws no third-party logos). */
function providerMark(id: string): HTMLElement {
  const p = providerOf(id)
  const el = avatar(p.name)
  el.classList.add("provider")
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
  r.addEventListener("click", async (e) => {
    if (!e.isTrusted || e.detail === 0 || busy) return
    if (!dwell.settled(pressedAt)) return say(dwell.visible ? "Click again in a moment." : "This menu is covered.")
    busy = true
    try {
      if (!(await confirmPick(dwell, pressedAt))) return say("This menu is covered.")
      await send<boolean>({ type: "db:menu-unlock", token })
    } finally {
      busy = false
    }
  })
  return r
}

/** Says something under the list, or (empty) nothing at all. */
function say(text: string) {
  foot.textContent = text
  foot.hidden = !text
}

function setCaption(site: string) {
  caption.textContent = site
  caption.hidden = !site
}

/** The one highlight, which slides between rows. Its y and height spring together, and retarget mid-flight. */
const hl = { y: new Spring(0, 0.3), height: new Spring(0, 0.3), raf: 0, shown: false }

function stepHighlight() {
  highlightEl.style.transform = `translateY(${hl.y.value}px)`
  highlightEl.style.height = `${hl.height.value}px`
  hl.raf = hl.y.done && hl.height.done ? 0 : requestAnimationFrame(stepHighlight)
}

/** Puts the highlight on the active row: sliding there with `slide`, at once otherwise. */
function highlight(slide = true) {
  const rows = Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row"))
  rows.forEach((el, i) => {
    el.classList.toggle("active", i === active)
    el.setAttribute("aria-selected", String(i === active))
  })
  const el = rows[active]
  highlightEl.hidden = !el
  if (!el) return
  // Layout positions, not what's on screen: rows may be sliding.
  const y = rowsEl.offsetTop + el.offsetTop
  const height = el.offsetHeight
  if (slide && hl.shown) {
    hl.y.to(y)
    hl.height.to(height)
  } else {
    hl.y.jump(y)
    hl.height.jump(height)
  }
  hl.shown = true
  if (!hl.raf) hl.raf = requestAnimationFrame(stepHighlight)
  el.scrollIntoView({ block: "nearest" })
}

/** The row (or button) being pressed: a darker highlight and a ring on its avatar, until the pick goes ahead or doesn't. */
function press(el: HTMLElement) {
  relax()
  // Nothing in the frame animates while the press is checked: running
  // animations pause the visibility readings the check relies on.
  document.body.classList.add("held")
  el.classList.add("pressed")
  if (el.classList.contains("row")) {
    highlightEl.classList.add("pressing")
    el.querySelector(".avatar")?.classList.add("busy")
  }
}

function relax() {
  document.body.classList.remove("held")
  highlightEl.classList.remove("pressing")
  for (const el of Array.from(document.querySelectorAll(".pressed"))) el.classList.remove("pressed")
  for (const el of Array.from(document.querySelectorAll(".avatar.busy"))) el.classList.remove("busy")
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
      const anim = animateTo(r, reduced ? { opacity: "0" } : { opacity: "0", filter: "blur(3px)", transform: "scale(0.96)" }, 0.25, { fill: false })
      if (anim) anim.finished.then(finish, finish)
      else finish()
    } else if (!shown(r) && want) {
      for (const a of r.getAnimations()) a.cancel()
      r.classList.remove("leaving")
      r.hidden = false
      r.style.cssText = ""
      if (typeof r.animate === "function")
        r.animate(reduced ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, filter: "blur(3px)", transform: "scale(0.96)" }, { opacity: 1, filter: "blur(0px)", transform: "none" }], timing(0.3))
    }
  })
  if (!reduced)
    for (const [r, top] of before) {
      if (!shown(r)) continue
      const dy = top - r.getBoundingClientRect().top
      if (Math.abs(dy) > 0.5) r.animate([{ transform: `translateY(${dy}px)` }, { transform: "none" }], spring(0.4))
    }
  const left = visible()
  if (left.length && !left.includes(active)) active = left[0]
  if (left.length) highlight(true)
  else highlightEl.hidden = true
  // The rows' own animations pause the frame's visibility readings, so the
  // dwell counts from when they're over, as if the menu had moved.
  dwell.moved(performance.now())
  setTimeout(() => dwell.moved(performance.now()), NARROW_SETTLES_MS)
  port?.postMessage({ type: "db:matches", count: left.length })
}

function showStatus(status: Status) {
  accounts = []
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
  if (!dwell.settled(pressedAt)) {
    relax()
    return say(dwell.visible ? "Pick again in a moment." : COVERED)
  }
  busy = true
  if (!(await confirmPick(dwell, pressedAt))) {
    busy = false
    relax()
    return say(COVERED)
  }
  // "Sign in with …" fills nothing: the page's own button for it gets a ring, and the user clicks it.
  if ("provider" in a) return signInWith(i, a.provider)
  // Checked: now it may move. The ring spins while the fill is on its way.
  document.body.classList.remove("held")
  highlightEl.classList.remove("pressing")
  for (const el of Array.from(rowsEl.querySelectorAll(".avatar.busy"))) el.classList.add("spinning")
  const passkey = "passkey" in a
  const label = fold(rowsEl.querySelectorAll<HTMLElement>("button.row")[i]?.querySelector<HTMLElement>(".avatar") ?? null, passkey ? "Signing in…" : "Filling…")
  const ref = "identity" in a ? a.identity.ref : "card" in a ? a.card.ref : passkey ? a.passkey.ref : "account" in a ? a.account.ref : ""
  const reply = await send<PickReply>("generate" in a ? { type: "db:menu-generate", token } : { type: "db:menu-pick", token, ref })
  busy = false
  if (reply?.ok) {
    // A passkey's sign-in closes the surface from the background once it's through.
    if (passkey) return
    settle(label, "Filled", true)
    return void setTimeout(() => done(), FILLED_STAYS_MS + 450)
  }
  const message = reply?.message || "Couldn't fill. Try again."
  say(message)
  label.title = message
  settle(label, "Couldn't fill", false)
  setTimeout(() => done(), FAILED_STAYS_MS)
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
const host = { springs: null as Record<"left" | "top" | "width" | "height", Spring> | null, width: 0, raf: 0, waiters: [] as Array<{ width: number | null; go: () => void }> }

function placePill() {
  const pill = document.querySelector<HTMLElement>(".pill")
  const s = host.springs
  if (!pill) return void (host.raf = 0)
  // The frame is the pill's place plus these offsets: undo them, anchored at the right
  // (pills grow leftward from the end of the field, and from the top right of the page).
  const ox = s ? s.left.value : 0
  const oy = s ? s.top.value : 0
  const ow = s ? s.width.value : 0
  const oh = s ? s.height.value : 0
  pill.style.right = `${ox + ow}px`
  pill.style.top = `${-oy + (innerHeight - oh) / 2}px`
  const moving = s && !(s.left.done && s.top.done && s.width.done && s.height.done)
  host.raf = moving ? requestAnimationFrame(placePill) : 0
}

/** The content script's springs for the frame, as it starts or changes the fold. */
function onFold(data: { width?: unknown; at?: unknown; springs?: Record<string, SpringState> }) {
  if (mode !== "pill" || typeof data.at !== "number" || !data.springs) return
  const resume = (k: "left" | "top" | "width" | "height") => Spring.resume(data.springs![k], data.at as number)
  host.springs = { left: resume("left"), top: resume("top"), width: resume("width"), height: resume("height") }
  host.width = typeof data.width === "number" ? data.width : host.width
  placePill()
  if (!host.raf) host.raf = requestAnimationFrame(placePill)
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
 * size and place from the start. Returns the pill's label.
 */
function fold(persist: HTMLElement | null, text: string, persistIsLabel = false, lead?: HTMLElement): HTMLElement {
  mode = "pill"
  const pill = h("div", { class: "pill waiting", role: "status" })
  const label = persistIsLabel && persist ? h("span", { class: "pill-label" }) : h("span", { class: "pill-label" }, text)
  label.dataset.text = persistIsLabel && persist ? (persist.dataset.text ?? text) : text
  const mark = h("span", { class: "pill-mark", "aria-hidden": "true" }, icon("check"))
  const slots = { lead: h("span", { class: "pill-slot" }), persist: h("span", { class: "pill-slot" }) }
  if (lead) pill.append(slots.lead)
  if (persist && !persistIsLabel) pill.append(slots.persist)
  pill.append(label, mark)
  surface.classList.add("folded")
  document.body.append(pill)
  // Whatever goes fades where it is; the pill is the main change.
  for (const el of Array.from(surface.children) as HTMLElement[]) {
    el.setAttribute("aria-hidden", "true")
    el.style.pointerEvents = "none"
    animateTo(el, reducedMotion() ? { opacity: "0" } : { opacity: "0", filter: "blur(3px)", transform: "scale(0.96)" }, 0.25)
  }
  // The pill's size, before anything moves into it: the label's text and the slots' sizes.
  if (persistIsLabel && persist) label.append(...Array.from(persist.cloneNode(true).childNodes))
  const size = (slot: HTMLElement, el: HTMLElement | null | undefined, w: number) => {
    if (!el) return
    slot.style.cssText = `display:inline-block;flex-shrink:0;width:${w}px;height:${w}px`
  }
  size(slots.lead, lead, 22)
  size(slots.persist, persist && !persistIsLabel ? persist : null, 22)
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
      if (reducedMotion()) return
      const to = (asLabel ? target : el).getBoundingClientRect()
      const dx = from.left + from.width / 2 - (to.left + to.width / 2)
      const dy = from.top + from.height / 2 - (to.top + to.height / 2)
      const scale = to.width && !asLabel ? from.width / to.width : 1
      ;(asLabel ? label : el).animate([{ transform: `translate(${dx}px, ${dy}px) scale(${scale})` }, { transform: "none" }], spring(0.38))
    }
    moveIn(lead, slots.lead)
    if (persistIsLabel) moveIn(persist, slots.persist, true)
    else moveIn(persist, slots.persist)
    if (!persistIsLabel && !reducedMotion()) label.animate([{ opacity: 0 }, { opacity: 1 }], timing(0.3))
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
 * The pill says how it went. Its width leads: the new width goes to the
 * content script first, and the label rolls (and the check comes in) only
 * once the frame has started toward it.
 */
function settle(label: HTMLElement, text: string, ok: boolean) {
  const pill = label.parentElement
  if (!pill) return
  // The check takes 20px when it shows (its 14px, the gap, less its pull-in).
  const grow = widthOf(label, text) - label.getBoundingClientRect().width + (ok ? 20 : 0)
  const width = Math.ceil(pill.getBoundingClientRect().width + grow)
  report(grow)
  // The frame's width springs over .37 s from when the content script hears of
  // it; the label rolls over .45 s, a beat later, so the width stays ahead.
  whenWide(width, () =>
    setTimeout(() => {
      const mark = pill.querySelector<HTMLElement>(".pill-mark")
      if (mark && !reducedMotion()) {
        const { easing, duration } = spring(0.45)
        mark.style.transition = `width ${duration}ms ${easing}, margin-left ${duration}ms ${easing}, opacity 200ms ease-out 120ms`
      }
      rollLabel(label, text)
      relax()
      pill.classList.toggle("ok", ok)
      pill.classList.toggle("failed", !ok)
    }, WIDTH_LEAD_MS),
  )
}

// ---- Keys and presses ----------------------------------------------------------

addEventListener("pointerdown", (e) => {
  if (!e.isTrusted) return
  pressedAt = e.timeStamp
  // The keyboard may pick after a press only if the press itself would have.
  const press = entry.pressed()
  if (dwell.settled(e.timeStamp)) void confirmPick(dwell, e.timeStamp).then((ok) => ok && entry.confirmed(press))
}, true)
addEventListener("focus", (e) => void (e.isTrusted && e.target === window && entry.focused(performance.now())))
addEventListener("blur", (e) => void (e.target === window && entry.blurred()))

document.addEventListener("keydown", (e) => {
  if (e.isTrusted) pressedAt = e.timeStamp
  if (e.key === "Escape") return void send({ type: "db:menu-dismiss", token })
  if (mode === "save") return
  if (e.key === "Enter" || e.key === " ") e.preventDefault()
  const rows = visible()
  if (!rows.length || mode !== "accounts") return
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
  highlight(true)
})

function show(reply: MenuLoadReply) {
  if (reply.kind === "offer") return showOffer(reply)
  if (reply.kind === "notice") return showNotice(reply)
  if (mode !== "accounts") return
  if (reply.kind === "status") return showStatus(reply.status)
  if (reply.kind === "forms") return showForms(reply)
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
    highlightEl.hidden = true
    rowsEl.replaceChildren(notice(icon("keyhole"), "No logins here", `Nothing saved for ${reply.site}`))
    setCaption("")
    return say("")
  }
  rowsEl.replaceChildren(...accounts.map(row))
  // No site over logins: they're only ever the page's own site's (or a same-site frame's), which the page shows.
  setCaption("")
  say("")
  // The list is already at rest when it opens: no slide on the first paint.
  if (query) for (const [i, r] of Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row")).entries()) r.hidden = !matches(accounts[i], query)
  const left = visible()
  if (left.length && !left.includes(active)) active = left[0]
  highlight(false)
  if (query) port?.postMessage({ type: "db:matches", count: left.length })
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
    highlightEl.hidden = true
    rowsEl.replaceChildren(notice(icon(reply.form === "card" ? "card" : "keyhole"), reply.form === "card" ? "No cards saved" : "No addresses saved", "Add one in Deadbolt"))
    setCaption("")
    return say("")
  }
  rowsEl.replaceChildren(...accounts.map(row))
  // Where a pick goes, always: a payment provider's frames on the site, or the site itself.
  setCaption(reply.into ? `Into ${reply.into} on ${reply.site}` : `On ${reply.site}`)
  say(reply.passphrase ? "Deadbolt asks for your passphrase first." : reply.verify ? "Deadbolt may ask for Touch ID." : "")
  if (query) for (const [i, r] of Array.from(rowsEl.querySelectorAll<HTMLElement>("button.row")).entries()) r.hidden = !matches(accounts[i], query)
  const left = visible()
  if (left.length && !left.includes(active)) active = left[0]
  highlight(false)
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
  const pill = h("div", { class: "pill ok", role: "status" }, avatar(notice.title), label, h("span", { class: "pill-mark", "aria-hidden": "true" }, icon("check")))
  document.body.append(pill)
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
  document.body.classList.add("save")
  document.body.dataset.offer = offerState
  const status = h("p", { class: "offer-status", role: "status" })
  const saveLabel = h("span", { class: "roll-label" }, "Save")
  saveLabel.dataset.text = "Save"
  const save = h("button", { class: "btn primary", type: "button" }, saveLabel)
  const later = h("button", { class: "btn", type: "button" }, "Not now")
  const never = h("button", { class: "link never", type: "button" }, "Never for this site")
  const bar = h("span", { class: "bar", "aria-hidden": "true" })
  const mark = h("span", { class: "offer-mark", "aria-hidden": "true" }, svg(ICONS.deadbolt))
  const row = h("div", { class: "offer-row" }, mark, h("h1", { class: "offer-title" }, offer.update ? "Update password?" : "Save login?"), save)
  const section = h(
    "section",
    { class: "offer", "aria-label": offer.update ? "Update password" : "Save login" },
    row,
    h(
      "div",
      { class: "offer-more" },
      h("p", { class: "offer-user" }, h("span", { class: "value" }, offer.username), h("span", { class: "site" }, ` · ${offer.site}`)),
      status,
      h("div", { class: "offer-actions" }, never, later),
    ),
    bar,
  )
  const dot = h("button", { class: "dot", type: "button", "aria-label": offer.update ? "Update password?" : "Save login?" }, svg(ICONS.deadbolt))
  surface.replaceChildren(section, dot)

  // The compact pill: the top row, from the mark (with the row's padding) to the corner.
  const compactWidth = () => Math.ceil(section.getBoundingClientRect().right - mark.getBoundingClientRect().left + 12)
  offerSize = () => {
    if (offerState === "dot") return { width: DOT, height: DOT }
    const box = section.getBoundingClientRect()
    if (offerState === "open") return { width: Math.ceil(box.width), height: Math.ceil(box.height) }
    return { width: compactWidth(), height: ROW }
  }
  // The bar runs along the compact pill's bottom edge.
  bar.style.width = `${compactWidth()}px`

  // ---- Shape ----
  let grace: ReturnType<typeof setTimeout> | undefined
  let reopenedAt = -Infinity
  const shape = (next: OfferState) => {
    clearTimeout(grace)
    if (next === offerState || mode !== "save") return
    const fromDot = offerState === "dot"
    offerState = next
    document.body.dataset.offer = next
    if (fromDot) reopenedAt = performance.now()
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
  dot.addEventListener("focus", () => shape("compact"))
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
  }
  say("")
  const answer = async (choice: OfferChoice, e: MouseEvent) => {
    // Real presses only; Enter or Space only once the user came into the surface themselves.
    if (!e.isTrusted || busy || offerState === "dot" || (e.detail === 0 && !entry.entered)) return
    if (!dwell.settled(pressedAt)) {
      relax()
      shape("open")
      return say(dwell.visible ? "Press again in a moment." : "This offer is covered. Nothing was saved.")
    }
    busy = true
    if (e.currentTarget instanceof HTMLElement) press(e.currentTarget)
    if (!(await confirmPick(dwell, pressedAt))) {
      busy = false
      relax()
      shape("open")
      return say("This offer is covered. Nothing was saved.")
    }
    document.body.classList.remove("held")
    // "Saving…" rolls in the button itself, and stays long enough to read.
    const shownAt = performance.now()
    if (choice === "save") {
      document.body.classList.add("busy")
      rollLabel(saveLabel, "Saving…")
    }
    const reply = await send<ChooseReply>({ type: "db:surface-choose", token, choice })
    if (choice !== "save") return leaveLikeSave()
    if (reply?.ok) {
      await new Promise((r) => setTimeout(r, Math.max(0, SAVING_READS_MS - (performance.now() - shownAt))))
      const label = fold(saveLabel, "Saving…", true, mark)
      // Once the pill has its place, its label rolls on to the result: "Saved"
      // for a new login and an update alike, so the pill is the same either way.
      return void setTimeout(() => {
        settle(label, "Saved", true)
        setTimeout(() => done(true), FILLED_STAYS_MS + 450)
      }, 380)
    }
    if (!reply || ("gone" in reply && reply.gone)) return leaveLikeSave()
    // Locked or busy: open, say so in place, and let Save be pressed again, for a while.
    busy = false
    relax()
    document.body.classList.remove("busy")
    rollLabel(saveLabel, "Save")
    shape("open")
    say(reply.message)
    rearm()
  }
  // The press shows at once; what it does waits for the checks.
  for (const b of [save, later, never]) b.addEventListener("pointerdown", (e) => e.isTrusted && e.button === 0 && !busy && press(b))
  save.addEventListener("click", (e) => void answer("save", e))
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
  // Came with the token, so it's the content script's: the page never sees it.
  if (channel) {
    port = channel
    channel.onmessage = (e: MessageEvent<{ type?: unknown }>) => {
      const data = e.data as { type?: unknown; query?: unknown; near?: unknown }
      if (data?.type === "db:menu-enter") entry.offered(performance.now(), document.hasFocus())
      else if (data?.type === "db:fold") onFold(e.data as Parameters<typeof onFold>[0])
      else if (data?.type === "db:filter" && typeof data.query === "string") narrow(data.query)
      // The pointer near the offer pauses its bar, as being on it does.
      else if (data?.type === "db:near") document.body.classList.toggle("near", data.near === true)
      else if (data?.type === "db:tuck") tuck()
      else if (data?.type === "db:away") away()
    }
  }
  // Keep the frame exactly as big as the content (fonts load late and change
  // sizes): the visibility guard only trusts a fully visible surface.
  report()
}

addEventListener("message", (e: MessageEvent<{ type?: unknown; token?: unknown }>) => {
  if (window.parent === window || e.source !== window.parent) return
  // The page can send this too, but it only ever makes the menu wait longer.
  if (e.data?.type === "db:menu-moved") return dwell.moved(performance.now())
  if (!token && e.data?.type === "db:menu-token" && typeof e.data.token === "string") void claim(e.data.token, e.origin, e.ports[0])
})
if (window.parent !== window) window.parent.postMessage({ type: "db:menu-ready" }, "*")

// Unlocking in the app, or a sync, updates the open menu in place.
chrome.runtime.onMessage.addListener((message: StatusChanged) => {
  if (message?.type === "db:status") void load()
})
