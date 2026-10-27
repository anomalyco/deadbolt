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

import type { ChooseReply, FieldRole, MenuLoadReply, MenuPasskey, OfferChoice, PickReply, Status, StatusChanged, SurfaceMode, ToBackground } from "./messages"
import type { Account } from "./protocol"
import { avatar, confirmPick, Dwell, Entry, h, icon, ICONS, svg, watchVisibility } from "./ui/dom"
import { animateTo, reducedMotion, rollLabel, ROLL_CSS, spring, Spring, timing, type SpringState } from "./ui/motion"

/** A row: a login to fill, or a passkey the page's sign-in is waiting for. */
type Row = { passkey: MenuPasskey } | { account: Account }

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
const listEl = document.getElementById("list")!
let accounts: Row[] = []
let focused: FieldRole = "username"
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
/** How long a pill says how it went before it goes. */
const FILLED_STAYS_MS = 900
const FAILED_STAYS_MS = 1800
/** How far the frame's width leads a pill's label roll. */
const WIDTH_LEAD_MS = 80
/** "Saving…" stays in the Save button at least this long, so it can be read. */
const SAVING_READS_MS = 520

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
/** Tells the parent the size this mode needs, whenever it changes. */
function report(grow = 0) {
  if (!token) return
  const height = Math.ceil(mode === "pill" ? 32 : surface.getBoundingClientRect().height)
  const pill = document.querySelector<HTMLElement>(".pill")
  // The pill hugs its content: it is the whole pill, padding included.
  const width = mode === "pill" && pill ? Math.ceil(pill.getBoundingClientRect().width + grow) : mode === "save" ? 320 : undefined
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

function row(item: Row, i: number): HTMLElement {
  const [tile, title, sub] =
    "passkey" in item
      ? [avatar("", icon("passkey")), item.passkey.username || "Passkey", `Passkey · ${item.passkey.vault}`]
      : [avatar(item.account.title), item.account.title, focused === "otp" ? "Fill the current code" : item.account.username || "No username"]
  const r = h(
    "button",
    { class: `row${i === active ? " active" : ""}`, type: "button", role: "option", "aria-selected": String(i === active) },
    tile,
    h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)),
    h("kbd", { class: "enter", "aria-hidden": "true" }, "⏎"),
  )
  // A pointer's click only: Enter or Space on a focused row clicks it too (detail 0).
  r.addEventListener("click", (e) => e.isTrusted && e.detail > 0 && void pick(i))
  r.addEventListener("pointermove", () => {
    if (active === i) return
    active = i
    // The pointer is the user's own hand: the highlight lands under it at once.
    highlight(false)
  })
  return r
}

function notice(glyph: Element, title: string, sub: string): HTMLElement {
  return h("div", { class: "row notice" }, avatar("", glyph), h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)))
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
  const y = el.getBoundingClientRect().top - listEl.getBoundingClientRect().top + listEl.scrollTop
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

function showStatus(status: Status) {
  accounts = []
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
  if (!a || busy || mode !== "accounts") return
  if (!dwell.settled(pressedAt)) return say(dwell.visible ? "Pick again in a moment." : COVERED)
  busy = true
  if (!(await confirmPick(dwell, pressedAt))) {
    busy = false
    return say(COVERED)
  }
  const passkey = "passkey" in a
  const label = fold(rowsEl.querySelectorAll<HTMLElement>("button.row")[i]?.querySelector<HTMLElement>(".avatar") ?? null, passkey ? "Signing in…" : "Filling…")
  const reply = await send<PickReply>({ type: "db:menu-pick", token, ref: passkey ? a.passkey.ref : a.account.ref })
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
  if (!accounts.length || mode !== "accounts") return
  if (e.key === "ArrowDown") active = Math.min(active + 1, accounts.length - 1)
  else if (e.key === "ArrowUp") active = Math.max(active - 1, 0)
  else if (e.key === "Enter") return void (entry.entered ? pick(active) : say("Press ↓ in the field to choose."))
  else return
  e.preventDefault()
  highlight(true)
})

function show(reply: MenuLoadReply) {
  if (reply.kind === "offer") return showOffer(reply)
  if (mode !== "accounts") return
  if (reply.kind === "status") return showStatus(reply.status)
  accounts = [...(reply.passkeys ?? []).map((passkey) => ({ passkey })), ...reply.accounts.map((account) => ({ account }))]
  focused = reply.focused
  active = Math.min(active, Math.max(accounts.length - 1, 0))
  if (!accounts.length) {
    highlightEl.hidden = true
    rowsEl.replaceChildren(notice(icon("keyhole"), "No logins here", `Nothing saved for ${reply.site}`))
    setCaption("")
    return say("")
  }
  rowsEl.replaceChildren(...accounts.map(row))
  setCaption(accounts.length >= 2 ? reply.site : "")
  say("")
  // The list is already at rest when it opens: no slide on the first paint.
  highlight(false)
}

// ---- The save offer --------------------------------------------------------------

/**
 * "Save login?" after a confirmed sign-in, at the top right of the page. It
 * shows the site and username only; the password stays in the background.
 * A bar empties over twelve seconds (paused while the pointer or focus is
 * on it), then the surface leaves and the offer waits in the toolbar.
 */
function showOffer(offer: Extract<MenuLoadReply, { kind: "offer" }>) {
  mode = "save"
  document.body.classList.add("save")
  const status = h("p", { class: "offer-status", role: "status" })
  const saveLabel = h("span", { class: "roll-label" }, "Save")
  saveLabel.dataset.text = "Save"
  const save = h("button", { class: "btn primary", type: "button" }, saveLabel)
  const later = h("button", { class: "btn", type: "button" }, "Not now")
  const never = h("button", { class: "link never", type: "button" }, "Never for this site")
  const bar = h("span", { class: "bar", "aria-hidden": "true" })
  bar.style.animationDuration = `${OFFER_STAYS_MS}ms`
  let barEnded = false
  bar.addEventListener("animationend", () => {
    barEnded = true
    if (!busy) leaveLikeSave()
  })
  /** Runs the bar again for a while, after a save that failed once its time was up. */
  const rearm = () => {
    barEnded = false
    bar.style.animation = "none"
    void bar.offsetWidth
    bar.style.animation = ""
    bar.style.animationDuration = `${OFFER_REARM_MS}ms`
  }
  surface.replaceChildren(
    h(
      "section",
      { class: "offer", "aria-label": offer.update ? "Update password" : "Save login" },
      h(
        "div",
        { class: "offer-head" },
        h("span", { class: "offer-mark", "aria-hidden": "true" }, svg(ICONS.deadbolt)),
        h("h1", { class: "offer-title" }, offer.update ? "Update password?" : `Save login for ${offer.site}?`),
      ),
      h("p", { class: "offer-user" }, h("span", { class: "value" }, offer.username), offer.update ? h("span", { class: "site" }, ` · ${offer.site}`) : null),
      status,
      h("div", { class: "offer-actions" }, never, later, save),
      bar,
    ),
  )
  const say = (text: string) => {
    status.hidden = !text
    if (text) rollLabel(status, text)
  }
  say("")
  const answer = async (choice: OfferChoice, e: MouseEvent) => {
    // Real presses only; Enter or Space only once the user came into the surface themselves.
    if (!e.isTrusted || busy || (e.detail === 0 && !entry.entered)) return
    if (!dwell.settled(pressedAt)) return say(dwell.visible ? "Press again in a moment." : "This offer is covered. Nothing was saved.")
    busy = true
    if (!(await confirmPick(dwell, pressedAt))) {
      busy = false
      return say("This offer is covered. Nothing was saved.")
    }
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
      const mark = document.querySelector<HTMLElement>(".offer-mark") ?? h("span", { class: "offer-mark", "aria-hidden": "true" }, svg(ICONS.deadbolt))
      const label = fold(saveLabel, "Saving…", true, mark)
      // Once the pill has its place, its label rolls on to the result: "Saved"
      // for a new login and an update alike, so the pill is the same either way.
      return void setTimeout(() => {
        settle(label, "Saved", true)
        setTimeout(() => done(true), FILLED_STAYS_MS + 450)
      }, 380)
    }
    if (!reply || ("gone" in reply && reply.gone)) return leaveLikeSave()
    // Locked or busy: say so in place, and let Save be pressed again, for a while.
    busy = false
    document.body.classList.remove("busy")
    rollLabel(saveLabel, "Save")
    say(reply.message)
    if (barEnded) rearm()
  }
  save.addEventListener("click", (e) => void answer("save", e))
  later.addEventListener("click", (e) => void answer("later", e))
  never.addEventListener("click", (e) => void answer("never", e))
  report()
}

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
      if (e.data?.type === "db:menu-enter") entry.offered(performance.now(), document.hasFocus())
      else if (e.data?.type === "db:fold") onFold(e.data as Parameters<typeof onFold>[0])
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
