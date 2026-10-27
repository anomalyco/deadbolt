// The inline menu under a login field. It runs as an extension page inside an
// iframe on the login page, so the page can neither read nor click it. Ported
// from Foyer (github.com/R44VC0RP/foyer, src/menu.ts, by Ryan Vogel).

import type { FieldRole, MenuLoadReply, MenuPasskey, PickReply, Status, StatusChanged, ToBackground } from "./messages"
import type { Account } from "./protocol"
import { confirmPick, Dwell, Entry, h, icon, monogram, reportHeight, watchVisibility } from "./ui/dom"

/** A row: a login to fill, or a passkey the page's sign-in is waiting for. */
type Row = { passkey: MenuPasskey } | { account: Account }

// Set once the background accepts a token from the parent window.
let token = ""
let parentOrigin = ""
const list = document.getElementById("list")!
const foot = document.getElementById("foot")!
let accounts: Row[] = []
/** The menu offers a generated password (one row) instead of accounts. */
let generating = false
let focused: FieldRole = "username"
let active = 0
let busy = false
/** When the user last pressed a key or pointer in the menu: what a pick is judged at. */
let pressedAt = -Infinity
const dwell = new Dwell(500)
watchVisibility(dwell)
/** Whether the keyboard may pick: see Entry. */
const entry = new Entry()
const COVERED = "This menu is covered. Nothing was filled."

function send<T>(message: ToBackground): Promise<T | null> {
  return chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>
}

function row(item: Row, i: number): HTMLElement {
  const [tile, title, sub] =
    "passkey" in item
      ? [h("span", { class: "tile passkey", "aria-hidden": "true" }, icon("passkey")), item.passkey.username || "Passkey", `Passkey · ${item.passkey.vault}`]
      : [monogram(item.account.title), item.account.title, focused === "otp" ? "Fill the current code" : item.account.username || "No username"]
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
    highlight()
  })
  return r
}

function generateRow(): HTMLElement {
  const r = h(
    "button",
    { class: "row active", type: "button", role: "option", "aria-selected": "true" },
    h("span", { class: "tile soft", "aria-hidden": "true" }, icon("key")),
    h("span", { class: "text" }, h("span", { class: "title" }, "Use a strong password"), h("span", { class: "sub" }, "Saved only if you sign up with it")),
    h("kbd", { class: "enter", "aria-hidden": "true" }, "⏎"),
  )
  r.addEventListener("click", (e) => e.isTrusted && e.detail > 0 && void pick(0))
  return r
}

function notice(glyph: Element, title: string, sub: string): HTMLElement {
  return h("div", { class: "row notice" }, h("span", { class: "tile soft" }, glyph), h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub" }, sub)))
}

function footer(left: string, right = "") {
  foot.replaceChildren(h("span", { class: "foot-site" }, icon("keyhole"), h("span", { class: "mono" }, left)), h("span", { class: "foot-hint" }, right))
}

function highlight() {
  Array.from(list.children).forEach((el, i) => {
    el.classList.toggle("active", i === active)
    el.setAttribute("aria-selected", String(i === active))
  })
  ;(list.children[active] as HTMLElement | undefined)?.scrollIntoView({ block: "nearest" })
}

function showStatus(status: Status) {
  accounts = []
  generating = false
  if (status.state === "locked") {
    list.replaceChildren(notice(icon("lock"), "Deadbolt is locked", "Unlock it in the app, then come back"))
    footer("Deadbolt", "Locked")
  } else {
    list.replaceChildren(notice(icon("plug"), "Deadbolt isn't available", "Open the toolbar button to see why"))
    footer("Deadbolt")
  }
}

/**
 * A pick counts only if the menu had been fully visible and still for half a
 * second when the key or pointer went down, and stays so for a moment after
 * (see confirmPick). Mouse and keyboard alike. Enter counts only once the
 * user entered the menu themselves (see Entry).
 */
async function pick(i: number) {
  const a = accounts[i]
  if ((!a && !generating) || busy) return
  if (!dwell.settled(pressedAt)) return footer("", dwell.visible ? "Pick again in a moment." : COVERED)
  busy = true
  if (!(await confirmPick(dwell, pressedAt))) {
    busy = false
    return footer("", COVERED)
  }
  footer("", a && "passkey" in a ? "Signing in…" : "Filling…")
  const reply = await send<PickReply>(!a ? { type: "db:menu-generate", token } : { type: "db:menu-pick", token, ref: "passkey" in a ? a.passkey.ref : a.account.ref })
  busy = false
  if (!reply?.ok) footer("", reply?.message || "Couldn't fill. Try again.")
}

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
  if (e.key === "Enter" || e.key === " ") e.preventDefault()
  if (generating) return void (e.key === "Enter" && (entry.entered ? pick(0) : footer("", "Press ↓ in the field to choose.")))
  if (!accounts.length) return
  if (e.key === "ArrowDown") active = Math.min(active + 1, accounts.length - 1)
  else if (e.key === "ArrowUp") active = Math.max(active - 1, 0)
  else if (e.key === "Enter") return void (entry.entered ? pick(active) : footer("", "Press ↓ in the field to choose."))
  else return
  e.preventDefault()
  highlight()
})

function show(reply: MenuLoadReply) {
  if (reply.kind === "status") return showStatus(reply.status)
  if (reply.kind === "generate") {
    accounts = []
    generating = true
    active = 0
    list.replaceChildren(generateRow())
    return footer(reply.site, "⏎ to fill")
  }
  generating = false
  accounts = [...(reply.passkeys ?? []).map((passkey) => ({ passkey })), ...reply.accounts.map((account) => ({ account }))]
  focused = reply.focused
  active = Math.min(active, Math.max(accounts.length - 1, 0))
  if (!accounts.length) {
    list.replaceChildren(notice(icon("keyhole"), "No logins here", `Nothing saved for ${reply.site}`))
    return footer(reply.site)
  }
  list.replaceChildren(...accounts.map(row))
  footer(reply.site, "↑↓ to choose")
}

async function load() {
  const reply = token ? await send<MenuLoadReply>({ type: "db:menu-load", token, parent: parentOrigin }) : null
  if (reply) show(reply)
}

/**
 * The content script that opened this menu posts its token from the parent
 * window. The page is that window too and can post first, so every offer is
 * tried and the first the background accepts wins.
 */
async function claim(offered: string, origin: string, port: MessagePort | undefined) {
  const reply = await send<MenuLoadReply>({ type: "db:menu-load", token: offered, parent: origin })
  if (token) return
  if (!reply) return footer("", "This menu has expired.")
  token = offered
  parentOrigin = origin
  show(reply)
  // Came with the token, so it's the content script's: the page never sees it.
  if (port) port.onmessage = (e: MessageEvent<{ type?: unknown }>) => void (e.data?.type === "db:menu-enter" && entry.offered(performance.now(), document.hasFocus()))
  // Keep the frame exactly as tall as the content (fonts load late and change
  // heights): the visibility guard only trusts a fully visible menu.
  reportHeight((height) => void send({ type: "db:menu-resize", token, height }))
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
