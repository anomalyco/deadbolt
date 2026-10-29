// Toolbar popup: how Deadbolt is doing, an offer to save or update the login
// just used, and this site's logins with Fill and Copy username. Passwords are
// never copied: anything on the clipboard can be read by every app, and
// clipboard managers keep it.

import type { LearnReply, Learning, PickReply, PopupReply, Status, StatusChanged, ToBackground } from "./messages"
import type { Account } from "./protocol"
import { provider } from "./signin"
import { h, icon, ICONS, monogram, svg } from "./ui/dom"
import { offerCard } from "./ui/offer"
import { passkeyCard } from "./ui/passkey"
import { mountVault } from "./vault/app"
import { animateTo, reducedMotion, ROLL_CSS, timing } from "./ui/motion"

declare const DEADBOLT_NATIVE: boolean | undefined
/** Native builds use `deadbolt browser-host`; `--standalone` uses the browser-only device on device.html. */
const native = typeof DEADBOLT_NATIVE !== "undefined" && DEADBOLT_NATIVE === true

const root = document.getElementById("app")!
if (native) document.head.append(h("style", {}, ROLL_CSS))
let tabId: number | undefined
let rendered = ""
let learningShown = false

function send<T>(message: ToBackground): Promise<T | null> {
  return chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>
}

const code = (text: string) => h("code", {}, text)

function commandBlock(command: string): HTMLElement {
  const copy = h("button", { class: "icon-button", type: "button", title: "Copy command", "aria-label": "Copy command" }, icon("copy"))
  copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(command).catch(() => {})
    swapIcon(copy, "check")
  })
  return h("div", { class: "command" }, h("code", {}, command), copy)
}

function swapIcon(button: HTMLElement, name: "check" | "copy") {
  button.replaceChildren(icon(name))
  button.classList.add("confirmed")
  setTimeout(() => {
    button.replaceChildren(icon("copy"))
    button.classList.remove("confirmed")
  }, 1400)
}

// Deadbolt has no URL scheme or host message that opens the app, so "Open
// Deadbolt" says where to find it instead of launching it.
function openApp() {
  if (!native) {
    void chrome.tabs.create({ url: chrome.runtime.getURL("device.html") })
    window.close()
    return
  }
  const help = document.getElementById("open-help")
  if (help) {
    help.hidden = !help.hidden
    return
  }
  document.querySelector(".body")?.append(
    h(
      "section",
      { class: "open-help", id: "open-help" },
      para("Open ", h("strong", {}, "Deadbolt"), " from Applications or Spotlight. From a terminal, ", code("deadbolt unlock"), " unlocks it too."),
    ),
  )
}

function pill(status: Status): HTMLElement {
  const [label, tone] =
    status.state === "ready"
      ? ["Unlocked", "ok"]
      : status.state === "locked"
        ? ["Locked", "warn"]
        : status.state === "connecting"
          ? ["Connecting", ""]
          : status.state === "not-set-up"
            ? ["Not set up", ""]
            : ["Not connected", "bad"]
  return h("span", { class: `pill ${tone}` }, label)
}

function state(glyph: Element, title: string, ...body: Array<Node | string | null>): HTMLElement {
  return h("section", { class: "state" }, h("span", { class: "state-icon" }, glyph), h("h2", {}, title), ...body.filter((b): b is Node | string => b !== null))
}

function para(...parts: Array<Node | string>): HTMLElement {
  const p = h("p", { class: "muted" })
  p.append(...parts)
  return p
}

function statusBody(status: Status): HTMLElement | null {
  switch (status.state) {
    case "connecting":
      return state(icon("keyhole"), "Connecting to Deadbolt…")
    case "not-installed":
      return state(
        icon("plug"),
        "Connect Deadbolt to this browser",
        para("Deadbolt's browser helper isn't installed. Run this in a terminal, then open this menu again:"),
        commandBlock("deadbolt browser install"),
      )
    case "disconnected":
      return state(
        icon("plug"),
        "Can't reach Deadbolt",
        para(status.message),
        para("If you moved or updated Deadbolt, install the browser helper again:"),
        commandBlock("deadbolt browser install"),
      )
    case "unavailable":
      return state(icon("plug"), "Deadbolt couldn't start", para(status.detail || "The agent didn't answer."))
    case "not-set-up":
      if (!native) return state(icon("keyhole"), "Set up Deadbolt", para("Pair with a device that has your vault, or create a new vault."), openButton(true, "Set up"))
      return state(icon("keyhole"), "Set up Deadbolt first", para("Create your vault in the Deadbolt app, or run ", code("deadbolt init"), "."), openButton(true))
    case "locked": {
      if (!native) return state(icon("lock"), "Unlock Deadbolt", para(status.detail || "Unlock it to fill passwords."), openButton(true, "Unlock"))
      return state(
        icon("lock"),
        "Unlock Deadbolt",
        para("Unlock it in the app, or run ", code("deadbolt unlock"), ". The browser never asks for your passphrase."),
        openButton(true),
      )
    }
    case "ready":
      return null
  }
}

function openButton(primary: boolean, label = "Open Deadbolt"): HTMLElement {
  const b = h("button", { class: `btn${primary ? " primary" : ""}`, type: "button" }, label)
  b.addEventListener("click", openApp)
  return b
}

function accountRow(a: Account, first: boolean): HTMLElement {
  const fill = h("button", { class: `btn${first ? " primary" : ""}`, type: "button" }, "Fill")
  const copy = h(
    "button",
    {
      class: "icon-button",
      type: "button",
      title: a.username ? "Copy username" : "No username",
      "aria-label": a.username ? `Copy username ${a.username}` : "No username",
    },
    icon("copy"),
  )
  if (!a.username) copy.setAttribute("disabled", "")
  // "Sign in with Google · kit@gmail.com" for a login that signs in with another account.
  const via = a.signIn ? `Sign in with ${provider(a.signIn.provider).name}${a.signIn.account ? ` · ${a.signIn.account}` : ""}` : ""
  const sub = via && !a.hasPassword ? via : [a.username || "No username", a.hasTotp ? "2FA code" : "", via].filter(Boolean).join(" · ")
  // One that signs in with another account and has no password has nothing to fill.
  const fillable = a.hasPassword || !a.signIn
  const row = h(
    "div",
    { class: "account" },
    monogram(a.title),
    h("div", { class: "account-text" }, h("div", { class: "account-title" }, a.title), h("div", { class: "account-sub" }, sub)),
    copy,
    fillable ? fill : null,
  )
  copy.addEventListener("click", async () => {
    if (!a.username) return
    await navigator.clipboard.writeText(a.username).catch(() => {})
    swapIcon(copy, "check")
  })
  fill.addEventListener("click", async () => {
    if (tabId === undefined) return
    fill.setAttribute("disabled", "")
    const reply = await send<PickReply>({ type: "db:popup-fill", tabId, ref: a.ref })
    if (reply?.ok) return window.close()
    fill.removeAttribute("disabled")
    showError(reply?.message || "Couldn't fill.")
  })
  return row
}

function showError(message: string) {
  const el = document.getElementById("error")
  if (!el) return
  el.textContent = message
  el.hidden = false
}

/** "Saving is off for acme.com. Turn on": undoes Never for this site. */
function savingOffLine(site: string): HTMLElement {
  const on = h("button", { class: "link", type: "button" }, "Turn on")
  on.addEventListener("click", async () => {
    if (tabId === undefined) return
    on.setAttribute("disabled", "")
    await send<boolean>({ type: "db:popup-saving-on", tabId })
    void render(true)
  })
  return h("p", { class: "note saving-off" }, h("span", {}, `Saving is off for ${site}.`), on)
}

async function learn(on: boolean, button: HTMLElement, status: HTMLElement) {
  if (tabId === undefined) return
  button.setAttribute("disabled", "")
  const reply = await send<LearnReply>({ type: "db:popup-learn", tabId, on })
  button.removeAttribute("disabled")
  if (reply && !reply.ok) {
    status.textContent = reply.message || "Couldn't start learning."
    status.hidden = false
    return
  }
  // Learning starts with the user signing in by hand: out of the way.
  if (on) return window.close()
  void render(true)
}

/** "Learning acme.com": sign in by hand, Deadbolt records the form's shape. */
function learningCard(l: Learning): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const stop = h("button", { class: "btn primary", type: "button" }, "Stop")
  stop.addEventListener("click", () => void learn(false, stop, status))
  const minutes = Math.max(1, Math.ceil((l.until - Date.now()) / 60_000))
  return h(
    "section",
    { class: "offer", "aria-label": "Learning this site" },
    h("h2", {}, `Learning ${l.site}`),
    para("Sign in by hand. Deadbolt records how the form is built and which fields you type into, never what you type."),
    para("Frames from other sites on the page, like chat widgets and ads, are logged too, by shape only."),
    h(
      "div",
      { class: "box" },
      h("div", { class: "line" }, h("span", { class: "muted" }, "Steps logged"), h("span", { class: "value" }, String(l.steps))),
      h("div", { class: "line" }, h("span", { class: "muted" }, "Stops"), h("span", { class: "value" }, `after you sign in, or in ${minutes} min`)),
    ),
    status,
    h("div", { class: "buttons" }, stop),
  )
}

/** "Form not filling here? Learn this site". */
function learnLine(): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const start = h("button", { class: "link", type: "button" }, "Learn this site")
  start.addEventListener("click", () => void learn(true, start, status))
  return h("div", {}, h("p", { class: "note saving-off" }, h("span", {}, "Deadbolt missing the form here?"), start), status)
}

/** With an offer showing, its Save is the one primary button. */
function siteBody(reply: PopupReply): HTMLElement {
  if (reply.unfillable === "scheme") return state(icon("keyhole"), "Nothing to fill here", para("Open a website to see its logins."))
  if (reply.unfillable === "insecure")
    return state(icon("lock"), "Not a secure page", para(`Deadbolt fills only on https pages and local dev hosts. ${reply.host ?? "This page"} uses plain http.`))
  const error = h("p", { class: "error", id: "error", role: "status" })
  error.hidden = !reply.error
  if (reply.error) error.textContent = reply.error
  const site = reply.site || reply.host || ""
  if (!reply.accounts.length)
    return h(
      "section",
      { class: "site" },
      h("div", { class: "section-head" }, h("span", { class: "label" }, "Logins"), h("span", { class: "mono muted" }, site)),
      h("div", { class: "empty" }, `No logins saved for ${site}. Sign in and Deadbolt offers to save it.`),
      error,
    )
  return h(
    "section",
    { class: "site" },
    h("div", { class: "section-head" }, h("span", { class: "label" }, "Logins"), h("span", { class: "mono muted" }, site)),
    h("div", { class: "list" }, ...reply.accounts.map((a, i) => accountRow(a, i === 0 && !reply.offer))),
    error,
    h("p", { class: "note" }, icon("lock"), h("span", {}, "Deadbolt never copies passwords: any app can read the clipboard. Fill puts them straight into the page.")),
  )
}

/** A lock button for the browser-only Deadbolt, which has no app to lock it from. */
function lockButton(): HTMLElement {
  const b = h("button", { class: "link", type: "button" }, icon("lock"), "Lock")
  b.addEventListener("click", async () => {
    b.setAttribute("disabled", "")
    await send<Status>({ type: "db:popup-lock" })
    void render(true)
  })
  return b
}

async function render(changed = false) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  tabId = tab?.id
  const reply = tabId === undefined ? null : await send<PopupReply>({ type: "db:popup-load", tabId })
  paint(reply, changed)
}

function paint(reply: PopupReply | null, changed: boolean) {
  const status: Status = reply?.status ?? { state: "disconnected", message: "The extension's background worker didn't answer." }
  const body = statusBody(status) ?? (reply ? siteBody(reply) : null)

  // Status pushes re-render; skip it when nothing visible changed.
  const key = JSON.stringify([status, reply?.site, reply?.accounts, reply?.unfillable, reply?.error, reply?.offer, reply?.passkey, reply?.savingOff, reply?.learning])
  learningShown = !!reply?.learning
  if (key === rendered && !changed) return
  const first = rendered === ""
  rendered = key

  // Locked and not set up already have an Open Deadbolt button.
  const hasOpen = status.state === "locked" || status.state === "not-set-up"
  const open = hasOpen ? null : h("button", { class: "link", type: "button" }, "Open Deadbolt", icon("arrow"))
  open?.addEventListener("click", openApp)
  const oldBody = root.querySelector<HTMLElement>(".body")
  const oldTop = oldBody?.offsetTop ?? 0
  const body2 = h(
      "div",
      { class: "body" },
      ...(reply?.passkey
        ? [
            // Touch ID, or the page, takes it from here.
            passkeyCard(reply.passkey, tabId, { chosen: () => window.close(), ended: () => void render(true) }),
          ]
        : [
            reply?.learning ? learningCard(reply.learning) : null,
            reply?.offer ? offerCard(reply.offer, tabId, () => void render(true)) : null,
            body,
            reply?.savingOff && !reply.offer ? savingOffLine(reply.savingOff) : null,
            // Learning keeps no logins, so it works locked too; it needs a page to learn.
            reply && !reply.learning && !reply.unfillable && reply.host && (status.state === "ready" || status.state === "locked") ? learnLine() : null,
          ]),
  )
  root.replaceChildren(
    h("header", { class: "top" }, h("span", { class: "logo" }, svg(ICONS.deadbolt)), h("span", { class: "brand" }, "Deadbolt"), pill(status)),
    body2,
    h("footer", { class: "bottom" }, open ?? h("span"), status.state === "ready" ? (native ? h("span", { class: "mono faint" }, status.version.split("+")[0]) : lockButton()) : null),
  )
  // The first paint is at rest. After that, a whole new state is softened:
  // the old one blurs, shrinks and fades out over the new one as it comes in,
  // on the same frame, never waiting for the exit.
  if (first || !oldBody) return
  oldBody.classList.add("leaving")
  oldBody.style.top = `${oldTop}px`
  root.append(oldBody)
  const out = animateTo(oldBody, reducedMotion() ? { opacity: "0" } : { opacity: "0", filter: "blur(4px)", transform: "scale(0.96)" }, 0.25, { fill: false })
  if (out) out.finished.then(() => oldBody.remove(), () => oldBody.remove())
  else oldBody.remove()
  body2.animate(
    reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, filter: "blur(4px)", transform: "scale(0.96)" }, { opacity: 1, filter: "blur(0px)", transform: "none" }],
    timing(0.3),
  )
}

if (native) {
  chrome.runtime.onMessage.addListener((message: StatusChanged) => {
    if (message?.type === "db:status") void render()
  })

  // While learning, the step count follows along.
  setInterval(() => {
    if (learningShown) void render()
  }, 1000)

  // A vault that's slow to answer shows that it's connecting, never an empty popup.
  const slow = setTimeout(() => rendered === "" && paint({ status: { state: "connecting" }, accounts: [] }, false), 300)
  void render().finally(() => clearTimeout(slow))
} else {
  // The browser-only Deadbolt has no app: the popup is the vault itself (src/vault).
  mountVault(root, "popup")
}
