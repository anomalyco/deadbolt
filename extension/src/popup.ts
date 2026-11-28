// Toolbar popup: how Deadbolt is doing, an offer to save or update the login
// just used, and this site's logins with Fill and Copy username. Passwords are
// never copied: anything on the clipboard can be read by every app, and
// clipboard managers keep it.

import type { PickReply, PopupReply, Status, StatusChanged, ToBackground } from "./messages"
import type { Account } from "./protocol"
import { provider } from "./signin"
import { h, icon, ICONS, monogram, svg } from "./ui/dom"
import { offerCard } from "./ui/offer"
import { passkeyCard } from "./ui/passkey"
import { recordControl, savingOffLine } from "./ui/site-notes"
import { animateTo, reducedMotion, ROLL_CSS, timing } from "./ui/motion"
import { appearanceRows } from "./ui/appearance"
import { signInRow } from "./ui/signin-setting"
import { iconSettings, onIconSettings, type IconSettings } from "./ui/icon-store"
import { siteTile } from "./ui/site-icon"

const root = document.getElementById("app")!
document.head.append(h("style", {}, ROLL_CSS))
let tabId: number | undefined
let rendered = ""
/** Where rows show site icons; the popup's settings change them. */
let icons: IconSettings = { menu: false, vault: true }
/** The settings show in place of the site's logins. */
let settingsOpen = false
/** The control to give focus back to once the popup has repainted (its data-focus), as a repaint replaces every element. */
let refocus: string | null = null
/** What a screen reader says as it happens ("Copied the username"); outside #app, so a repaint keeps it. */
const live = h("p", { class: "sr-only", role: "status", "aria-live": "polite" })
document.body.append(live)
function announce(text: string) {
  live.textContent = ""
  setTimeout(() => (live.textContent = text), 50)
}
/** Record: in the header and under it on every web page, whatever Deadbolt's state (see ui/site-notes.ts). */
const record = recordControl(() => tabId, announce)
/** A login's tile: its site's icon, dithered in the first time this popup shows it, or its letter (see ui/site-icon.ts). */
function tileFor(a: Account, index: number): HTMLElement {
  const url = a.urls.find(Boolean) ?? ""
  if (!icons.vault || !url) return monogram(a.title)
  return siteTile(a.title, url, { reveal: true, once: url, delay: Math.min(index, 8) * 28 })
}

/** The popup's settings: signing in, Appearance, and a way back. */
function settingsBody(): HTMLElement {
  const done = h("button", { class: "btn", type: "button" }, "Done")
  done.addEventListener("click", () => {
    settingsOpen = false
    refocus = "settings"
    void render(true)
  })
  return h(
    "section",
    { class: "site settings" },
    h("div", { class: "section-head" }, h("span", { class: "label" }, "Signing in")),
    signInRow(announce),
    h("div", { class: "section-head" }, h("span", { class: "label" }, "Appearance")),
    ...appearanceRows(icons, announce),
    h("p", { class: "hint" }, "Well-known sites' marks come from Simple Icons, bundled; they're their owners' trademarks."),
    h("div", { class: "buttons" }, done),
  )
}

function send<T>(message: ToBackground): Promise<T | null> {
  return chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>
}

const code = (text: string) => h("code", {}, text)

function commandBlock(command: string): HTMLElement {
  const copy = h("button", { class: "icon-button", type: "button", title: "Copy command", "aria-label": "Copy command" }, icon("copy"))
  copy.addEventListener("click", async () => {
    if (!(await writeClipboard(command))) return announce("Couldn't copy.")
    swapIcon(copy, "check")
    announce("Copied the command")
  })
  return h("div", { class: "command" }, h("code", {}, command), copy)
}

/** Writes `text` to the clipboard: whether it could. */
const writeClipboard = (text: string) => navigator.clipboard.writeText(text).then(() => true, () => false)

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
      return state(icon("plug"), "Deadbolt couldn't start", para(status.detail || "The daemon didn't answer."))
    case "not-set-up":
      return state(icon("keyhole"), "Set up Deadbolt first", para("Create your vault in the Deadbolt app, or run ", code("deadbolt init"), "."), openButton(true))
    case "locked": {
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

function openButton(primary: boolean): HTMLElement {
  const b = h("button", { class: `btn${primary ? " primary" : ""}`, type: "button" }, "Open Deadbolt")
  b.addEventListener("click", openApp)
  return b
}

function accountRow(a: Account, first: boolean, index = 0): HTMLElement {
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
  // "Sign in with Google · alex@gmail.com" for a login that signs in with another account.
  const via = a.signIn ? `Sign in with ${provider(a.signIn.provider).name}${a.signIn.account ? ` · ${a.signIn.account}` : ""}` : ""
  const sub = via && !a.hasPassword ? via : [a.username || "No username", a.hasTotp ? "2FA code" : "", via].filter(Boolean).join(" · ")
  // One that signs in with another account and has no password has nothing to fill.
  const fillable = a.hasPassword || !a.signIn
  const row = h(
    "div",
    { class: "account" },
    tileFor(a, index),
    h("div", { class: "account-text" }, h("div", { class: "account-title" }, a.title), h("div", { class: "account-sub" }, sub)),
    copy,
    fillable ? fill : null,
  )
  copy.addEventListener("click", async () => {
    if (!a.username) return
    if (!(await writeClipboard(a.username))) return announce("Couldn't copy.")
    swapIcon(copy, "check")
    announce("Copied the username")
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
  announce(message)
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
    h("div", { class: "list" }, ...reply.accounts.map((a, i) => accountRow(a, i === 0 && !reply.offer, i))),
    reply.accounts.some((a) => a.recipe) ? resetLearnedButton() : null,
    error,
    h("p", { class: "note" }, icon("lock"), h("span", {}, "Deadbolt never copies passwords: any app can read the clipboard. Fill puts them straight into the page.")),
  )
}

/**
 * A form the user taught Deadbolt on this page (content/recipe.ts): forget
 * it, and the page is left to the scan again.
 */
function resetLearnedButton(): HTMLElement {
  const b = h("button", { class: "link learned", type: "button", title: "Deadbolt learned this page's sign-in form when you filled it by hand" }, "Reset learned form")
  b.addEventListener("click", async () => {
    if (tabId === undefined) return
    b.setAttribute("disabled", "")
    const ok = await send<boolean>({ type: "db:popup-recipe-reset", tabId })
    announce(ok ? "Deadbolt forgot this form" : "Nothing to reset")
    void render(true)
  })
  return b
}

/** Opens and closes the popup's settings. */
function settingsButton(): HTMLElement {
  const b = h("button", { class: `icon-button${settingsOpen ? " on" : ""}`, type: "button", title: "Settings", "aria-label": "Settings", "aria-pressed": String(settingsOpen), "data-focus": "settings" }, icon("gear"))
  b.addEventListener("click", () => {
    settingsOpen = !settingsOpen
    refocus = "settings"
    void render(true)
  })
  return b
}

async function render(changed = false) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  tabId = tab?.id
  void record.refresh()
  const reply = tabId === undefined ? null : await send<PopupReply>({ type: "db:popup-load", tabId })
  paint(reply, changed)
}

function paint(reply: PopupReply | null, changed: boolean) {
  const status: Status = reply?.status ?? { state: "disconnected", message: "The extension's background worker didn't answer." }
  const body = settingsOpen ? settingsBody() : (statusBody(status) ?? (reply ? siteBody(reply) : null))

  // Status pushes re-render; skip it when nothing visible changed.
  const key = JSON.stringify([status, reply?.site, reply?.accounts, reply?.unfillable, reply?.error, reply?.offer, reply?.passkey, reply?.savingOff, settingsOpen, icons.vault])
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
      ...(settingsOpen
        ? [body]
        : reply?.passkey
        ? [
            // Touch ID, or the page, takes it from here.
            passkeyCard(reply.passkey, tabId, { chosen: () => window.close(), ended: () => void render(true) }),
          ]
        : [
            reply?.offer ? offerCard(reply.offer, tabId, () => void render(true)) : null,
            body,
            reply?.savingOff && !reply.offer ? savingOffLine(reply.savingOff, tabId, () => void render(true)) : null,
          ]),
  )
  root.replaceChildren(
    h("header", { class: "top" }, h("span", { class: "logo" }, svg(ICONS.deadbolt)), h("h1", { class: "brand" }, "Deadbolt"), record.button, pill(status)),
    record.bar,
    body2,
    h("footer", { class: "bottom" }, open ?? h("span"), h("span", { class: "bottom-end" }, status.state === "ready" ? h("span", { class: "mono faint" }, status.version.split("+")[0]) : null, settingsButton())),
  )
  // Keyboard focus stays on the button that repainted the popup, not on the page's body.
  if (refocus) root.querySelector<HTMLElement>(`[data-focus="${refocus}"]`)?.focus({ preventScroll: true })
  refocus = null
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

// The settings, here or in another popup, show at once.
onIconSettings((now) => {
  icons = now
  void render()
})
chrome.runtime.onMessage.addListener((message: StatusChanged) => {
  if (message?.type === "db:status") void render()
})

// A vault that's slow to answer shows that it's connecting, never an empty popup.
const slow = setTimeout(() => rendered === "" && paint({ status: { state: "connecting" }, accounts: [] }, false), 300)
void iconSettings()
  .then((now) => (icons = now))
  .then(() => render())
  .finally(() => clearTimeout(slow))
