// Toolbar popup: how Deadbolt is doing, an offer to save or update the login
// just used, and this site's logins with Fill and Copy username. Passwords are
// never copied: anything on the clipboard can be read by every app, and
// clipboard managers keep it.

import type { ChooseReply, OfferChoice, PasskeyChoice, PasskeyPrompt, PickReply, PopupReply, SaveOffer, Status, StatusChanged, ToBackground } from "./messages"
import type { Account } from "./protocol"
import { h, icon, ICONS, monogram, svg } from "./ui/dom"

const root = document.getElementById("app")!
let tabId: number | undefined
let rendered = ""

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
  const sub = [a.username || "No username", a.hasTotp ? "2FA code" : ""].filter(Boolean).join(" · ")
  const row = h(
    "div",
    { class: "account" },
    monogram(a.title),
    h("div", { class: "account-text" }, h("div", { class: "account-title" }, a.title), h("div", { class: "account-sub" }, sub)),
    copy,
    fill,
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

/** "Save login for acme.com?": browser UI, where the page can't see it. */
function offerCard(offer: SaveOffer): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const card = h(
    "section",
    { class: "offer", "aria-label": offer.update ? "Update password" : "Save login" },
    h("h2", {}, offer.update ? `Update password for ${offer.username}?` : `Save login for ${offer.site}?`),
    h(
      "div",
      { class: "box" },
      h("div", { class: "line" }, h("span", { class: "muted" }, offer.update ? "Site" : "Username"), h("span", { class: "value" }, offer.update ? offer.site : offer.username)),
      h("div", { class: "line" }, h("span", { class: "muted" }, offer.update ? "New password" : "Password"), h("span", { class: "value dots" }, "••••••••••")),
    ),
    status,
  )
  const choose = async (choice: OfferChoice, button: HTMLElement) => {
    if (tabId === undefined) return
    card.classList.add("busy")
    button.setAttribute("disabled", "")
    const reply = await send<ChooseReply>({ type: "db:popup-offer", tabId, id: offer.id, choice })
    card.classList.remove("busy")
    button.removeAttribute("disabled")
    // Another offer took this one's place: show that one instead.
    if (reply && !reply.ok && reply.gone) return void render(true)
    if (!reply?.ok) {
      status.textContent = reply?.message || "Couldn't save."
      status.hidden = false
      return
    }
    if (choice !== "save") return void render(true)
    card.replaceChildren(h("div", { class: "done" }, h("span", { class: "done-mark" }, icon("check")), h("span", {}, reply.message)))
    setTimeout(() => void render(true), 1200)
  }
  const never = h("button", { class: "link", type: "button" }, "Never for this site")
  const later = h("button", { class: "btn", type: "button" }, "Not now")
  const save = h("button", { class: "btn primary", type: "button" }, "Save")
  never.addEventListener("click", () => void choose("never", never))
  later.addEventListener("click", () => void choose("later", later))
  save.addEventListener("click", () => void choose("save", save))
  card.append(h("div", { class: "buttons" }, never, later, save))
  return card
}

/**
 * A page's passkey call, asked here rather than in the page: "Sign in to
 * acme.com with a passkey?" or "Save a passkey for acme.com?".
 */
function passkeyCard(prompt: PasskeyPrompt): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const card = h("section", { class: "offer passkey-prompt", "aria-label": prompt.kind === "get" ? "Sign in with a passkey" : "Save a passkey" })
  const choose = async (choice: PasskeyChoice, button: HTMLElement) => {
    if (tabId === undefined) return
    card.classList.add("busy")
    button.setAttribute("disabled", "")
    const reply = await send<{ ok: boolean }>({ type: "pk:popup-choose", tabId, id: prompt.id, choice })
    // Touch ID, or the page, takes it from here.
    if (reply?.ok) return window.close()
    status.textContent = "This request has ended."
    status.hidden = false
    setTimeout(() => void render(true), 1200)
  }
  const button = (label: string, choice: PasskeyChoice, primary = false) => {
    const b = h("button", { class: `btn${primary ? " primary" : ""}`, type: "button" }, label)
    b.addEventListener("click", () => void choose(choice, b))
    return b
  }
  const touch = prompt.verify ? h("p", { class: "note" }, icon("lock"), h("span", {}, "Deadbolt asks for Touch ID next.")) : null
  const other = button("Use another device", { action: "fallback" })
  if (prompt.kind === "get") {
    card.append(
      h("h2", {}, `Sign in to ${prompt.rpId} with a passkey?`),
      h(
        "div",
        { class: "list" },
        ...prompt.passkeys.map((k, i) =>
          h(
            "div",
            { class: "account" },
            h("span", { class: "tile", "aria-hidden": "true" }, icon("passkey")),
            h("div", { class: "account-text" }, h("div", { class: "account-title" }, k.username || "Passkey"), h("div", { class: "account-sub" }, `Passkey · ${k.vault}`)),
            button("Sign in", { action: "use", ref: k.ref }, i === 0),
          ),
        ),
      ),
      status,
      touch ?? "",
      h("div", { class: "buttons" }, other, button("Cancel", { action: "cancel" })),
    )
  } else if (prompt.registered) {
    card.append(
      h("h2", {}, "This passkey is already saved"),
      para(`Deadbolt already has a passkey for this account on ${prompt.rpId}.`),
      status,
      h("div", { class: "buttons" }, other, button("OK", { action: "cancel" }, true)),
    )
  } else {
    card.append(
      h("h2", {}, `Save a passkey for ${prompt.rpId}?`),
      h(
        "div",
        { class: "box" },
        h("div", { class: "line" }, h("span", { class: "muted" }, "Username"), h("span", { class: "value" }, prompt.username || "None")),
        h("div", { class: "line" }, h("span", { class: "muted" }, "Site"), h("span", { class: "value" }, prompt.rpId)),
      ),
      status,
      touch ?? "",
      h("div", { class: "buttons" }, other, button("Cancel", { action: "cancel" }), button("Save", { action: "save" }, true)),
    )
  }
  return card
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
    h("div", { class: "list" }, ...reply.accounts.map((a, i) => accountRow(a, i === 0))),
    error,
    h("p", { class: "note" }, icon("lock"), h("span", {}, "Deadbolt never copies passwords: any app can read the clipboard. Fill puts them straight into the page.")),
  )
}

async function render(changed = false) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  tabId = tab?.id
  const reply = tabId === undefined ? null : await send<PopupReply>({ type: "db:popup-load", tabId })
  const status: Status = reply?.status ?? { state: "disconnected", message: "The extension's background worker didn't answer." }
  const body = statusBody(status) ?? (reply ? siteBody(reply) : null)

  // Status pushes re-render; skip it when nothing visible changed.
  const key = JSON.stringify([status, reply?.site, reply?.accounts, reply?.unfillable, reply?.error, reply?.offer, reply?.passkey, reply?.savingOff])
  if (key === rendered && !changed) return
  const first = rendered === ""
  rendered = key

  // Locked and not set up already have an Open Deadbolt button.
  const hasOpen = status.state === "locked" || status.state === "not-set-up"
  const open = hasOpen ? null : h("button", { class: "link", type: "button" }, "Open Deadbolt", icon("arrow"))
  open?.addEventListener("click", openApp)
  root.replaceChildren(
    h("header", { class: "top" }, h("span", { class: "logo" }, svg(ICONS.deadbolt)), h("span", { class: "brand" }, "Deadbolt"), pill(status)),
    h(
      "div",
      { class: `body${first ? "" : " changed"}` },
      ...(reply?.passkey ? [passkeyCard(reply.passkey)] : [reply?.offer ? offerCard(reply.offer) : null, body, reply?.savingOff && !reply.offer ? savingOffLine(reply.savingOff) : null]),
    ),
    h("footer", { class: "bottom" }, open ?? h("span"), status.state === "ready" ? h("span", { class: "mono faint" }, status.version.split("+")[0]) : null),
  )
}

chrome.runtime.onMessage.addListener((message: StatusChanged) => {
  if (message?.type === "db:status") void render()
})

void render()
