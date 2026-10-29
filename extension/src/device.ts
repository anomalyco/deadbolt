// device.html: the browser-only Deadbolt's own page (bg/standalone.ts). Set
// up a vault, unlock and lock it, pair another device and see the vault's
// devices, sync, add logins by hand and list them all. It's also the extension's options page. Passphrases and
// passwords go to the background in one message and are never kept here or
// in storage.

import type { DeviceCommand, DeviceReply, Status, StatusChanged, VaultDevice } from "./messages"
import { account, type Account } from "./protocol"
import { h, icon, ICONS, svg } from "./ui/dom"

declare const DEADBOLT_NATIVE: boolean | undefined
const native = typeof DEADBOLT_NATIVE !== "undefined" && DEADBOLT_NATIVE === true

const root = document.getElementById("app")!
let status: Status = { state: "connecting" }
/**
 * The vault's logins and devices, filled in place (so a refresh never throws
 * away what's being typed in a form): null until the vault first answers.
 */
let logins: Account[] | null = null
let devices: VaultDevice[] | null = null
const loginsEl = h("div", { class: "list" })
const devicesEl = h("div", { class: "list" })
/** A line under the header after a command: what happened and how long it took. */
let note: { text: string; error: boolean } | null = null

function run(command: DeviceCommand): Promise<DeviceReply> {
  return (chrome.runtime.sendMessage({ type: "db:device", command }) as Promise<DeviceReply | null>).then(
    (r) => r ?? { ok: false, message: "The extension's background worker didn't answer.", status },
    (err) => ({ ok: false, message: String((err as Error)?.message ?? err), status }),
  )
}

const para = (...parts: Array<Node | string>) => {
  const p = h("p", { class: "muted" })
  p.append(...parts)
  return p
}

function field(label: string, attrs: Record<string, string>): HTMLInputElement {
  return h("input", { class: "input", "aria-label": label, placeholder: label, autocomplete: "off", spellcheck: "false", ...attrs })
}

/** A form whose submit runs `act` with its button disabled, then re-renders. */
function form(title: string, inputs: HTMLInputElement[], label: string, act: () => Promise<DeviceReply | void>, ...extra: Node[]): HTMLElement {
  const button = h("button", { class: "btn primary", type: "submit" }, label)
  const f = h("form", { class: "card" }, h("h2", {}, title), ...extra, ...inputs, h("div", { class: "buttons" }, button))
  f.addEventListener("submit", async (event) => {
    event.preventDefault()
    button.disabled = true
    try {
      const reply = await act()
      if (reply) {
        status = reply.status
        if (!reply.ok) note = { text: reply.message, error: true }
      }
    } finally {
      for (const i of inputs) if (i.type === "password") i.value = ""
      button.disabled = false
      render()
      if (status.state === "ready") void refresh()
    }
  })
  return f
}

const done = (what: string, r: DeviceReply) => {
  if (r.ok) note = { text: `${what} in ${r.ms} ms.`, error: false }
  return r
}

function createForm(): HTMLElement {
  const name = field("Vault name", { value: "personal", pattern: "[a-z][a-z0-9_\\-]{0,63}", maxlength: "64", title: "Start with a lowercase letter; use lowercase letters, digits, hyphens or underscores." })
  const pass = field("Passphrase", { type: "password", autocomplete: "new-password" })
  const again = field("Passphrase again", { type: "password", autocomplete: "new-password" })
  return form(
    "Create a vault in this browser",
    [name, pass, again],
    "Create vault",
    async () => {
      if (!pass.value || pass.value !== again.value) {
        note = { text: pass.value ? "The passphrases don't match." : "Choose a passphrase.", error: true }
        return
      }
      return done("Created", await run({ type: "device-create", name: name.value.trim() || "personal", passphrase: pass.value }))
    },
    para("This browser becomes a Deadbolt device of its own. Pair it with your other devices once it's set up."),
  )
}

function unlockForm(): HTMLElement {
  const pass = field("Passphrase", { type: "password", autocomplete: "current-password" })
  return form("Unlock Deadbolt", [pass], "Unlock", async () => done("Unlocked", await run({ type: "device-unlock", passphrase: pass.value })))
}

function pairForm(): HTMLElement {
  const code = field("Join code", {})
  return form(
    "Pair another device",
    [code],
    "Pair",
    async () => {
      const r = await run({ type: "device-pair", code: code.value.trim() })
      // What changed is the device list (refreshed below), not how long it took.
      if (r.ok) note = { text: "Paired.", error: false }
      return r
    },
    para("On the other device, run ", h("code", {}, "deadbolt join"), " and type the code it shows here."),
  )
}

function originOf(url: string): string | null {
  try {
    const u = new URL(url.includes("://") ? url : `https://${url}`)
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null
  } catch {
    return null
  }
}

function saveForm(): HTMLElement {
  const url = field("Website", { type: "url", value: "https://" })
  const title = field("Title", {})
  const username = field("Username", { autocomplete: "off" })
  const password = field("Password", { type: "password", autocomplete: "new-password" })
  return form("Add a login", [url, title, username, password], "Save", async () => {
    const origin = originOf(url.value.trim())
    if (!origin || !password.value) {
      note = { text: origin ? "Enter a password." : "Enter the site's address.", error: true }
      return
    }
    const entry = { url: origin, title: title.value.trim() || new URL(origin).hostname, username: username.value.trim(), password: password.value }
    return done("Saved", await run({ type: "save", origin, entry }))
  })
}

const row = (title: string, sub: string) => h("div", { class: "row" }, h("span", {}, title), h("span", { class: "mono muted" }, sub))

function showLogins() {
  if (!logins) return loginsEl.replaceChildren(para("Loading…"))
  loginsEl.replaceChildren(...(logins.length ? logins.map((a) => row(a.title, a.username ?? "")) : [para("No logins yet.")]))
}

function showDevices() {
  if (!devices) return devicesEl.replaceChildren(para("Loading…"))
  devicesEl.replaceChildren(...devices.map((d) => row(d.name, d.current ? "This browser" : d.id.slice(0, 8))))
}

function vaultDevice(v: unknown): VaultDevice | null {
  const d = v as Partial<VaultDevice> | null
  return d && typeof d.id === "string" && typeof d.name === "string" ? { id: d.id, name: d.name, current: d.current === true } : null
}

/** Reads the vault's logins and devices again, into their lists in place. */
async function refresh() {
  const [l, d] = await Promise.all([run({ type: "device-logins" }), run({ type: "device-devices" })])
  if (status.state !== "ready") return
  if (l.ok && Array.isArray(l.reply.accounts)) logins = l.reply.accounts.map(account).filter((a): a is Account => a !== null)
  if (d.ok && Array.isArray(d.reply.devices)) devices = d.reply.devices.map(vaultDevice).filter((x): x is VaultDevice => x !== null)
  showLogins()
  showDevices()
}

function readyBody(): HTMLElement[] {
  const sync = h("button", { class: "btn", type: "button" }, "Sync now")
  sync.addEventListener("click", async () => {
    sync.disabled = true
    const r = await run({ type: "device-sync" })
    status = r.status
    // The vault syncs in the background; the lists follow as it does.
    note = r.ok ? { text: "Sync requested.", error: false } : { text: r.message, error: true }
    render()
    if (status.state === "ready") void refresh()
  })
  const lock = h("button", { class: "btn", type: "button" }, icon("lock"), "Lock")
  lock.addEventListener("click", async () => {
    lock.disabled = true
    status = (await run({ type: "device-lock" })).status
    note = null
    render()
  })
  return [
    h("div", { class: "buttons" }, sync, lock),
    h("section", { class: "card" }, h("h2", {}, "Devices"), devicesEl),
    pairForm(),
    saveForm(),
    h("section", { class: "card" }, h("h2", {}, "Logins"), loginsEl),
  ]
}

function settings(): HTMLElement {
  return h(
    "section",
    { class: "card" },
    h("h2", {}, "Locking"),
    para("Comfortable: Deadbolt locks after an hour without use, when the screen locks, and when the browser quits. The unlocked vault lives only in this browser's memory."),
  )
}

function body(): HTMLElement[] {
  if (native) return [h("section", { class: "card" }, para("This build talks to Deadbolt through ", h("code", {}, "deadbolt browser-host"), ". Set up and unlock Deadbolt in the app."))]
  switch (status.state) {
    case "not-set-up":
      return [createForm()]
    case "locked":
      return [unlockForm(), settings()]
    case "ready":
      return [...readyBody(), settings()]
    case "connecting":
      return [para("Starting Deadbolt…")]
    case "unavailable":
      return [h("section", { class: "card" }, h("h2", {}, "Deadbolt couldn't start"), para(status.detail || "The vault didn't answer."))]
    default:
      return [h("section", { class: "card" }, h("h2", {}, "Deadbolt isn't running"), para("Reload the extension and try again."))]
  }
}

function pill(): HTMLElement {
  const [label, tone] = status.state === "ready" ? ["Unlocked", "ok"] : status.state === "locked" ? ["Locked", "warn"] : status.state === "not-set-up" ? ["Not set up", ""] : ["Starting", ""]
  return h("span", { class: `pill ${tone}` }, label)
}

function render() {
  if (status.state !== "ready") {
    logins = null
    devices = null
  }
  showLogins()
  showDevices()
  root.replaceChildren(
    h("header", { class: "top" }, h("span", { class: "logo" }, svg(ICONS.deadbolt)), h("span", { class: "brand" }, "Deadbolt"), pill()),
    note ? h("p", { class: note.error ? "error" : "muted", role: "status", id: "note" }, note.text) : h("span"),
    ...body(),
  )
}

chrome.runtime.onMessage.addListener((message: StatusChanged) => {
  if (message?.type !== "db:status") return
  const key = JSON.stringify(status)
  status = message.status
  // Don't throw away what's being typed for a push that changes nothing;
  // a push while unlocked (a sync, a save) may still have changed the lists.
  if (JSON.stringify(status) !== key) render()
  if (status.state === "ready") void refresh()
})

render()
if (!native) void run({ type: "device-status" }).then((r) => {
  status = r.status
  render()
  if (status.state === "ready") void refresh()
})
