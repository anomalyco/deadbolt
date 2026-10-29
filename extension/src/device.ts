// device.html: the browser-only Deadbolt's own page (bg/standalone.ts). Set
// up a vault (a new one, or by pairing with a device that has one), unlock
// and lock it, pair another device and see the vault's
// devices, sync, add logins by hand and list them all. It's also the extension's options page. Passphrases and
// passwords go to the background in one message and are never kept here or
// in storage.

import type { DeviceCommand, DeviceReply, JoinStatus, Status, StatusChanged, VaultDevice } from "./messages"
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

/** First run: what the page shows while not set up. The pairing code lives in the vault's worker, which a reloaded page asks again. */
type Join =
  | { step: "choose" }
  | { step: "create" }
  | { step: "starting" }
  | { step: "waiting"; code: string }
  | { step: "admitted"; vault?: string }
  | { step: "failed"; message: string }
  | { step: "cancelling" }
let join: Join = { step: "choose" }
/** Bumped by every change of step, so an answer to an older one (a poll, a start, a finish) never brings it back. */
let joinGen = 0
let pollTimer: ReturnType<typeof setTimeout> | undefined
/** The generation whose device-join-start this page is still waiting for, if any. */
let startedAt = -1
const POLL_MS = 1500

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

function stopPoll() {
  clearTimeout(pollTimer)
  pollTimer = undefined
}

/** While the vault is getting a code or waiting to be admitted, asks again shortly. */
function polling() {
  stopPoll()
  if (join.step === "waiting" || join.step === "starting") pollTimer = setTimeout(() => void check(), POLL_MS)
}

function setJoin(next: Join) {
  joinGen++
  join = next
  polling()
}

/** Shows `next`, redrawing only if the step changed, so a poll never throws away what's typed. */
function show(next: Join) {
  if (JSON.stringify(next) === JSON.stringify(join)) {
    polling()
    return
  }
  setJoin(next)
  render()
}

function joinStep(r: Record<string, unknown>): Join | null {
  const s = r as Partial<JoinStatus>
  if (s.type !== "device-join-status") return null
  switch (s.phase) {
    case "waiting":
      // No code yet: the vault is still reaching its relay.
      return typeof s.code === "string" && s.code ? { step: "waiting", code: s.code } : { step: "starting" }
    case "admitted":
      return typeof s.vault === "string" && s.vault ? { step: "admitted", vault: s.vault } : { step: "admitted" }
    case "failed":
      return { step: "failed", message: typeof s.message === "string" && s.message ? s.message : "Pairing didn't work." }
    case "idle":
      // Nothing to come back to. A create the user had opened stays open, as
      // does a start the vault hasn't taken up yet.
      if (join.step === "create" || (join.step === "starting" && startedAt === joinGen)) return join
      return join.step === "waiting" || join.step === "starting" || join.step === "admitted"
        ? { step: "failed", message: "The pairing was interrupted. Start again." }
        : { step: "choose" }
  }
  return null
}

/** Asks the vault how the join is going; while it's waiting, again shortly. */
async function check() {
  stopPoll()
  const gen = joinGen
  const r = await run({ type: "device-join-status" })
  if (gen !== joinGen || status.state !== "not-set-up") return
  const next: Join | null = r.ok ? joinStep(r.reply) : { step: "failed", message: r.message || "The pairing was interrupted. Start again." }
  if (next) show(next)
  else polling()
}

async function startJoin() {
  note = null
  setJoin({ step: "starting" })
  render()
  const gen = (startedAt = joinGen)
  const r = await run({ type: "device-join-start" })
  if (gen !== joinGen) return
  startedAt = -1
  const code = r.ok && typeof r.reply.code === "string" ? r.reply.code : ""
  setJoin(code ? { step: "waiting", code } : { step: "failed", message: r.ok ? "The vault didn't give a pairing code." : r.message })
  render()
}

/** Ends the join (its worker, and everything it held) and goes back to the first choice. */
async function cancelJoin() {
  note = null
  setJoin({ step: "cancelling" })
  render()
  const gen = joinGen
  const r = await run({ type: "device-join-cancel" })
  if (gen !== joinGen) return
  status = r.status
  if (!r.ok) note = { text: r.message, error: true }
  setJoin({ step: "choose" })
  render()
}

function button(label: string, act: () => void, primary = false): HTMLButtonElement {
  const b = h("button", { class: primary ? "btn primary" : "btn", type: "button" }, label)
  b.addEventListener("click", () => {
    b.disabled = true
    act()
  })
  return b
}

const card = (title: string, ...children: Node[]) => h("section", { class: "card" }, h("h2", {}, title), ...children)

function chooser(): HTMLElement {
  return card(
    "Set up Deadbolt",
    para("Pair this browser with a device that has your vault, or start a new vault here."),
    h(
      "div",
      { class: "buttons" },
      button("Pair with an existing device", () => void startJoin(), true),
      button("Create a new vault", () => {
        note = null
        show({ step: "create" })
      }),
    ),
  )
}

function waiting(code: string): HTMLElement {
  const copy = h("button", { class: "btn", type: "button" }, icon("copy"), "Copy")
  copy.addEventListener("click", () => {
    navigator.clipboard.writeText(code).then(
      () => copy.replaceChildren(icon("check"), "Copied"),
      () => {},
    )
  })
  return card(
    "Pair with an existing device",
    h("div", { class: "join-code" }, h("span", { class: "mono", id: "join-code" }, code), copy),
    para("On a device that has your vault, run ", h("code", {}, `deadbolt pair ${code}`), ", or use Pair in the Deadbolt app."),
    para("Waiting for the other device…"),
    h("div", { class: "buttons" }, button("Cancel", () => void cancelJoin())),
  )
}

function finishForm(vault?: string): HTMLElement {
  const pass = field("Passphrase", { type: "password", autocomplete: "new-password" })
  const again = field("Passphrase again", { type: "password", autocomplete: "new-password" })
  const f = form(
    "Choose a passphrase for this browser",
    [pass, again],
    "Finish",
    async () => {
      if (!pass.value || pass.value !== again.value) {
        note = { text: pass.value ? "The passphrases don't match." : "Choose a passphrase.", error: true }
        return
      }
      const gen = joinGen
      const r = await run({ type: "device-join-finish", passphrase: pass.value })
      // Cancelled meanwhile: that answer is for a join that's gone.
      if (gen !== joinGen && status.state === "not-set-up") return
      if (r.ok) {
        setJoin({ step: "choose" })
        return done("Joined", r)
      }
      // The join may be gone (expired, say): show what's left of it.
      void check()
      return r
    },
    para(vault ? `This browser was admitted to ${vault}. ` : "This browser was admitted to your vault. ", "This passphrase unlocks Deadbolt in this browser only; it isn't a password your other devices share."),
  )
  f.querySelector(".buttons")?.append(button("Cancel", () => void cancelJoin()))
  return f
}

function joinBody(): HTMLElement[] {
  switch (join.step) {
    case "choose":
      return [chooser()]
    case "create":
      return [chooser(), createForm()]
    case "starting":
      return [card("Pair with an existing device", para("Getting a pairing code…"), h("div", { class: "buttons" }, button("Cancel", () => void cancelJoin())))]
    case "cancelling":
      return [card("Pair with an existing device", para("Cancelling…"))]
    case "waiting":
      return [waiting(join.code)]
    case "admitted":
      return [finishForm(join.vault)]
    case "failed":
      return [
        card(
          "Pairing didn't work",
          h("p", { class: "error" }, join.message),
          h("div", { class: "buttons" }, button("Try again", () => void startJoin(), true), button("Cancel", () => void cancelJoin())),
        ),
      ]
  }
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
      return joinBody()
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
  // Set up (or gone) under the page: a join's step means nothing now.
  if (status.state !== "not-set-up" && join.step !== "choose") setJoin({ step: "choose" })
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
  if (JSON.stringify(status) !== key) {
    render()
    if (status.state === "not-set-up") void check()
  } else if (status.state === "not-set-up" && join.step === "admitted") {
    // Screen lock or worker loss can discard an unpersisted welcome even
    // though the general status stays not-set-up.
    void check()
  }
  if (status.state === "ready") void refresh()
})

addEventListener("pagehide", stopPoll)

render()
if (!native) void run({ type: "device-status" }).then(async (r) => {
  status = r.status
  // A reloaded page picks up a join where it was.
  if (status.state === "not-set-up") await check()
  render()
  if (status.state === "ready") void refresh()
})
