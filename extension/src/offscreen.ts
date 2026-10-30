// The offscreen document: it only owns the vault's worker (vault-worker.ts),
// which holds the unlocked vault and runs its sync, and passes the service
// worker's requests to it as they come, so a list never waits behind a sync
// or a pairing. Only a create, an unlock or a join's start or finish waits for the one before it:
// they set the vault up, and two at once would race. Lock ends the worker at
// once, even mid-KDF or mid-pairing, fails everything in flight or waiting,
// and the next request starts a fresh, locked one. So does the engine
// failing (a WebAssembly trap), which also gives up its storage lock. It also
// empties the clipboard of a password Deadbolt copied, if it's still there
// (bg/clipboard.ts). Only the service worker may ask (checked by its exact URL).

import { holds } from "./bg/clipboard"
import { VAULT_CHANGED, VAULT_CLIPBOARD, VAULT_LOCK, VAULT_REQUEST, type VaultChanged, type VaultClipboard, type VaultRequest, type VaultResponse, type WorkerResponse } from "./bg/vault-messages"

const BACKGROUND = chrome.runtime.getURL("background.js")
/** The requests that set the vault up, run one at a time. */
const SETUP = new Set(["device-create", "device-unlock", "device-join-start", "device-join-finish", "device-biometric-info"])

interface Pending {
  resolve: (response: VaultResponse) => void
}

let worker: Worker | null = null
let nextId = 1
const pending = new Map<number, Pending>()
/** The tail of the setup queue: each setup request starts once the one before it is answered. */
let setup: Promise<unknown> = Promise.resolve()
/** Bumped by every stop, so a setup queued before it never reaches the new worker. */
let generation = 0

function start(): Worker {
  const w = new Worker(chrome.runtime.getURL("vault-worker.js"))
  w.onmessage = (event: MessageEvent<WorkerResponse>) => {
    if (w !== worker) return
    const m = event.data
    if ("change" in m) {
      if (m.change === "items") void chrome.runtime.sendMessage({ type: VAULT_CHANGED, change: "items" } satisfies VaultChanged).catch(() => {})
      return
    }
    // Background tasks can trap without a request id. Stop before looking up
    // a pending request, so their OPFS handle is released too.
    if ("error" in m && m.fatal) return fail(String(m.error))
    const p = m.id === undefined ? undefined : pending.get(m.id)
    if (!p || m.id === undefined) return
    pending.delete(m.id)
    p.resolve("error" in m ? { error: String(m.error) } : { reply: m.reply })
  }
  // A worker that fails has lost its unlocked vault; say so.
  w.onerror = (event) => {
    event.preventDefault()
    if (w === worker) fail("Deadbolt's vault stopped. Unlock it again.")
  }
  return w
}

/** Ends the worker and fails everything in flight or waiting. */
function stop(message: string) {
  generation++
  worker?.terminate()
  worker = null
  for (const p of pending.values()) p.resolve({ error: message, locked: true })
  pending.clear()
  setup = Promise.resolve()
}

/** The worker failed under the vault: end it and tell the service worker it's locked. */
function fail(message: string) {
  stop(message)
  void chrome.runtime.sendMessage({ type: VAULT_CHANGED, change: "locked" } satisfies VaultChanged).catch(() => {})
}

function post(body: VaultRequest["body"]): Promise<VaultResponse> {
  worker ??= start()
  const id = nextId++
  const w = worker
  return new Promise<VaultResponse>((resolve) => {
    pending.set(id, { resolve })
    w.postMessage({ id, body })
  })
}

function request(body: VaultRequest["body"]): Promise<VaultResponse> {
  if (!SETUP.has(body.type)) return post(body)
  const at = generation
  const run = setup.then(() => (at === generation ? post(body) : ({ error: "Deadbolt locked.", locked: true } satisfies VaultResponse)))
  setup = run
  return run
}

/** What the clipboard holds, read by pasting (needs clipboardRead), or null if it can't be read. */
function readClipboard(): string | null {
  const area = document.createElement("textarea")
  document.body.append(area)
  area.focus()
  const ok = document.execCommand("paste")
  const text = area.value
  area.remove()
  return ok ? text : null
}

/** Puts `text` on the clipboard by copying (needs clipboardWrite). */
function writeClipboard(text: string): boolean {
  const copy = (e: ClipboardEvent) => {
    e.clipboardData?.setData("text/plain", text)
    e.preventDefault()
  }
  document.addEventListener("copy", copy)
  try {
    return document.execCommand("copy")
  } finally {
    document.removeEventListener("copy", copy)
  }
}

/** Empties the clipboard only if it still holds what Deadbolt copied: never what the user copied since. */
async function clearIfOurs(copied: { salt: string; hash: string }): Promise<boolean> {
  const text = readClipboard()
  if (text === null || !(await holds(copied, text))) return false
  return writeClipboard("")
}

chrome.runtime.onMessage.addListener((message: { type?: unknown; body?: unknown; salt?: unknown; hash?: unknown }, sender, respond) => {
  if (message?.type !== VAULT_REQUEST && message?.type !== VAULT_LOCK && message?.type !== VAULT_CLIPBOARD) return
  if (sender.id !== chrome.runtime.id || sender.tab || sender.url !== BACKGROUND) return
  if (message.type === VAULT_CLIPBOARD) {
    const m = message as VaultClipboard
    if (typeof m.salt !== "string" || typeof m.hash !== "string") return void respond(false)
    void clearIfOurs(m).then(respond, () => respond(false))
    return true
  }
  if (message.type === VAULT_LOCK) {
    stop("Deadbolt locked.")
    respond(true)
    return
  }
  const body = message.body
  if (typeof body !== "object" || body === null || typeof (body as { type?: unknown }).type !== "string") {
    respond({ error: "Deadbolt didn't understand that request. Reload the extension and try again." } satisfies VaultResponse)
    return
  }
  void request(body as VaultRequest["body"]).then(respond)
  return true
})
