// The offscreen document: it only owns the vault's worker (vault-worker.ts),
// which holds the unlocked vault and runs its sync, and passes the service
// worker's requests to it one at a time, so a create, an unlock and a sync
// never overlap. Lock ends the worker at once, even mid-KDF or mid-pairing,
// and the next request starts a fresh, locked one. Only the service worker
// may ask (checked by its exact URL).

import { VAULT_CHANGED, VAULT_LOCK, VAULT_REQUEST, type VaultChanged, type VaultRequest, type VaultResponse, type WorkerResponse } from "./bg/vault-messages"

const BACKGROUND = chrome.runtime.getURL("background.js")

interface Pending {
  resolve: (response: VaultResponse) => void
}

let worker: Worker | null = null
let nextId = 1
const pending = new Map<number, Pending>()
/** The tail of the queue: each request starts once the one before it is answered. */
let queue: Promise<unknown> = Promise.resolve()
/** Bumped by every stop, so requests queued before it don't reach a new worker. */
let generation = 0

function start(): Worker {
  const w = new Worker(chrome.runtime.getURL("vault-worker.js"))
  w.onmessage = (event: MessageEvent<WorkerResponse>) => {
    const m = event.data
    const p = pending.get(m?.id)
    if (!p) return
    pending.delete(m.id)
    p.resolve("error" in m ? { error: String(m.error) } : { reply: m.reply })
  }
  // A worker that fails has lost its unlocked vault; say so.
  w.onerror = (event) => {
    event.preventDefault()
    stop(`Deadbolt's vault stopped: ${event.message || "it failed"}.`)
    void chrome.runtime.sendMessage({ type: VAULT_CHANGED, change: "locked" } satisfies VaultChanged).catch(() => {})
  }
  return w
}

/** Ends the worker and fails everything in flight or queued. */
function stop(message: string) {
  generation++
  worker?.terminate()
  worker = null
  for (const p of pending.values()) p.resolve({ error: message, locked: true })
  pending.clear()
  queue = Promise.resolve()
}

function request(body: VaultRequest["body"]): Promise<VaultResponse> {
  const at = generation
  const run = queue.then(() => {
    if (at !== generation) return { error: "Deadbolt locked.", locked: true } satisfies VaultResponse
    worker ??= start()
    const id = nextId++
    const w = worker
    return new Promise<VaultResponse>((resolve) => {
      pending.set(id, { resolve })
      w.postMessage({ id, body })
    })
  })
  queue = run
  return run
}

chrome.runtime.onMessage.addListener((message: { type?: unknown; body?: unknown }, sender, respond) => {
  if (message?.type !== VAULT_REQUEST && message?.type !== VAULT_LOCK) return
  if (sender.id !== chrome.runtime.id || sender.tab || sender.url !== BACKGROUND) return
  if (message.type === VAULT_LOCK) {
    stop("Deadbolt locked.")
    respond(true)
    return
  }
  const body = message.body
  if (typeof body !== "object" || body === null || typeof (body as { type?: unknown }).type !== "string") {
    respond({ error: "Malformed request." } satisfies VaultResponse)
    return
  }
  void request(body as VaultRequest["body"]).then(respond)
  return true
})
