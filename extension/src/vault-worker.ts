// The vault's worker, owned by the offscreen document: it loads the Rust core
// (crates/ext-core, built into wasm/ by scripts/wasm.sh) and answers each
// request with its `request(body)`, whose replies are already plain JSON. The
// unlocked vault lives in this worker's memory and nowhere else; terminating
// the worker locks it.

import type { WorkerRequest, WorkerResponse } from "./bg/vault-messages"

interface Core {
  default(init: { module_or_path: URL }): Promise<unknown>
  request(body: unknown): Promise<unknown>
}

const scope = self as unknown as {
  location: Location
  postMessage(message: WorkerResponse): void
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null
}

const GLUE = new URL("wasm/deadbolt_ext_core.js", scope.location.href)
let core: Promise<Core> | null = null
/** Set once the engine trapped: its memory is unusable, so nothing more runs here. */
let dead: string | null = null

function load(): Promise<Core> {
  core ??= (import(GLUE.href) as Promise<Core>).then(async (m) => {
    await m.default({ module_or_path: new URL("deadbolt_ext_core_bg.wasm", GLUE) })
    return m
  })
  // A failed load is tried again on the next request.
  core.catch(() => (core = null))
  return core
}

/** Background wasm tasks can trap outside any request's promise. */
function fatal(error: unknown, id?: number): boolean {
  if (!(error instanceof WebAssembly.RuntimeError)) return false
  dead = `Deadbolt's vault stopped: ${error.message || "it failed"}.`
  scope.postMessage({ id, error: dead, fatal: true })
  return true
}

self.addEventListener("unhandledrejection", (event: PromiseRejectionEvent) => {
  if (fatal(event.reason)) event.preventDefault()
})
self.addEventListener("error", (event: ErrorEvent) => {
  if (fatal(event.error)) event.preventDefault()
})

scope.onmessage = async (event) => {
  const { id, body } = event.data
  if (dead) return scope.postMessage({ id, error: dead, fatal: true })
  let engine: Core
  try {
    engine = await load()
  } catch (err) {
    if (fatal(err, id)) return
    return scope.postMessage({ id, error: `Deadbolt's vault engine didn't load: ${(err as Error)?.message ?? err}` })
  }
  try {
    scope.postMessage({ id, reply: await engine.request(body) })
  } catch (err) {
    // A trap (a Rust panic is one) leaves the engine's memory half-changed.
    if (fatal(err, id)) return
    scope.postMessage({ id, error: String((err as Error)?.message ?? err) })
  }
}
