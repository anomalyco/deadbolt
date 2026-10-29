// The vault's worker, owned by the offscreen document: it loads the Rust core
// (crates/ext-core, built into wasm/ by scripts/wasm.sh) and answers one
// request at a time with its `request(body)`. The unlocked vault lives in this
// worker's memory and nowhere else; terminating the worker locks it.

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

function load(): Promise<Core> {
  core ??= (import(GLUE.href) as Promise<Core>).then(async (m) => {
    await m.default({ module_or_path: new URL("deadbolt_ext_core_bg.wasm", GLUE) })
    return m
  })
  // A failed load is tried again on the next request.
  core.catch(() => (core = null))
  return core
}

/** Plain objects for structured clone and the protocol parser, if the core hands back Maps. */
function plain(v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), plain(x)]))
  if (Array.isArray(v)) return v.map(plain)
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]))
  return v
}

scope.onmessage = async (event) => {
  const { id, body } = event.data
  try {
    const engine = await load().catch((err) => {
      throw new Error(`Deadbolt's vault engine didn't load: ${(err as Error)?.message ?? err}`)
    })
    scope.postMessage({ id, reply: plain(await engine.request(body)) })
  } catch (err) {
    scope.postMessage({ id, error: String((err as Error)?.message ?? err) })
  }
}
