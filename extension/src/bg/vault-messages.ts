// Messages between the service worker (bg/standalone.ts), the offscreen
// document (offscreen.ts) and its vault worker (vault-worker.ts). They start
// with `db-vault:`, which the background's `db:` listener and the extension's
// pages ignore; each side checks the sender's exact URL.

import type { Change } from "../protocol"

export const VAULT_REQUEST = "db-vault:request"
export const VAULT_LOCK = "db-vault:lock"
export const VAULT_CHANGED = "db-vault:changed"

/** Service worker to offscreen: one request for the vault (a protocol request or a device-* command). */
export interface VaultRequest {
  type: typeof VAULT_REQUEST
  body: Record<string, unknown> & { type: string }
}
/** Service worker to offscreen: end the vault's worker now. Answered with true. */
export interface VaultLock {
  type: typeof VAULT_LOCK
}
/** Offscreen to service worker: the vault changed without being asked (its worker stopped, say). */
export interface VaultChanged {
  type: typeof VAULT_CHANGED
  change: Change
}

/** The vault's reply, or why there is none. `locked`: the worker was ended under the request. */
export type VaultResponse = { reply: unknown } | { error: string; locked?: boolean }

/** Offscreen document to its worker, and back. */
export interface WorkerRequest {
  id: number
  body: Record<string, unknown>
}
/**
 * `fatal`: the vault engine itself failed (a WebAssembly trap, such as a Rust
 * panic), so its memory can't be trusted; the offscreen document ends the
 * worker and starts a fresh, locked one on the next request.
 */
export type WorkerResponse = { id: number; reply: unknown } | { id?: number; error: string; fatal?: true } | { change: "items" }
