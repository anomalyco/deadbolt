// What the background's autofill, save, forms, passkey and learning code asks
// of Deadbolt. Two implementations: the native host (bg/host.ts, `deadbolt
// browser-host`, built with `scripts/build.ts --native`) and the standalone
// device (bg/standalone.ts, the default), where the extension is a Deadbolt
// device of its own with the Rust vault running in an offscreen worker.

import type { Status } from "../messages"
import type { Change, ErrorCode, ReplyFor, RequestBody } from "../protocol"

export class HostError extends Error {
  constructor(
    readonly code: ErrorCode | "disconnected" | "timeout",
    message: string,
  ) {
    super(message)
  }
}

export interface SendOptions {
  timeout?: number
  onId?: (id: number) => void
  signal?: AbortSignal
}

export type Listener = (status: Status, change?: Change) => void

export interface VaultBackend {
  status: Status
  /** What the vault said it can do in its last hello; a feature it doesn't name is never offered. */
  capabilities: string[]
  onChange(listener: Listener): () => void
  /** Resolves once hello has been answered (or failed). */
  connect(): Promise<void>
  /** Try again now, e.g. when the popup opens. */
  reconnectNow(): Promise<void>
  send<T extends keyof ReplyFor>(body: Extract<RequestBody, { type: T }>, options?: SendOptions): Promise<ReplyFor[T]>
  /** The user did something (opened the popup, filled, saved): restarts the idle lock, where there is one. */
  used?(): void
}

export const cancelled = () => new HostError("cancelled", "The request was cancelled.")
