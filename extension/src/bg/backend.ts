// What the background's autofill, save, forms, passkey and learning code asks
// of Deadbolt: the native host (bg/host.ts, `deadbolt browser-host`), and
// the tests' fakes.

import type { Status } from "../messages"
import type { Change, ErrorCode, ReplyFor, RequestBody, UnlockPromptReply } from "../protocol"

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
  /** Touch ID, or Deadbolt's window for the passphrase (`unlock-prompt`); hello follows when no `unlocked` push may. */
  unlockPrompt(): Promise<UnlockPromptReply>
}

export const cancelled = () => new HostError("cancelled", "The request was cancelled.")
