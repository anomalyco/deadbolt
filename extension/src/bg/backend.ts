// What the background's autofill, save, forms, passkey and learning code asks
// of Deadbolt. Two implementations: the native host (bg/host.ts, `deadbolt
// browser-host`, the default build) and the standalone
// device (bg/standalone.ts, built with `scripts/build.ts --standalone`), where the extension is a Deadbolt
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
  /**
   * The browser-only vault only: a fill the vault answered `passphrase_needed`
   * (a card's number or code under Strict). Asks for the passphrase in
   * Deadbolt's own popup or device.html, never the page, and runs the fill
   * once with it. Rejects if the user cancels, Deadbolt locks, `signal`
   * aborts (the page navigated) or nobody answers in time.
   */
  reauth?(body: Extract<RequestBody, { type: "fill-form" }>, ask: ReauthAsk, signal: AbortSignal): Promise<ReplyFor["fill-form"]>
  /** The browser-only vault only: whether a card's number or code asks for the passphrase (Strict), so the menu can say so. */
  asksPassphrase?(): Promise<boolean>
}

/** What a passphrase prompt for a fill says, and the tab it's for. */
export interface ReauthAsk {
  tabId: number
  /** The item, as the menu names it: "Visa •••• 4242". */
  title: string
  site: string
}

export const cancelled = () => new HostError("cancelled", "The request was cancelled.")
