// The one connection to `deadbolt browser-host`. The service worker keeps a
// single native port open (an open port also keeps the worker alive), sends
// hello on every connect, reconnects with backoff when the host goes away,
// and turns `changed` pushes into a status that the popup and menus follow.

import type { Status } from "../messages"
import { NATIVE_HOST, parseHostMessage, PROTOCOL, REPLY_TYPE, type Change, type ErrorReply, type Reply, type ReplyFor, type RequestBody } from "../protocol"
import { cancelled, HostError, type Listener, type SendOptions, type VaultBackend } from "./backend"

const TIMEOUT_MS = 30_000
const BACKOFF_MS = [1_000, 2_000, 5_000, 10_000, 30_000, 60_000]

interface Pending {
  resolve: (reply: Reply) => void
  reject: (error: HostError) => void
  timer: ReturnType<typeof setTimeout>
}

/** The browser's message when no manifest for the host is installed. */
const NOT_FOUND = /native messaging host not found/i

export class Host implements VaultBackend {
  private port: chrome.runtime.Port | null = null
  private nextId = 1
  private pending = new Map<number, Pending>()
  private attempt = 0
  private retry: ReturnType<typeof setTimeout> | undefined
  private listeners = new Set<Listener>()
  private ready: Promise<void> | null = null
  status: Status = { state: "connecting" }
  /** What the host said it can do in its last hello. */
  capabilities: string[] = []

  constructor(private connectNative: (name: string) => chrome.runtime.Port = (name) => chrome.runtime.connectNative(name)) {}

  onChange(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private setStatus(status: Status, change?: Change) {
    this.status = status
    for (const listener of this.listeners) listener(status, change)
  }

  /** Connects if needed and resolves once hello has been answered (or failed). */
  connect(): Promise<void> {
    if (this.ready) return this.ready
    clearTimeout(this.retry)
    this.ready = new Promise<void>((resolve) => {
      let port: chrome.runtime.Port
      try {
        port = this.connectNative(NATIVE_HOST)
      } catch (err) {
        this.disconnected(String((err as Error)?.message ?? err))
        return resolve()
      }
      this.port = port
      port.onMessage.addListener((raw) => this.received(raw))
      port.onDisconnect.addListener(() => {
        if (this.port !== port) return
        this.disconnected(chrome.runtime.lastError?.message ?? "Deadbolt's browser helper stopped.")
        resolve()
      })
      void this.hello().finally(resolve)
    })
    return this.ready
  }

  /** Asks the host how Deadbolt is doing. Hello also starts the agent. */
  async hello(change?: Change): Promise<void> {
    try {
      const reply = await this.send({ type: "hello" })
      this.attempt = 0
      this.capabilities = reply.capabilities
      if (reply.protocol !== PROTOCOL) {
        const detail = `This extension speaks protocol ${PROTOCOL}, but Deadbolt speaks ${reply.protocol}. Update both.`
        this.setStatus({ state: "unavailable", detail }, change)
      } else if (reply.status === "ready") this.setStatus({ state: "ready", version: reply.version }, change)
      else this.setStatus({ state: reply.status, detail: reply.detail }, change)
    } catch (err) {
      if (err instanceof HostError && err.code === "disconnected") return
      this.setStatus({ state: "unavailable", detail: (err as Error).message }, change)
    }
  }

  /**
   * `onId` hears the request's id, which `passkey-cancel` names. A request
   * whose `signal` aborts before it's written, while the port reconnects
   * say, is never written.
   */
  async send<T extends keyof ReplyFor>(body: Extract<RequestBody, { type: T }>, { timeout = TIMEOUT_MS, onId, signal }: SendOptions = {}): Promise<ReplyFor[T]> {
    if (signal?.aborted) throw cancelled()
    if (!this.port) await this.connect()
    const port = this.port
    if (!port) throw new HostError("disconnected", disconnectedMessage(this.status))
    // Nothing is awaited from here to postMessage.
    if (signal?.aborted) throw cancelled()
    const id = this.nextId++
    onId?.(id)
    const reply = await new Promise<Reply>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new HostError("timeout", "Deadbolt didn't answer in time."))
      }, timeout)
      this.pending.set(id, { resolve, reject, timer })
      try {
        port.postMessage({ ...body, id })
      } catch (err) {
        clearTimeout(timer)
        this.pending.delete(id)
        reject(new HostError("disconnected", String((err as Error)?.message ?? err)))
      }
    })
    if (reply.type === "error") {
      const error = reply as ErrorReply
      // A locked reply means the vault locked under us; follow it.
      if (error.code === "locked" && this.status.state === "ready") void this.hello()
      throw new HostError(error.code, error.message)
    }
    const expected = REPLY_TYPE[body.type as T]
    if (reply.type !== expected) throw new HostError("failed", `Expected a ${expected} reply, got ${reply.type}.`)
    return reply as ReplyFor[T]
  }

  private received(raw: unknown) {
    const message = parseHostMessage(raw)
    if (!message) return
    if (message.kind === "changed") return this.changed(message.change)
    if (typeof message.id !== "number") return
    const pending = this.pending.get(message.id)
    if (!pending) return
    this.pending.delete(message.id)
    clearTimeout(pending.timer)
    pending.resolve(message.reply)
  }

  private changed(change: Change) {
    switch (change) {
      case "locked":
        this.setStatus({ state: "locked", detail: "Unlock Deadbolt to fill passwords" }, change)
        break
      case "stopped":
        // Hello would start the agent again; wait for `started`, which the
        // host sends once an agent runs again. A host that couldn't watch the
        // agent never says `stopped`; a `locked` error then asks hello (send).
        this.setStatus({ state: "locked", detail: "Deadbolt isn't running" }, change)
        break
      case "unlocked":
      case "started":
        void this.hello(change)
        break
      case "items":
        this.setStatus(this.status, change)
        break
    }
  }

  private disconnected(message: string) {
    this.port = null
    this.ready = null
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer)
      p.reject(new HostError("disconnected", message))
      this.pending.delete(id)
    }
    this.setStatus(NOT_FOUND.test(message) ? { state: "not-installed" } : { state: "disconnected", message })
    const delay = BACKOFF_MS[Math.min(this.attempt++, BACKOFF_MS.length - 1)]
    clearTimeout(this.retry)
    this.retry = setTimeout(() => void this.connect(), delay)
  }

  /** Try again now, e.g. when the popup opens after `deadbolt browser install`. */
  reconnectNow(): Promise<void> {
    if (this.port) return this.ready ?? Promise.resolve()
    this.attempt = 0
    return this.connect()
  }
}

export function disconnectedMessage(status: Status): string {
  if (status.state === "not-installed") return "Deadbolt's browser helper isn't installed."
  if (status.state === "disconnected") return status.message
  return "Deadbolt isn't connected."
}
