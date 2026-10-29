// The extension as a Deadbolt device of its own: no CLI, app or native host.
// The Rust vault (crates/ext-core, compiled to wasm) runs in a worker that an
// offscreen document owns, because the service worker sleeps after ~30 s and
// the unlocked vault, its sync and its pairing have to outlive that. This
// class is the service worker's side: it keeps the offscreen document open,
// sends it requests, follows the vault's status, and locks the vault on the
// lock preset's rules (docs/extension-device.md).
//
// The unwrapped key lives only in the worker's memory. Nothing secret is put
// in chrome.storage; closing the browser, a crash of the offscreen document or
// its worker, and Lock all end that memory, so each leaves the vault locked.

import type { DeviceCommand, DeviceReply, Status } from "../messages"
import { parseReply, PROTOCOL, REPLY_TYPE, type Change, type ReplyFor, type RequestBody } from "../protocol"
import { cancelled, HostError, type Listener, type SendOptions, type VaultBackend } from "./backend"
import { VAULT_CHANGED, VAULT_LOCK, VAULT_REQUEST, type VaultChanged, type VaultLock, type VaultRequest, type VaultResponse } from "./vault-messages"

export const OFFSCREEN_PAGE = "offscreen.html"
export const DEVICE_PAGE = "device.html"
const TIMEOUT_MS = 30_000
/** Creating or unlocking runs the passphrase KDF; pairing waits for the other device. */
const SLOW_MS: Partial<Record<string, number>> = {
  "device-create": 120_000,
  "device-unlock": 120_000,
  "device-pair": 300_000,
  "device-sync": 120_000,
  // Starting a join waits up to 20 s for the relay; finishing runs the KDF.
  "device-join-start": 60_000,
  "device-join-finish": 120_000,
}

/**
 * The Comfortable preset, the contract's default: lock after an hour without
 * use, when the screen locks, and when the browser quits. Strict (5 min) and
 * Relaxed (12 h, screen lock ignored) are a follow-up, as is keeping the key
 * in chrome.storage.session so an offscreen restart doesn't lock (a proposal
 * requiring its own security review).
 */
const IDLE_LOCK_MS = 60 * 60_000
const SYNC_EVERY_MIN = 5
/** A sync on wake (the popup opening, say) at most this often. */
const SYNC_AFTER_MS = 30_000
const TICK_ALARM = "deadbolt-idle"
const SYNC_ALARM = "deadbolt-sync"
const LAST_USE_KEY = "deadbolt.lastUse"

/**
 * What this device does today. Anything else is refused here, before the
 * vault sees it, and no capability is claimed for it: generated passwords,
 * passkeys, forms and the learning log are follow-ups.
 */
const SUPPORTED = new Set<string>(["hello", "list", "fill", "check", "save"])
/** Requests that count as use for the idle lock. Listing a page's logins doesn't (docs/autofill.md). */
const USES = new Set<string>(["fill", "save"])

/** device.html's commands that don't count as use. */
const PAGE_READS = new Set<string>(["device-status", "device-lock", "device-logins", "device-devices", "list", "device-join-status", "device-join-cancel"])
/**
 * Commands that change nothing hello would report. Until a join finishes,
 * nothing is persisted and hello stays not-set-up, so starting and polling
 * one don't ask it again.
 */
const QUIET = new Set<string>(["device-logins", "device-devices", "device-join-start", "device-join-status"])
/** Commands that name this browser to the vault's other devices. */
const NAMED = new Set<string>(["device-create", "device-unlock", "device-join-start", "device-join-finish"])

const unsupported = () => new HostError("failed", "The browser-only Deadbolt can't do this yet.")

export class StandaloneBackend implements VaultBackend {
  status: Status = { state: "connecting" }
  capabilities: string[] = []
  private listeners = new Set<Listener>()
  private ready: Promise<void> | null = null
  private creating: Promise<void> | null = null
  private lastUse = 0
  /** The last use, read back after the service worker restarts. */
  private loaded: Promise<void>
  private lastSync = 0

  constructor() {
    // Registered synchronously, so the events wake the service worker.
    chrome.runtime.onMessage.addListener((message: VaultChanged, sender) => {
      if (message?.type !== VAULT_CHANGED || !fromOffscreen(sender)) return
      void this.hello(message.change)
    })
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === TICK_ALARM) void this.tick()
      if (alarm.name === SYNC_ALARM) void this.sync()
    })
    chrome.idle.onStateChanged.addListener((state) => {
      if (state === "locked") void this.lock()
    })
    // Creating an alarm that exists starts its period over, and the service
    // worker starts far more often than once a minute: only make missing ones.
    void ensureAlarm(TICK_ALARM, 1)
    void ensureAlarm(SYNC_ALARM, SYNC_EVERY_MIN)
    this.loaded = chrome.storage.session.get(LAST_USE_KEY).then(
      (got) => {
        const at = got[LAST_USE_KEY]
        if (typeof at === "number") this.lastUse = Math.max(this.lastUse, at)
      },
      () => {},
    )
  }

  onChange(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private setStatus(status: Status, change?: Change) {
    this.status = status
    for (const listener of this.listeners) listener(status, change)
  }

  connect(): Promise<void> {
    this.ready ??= this.hello().finally(() => (this.ready = null))
    return this.ready
  }

  reconnectNow(): Promise<void> {
    return this.connect()
  }

  used() {
    this.lastUse = Date.now()
    void chrome.storage.session.set({ [LAST_USE_KEY]: this.lastUse }).catch(() => {})
    if (this.status.state === "ready" && this.lastUse - this.lastSync > SYNC_AFTER_MS) void this.sync()
  }

  /** Asks the vault how it is; `change` is passed on to listeners with the status. */
  async hello(change?: Change): Promise<void> {
    try {
      const reply = await this.request({ type: "hello" }, TIMEOUT_MS)
      if (reply.type !== "hello") throw new HostError("failed", `Expected a hello reply, got ${reply.type}.`)
      this.capabilities = reply.capabilities
      if (reply.protocol !== PROTOCOL) {
        this.setStatus({ state: "unavailable", detail: `This extension speaks protocol ${PROTOCOL}, but its vault speaks ${reply.protocol}.` }, change)
      } else if (reply.status === "ready") this.setStatus({ state: "ready", version: reply.version }, change)
      else this.setStatus({ state: reply.status, detail: reply.detail }, change)
    } catch (err) {
      this.capabilities = []
      this.setStatus({ state: "unavailable", detail: (err as Error).message }, change)
    }
  }

  async send<T extends keyof ReplyFor>(body: Extract<RequestBody, { type: T }>, { timeout = TIMEOUT_MS, signal }: SendOptions = {}): Promise<ReplyFor[T]> {
    if (signal?.aborted) throw cancelled()
    // `onId` names a request for passkey-cancel; passkeys aren't supported here.
    if (!SUPPORTED.has(body.type)) throw unsupported()
    if (USES.has(body.type)) this.used()
    const reply = await this.request(body as Record<string, unknown> & { type: string }, timeout)
    if (reply.type === "error") {
      if (reply.code === "locked" && this.status.state === "ready") void this.hello("locked")
      throw new HostError(reply.code, reply.message)
    }
    const expected = REPLY_TYPE[body.type as T]
    if (reply.type !== expected) throw new HostError("failed", `Expected a ${expected} reply, got ${reply.type}.`)
    if (body.type === "save") void this.hello("items")
    return reply as ReplyFor[T]
  }

  /** device.html's commands (see DeviceCommand); the background checks the sender (fromDevicePage). */
  async device(command: DeviceCommand): Promise<DeviceReply> {
    const started = Date.now()
    const fail = (message: string): DeviceReply => ({ ok: false, message, status: this.status })
    // The user working on the vault's own page is use. The page reading the
    // vault (its status, logins and devices, which it does again on every
    // change) isn't, so an open page never keeps the vault unlocked; nor is Lock.
    if (!PAGE_READS.has(command.type)) this.used()
    if (command.type === "device-lock") {
      await this.lock()
      return { ok: true, reply: { type: "device-lock", ok: true }, ms: Date.now() - started, status: this.status }
    }
    if (command.type === "device-join-cancel") {
      // The vault never sees a cancel: ending its worker, as Lock does, drops
      // the pending join and everything it held in memory.
      await this.lock()
      return { ok: true, reply: { type: "device-join-cancel", ok: true }, ms: Date.now() - started, status: this.status }
    }
    if (command.type === "device-status") {
      await this.hello()
      return { ok: true, reply: { type: "hello" }, ms: Date.now() - started, status: this.status }
    }
    if (command.type === "save" || command.type === "list") {
      try {
        const reply = command.type === "save" ? await this.send({ type: "save", origin: command.origin, entry: command.entry }) : await this.send({ type: "list", origin: command.origin })
        return { ok: true, reply: { ...reply }, ms: Date.now() - started, status: this.status }
      } catch (err) {
        return fail((err as Error).message)
      }
    }
    // The vault names this device to the others it pairs with: "Chrome on macOS".
    const body = NAMED.has(command.type) ? { ...command, deviceName: deviceName() } : command
    let raw: Record<string, unknown>
    try {
      raw = await this.raw(body, SLOW_MS[command.type] ?? TIMEOUT_MS)
    } catch (err) {
      return fail((err as Error).message)
    }
    const ms = Date.now() - started
    if (raw.type === "error") {
      await this.hello()
      return fail(typeof raw.message === "string" && raw.message ? raw.message : "The vault refused.")
    }
    if (command.type === "device-unlock" || command.type === "device-create" || command.type === "device-join-finish") {
      this.used()
      await this.hello("unlocked")
      // Catch up with the other devices now, not at the next sync alarm.
      void this.sync()
    } else if (command.type === "device-pair" || command.type === "device-sync") {
      this.lastSync = Date.now()
      await this.hello("items")
    } else if (!QUIET.has(command.type)) await this.hello()
    return { ok: true, reply: raw, ms, status: this.status }
  }

  /**
   * Ends the unlocked vault now: the offscreen document terminates the worker,
   * whatever it's in the middle of (a KDF, a pairing, a sync), and fails its
   * requests. A fresh worker starts locked on the next request. If the
   * document doesn't answer, it's closed, which ends the memory just as well.
   */
  async lock(): Promise<void> {
    const unlocked = this.status.state === "ready"
    const ok = await this.message<boolean>({ type: VAULT_LOCK } satisfies VaultLock, 5_000).catch(() => false)
    if (!ok) await chrome.offscreen.closeDocument().catch(() => {})
    this.capabilities = []
    // Only an unlocked vault is known to be locked now. Before the first one
    // (a join waiting, say) there's nothing to unlock: the fresh worker says
    // how it is.
    if (!unlocked) return this.hello()
    this.setStatus({ state: "locked", detail: "Unlock Deadbolt to fill passwords" }, "locked")
  }

  private async tick() {
    await this.loaded
    // Woken by the alarm, the service worker may not have heard from the vault yet.
    if (this.status.state === "connecting") await this.connect()
    if (this.status.state !== "ready") return
    if (Date.now() - this.lastUse >= IDLE_LOCK_MS) await this.lock()
  }

  private async sync() {
    if (this.status.state !== "ready") return
    this.lastSync = Date.now()
    const raw = await this.raw({ type: "device-sync" }, SLOW_MS["device-sync"]!).catch(() => null)
    if (raw && raw.type !== "error") void this.hello("items")
  }

  /** A protocol request, its reply checked like the native host's. */
  private async request(body: Record<string, unknown> & { type: string }, timeout: number) {
    const raw = await this.raw(body, timeout)
    const reply = parseReply(raw)
    if (!reply) throw new HostError("failed", "The vault's reply was malformed.")
    return reply
  }

  private async raw(body: Record<string, unknown> & { type: string }, timeout: number): Promise<Record<string, unknown>> {
    const response = await this.message<VaultResponse>({ type: VAULT_REQUEST, body } satisfies VaultRequest, timeout)
    if (!response) throw new HostError("disconnected", "Deadbolt's vault didn't start.")
    if ("error" in response) throw new HostError(response.locked ? "locked" : "failed", response.error)
    const reply = response.reply
    if (typeof reply !== "object" || reply === null || Array.isArray(reply)) throw new HostError("failed", "The vault's reply was malformed.")
    return reply as Record<string, unknown>
  }

  private async message<T>(message: VaultRequest | VaultLock, timeout: number): Promise<T | null> {
    await this.offscreen()
    let timer: ReturnType<typeof setTimeout> | undefined
    const expired = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new HostError("timeout", "Deadbolt's vault didn't answer in time.")), timeout)))
    try {
      return (await Promise.race([chrome.runtime.sendMessage(message), expired])) as T | null
    } catch (err) {
      if (err instanceof HostError) throw err
      throw new HostError("disconnected", String((err as Error)?.message ?? err))
    } finally {
      clearTimeout(timer)
    }
  }

  /** Opens the offscreen document if it isn't open (one at a time, as Chrome allows). */
  private async offscreen(): Promise<void> {
    const url = chrome.runtime.getURL(OFFSCREEN_PAGE)
    const open = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"], documentUrls: [url] })
    if (open.length) return
    this.creating ??= chrome.offscreen
      .createDocument({ url: OFFSCREEN_PAGE, reasons: ["WORKERS"], justification: "Runs the vault and its sync in a worker that outlives the service worker." })
      .catch((err) => {
        // Another call opened it first.
        if (!/single offscreen/i.test(String(err?.message ?? err))) throw err
      })
      .finally(() => (this.creating = null))
    await this.creating
  }
}

function fromOffscreen(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && !sender.tab && sender.url === chrome.runtime.getURL(OFFSCREEN_PAGE)
}

async function ensureAlarm(name: string, periodInMinutes: number) {
  const existing = await chrome.alarms.get(name).catch(() => undefined)
  if (!existing) await chrome.alarms.create(name, { periodInMinutes })
}

/** Only this extension's own device.html (in any tab, with any query or hash) may manage the vault: never a content script, the inline menu or another page. */
export function fromDevicePage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && sender.url?.split(/[?#]/)[0] === chrome.runtime.getURL(DEVICE_PAGE)
}

const text = (v: unknown, max: number): v is string => typeof v === "string" && v.length <= max
const origin = (v: unknown): v is string => {
  if (!text(v, 2048)) return false
  try {
    const u = new URL(v)
    return (u.protocol === "https:" || u.protocol === "http:") && u.origin === v
  } catch {
    return false
  }
}

/** A DeviceCommand rebuilt from the page's message with only its known fields, or null. */
export function deviceCommand(raw: unknown): DeviceCommand | null {
  if (typeof raw !== "object" || raw === null) return null
  const c = raw as Record<string, unknown>
  switch (c.type) {
    case "device-status":
    case "device-lock":
    case "device-sync":
    case "device-logins":
    case "device-devices":
      return { type: c.type }
    case "device-create":
      return text(c.passphrase, 1024) && c.passphrase && text(c.name, 200) ? { type: "device-create", passphrase: c.passphrase, name: c.name } : null
    case "device-unlock":
      return text(c.passphrase, 1024) ? { type: "device-unlock", passphrase: c.passphrase } : null
    case "device-join-start":
    case "device-join-status":
    case "device-join-cancel":
      return { type: c.type }
    case "device-join-finish":
      return text(c.passphrase, 1024) && c.passphrase ? { type: "device-join-finish", passphrase: c.passphrase } : null
    case "device-pair":
      return text(c.code, 200) && c.code ? { type: "device-pair", code: c.code } : null
    case "list":
      return origin(c.origin) ? { type: "list", origin: c.origin } : null
    case "save": {
      const e = c.entry as Record<string, unknown> | undefined
      if (!origin(c.origin) || !e || !text(e.title, 500) || !text(e.url, 2048) || !text(e.username, 500) || !text(e.password, 4096) || !e.password) return null
      return { type: "save", origin: c.origin, entry: { title: e.title, url: e.url, username: e.username, password: e.password } }
    }
  }
  return null
}

interface Brand {
  brand: string
}
/** What `navigator` says about the browser (Chromium's User-Agent Client Hints, then the user agent). */
export interface Nav {
  userAgent?: string
  userAgentData?: { brands?: Brand[]; platform?: string }
}

/** Brands as Client Hints name them ("Google Chrome", "Microsoft Edge"), else as the user agent does ("Edg/", "OPR/"). */
const BROWSERS: Array<[RegExp, string]> = [
  [/edge|\bedg\//i, "Edge"],
  [/opera|\bopr\//i, "Opera"],
  [/brave/i, "Brave"],
  [/vivaldi/i, "Vivaldi"],
  [/chrome/i, "Chrome"],
]
const SYSTEMS: Array<[RegExp, string]> = [
  [/android/i, "Android"],
  [/cros|chrome ?os/i, "ChromeOS"],
  [/mac/i, "macOS"],
  [/win/i, "Windows"],
  [/linux|x11/i, "Linux"],
]

const named = (table: Array<[RegExp, string]>, values: string[]) => table.find(([re]) => values.some((v) => re.test(v)))?.[1]

/** This browser as the other devices see it: "Chrome on macOS", "Edge on Windows", "Chromium on Linux". */
export function deviceName(nav: Nav = navigator as unknown as Nav): string {
  const hints = nav.userAgentData
  const brands = (hints?.brands ?? []).map((b) => b.brand)
  // With Client Hints, a browser that names no brand of its own is Chromium (the user agent says Chrome for all of them).
  const browser = named(BROWSERS, brands.length ? brands : [nav.userAgent ?? ""]) ?? "Chromium"
  const system = named(SYSTEMS, [hints?.platform || nav.userAgent || ""])
  return system ? `${browser} on ${system}` : browser
}
