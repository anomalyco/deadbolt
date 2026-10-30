// The extension as a Deadbolt device of its own: no CLI, app or native host.
// The Rust vault (crates/ext-core, compiled to wasm) runs in a worker that an
// offscreen document owns, because the service worker sleeps after ~30 s and
// the unlocked vault, its sync and its pairing have to outlive that. This
// class is the service worker's side: it keeps the offscreen document open,
// sends it requests, follows the vault's status, and locks the vault on the
// lock preset's rules (docs/extension-device.md).
//
// Every preset keeps keys only in worker memory. Losing the worker or its
// offscreen owner locks the vault; no trusted page can read a retained key.

import { DEFAULT_PRESET, isPreset, PRESETS, VAULT_NAME } from "../device-rules"
import type { DeviceCommand, DeviceReply, ItemInput, LockPreset, Reauth, ReauthChanged, Status, UnlockProof } from "../messages"
import { parseReply, PROTOCOL, REPLY_TYPE, type Change, type ReplyFor, type RequestBody } from "../protocol"
import { cancelled, HostError, type Listener, type ReauthAsk, type ReauthBody, type ReauthReply, type SendOptions, type VaultBackend } from "./backend"
import { CLEAR_AFTER_MS, CLIPBOARD_ALARM, CLIPBOARD_PERMISSIONS, COPIED_KEY, digest, isCopied, type Copied } from "./clipboard"
import { appendLearnLine } from "./learn-log"
import { VAULT_CHANGED, VAULT_CLIPBOARD, VAULT_LOCK, VAULT_REQUEST, type VaultChanged, type VaultClipboard, type VaultLock, type VaultRequest, type VaultResponse } from "./vault-messages"

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
  // Strict checks the passphrase (the KDF) before a password is shown, or a card's number filled.
  "device-secret": 120_000,
  "device-reauth-confirm": 120_000,
  // Strict checks the passphrase before a passkey is deleted, from Settings or the item list.
  "device-delete": 120_000,
  "device-item-delete": 120_000,
  "device-biometric-set": 120_000,
  "device-biometric-check": 120_000,
}
/** How long a fill waits for its passphrase before it's dropped. */
const REAUTH_MS = 2 * 60_000
const EXPIRED = "This request isn't waiting anymore. Try again on the page."

/** The chosen preset (src/device-rules.ts), in chrome.storage.local: a setting, nothing secret. */
const PRESET_KEY = "deadbolt.lockPreset"
const SYNC_EVERY_MIN = 5
/** A sync on wake (the popup opening, say) at most this often. */
const SYNC_AFTER_MS = 30_000
const TICK_ALARM = "deadbolt-idle"
const SYNC_ALARM = "deadbolt-sync"
const LAST_USE_KEY = "deadbolt.lastUse"
/**
 * Wrong passphrases in a row, and until when another try is refused: after
 * three, 1 s, then 2, 4, … up to a minute (backoff). In chrome.storage.session
 * so a restarted service worker keeps counting.
 */
const TRIES_KEY = "deadbolt.passphraseTries"
const FREE_TRIES = 3
const MAX_WAIT_MS = 60_000
/** How long to refuse after `fails` wrong passphrases in a row. */
export const backoff = (fails: number) => (fails < FREE_TRIES ? 0 : Math.min(MAX_WAIT_MS, 1000 * 2 ** (fails - FREE_TRIES)))

/**
 * What this device does today, as the vault's hello names it. Anything else
 * is refused here, before the vault sees it, and no capability is claimed
 * for it. `learn` never reaches the vault: the
 * learning log is kept here (bg/learn-log.ts), locked or not, as the host
 * keeps it outside the agent.
 */
const SUPPORTED = new Set<string>(["hello", "list", "fill", "check", "save", "generate", "generate-check", "generate-keep", "generate-drop", "forms", "fill-form", "passkey-list", "passkey-create", "passkey-get", "passkey-cancel", "learn"])
/** Requests that count as use for the idle lock. Listing a page's logins or forms doesn't (docs/autofill.md). */
const USES = new Set<string>(["fill", "save", "fill-form", "generate", "passkey-create", "passkey-get"])

/**
 * As the native host (crates/cli/src/browser/host.rs): checks are a password
 * oracle and fills hand out secrets, so a runaway or hostile caller gets them
 * slowly: a burst, then one per interval.
 */
const CHECKS_RATE = { capacity: 20, everyMs: 1000 }
const FILLS_RATE = { capacity: 60, everyMs: 250 }
/** Learning logs a line per sign-in step and frame: a burst, then a steady trickle. */
const LEARNS_RATE = { capacity: 100, everyMs: 100 }
/** The host's limit on one request, which bounds a learning line too. */
const MAX_REQUEST = 64 * 1024
const RATED: Partial<Record<string, "checks" | "fills" | "passkeys" | "learns">> = {
  learn: "learns",
  check: "checks",
  "generate-check": "checks",
  fill: "fills",
  generate: "fills",
  "fill-form": "fills",
  "passkey-create": "passkeys",
  "passkey-get": "passkeys",
}

/** A token bucket: `capacity` at once, refilled one per `everyMs`. The host's Bucket, on Date.now(). */
class Bucket {
  private tokens: number
  private since: number

  constructor(
    private readonly rate: { capacity: number; everyMs: number },
    now = Date.now(),
  ) {
    this.tokens = rate.capacity
    this.since = now
  }

  take(now = Date.now()): boolean {
    // The wall clock went back: start counting from now, earning nothing for it.
    if (now < this.since) this.since = now
    const earned = Math.floor((now - this.since) / this.rate.everyMs)
    if (earned > 0) {
      this.tokens = Math.min(this.rate.capacity, this.tokens + earned)
      this.since = this.tokens === this.rate.capacity ? now : this.since + earned * this.rate.everyMs
    }
    if (this.tokens === 0) return false
    this.tokens -= 1
    return true
  }
}

/** The native host's refusal, word for word. */
const slowDown = () => new HostError("rate_limited", "too many requests; try again in a moment")

/** device.html's commands that don't count as use. */
const PAGE_READS = new Set<string>([
  "device-status",
  "device-lock",
  "device-passkeys",
  "device-devices",
  "device-items",
  "device-kinds",
  // An item's details, which an open detail asks again for every new one-time code.
  "device-item",
  "list",
  "device-join-status",
  "device-join-cancel",
  "device-settings",
  "device-biometric-info",
  "device-copied",
  "device-reauth",
  "device-reauth-cancel",
])
/**
 * Commands that change nothing hello would report. Until a join finishes,
 * nothing is persisted and hello stays not-set-up, so starting and polling
 * one don't ask it again.
 */
const QUIET = new Set<string>(["device-items", "device-kinds", "device-devices", "device-item", "device-secret", "device-generate", "device-join-start", "device-join-status"])
/** Commands that name this browser to the vault's other devices. */
const NAMED = new Set<string>(["device-create", "device-unlock", "device-join-start", "device-join-finish"])
/** Commands that open the vault: the worker is told the lock preset with them, and keeps Strict itself. */
const OPENS = new Set<string>(["device-create", "device-unlock", "device-join-finish"])
/** Commands that check a passphrase, and back off after wrong ones. */
const CHECKS = new Set<string>(["device-unlock", "device-secret", "device-delete", "device-item-delete", "device-reauth-confirm", "device-biometric-set", "device-biometric-check"])

const UNREADABLE = "Deadbolt's vault gave an answer it couldn't read. Reload the extension and try again."
const unsupported = () => new HostError("failed", "The browser-only Deadbolt can't do this yet.")

/** A fill waiting on the passphrase. It holds no passphrase: the one that answers it is used once and dropped. */
interface Pending {
  prompt: Reauth
  tabId: number
  body: ReauthBody
  /**
   * The passphrase check running for a passkey, whose authorization is spent
   * once. `key` is a hash of its passphrase salted with the prompt's id (never
   * the passphrase): the same passphrase sent again (two open vault surfaces)
   * shares its answer, and a different one waits for it, then runs on its own.
   */
  confirming?: { key: string; reply: Promise<DeviceReply> }
  /** The device.html tab opened to ask, closed again once it's answered. */
  opened?: number
  /**
   * A passphrase for it is being checked (`true`) or was (`false`). While one
   * is, the fill doesn't time out, so a slow KDF isn't dropped under the user;
   * once none is and the fill still waits (a wrong one), it gets REAUTH_MS again.
   */
  checking(on: boolean): void
  settle(result: { reply: ReauthReply } | { error: HostError }): void
}

export class StandaloneBackend implements VaultBackend {
  status: Status = { state: "connecting" }
  capabilities: string[] = []
  private listeners = new Set<Listener>()
  private ready: Promise<void> | null = null
  private creating: Promise<void> | null = null
  private lastUse = 0
  /** The last use, read back after the service worker restarts. */
  private loaded: Promise<void>
  private initialized = false
  private lastSync = 0
  preset: LockPreset = DEFAULT_PRESET
  private tries = { fails: 0, until: 0 }
  private copied: Copied | null = null
  /** At most one fill waits on the passphrase; a newer one replaces it. */
  private pending: Pending | null = null
  /**
   * device.html tabs opened for a fill that has ended, until they're closed:
   * a newer fill never counts on one of them to show its prompt.
   */
  private closing = new Set<number>()
  private buckets = { checks: new Bucket(CHECKS_RATE), fills: new Bucket(FILLS_RATE), passkeys: new Bucket({ capacity: 10, everyMs: 1000 }), learns: new Bucket(LEARNS_RATE) }
  private ceremonies = 0
  private epoch = 0
  private locking: Promise<void> | null = null

  constructor() {
    // Registered synchronously, so the events wake the service worker.
    chrome.runtime.onMessage.addListener((message: VaultChanged, sender) => {
      if (message?.type !== VAULT_CHANGED || !fromOffscreen(sender)) return
      void this.hello(message.change)
    })
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === TICK_ALARM) void this.tick()
      if (alarm.name === SYNC_ALARM) void this.sync()
      if (alarm.name === CLIPBOARD_ALARM) void this.clearClipboard()
    })
    chrome.idle.onStateChanged.addListener((state) => {
      if (state === "locked") void this.loaded.then(() => {
        if (PRESETS[this.preset].screenLock) return this.lock()
      })
    })
    // Creating an alarm that exists starts its period over, and the service
    // worker starts far more often than once a minute: only make missing ones.
    void ensureAlarm(TICK_ALARM, 1)
    void ensureAlarm(SYNC_ALARM, SYNC_EVERY_MIN)
    this.loaded = Promise.all([
      chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).then(() => {}),
      chrome.storage.session.get(LAST_USE_KEY).then(
        (got) => {
          const at = got[LAST_USE_KEY]
          if (typeof at === "number") this.lastUse = Math.max(this.lastUse, at)
        },
        () => {},
      ),
      chrome.storage.local.get(PRESET_KEY).then(
        (got) => {
          if (isPreset(got[PRESET_KEY])) this.preset = got[PRESET_KEY]
        },
        () => {},
      ),
      chrome.storage.session.get([TRIES_KEY, COPIED_KEY]).then(
        (got) => {
          const t = got[TRIES_KEY] as { fails?: unknown; until?: unknown } | undefined
          if (typeof t?.fails === "number" && typeof t.until === "number") this.tries = { fails: t.fails, until: t.until }
          if (isCopied(got[COPIED_KEY])) this.copied ??= got[COPIED_KEY]
        },
        () => {},
      ),
    ]).then(() => { this.initialized = true })
  }

  onChange(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private setStatus(status: Status, change?: Change) {
    this.status = status
    if (status.state !== "ready") this.endReauth(new HostError("locked", "Deadbolt locked. Nothing was filled."))
    for (const listener of this.listeners) listener(status, change)
  }

  connect(): Promise<void> {
    this.ready ??= this.hello().finally(() => (this.ready = null))
    return this.ready
  }

  reconnectNow(): Promise<void> {
    return this.connect()
  }

  used(force = false) {
    if (!this.initialized) {
      void this.loaded.then(() => this.used(force)).catch(() => {})
      return
    }
    if (!force && this.lastUse && Date.now() - this.lastUse >= PRESETS[this.preset].idleMs) return
    this.lastUse = Date.now()
    void chrome.storage.session.set({ [LAST_USE_KEY]: this.lastUse }).catch(() => {})
    if (this.status.state === "ready" && this.lastUse - this.lastSync > SYNC_AFTER_MS) void this.sync()
  }

  /** Asks the vault how it is; `change` is passed on to listeners with the status. */
  async hello(change?: Change): Promise<void> {
    try {
      const reply = await this.request({ type: "hello" }, TIMEOUT_MS)
      if (reply.type !== "hello") throw new HostError("failed", UNREADABLE)
      // Only what this build sends on: a capability it would refuse is never offered.
      // The learning log is this side's own, whatever the vault says.
      this.capabilities = [...reply.capabilities.filter((c) => c !== "learn" && (c === "passkeys" || SUPPORTED.has(c))), "learn"]
      if (reply.protocol !== PROTOCOL) {
        this.setStatus({ state: "unavailable", detail: "This extension and its vault are different versions. Reload the extension." }, change)
      } else if (reply.status === "ready") this.setStatus({ state: "ready", version: reply.version }, change)
      else this.setStatus({ state: reply.status, detail: reply.detail }, change)
    } catch (err) {
      this.capabilities = []
      this.setStatus({ state: "unavailable", detail: (err as Error).message }, change)
    }
  }

  async send<T extends keyof ReplyFor>(body: Extract<RequestBody, { type: T }>, { timeout = TIMEOUT_MS, signal }: SendOptions = {}): Promise<ReplyFor[T]> {
    if (signal?.aborted) throw cancelled()
    // Standalone cancels through the ceremony's AbortSignal, including its
    // passphrase prompt. There is no native prompt/request id to cancel.
    if (body.type === "passkey-cancel") return { type: "passkey-cancelled", found: false } as ReplyFor[T]
    if (!SUPPORTED.has(body.type)) throw unsupported()
    // Refused before the vault sees it, and before it counts as use.
    const rated = RATED[body.type]
    if (rated && !this.buckets[rated].take()) throw slowDown()
    // Counted before any await, so concurrent ceremonies can't all pass the cap.
    const ceremony = body.type === "passkey-create" || body.type === "passkey-get"
    if (ceremony && this.ceremonies >= 4) throw slowDown()
    if (ceremony) this.ceremonies++
    let reply
    try {
      await this.loaded
      if (signal?.aborted) throw cancelled()
      if (USES.has(body.type)) this.used()
      if (body.type === "learn") return (await this.learn(body as Extract<RequestBody, { type: "learn" }>)) as ReplyFor[T]
      reply = await this.request(body as Record<string, unknown> & { type: string }, timeout)
    } finally {
      if (ceremony) this.ceremonies--
    }
    if (signal?.aborted) throw cancelled()
    if (reply.type === "error") {
      if (reply.code === "locked" && this.status.state === "ready") void this.hello("locked")
      throw new HostError(reply.code, reply.message)
    }
    const expected = REPLY_TYPE[body.type as T]
    if (reply.type !== expected) throw new HostError("failed", UNREADABLE)
    if (body.type === "save") void this.hello("items")
    return reply as ReplyFor[T]
  }

  /** A line of a learning log, as the host's `learn`: kept here, never in the vault. */
  private async learn(body: Extract<RequestBody, { type: "learn" }>): Promise<ReplyFor["learn"]> {
    if (typeof body.line !== "object" || body.line === null || JSON.stringify(body).length > MAX_REQUEST) throw new HostError("bad_request", `a request is at most ${MAX_REQUEST} bytes`)
    const refused = await appendLearnLine(body.session, body.line).catch(() => "couldn't write the learning log")
    if (refused) throw new HostError(refused.startsWith("couldn't") ? "failed" : "bad_request", refused)
    return { type: "learned" }
  }

  /** device.html's commands (see DeviceCommand); the background checks the sender (fromVaultPage). */
  async device(command: DeviceCommand): Promise<DeviceReply> {
    const started = Date.now()
    const fail = (message: string, code?: string): DeviceReply => ({ ok: false, message, status: this.status, ...(code ? { code } : {}), ...(this.tries.until > Date.now() ? { retryAt: this.tries.until } : {}) })
    // The user working on the vault's own page is use. The page reading the
    // vault (its status, logins and devices, which it does again on every
    // change) isn't, so an open page never keeps the vault unlocked; nor is Lock.
    if (command.type !== "device-lock" && command.type !== "device-join-cancel") await this.loaded
    if (!PAGE_READS.has(command.type) && !OPENS.has(command.type)) this.used()
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
    if (command.type === "device-used") return { ok: true, reply: { type: "device-used" }, ms: 0, status: this.status }
    if (command.type === "device-settings" || command.type === "device-preset") {
      await this.loaded
      if (command.type === "device-preset") {
        // An unlock already under way would open with the old policy: it
        // fails instead, and is tried again under this one.
        this.epoch++
        // The worker holds the preset too, and enforces Strict itself: an
        // unlocked one hears of it first, so what this page and the passkey
        // prompts say is the preset the worker keeps. A locked one is told
        // when it opens. If it refuses, the vault locks rather than run on
        // a policy the page doesn't show.
        if (this.status.state === "ready") {
          const told = await this.raw({ type: "device-preset", preset: command.preset }, TIMEOUT_MS).catch((err: Error) => ({ type: "error", message: err.message }))
          if (told.type === "error") {
            await this.lock()
            return fail(typeof told.message === "string" && told.message ? told.message : "Deadbolt couldn't change the lock preset.")
          }
        }
        this.preset = command.preset
        await chrome.storage.local.set({ [PRESET_KEY]: command.preset }).catch(() => {})
      }
      return { ok: true, reply: { type: "device-settings", preset: this.preset, retryAt: this.tries.until }, ms: Date.now() - started, status: this.status }
    }
    if (command.type === "device-copied") {
      const clears = await this.copiedNow({ salt: command.salt, hash: command.hash })
      return { ok: true, reply: { type: "device-copied", clears }, ms: Date.now() - started, status: this.status }
    }
    if (command.type === "device-reauth") return { ok: true, reply: { type: "device-reauth", reauth: this.pending ? { ...this.pending.prompt } : null }, ms: 0, status: this.status }
    if (command.type === "device-reauth-cancel") {
      if (this.pending?.prompt.id === command.id) this.pending.settle({ error: cancelled() })
      return { ok: true, reply: { type: "device-reauth-cancel", ok: true }, ms: 0, status: this.status }
    }
    if (command.type === "device-secret" && !command.passphrase && !command.prf) {
      await this.loaded
      // Strict: showing a password asks for the passphrase every time.
      if (PRESETS[this.preset].reauth) return fail("Enter your passphrase to show this password.", "passphrase_needed")
    }
    const checks = CHECKS.has(command.type) && typeof (command as { passphrase?: string }).passphrase === "string"
    if (checks) {
      await this.loaded
      const wait = this.tries.until - Date.now()
      if (wait > 0) return fail(`Too many wrong passphrases. Try again in ${Math.ceil(wait / 1000)} s.`, "backoff")
    }
    if (command.type === "device-reauth-confirm") return this.confirm(command.id, command.prf ? { prf: command.prf } : { passphrase: command.passphrase! }, started)
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
    if (OPENS.has(command.type)) await this.loaded
    const body = {
      ...command,
      ...(NAMED.has(command.type) ? { deviceName: deviceName() } : {}),
      ...(OPENS.has(command.type) ? { preset: this.preset } : {}),
    }
    let raw: Record<string, unknown>
    const operation = this.epoch
    try {
      raw = await this.raw(body, SLOW_MS[command.type] ?? TIMEOUT_MS)
    } catch (err) {
      return fail((err as Error).message)
    }
    if (operation !== this.epoch) {
      // An opening command may have installed keys and the previous policy
      // after Lock or a preset change. Never leave that worker running.
      if (OPENS.has(command.type)) await this.lock()
      return fail("Deadbolt locked or its lock policy changed. Try again.", "locked")
    }
    const ms = Date.now() - started
    if (checks) await this.tried(raw.type === "error" && raw.code === "wrong_passphrase" ? "wrong" : raw.type === "error" ? "other" : "right")
    if (raw.type === "error") {
      await this.hello()
      return fail(typeof raw.message === "string" && raw.message ? raw.message : "Deadbolt couldn't do that.", typeof raw.code === "string" ? raw.code : undefined)
    }
    if (command.type === "device-unlock" || command.type === "device-create" || command.type === "device-join-finish") {
      this.used(true)
      if (operation !== this.epoch) {
        await this.lock()
        return fail("Deadbolt locked or its lock policy changed. Try again.", "locked")
      }
      if (command.type === "device-unlock") await chrome.storage.local.set({ "deadbolt.unlockMethod": command.prf ? "touch-id" : "passphrase" }).catch(() => {})
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
    this.epoch++
    this.locking ??= this.lockNow().finally(() => (this.locking = null))
    return this.locking
  }

  private async lockNow(): Promise<void> {
    const unlocked = this.status.state === "ready"
    this.endReauth(new HostError("locked", "Deadbolt locked. Nothing was filled."))
    // A copied password goes with the vault.
    await this.clearClipboard().catch(() => {})
    const ok = await this.message<boolean>({ type: VAULT_LOCK } satisfies VaultLock, 5_000).catch(() => false)
    if (!ok) await chrome.offscreen.closeDocument().catch(() => {})
    this.capabilities = []
    // Only an unlocked vault is known to be locked now. Before the first one
    // (a join waiting, say) there's nothing to unlock: the fresh worker says
    // how it is.
    if (!unlocked) {
      const reply = await this.transport({ type: "hello" }, TIMEOUT_MS).catch(() => null)
      this.setStatus({ state: reply?.status === "not-set-up" ? "not-set-up" : "locked" }, "locked")
      return
    }
    this.setStatus({ state: "locked", detail: "Unlock Deadbolt to fill passwords" }, "locked")
  }

  /**
   * A fill the vault wants the passphrase for: kept (without any passphrase)
   * until device.html or the popup answers it, and asked for there. The
   * popup opens over the tab if Chrome lets it; otherwise device.html opens
   * in a new tab. A page already open hears of it.
   */
  reauth<T extends ReauthBody["type"]>(body: Extract<ReauthBody, { type: T }>, ask: ReauthAsk, signal: AbortSignal): Promise<ReplyFor[T]> {
    const request: ReauthBody = body
    if (signal.aborted) return Promise.reject(cancelled())
    if (this.status.state !== "ready") return Promise.reject(new HostError("locked", "Deadbolt is locked. Nothing was filled."))
    this.endReauth(cancelled())
    return new Promise<ReplyFor[T]>((resolve, reject) => {
      let done = false
      let timer: ReturnType<typeof setTimeout> | undefined
      /** Passphrases being checked for it now (the popup and device.html may both answer). */
      let checks = 0
      const expire = () => {
        clearTimeout(timer)
        timer = setTimeout(() => p.settle({ error: cancelled() }), REAUTH_MS)
      }
      const abort = () => p.settle({ error: cancelled() })
      const p: Pending = {
        prompt: { id: newId(), title: reauthTitle(ask.title, request.type === "fill-form" ? "Card" : "Passkey"), site: ask.site, kind: request.type === "fill-form" ? "card" : request.type },
        tabId: ask.tabId,
        body: structuredClone(body),
        checking: (on) => {
          if (done) return
          checks = Math.max(0, checks + (on ? 1 : -1))
          if (checks) clearTimeout(timer)
          else expire()
        },
        settle: (result) => {
          if (done) return
          done = true
          clearTimeout(timer)
          signal.removeEventListener("abort", abort)
          let left = Promise.resolve()
          if (this.pending === p) {
            this.pending = null
            left = this.leave(p, "reply" in result)
            reauthChanged()
          }
          // A fill goes on once its page is in front again, where its fields are checked once more.
          if ("reply" in result) void left.catch(() => {}).then(() => resolve(result.reply as ReplyFor[T]))
          else reject(result.error)
        },
      }
      expire()
      signal.addEventListener("abort", abort, { once: true })
      this.pending = p
      reauthChanged()
      void this.askFor(p)
    })
  }

  /** Strict asks for the passphrase before a card's number or code is filled (the vault holds the same preset). */
  async asksPassphrase(): Promise<boolean> {
    await this.loaded
    return PRESETS[this.preset].reauth
  }

  /** Drops the waiting fill, if any, with `error`. */
  private endReauth(error: HostError) {
    this.pending?.settle({ error })
  }

  /**
   * Puts the prompt in front of the user. An open popup shows it, and so
   * does device.html only in the active tab of the focused window: one left
   * open in a background tab would never be seen. Otherwise the popup opens
   * over the page's tab, and failing that device.html opens in a new tab
   * beside it.
   */
  private async askFor(p: Pending) {
    const contexts = await chrome.runtime.getContexts({ contextTypes: ["POPUP" as chrome.runtime.ContextType, "TAB" as chrome.runtime.ContextType] }).catch(() => [])
    const base = (c: chrome.runtime.ExtensionContext) => (c.documentUrl ?? "").split(/[?#]/)[0]
    if (contexts.some((c) => c.contextType === "POPUP" && base(c) === chrome.runtime.getURL(POPUP_PAGE))) return
    for (const c of contexts) if (c.contextType === "TAB" && base(c) === chrome.runtime.getURL(DEVICE_PAGE) && !this.closing.has(c.tabId) && (await inFront(c.tabId))) return
    const action = chrome.action as typeof chrome.action & { openPopup?: (options?: { windowId?: number }) => Promise<void> }
    const tab = await chrome.tabs.get(p.tabId).catch(() => null)
    if (this.pending !== p) return
    if (tab?.active && typeof action.openPopup === "function") {
      const opened = await action.openPopup({ windowId: tab.windowId }).then(
        () => true,
        () => false,
      )
      if (opened || this.pending !== p) return
    }
    const page = await Promise.resolve(chrome.tabs.create({ url: `${chrome.runtime.getURL(DEVICE_PAGE)}#reauth`, ...(tab ? { windowId: tab.windowId } : {}) })).catch(() => undefined)
    if (page?.id === undefined) return
    if (this.pending === p) p.opened = page.id
    else void Promise.resolve(chrome.tabs.remove(page.id)).catch(() => {})
  }

  /**
   * Back to the page the fill is for. A fill that goes on brings its tab and
   * window to the front (it was answered in the popup or a device.html tab),
   * since its fields are checked again there. Only the device.html tab
   * opened to ask is closed, never one the user had open.
   */
  private async leave(p: Pending, filling: boolean) {
    // Claimed now, before any await, so a fill that replaces this one doesn't reuse the tab.
    const opened = p.opened
    if (opened !== undefined) this.closing.add(opened)
    if (filling || opened !== undefined) {
      const tab = await Promise.resolve()
        .then(() => chrome.tabs.update(p.tabId, { active: true }))
        .catch(() => undefined)
      const windowId = tab?.windowId ?? (await chrome.tabs.get(p.tabId).catch(() => null))?.windowId
      if (windowId !== undefined) {
        await Promise.resolve()
          .then(() => chrome.windows.update(windowId, { focused: true }))
          .catch(() => {})
      }
    }
    if (opened !== undefined) {
      await Promise.resolve()
        .then(() => chrome.tabs.remove(opened))
        .catch(() => {})
      this.closing.delete(opened)
    }
  }

  /**
   * The passphrase for the waiting fill `id`: the vault runs that fill with
   * it, once. A wrong one leaves the fill waiting for another try (with the
   * same backoff as unlocking); anything else ends it. The passphrase goes
   * to the vault in this one request and is kept nowhere.
   */
  private async confirm(id: string, proof: UnlockProof, started: number): Promise<DeviceReply> {
    const p = this.pending
    if (!p || p.prompt.id !== id) return { ok: false, message: EXPIRED, code: "expired", status: this.status }
    // A card may be filled after Touch ID. A passkey always takes the
    // passphrase: this keeps it waiting, so the passphrase can still answer it.
    if (p.body.type === "fill-form") return this.confirmOnce(p, proof, started)
    if (typeof proof.passphrase !== "string") return { ok: false, message: "Enter your passphrase to use this passkey.", code: "passphrase_needed", status: this.status }
    const passphrase = proof.passphrase
    const key = await digest(p.prompt.id, passphrase)
    const prior = p.confirming
    if (prior?.key === key) return prior.reply
    if (this.pending !== p) return { ok: false, message: EXPIRED, code: "expired", status: this.status }
    // Another passphrase is being checked: this one runs after it, if the request still waits and no backoff began.
    const after = () => this.confirmAfter(p, passphrase, started)
    const reply = prior ? prior.reply.then(after, after) : this.confirmOnce(p, { passphrase }, started)
    const entry = { key, reply }
    p.confirming = entry
    // Kept once the request has ended, so the same passphrase sent again late gets the same answer.
    const clear = () => {
      if (p.confirming === entry && this.pending === p) p.confirming = undefined
    }
    reply.then(clear, clear)
    return reply
  }

  /** A passkey's passphrase that waited for another check: it runs only if that one left the request waiting. */
  private async confirmAfter(p: Pending, passphrase: string, started: number): Promise<DeviceReply> {
    if (this.pending !== p) return { ok: false, message: EXPIRED, code: "expired", status: this.status }
    const wait = this.tries.until - Date.now()
    if (wait > 0) return { ok: false, message: `Too many wrong passphrases. Try again in ${Math.ceil(wait / 1000)} s.`, code: "backoff", status: this.status }
    return this.confirmOnce(p, { passphrase }, started)
  }

  private async confirmOnce(p: Pending, proof: UnlockProof, started: number): Promise<DeviceReply> {
    const fail = (message: string, code?: string): DeviceReply => ({ ok: false, message, status: this.status, ...(code ? { code } : {}) })
    let raw: Record<string, unknown>
    // The KDF may outlast the time left to answer: the fill waits on it, not the clock.
    p.checking(true)
    try {
      const passkey = p.body.type !== "fill-form"
      raw = await this.raw(passkey ? { type: "passkey-authorize", ceremony: p.body, passphrase: proof.passphrase } : { ...p.body, ...proof }, SLOW_MS["device-reauth-confirm"]!)
      // Checking the passphrase does not register/sign. Only a still-live
      // ceremony may spend its one-shot, command-bound authorization.
      if (passkey && raw.type === "passkey-authorized") {
        await this.tried("right")
        if (this.pending !== p) return fail(EXPIRED, "expired")
        raw = await this.raw({ type: "passkey-finish", token: raw.token }, TIMEOUT_MS)
      }
    } catch (err) {
      const error = err instanceof HostError ? err : new HostError("failed", UNREADABLE)
      p.settle({ error })
      // The worker ended under it (Lock, or Chrome discarding it): say how the vault is now.
      if ((error.code === "locked" || error.code === "disconnected") && this.status.state === "ready") await this.hello()
      return fail(error.message, error.code === "locked" ? "locked" : undefined)
    } finally {
      p.checking(false)
    }
    await this.tried(raw.type === "error" && raw.code === "wrong_passphrase" ? "wrong" : raw.type === "error" ? "other" : "right")
    // Cancelled, locked or replaced while the passphrase was checked: its values go nowhere.
    if (this.pending !== p) return fail(EXPIRED, "expired")
    const reply = parseReply(raw)
    if (reply?.type === "error" && reply.code === "wrong_passphrase") return fail(reply.message || "That passphrase isn't right.", "wrong_passphrase")
    if (reply?.type !== REPLY_TYPE[p.body.type]) {
      const error = reply?.type === "error" ? new HostError(reply.code, reply.message || "Deadbolt couldn't complete that request.") : new HostError("failed", UNREADABLE)
      p.settle({ error })
      // A fresh worker answers locked: the page should show Unlock, not a vault that's gone.
      if (error.code === "locked" && this.status.state === "ready") await this.hello("locked")
      return fail(error.message, reply?.type === "error" ? reply.code : undefined)
    }
    p.settle({ reply: reply as ReauthReply })
    return { ok: true, reply: { type: "device-reauth-confirm", ok: true }, ms: Date.now() - started, status: this.status }
  }

  /** Counts a passphrase check: wrong ones back off, a right one starts over, anything else leaves it. */
  private async tried(outcome: "right" | "wrong" | "other") {
    if (outcome === "other") return
    const fails = outcome === "wrong" ? this.tries.fails + 1 : 0
    this.tries = { fails, until: fails ? Date.now() + backoff(fails) : 0 }
    await chrome.storage.session.set({ [TRIES_KEY]: this.tries }).catch(() => {})
  }

  /**
   * The page copied a password or code: with the clipboard permissions,
   * remember the salted hash the page made of it and clear it in 30 s
   * (bg/clipboard.ts). Answers whether it will be cleared.
   */
  private async copiedNow(copied: Copied): Promise<boolean> {
    const granted = await chrome.permissions.contains({ permissions: CLIPBOARD_PERMISSIONS }).catch(() => false)
    if (!granted) return false
    this.copied = { salt: copied.salt, hash: copied.hash }
    await chrome.storage.session.set({ [COPIED_KEY]: this.copied }).catch(() => {})
    await chrome.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + CLEAR_AFTER_MS })
    return true
  }

  /** Empties the clipboard if it still holds what Deadbolt copied; forgets it either way. */
  async clearClipboard(): Promise<void> {
    await this.loaded
    const copied = this.copied
    if (!copied) return
    this.copied = null
    await chrome.storage.session.remove(COPIED_KEY).catch(() => {})
    await chrome.alarms.clear(CLIPBOARD_ALARM).catch(() => false)
    if (!(await chrome.permissions.contains({ permissions: CLIPBOARD_PERMISSIONS }).catch(() => false))) return
    await this.message<boolean>({ type: VAULT_CLIPBOARD, ...copied } satisfies VaultClipboard, 5_000).catch(() => false)
  }

  private async tick() {
    await this.loaded
    // Woken by the alarm, the service worker may not have heard from the vault yet.
    if (this.status.state === "connecting") await this.connect()
    if (this.status.state !== "ready") return
    if (Date.now() - this.lastUse >= PRESETS[this.preset].idleMs) await this.lock()
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
    if (!reply) throw new HostError("failed", UNREADABLE)
    return reply
  }

  private async raw(body: Record<string, unknown> & { type: string }, timeout: number): Promise<Record<string, unknown>> {
    const at = this.epoch
    await this.loaded
    await this.locking
    if (at !== this.epoch) throw new HostError("locked", "Deadbolt locked. Try again.")
    return this.transport(body, timeout)
  }

  private async transport(body: Record<string, unknown> & { type: string }, timeout: number): Promise<Record<string, unknown>> {
    const response = await this.message<VaultResponse>({ type: VAULT_REQUEST, body } satisfies VaultRequest, timeout)
    if (!response) throw new HostError("disconnected", "Deadbolt's vault didn't start. Reload the extension and try again.")
    if ("error" in response) throw new HostError(response.locked ? "locked" : "failed", response.error)
    const reply = response.reply
    if (typeof reply !== "object" || reply === null || Array.isArray(reply)) throw new HostError("failed", UNREADABLE)
    return reply as Record<string, unknown>
  }

  private async message<T>(message: VaultRequest | VaultLock | VaultClipboard, timeout: number): Promise<T | null> {
    await this.offscreen()
    let timer: ReturnType<typeof setTimeout> | undefined
    const expired = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new HostError("timeout", "Deadbolt's vault didn't answer in time.")), timeout)))
    try {
      return (await Promise.race([chrome.runtime.sendMessage(message), expired])) as T | null
    } catch (err) {
      if (err instanceof HostError) throw err
      // Chrome's own words ("Receiving end does not exist") mean nothing to a person.
      throw new HostError("disconnected", "Deadbolt's vault didn't start. Reload the extension and try again.")
    } finally {
      clearTimeout(timer)
    }
  }

  /** Opens the offscreen document if it isn't open (one at a time, as Chrome allows). */
  private async offscreen(): Promise<void> {
    const url = chrome.runtime.getURL(OFFSCREEN_PAGE)
    const open = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"], documentUrls: [url] })
    if (open.length) {
      // Chrome exposes the context before its script is ready to receive.
      // A concurrent request must still wait for the initial page load.
      await this.creating
      return
    }
    this.creating ??= chrome.offscreen
      .createDocument({
        url: OFFSCREEN_PAGE,
        reasons: ["WORKERS", "CLIPBOARD"],
        justification: "Runs the vault and its sync in a worker that outlives the service worker, and clears a copied password off the clipboard.",
      })
      .catch((err) => {
        // Another call opened it first.
        if (!/single offscreen/i.test(String(err?.message ?? err))) throw err
      })
      .finally(() => (this.creating = null))
    await this.creating
  }
}

/** Whether tab `tabId` is the one showing in the focused window. */
async function inFront(tabId: number | undefined): Promise<boolean> {
  if (tabId === undefined || tabId < 0) return false
  const tab = await chrome.tabs.get(tabId).catch(() => null)
  if (!tab?.active) return false
  const window = await Promise.resolve()
    .then(() => chrome.windows.get(tab.windowId))
    .catch(() => undefined)
  return window?.focused === true
}

/** Tells Deadbolt's own open pages that the fill waiting on the passphrase changed. */
function reauthChanged() {
  void Promise.resolve(chrome.runtime.sendMessage({ type: "db:reauth" } satisfies ReauthChanged)).catch(() => {})
}

/** Controls and bidi overrides, as the core strips them from passkey names (crates/core). */
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g
const MAX_TITLE = 64

/**
 * A passphrase prompt's title, which a page may have chosen (a passkey's
 * account name): no controls or bidi overrides, at most 64 characters (code
 * points, never half of one), trimmed; `fallback` when nothing is left.
 */
export function reauthTitle(title: string, fallback: string): string {
  const clean = Array.from(title.replace(UNSAFE_TEXT, "").trim()).slice(0, MAX_TITLE).join("").trimEnd()
  return clean || fallback
}

const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("")

function fromOffscreen(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && !sender.tab && sender.url === chrome.runtime.getURL(OFFSCREEN_PAGE)
}

async function ensureAlarm(name: string, periodInMinutes: number) {
  const existing = await chrome.alarms.get(name).catch(() => undefined)
  if (existing?.periodInMinutes !== periodInMinutes) await chrome.alarms.create(name, { periodInMinutes })
}

export const POPUP_PAGE = "popup.html"

/**
 * Only this extension's own device.html (in any tab, with any query or hash)
 * and its toolbar popup may manage the vault: never a content script, the
 * inline menu or another page. Neither page is web-accessible.
 */
export function fromVaultPage(sender: chrome.runtime.MessageSender): boolean {
  const url = sender.url?.split(/[?#]/)[0]
  return sender.id === chrome.runtime.id && (url === chrome.runtime.getURL(DEVICE_PAGE) || url === chrome.runtime.getURL(POPUP_PAGE))
}

const text = (v: unknown, max: number): v is string => typeof v === "string" && v.length <= max
const prf = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v)
/** A field's name as the core takes it: lowercase letters, digits, `-` and `_`, starting with a letter. */
const fieldName = (v: unknown): v is string => typeof v === "string" && /^[a-z][a-z0-9_-]{0,63}$/.test(v)
const reauthId = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{32}$/.test(v)
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
    case "device-items":
    case "device-kinds":
    case "device-passkeys":
    case "device-devices":
    case "device-settings":
    case "device-biometric-info":
    case "device-biometric-reset":
      return { type: c.type }
    case "device-sync":
      return c.wait === true ? { type: "device-sync", wait: true } : { type: "device-sync" }
    case "device-item":
      return text(c.ref, 200) && c.ref ? { type: "device-item", ref: c.ref } : null
    case "device-delete":
      if (!text(c.ref, 200) || !c.ref) return null
      if (c.passphrase === undefined) return { type: "device-delete", ref: c.ref }
      return text(c.passphrase, 1024) && c.passphrase ? { type: "device-delete", ref: c.ref, passphrase: c.passphrase } : null
    case "device-secret": {
      if (!text(c.ref, 200) || !c.ref) return null
      if (c.field !== undefined && !fieldName(c.field)) return null
      const field = c.field === undefined ? {} : { field: c.field as string }
      if (prf(c.prf)) return { type: "device-secret", ref: c.ref, ...field, prf: c.prf }
      if (c.passphrase === undefined) return { type: "device-secret", ref: c.ref, ...field }
      return text(c.passphrase, 1024) && c.passphrase ? { type: "device-secret", ref: c.ref, ...field, passphrase: c.passphrase } : null
    }
    case "device-save": {
      const e = c.entry as Record<string, unknown> | undefined
      if (!e || !text(e.title, 500) || !text(e.url, 2048) || !text(e.username, 500) || !text(e.password, 4096)) return null
      if ((e.otp !== undefined && !text(e.otp, 4096)) || (e.notes !== undefined && !text(e.notes, 65_536))) return null
      const entry = {
        title: e.title,
        url: e.url,
        username: e.username,
        password: e.password,
        ...(e.otp === undefined ? {} : { otp: e.otp as string }),
        ...(e.notes === undefined ? {} : { notes: e.notes as string }),
      }
      if (c.ref === undefined) return { type: "device-save", entry }
      return text(c.ref, 200) && c.ref ? { type: "device-save", ref: c.ref, entry } : null
    }
    case "device-item-save": {
      if (!Array.isArray(c.fields) || c.fields.length > 64) return null
      const fields: ItemInput[] = []
      for (const f of c.fields as Array<Record<string, unknown>>) {
        // A document's file is at most 10 MiB, 4/3 of that in base64.
        if (typeof f !== "object" || f === null || !fieldName(f.name) || !text(f.value, 14 << 20)) return null
        if (f.type !== undefined && !(text(f.type, 32) && /^[a-z]+$/.test(f.type))) return null
        fields.push({ name: f.name as string, value: f.value, ...(f.type === undefined ? {} : { type: f.type as string }) })
      }
      const remove = c.remove === undefined ? undefined : Array.isArray(c.remove) && c.remove.length <= 64 && c.remove.every(fieldName) ? (c.remove as string[]) : null
      if (remove === null || (c.name !== undefined && !text(c.name, 500))) return null
      const rest = { fields, ...(remove ? { remove } : {}), ...(c.name === undefined ? {} : { name: c.name as string }) }
      if (c.ref !== undefined) return text(c.ref, 200) && c.ref ? { type: "device-item-save", ref: c.ref, ...rest } : null
      return text(c.kind, 32) && /^[a-z-]+$/.test(c.kind) ? { type: "device-item-save", kind: c.kind, ...rest } : null
    }
    case "device-item-delete":
      if (!text(c.ref, 200) || !c.ref) return null
      if (c.passphrase === undefined) return { type: "device-item-delete", ref: c.ref }
      return text(c.passphrase, 1024) && c.passphrase ? { type: "device-item-delete", ref: c.ref, passphrase: c.passphrase } : null
    case "device-remove":
      return typeof c.id === "string" && /^[0-9a-f]{64}$/.test(c.id) ? { type: "device-remove", id: c.id } : null
    case "device-rename":
      return text(c.name, 64) && VAULT_NAME.test(c.name) ? { type: "device-rename", name: c.name } : null
    case "device-preset":
      return isPreset(c.preset) ? { type: "device-preset", preset: c.preset } : null
    case "device-used":
      return { type: "device-used" }
    case "device-generate":
      return Number.isInteger(c.length) && (c.length as number) >= 8 && (c.length as number) <= 256 && typeof c.symbols === "boolean"
        ? { type: "device-generate", length: c.length as number, symbols: c.symbols }
        : null
    case "device-copied":
      return isCopied(c) ? { type: "device-copied", salt: c.salt, hash: c.hash } : null
    case "device-reauth":
      return { type: "device-reauth" }
    case "device-reauth-confirm":
      if (reauthId(c.id) && prf(c.prf)) return { type: "device-reauth-confirm", id: c.id, prf: c.prf }
      return reauthId(c.id) && text(c.passphrase, 1024) && c.passphrase ? { type: "device-reauth-confirm", id: c.id, passphrase: c.passphrase } : null
    case "device-reauth-cancel":
      return reauthId(c.id) ? { type: "device-reauth-cancel", id: c.id } : null
    case "device-create":
      return text(c.passphrase, 1024) && c.passphrase && text(c.name, 200) ? { type: "device-create", passphrase: c.passphrase, name: c.name } : null
    case "device-unlock":
      if (prf(c.prf)) return { type: "device-unlock", prf: c.prf }
      return text(c.passphrase, 1024) ? { type: "device-unlock", passphrase: c.passphrase } : null
    case "device-biometric-set":
      return prf(c.prf) && text(c.token, 8192) && c.token && text(c.passphrase, 1024) && c.passphrase ? { type: "device-biometric-set", prf: c.prf, token: c.token, passphrase: c.passphrase } : null
    case "device-biometric-check":
      return text(c.passphrase, 1024) && c.passphrase ? { type: "device-biometric-check", passphrase: c.passphrase } : null
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
