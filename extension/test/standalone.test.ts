import { afterEach, beforeEach, describe, expect, setSystemTime, test } from "bun:test"
import { CLIPBOARD_ALARM, COPIED_KEY, digest, holds, record } from "../src/bg/clipboard"
import { backoff, deviceCommand, deviceName, fromVaultPage, StandaloneBackend } from "../src/bg/standalone"
import { VAULT_CHANGED, VAULT_CLIPBOARD, VAULT_LOCK, VAULT_REQUEST, type VaultClipboard, type VaultRequest } from "../src/bg/vault-messages"
import { ID, installChrome, pageSender, POPUP_URL, settle, type FakeChrome } from "./chrome"

const DEVICE_URL = `chrome-extension://${ID}/device.html`
const OFFSCREEN_URL = `chrome-extension://${ID}/offscreen.html`
const HOUR = 60 * 60_000

let fake: FakeChrome
/** What the vault says hello with. */
let vault: "ready" | "locked" | "not-set-up"

const requests = () => fake.sent.filter((m): m is VaultRequest => (m as VaultRequest).type === VAULT_REQUEST).map((m) => m.body)
const locks = () => fake.sent.filter((m) => (m as { type: string }).type === VAULT_LOCK).length
const fireAlarm = (name: string) => fake.alarmListeners.forEach((l) => l({ name }))

beforeEach(() => {
  fake = installChrome()
  chrome.storage.session.setAccessLevel = async () => {}
  vault = "ready"
  // The offscreen document, answering for its worker.
  fake.runtimeAnswer = (message) => {
    const m = message as VaultRequest
    if ((m.type as string) === VAULT_LOCK) {
      // A fresh worker: locked if a vault was persisted, else still not set up.
      if (vault === "ready") vault = "locked"
      return true
    }
    if (m.type !== VAULT_REQUEST) return undefined
    switch (m.body.type) {
      case "hello":
        return { reply: { type: "hello", protocol: 3, version: "test", status: vault, capabilities: [] } }
      case "device-unlock":
      case "device-secret":
        // The vault's own check: "wrong" is a wrong passphrase.
        if (m.body.passphrase === "wrong") return { reply: { type: "error", code: "wrong_passphrase", message: "That passphrase isn't right." } }
        if (m.body.type === "device-secret") return { reply: { type: "device-secret", value: "pw" } }
      // falls through
      case "device-create":
      case "device-join-finish":
        vault = "ready"
        return { reply: { type: m.body.type, ok: true } }
      case "fill-form":
        // Strict: a card's number needs the passphrase, every time.
        if (m.body.passphrase === undefined) return { reply: { type: "error", code: "passphrase_needed", message: "Enter your passphrase to continue." } }
        if (m.body.passphrase === "wrong") return { reply: { type: "error", code: "wrong_passphrase", message: "That passphrase isn't right." } }
        // Chrome discarded the worker: a fresh one answers, locked.
        if (m.body.passphrase === "discarded") {
          vault = "locked"
          return { reply: { type: "error", code: "locked", message: "Deadbolt is locked" } }
        }
        return { reply: { type: "fill-form", values: { number: "4242424242424242" }, verified: true } }
      case "device-biometric-check":
        // Touch ID enrollment checks the passphrase first, without opening anything.
        if (m.body.passphrase === "wrong") return { reply: { type: "error", code: "wrong_passphrase", message: "That passphrase isn't right." } }
        return { reply: { type: m.body.type, ok: true } }
      case "device-items":
        return { reply: { type: "device-items", items: [] } }
      case "device-join-start":
        return { reply: { type: "device-join-start", code: "4821-tidy-otter", phase: "waiting" } }
      case "device-join-status":
        return { reply: { type: "device-join-status", phase: "waiting", code: "4821-tidy-otter" } }
      default:
        return { reply: { type: m.body.type, ok: true } }
    }
  }
})

afterEach(() => setSystemTime())

describe("the vault's worker lost", () => {
  test("every preset locks once its worker or offscreen document is gone", async () => {
    for (const preset of ["comfortable", "relaxed", "strict"] as const) {
      const first = new StandaloneBackend()
      await first.device({ type: "device-preset", preset })
      expect((await first.device({ type: "device-unlock", passphrase: "right" })).ok).toBe(true)
      // Chrome discarded the worker or closed the offscreen document: a fresh one answers, locked.
      vault = "locked"
      const restarted = new StandaloneBackend()
      await restarted.connect()
      expect(restarted.status.state).toBe("locked")
      vault = "ready"
    }
  })

  test("an unlock crossing a preset change locks rather than keeping the old policy", async () => {
    vault = "locked"
    const answer = fake.runtimeAnswer
    let release!: () => void
    let opening!: () => void
    const reached = new Promise<void>(resolve => opening = resolve)
    fake.runtimeAnswer = (message) => {
      const m = message as VaultRequest
      if (m.type === VAULT_REQUEST && m.body.type === "device-unlock") {
        opening()
        return new Promise(resolve => { release = () => { vault = "ready"; resolve({ reply: { type: m.body.type, ok: true } }) } })
      }
      return answer?.(message)
    }
    const backend = new StandaloneBackend()
    await backend.connect()
    const unlock = backend.device({ type: "device-unlock", passphrase: "right" })
    await reached
    await backend.device({ type: "device-preset", preset: "strict" })
    release()
    expect((await unlock).ok).toBe(false)
    expect(vault).toBe("locked")
    expect(backend.status.state).toBe("locked")
  })

  test("Lock still terminates the worker if trusted storage initialization failed", async () => {
    chrome.storage.session.setAccessLevel = async () => { throw new Error("storage unavailable") }
    const backend = new StandaloneBackend()
    await backend.connect()
    expect(backend.status.state).toBe("unavailable")
    await backend.lock()
    expect(vault).toBe("locked")
    expect(locks()).toBe(1)
  })
})

describe("device page commands", () => {
  test("only this extension's own device.html and popup may send them", () => {
    expect(fromVaultPage({ id: ID, url: DEVICE_URL })).toBe(true)
    expect(fromVaultPage({ id: ID, url: `${DEVICE_URL}?from=popup#unlock`, tab: { id: 3 } as chrome.tabs.Tab, frameId: 0 })).toBe(true)
    expect(fromVaultPage({ id: ID, url: POPUP_URL })).toBe(true)
    // The inline menu, a content script, another extension and look-alike paths may not.
    expect(fromVaultPage({ id: ID, url: `chrome-extension://${ID}/menu.html` })).toBe(false)
    expect(fromVaultPage(pageSender())).toBe(false)
    expect(fromVaultPage(pageSender({ url: DEVICE_URL, id: "someone-else" }))).toBe(false)
    expect(fromVaultPage({ id: "other", url: DEVICE_URL })).toBe(false)
    expect(fromVaultPage({ id: ID, url: `chrome-extension://${ID}/device.html.js` })).toBe(false)
    expect(fromVaultPage({ id: ID, url: `chrome-extension://${ID}/sub/device.html` })).toBe(false)
    expect(fromVaultPage({ id: ID })).toBe(false)
  })

  test("are rebuilt from their known fields only", () => {
    expect(deviceCommand({ type: "device-unlock", passphrase: "p", deviceName: "Evil", extra: 1 })).toEqual({ type: "device-unlock", passphrase: "p" })
    expect(deviceCommand({ type: "device-create", passphrase: "", name: "personal" })).toBeNull()
    expect(deviceCommand({ type: "device-items", origin: "x" })).toEqual({ type: "device-items" })
    expect(deviceCommand({ type: "device-devices" })).toEqual({ type: "device-devices" })
    expect(deviceCommand({ type: "list", origin: "https://a.test/path" })).toBeNull()
    expect(deviceCommand({ type: "fill", origin: "https://a.test", ref: "r" })).toBeNull()
    expect(deviceCommand(null)).toBeNull()
  })

  test("join commands are rebuilt from their known fields only: the page can't name the device", () => {
    for (const type of ["device-join-start", "device-join-status", "device-join-cancel"] as const) {
      expect(deviceCommand({ type, deviceName: "Evil", code: "x", passphrase: "p", vault: "v" })).toEqual({ type })
    }
    expect(deviceCommand({ type: "device-join-finish", passphrase: "p", deviceName: "Evil", extra: 1 })).toEqual({ type: "device-join-finish", passphrase: "p" })
    expect(deviceCommand({ type: "device-join-finish", passphrase: "" })).toBeNull()
    expect(deviceCommand({ type: "device-join-finish" })).toBeNull()
    expect(deviceCommand({ type: "device-join-finish", passphrase: 7 })).toBeNull()
    expect(deviceCommand({ type: "device-join-finish", passphrase: "p".repeat(1025) })).toBeNull()
    expect(deviceCommand({ type: "device-join" })).toBeNull()
    expect(deviceCommand({ type: "device-join-start" })).toEqual({ type: "device-join-start" })
  })

  test("the vault page's own commands are rebuilt from their known fields only", () => {
    const id = "ab".repeat(32)
    expect(deviceCommand({ type: "device-sync", wait: true, extra: 1 })).toEqual({ type: "device-sync", wait: true })
    expect(deviceCommand({ type: "device-sync", wait: "yes" })).toEqual({ type: "device-sync" })
    expect(deviceCommand({ type: "device-item", ref: "v:i", origin: "x" })).toEqual({ type: "device-item", ref: "v:i" })
    expect(deviceCommand({ type: "device-item" })).toBeNull()
    expect(deviceCommand({ type: "device-secret", ref: "v:i" })).toEqual({ type: "device-secret", ref: "v:i" })
    expect(deviceCommand({ type: "device-secret", ref: "v:i", passphrase: "" })).toBeNull()
    expect(deviceCommand({ type: "device-secret", ref: "v:i", passphrase: "p" })).toEqual({ type: "device-secret", ref: "v:i", passphrase: "p" })
    const entry = { title: "Acme", url: "https://acme.test", username: "alex", password: "" }
    expect(deviceCommand({ type: "device-save", entry: { ...entry, extra: 1 } })).toEqual({ type: "device-save", entry })
    expect(deviceCommand({ type: "device-save", ref: "v:i", entry })).toEqual({ type: "device-save", ref: "v:i", entry })
    expect(deviceCommand({ type: "device-save", ref: "", entry })).toBeNull()
    expect(deviceCommand({ type: "device-save", entry: { ...entry, password: 7 } })).toBeNull()
    expect(deviceCommand({ type: "device-save", entry: { ...entry, otp: "JBSWY3DP", notes: "" } })).toEqual({ type: "device-save", entry: { ...entry, otp: "JBSWY3DP", notes: "" } })
    expect(deviceCommand({ type: "device-secret", ref: "v:i", field: "private-key" })).toEqual({ type: "device-secret", ref: "v:i", field: "private-key" })
    expect(deviceCommand({ type: "device-secret", ref: "v:i", field: "private-key", prf: "ab".repeat(32) })).toEqual({ type: "device-secret", ref: "v:i", field: "private-key", prf: "ab".repeat(32) })
    expect(deviceCommand({ type: "device-secret", ref: "v:i", field: "../x" })).toBeNull()
    const fields = [{ name: "credential", value: "sk_test", extra: 1 }]
    expect(deviceCommand({ type: "device-item-save", kind: "api", name: "Stripe", fields })).toEqual({ type: "device-item-save", kind: "api", name: "Stripe", fields: [{ name: "credential", value: "sk_test" }] })
    expect(deviceCommand({ type: "device-item-save", ref: "v:i", fields: [], remove: ["notes"] })).toEqual({ type: "device-item-save", ref: "v:i", fields: [], remove: ["notes"] })
    expect(deviceCommand({ type: "device-item-save", ref: "v:i", fields: [{ name: "Bad Name", value: "x" }] })).toBeNull()
    expect(deviceCommand({ type: "device-item-save", fields: [] })).toBeNull()
    expect(deviceCommand({ type: "device-item-delete", ref: "v:i" })).toEqual({ type: "device-item-delete", ref: "v:i" })
    expect(deviceCommand({ type: "device-remove", id })).toEqual({ type: "device-remove", id })
    expect(deviceCommand({ type: "device-remove", id: "AB".repeat(32) })).toBeNull()
    expect(deviceCommand({ type: "device-remove", id: "ab" })).toBeNull()
    expect(deviceCommand({ type: "device-rename", name: "work" })).toEqual({ type: "device-rename", name: "work" })
    expect(deviceCommand({ type: "device-rename", name: "Work" })).toBeNull()
    expect(deviceCommand({ type: "device-preset", preset: "strict" })).toEqual({ type: "device-preset", preset: "strict" })
    expect(deviceCommand({ type: "device-preset", preset: "toString" })).toBeNull()
    expect(deviceCommand({ type: "device-settings", preset: "relaxed" })).toEqual({ type: "device-settings" })
    expect(deviceCommand({ type: "device-used", ref: "x" })).toEqual({ type: "device-used" })
    expect(deviceCommand({ type: "device-generate", length: 24, symbols: false })).toEqual({ type: "device-generate", length: 24, symbols: false })
    expect(deviceCommand({ type: "device-generate", length: 4, symbols: true })).toBeNull()
    expect(deviceCommand({ type: "device-generate", length: 24.5, symbols: true })).toBeNull()
    // A copy is named by its salted hash only; the value itself is refused.
    const salt = "0".repeat(32)
    const hash = "f".repeat(64)
    expect(deviceCommand({ type: "device-copied", salt, hash, value: "pw" })).toEqual({ type: "device-copied", salt, hash })
    expect(deviceCommand({ type: "device-copied", value: "pw" })).toBeNull()
    expect(deviceCommand({ type: "device-copied", salt: "x", hash })).toBeNull()
    expect(deviceCommand({ type: "device-copied", salt, hash: hash.toUpperCase() })).toBeNull()
    const reauthId = "a".repeat(32)
    expect(deviceCommand({ type: "device-reauth", id: reauthId })).toEqual({ type: "device-reauth" })
    expect(deviceCommand({ type: "device-reauth-confirm", id: reauthId, passphrase: "p", extra: 1 })).toEqual({ type: "device-reauth-confirm", id: reauthId, passphrase: "p" })
    expect(deviceCommand({ type: "device-reauth-confirm", id: reauthId, passphrase: "" })).toBeNull()
    expect(deviceCommand({ type: "device-reauth-confirm", id: "nope", passphrase: "p" })).toBeNull()
    expect(deviceCommand({ type: "device-reauth-cancel", id: reauthId })).toEqual({ type: "device-reauth-cancel", id: reauthId })
    expect(deviceCommand({ type: "device-biometric-check", passphrase: "p", prf: "x", token: "t", extra: 1 })).toEqual({ type: "device-biometric-check", passphrase: "p" })
    expect(deviceCommand({ type: "device-biometric-check", passphrase: "" })).toBeNull()
    expect(deviceCommand({ type: "device-biometric-check" })).toBeNull()
    expect(deviceCommand({ type: "device-biometric-check", passphrase: 7 })).toBeNull()
    expect(deviceCommand({ type: "device-biometric-check", passphrase: "p".repeat(1025) })).toBeNull()
  })

  test("a join starts and polls without counting as use or asking hello again", async () => {
    vault = "not-set-up"
    const backend = new StandaloneBackend()
    await backend.connect()
    fake.sent.length = 0
    const start = await backend.device({ type: "device-join-start" })
    expect(start).toEqual({ ok: true, reply: { type: "device-join-start", code: "4821-tidy-otter", phase: "waiting" }, ms: expect.any(Number), status: { state: "not-set-up", detail: undefined } })
    // Starting is the user at work; the page polling while it waits isn't.
    await settle()
    delete fake.session["deadbolt.lastUse"]
    for (let i = 0; i < 3; i++) await backend.device({ type: "device-join-status" })
    await settle()
    expect(requests()).toEqual([{ type: "device-join-start", deviceName: expect.any(String) }, { type: "device-join-status" }, { type: "device-join-status" }, { type: "device-join-status" }])
    expect(fake.session["deadbolt.lastUse"]).toBeUndefined()
  })

  test("finishing a join names this browser, unlocks and syncs at once", async () => {
    vault = "not-set-up"
    const backend = new StandaloneBackend()
    await backend.connect()
    const changes: Array<string | undefined> = []
    backend.onChange((_, change) => changes.push(change))
    const reply = await backend.device({ type: "device-join-finish", passphrase: "browser pass" })
    expect(reply.ok).toBe(true)
    expect(reply.status.state).toBe("ready")
    await settle()
    const sent = requests()
    const finish = sent.findIndex((b) => b.type === "device-join-finish")
    expect(sent[finish]).toEqual({ type: "device-join-finish", passphrase: "browser pass", deviceName: expect.any(String), preset: "comfortable" })
    expect(sent.slice(finish + 1).some(b => b.type === "hello")).toBe(true)
    expect(sent.slice(finish + 2).some((b) => b.type === "device-sync")).toBe(true)
    expect(changes[0]).toBe("unlocked")
  })

  test("cancelling a join ends the worker and never reaches the vault", async () => {
    vault = "not-set-up"
    const backend = new StandaloneBackend()
    await backend.connect()
    await backend.device({ type: "device-join-start" })
    const states: string[] = []
    backend.onChange((s) => states.push(s.state))
    fake.sent.length = 0
    const reply = await backend.device({ type: "device-join-cancel" })
    expect(reply).toEqual({ ok: true, reply: { type: "device-join-cancel", ok: true }, ms: expect.any(Number), status: { state: "not-set-up", detail: undefined } })
    expect(locks()).toBe(1)
    expect(requests()).toEqual([{ type: "hello" }])
    // Nothing to unlock: the page never sees "locked" for a vault that doesn't exist.
    expect(states).toEqual(["not-set-up"])
  })

  test("create and unlock name this browser, then sync at once", async () => {
    vault = "locked"
    const backend = new StandaloneBackend()
    await backend.connect()
    expect(backend.status.state).toBe("locked")
    const reply = await backend.device({ type: "device-unlock", passphrase: "correct horse" })
    expect(reply.ok).toBe(true)
    expect(reply.status.state).toBe("ready")
    await settle()
    const sent = requests()
    const unlock = sent.findIndex((b) => b.type === "device-unlock")
    expect(sent[unlock]).toEqual({ type: "device-unlock", passphrase: "correct horse", deviceName: expect.any(String), preset: "comfortable" })
    expect(sent.slice(unlock + 1).some(b => b.type === "hello")).toBe(true)
    // No waiting for the five-minute sync alarm.
    expect(sent.slice(unlock + 2).some((b) => b.type === "device-sync")).toBe(true)
  })

  test("the page reading the vault isn't use, so an open page doesn't keep it unlocked", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    await backend.device({ type: "device-items" })
    await backend.device({ type: "device-devices" })
    await backend.device({ type: "device-status" })
    await settle()
    expect(fake.session["deadbolt.lastUse"]).toBeUndefined()
    await backend.device({ type: "device-sync" })
    expect(typeof fake.session["deadbolt.lastUse"]).toBe("number")
  })
})

describe("idle lock", () => {
  test("locks an hour after the last use, not before", async () => {
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    backend.used()
    setSystemTime(new Date(start.getTime() + HOUR - 1000))
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(0)
    expect(backend.status.state).toBe("ready")
    setSystemTime(new Date(start.getTime() + HOUR))
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(1)
    expect(backend.status.state).toBe("locked")
  })

  test("a service worker woken by the alarm still locks a vault left idle", async () => {
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(new Date(start.getTime() + 2 * HOUR))
    fake.session["deadbolt.lastUse"] = start.getTime()
    const backend = new StandaloneBackend()
    // The alarm comes before anyone asked the vault how it is.
    expect(backend.status.state).toBe("connecting")
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(1)
    expect(backend.status.state).toBe("locked")
  })

  test("the screen locking locks the vault", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    fake.idleListeners.forEach((l) => l("locked"))
    await settle()
    expect(locks()).toBe(1)
    expect(backend.status.state).toBe("locked")
  })

  test("Strict locks after five minutes; the preset is kept in local storage", async () => {
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    const reply = await backend.device({ type: "device-preset", preset: "strict" })
    expect(reply.ok && reply.reply).toMatchObject({ type: "device-settings", preset: "strict" })
    expect(fake.local["deadbolt.lockPreset"]).toBe("strict")
    backend.used()
    setSystemTime(new Date(start.getTime() + 5 * 60_000 - 1000))
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(0)
    setSystemTime(new Date(start.getTime() + 5 * 60_000))
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(1)
    // A restarted service worker reads it back.
    const again = new StandaloneBackend()
    const settings = await again.device({ type: "device-settings" })
    expect(settings.ok && settings.reply.preset).toBe("strict")
  })

  test("Relaxed stays unlocked when the screen locks, and for longer than an hour", async () => {
    fake.local["deadbolt.lockPreset"] = "relaxed"
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    backend.used()
    fake.idleListeners.forEach((l) => l("locked"))
    setSystemTime(new Date(start.getTime() + 11 * HOUR))
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(0)
    expect(backend.status.state).toBe("ready")
    setSystemTime(new Date(start.getTime() + 12 * HOUR))
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(1)
  })

  test("Strict asks for the passphrase before a password is shown", async () => {
    fake.local["deadbolt.lockPreset"] = "strict"
    const backend = new StandaloneBackend()
    await backend.connect()
    fake.sent.length = 0
    const secrets = () => requests().filter((b) => b.type === "device-secret")
    const refused = await backend.device({ type: "device-secret", ref: "v:i" })
    expect(refused.ok).toBe(false)
    expect(secrets()).toEqual([])
    const asked = await backend.device({ type: "device-secret", ref: "v:i", passphrase: "p" })
    expect(asked.ok).toBe(true)
    expect(secrets()).toEqual([{ type: "device-secret", ref: "v:i", passphrase: "p" }])
  })

  test("a service worker restart doesn't start the alarms over", async () => {
    new StandaloneBackend()
    await settle()
    expect(fake.alarmsCreated).toEqual({ "deadbolt-idle": 1, "deadbolt-sync": 1 })
    new StandaloneBackend()
    await settle()
    expect(fake.alarmsCreated).toEqual({ "deadbolt-idle": 1, "deadbolt-sync": 1 })
  })

  test("existing alarms with different or missing periods are updated once", async () => {
    fake.alarms["deadbolt-idle"] = { periodInMinutes: 2 }
    fake.alarms["deadbolt-sync"] = {}
    new StandaloneBackend()
    await settle()
    expect(fake.alarms).toEqual({ "deadbolt-idle": { periodInMinutes: 1 }, "deadbolt-sync": { periodInMinutes: 5 } })
    expect(fake.alarmsCreated).toEqual({ "deadbolt-idle": 1, "deadbolt-sync": 1 })
    new StandaloneBackend()
    await settle()
    expect(fake.alarmsCreated).toEqual({ "deadbolt-idle": 1, "deadbolt-sync": 1 })
  })

  test("the vault's worker stopping is heard only from the offscreen document", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    vault = "locked"
    const changed = { type: VAULT_CHANGED, change: "locked" }
    fake.listeners.forEach((l) => l(changed, pageSender(), () => {}))
    fake.listeners.forEach((l) => l(changed, { id: ID, url: DEVICE_URL }, () => {}))
    await settle()
    expect(backend.status.state).toBe("ready")
    fake.listeners.forEach((l) => l(changed, { id: ID, url: OFFSCREEN_URL }, () => {}))
    await settle()
    expect(backend.status.state).toBe("locked")
  })
})

describe("device name", () => {
  test("is the browser and its OS", () => {
    const hints = (platform: string, ...brands: string[]) => ({ userAgentData: { platform, brands: brands.map((brand) => ({ brand })) } })
    expect(deviceName(hints("macOS", "Google Chrome", "Chromium", "Not_A Brand"))).toBe("Chrome on macOS")
    expect(deviceName(hints("Windows", "Chromium", "Microsoft Edge", "Not_A Brand"))).toBe("Edge on Windows")
    expect(deviceName(hints("Linux", "Chromium", "Not_A Brand"))).toBe("Chromium on Linux")
    expect(deviceName(hints("Chrome OS", "Google Chrome", "Chromium"))).toBe("Chrome on ChromeOS")
    expect(deviceName({ userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0" })).toBe("Edge on Linux")
    expect(deviceName({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" })).toBe("Chrome on macOS")
    expect(deviceName({})).toBe("Chromium")
  })
})

describe("use", () => {
  test("a login's details left open, asking for each new one-time code, still idle-lock", async () => {
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    // Opening it is use, once.
    await backend.device({ type: "device-used" })
    await backend.device({ type: "device-item", ref: "v:i" })
    // Then a poll every 30 s, for over an hour.
    for (let t = 30_000; t <= HOUR; t += 30_000) {
      setSystemTime(new Date(start.getTime() + t))
      await backend.device({ type: "device-item", ref: "v:i" })
    }
    fireAlarm("deadbolt-idle")
    await settle()
    expect(locks()).toBe(1)
    expect(backend.status.state).toBe("locked")
  })
})

describe("lock preset in the worker", () => {
  test("goes with every unlock, and to an unlocked worker when it changes", async () => {
    fake.local["deadbolt.lockPreset"] = "strict"
    vault = "locked"
    const backend = new StandaloneBackend()
    await backend.connect()
    await backend.device({ type: "device-unlock", passphrase: "p" })
    expect(requests().find((b) => b.type === "device-unlock")).toMatchObject({ preset: "strict" })
    await backend.device({ type: "device-preset", preset: "relaxed" })
    expect(requests().filter((b) => b.type === "device-preset")).toEqual([{ type: "device-preset", preset: "relaxed" }])
  })
})

describe("wrong passphrases", () => {
  test("back off after three: 1 s, 2 s, 4 s, … at most a minute", () => {
    expect([1, 2, 3, 4, 5, 6, 9, 20].map(backoff)).toEqual([0, 0, 1000, 2000, 4000, 8000, 60_000, 60_000])
  })

  test("refused during the wait without reaching the vault, and a right one starts over", async () => {
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    vault = "locked"
    const backend = new StandaloneBackend()
    await backend.connect()
    const unlocks = () => requests().filter((b) => b.type === "device-unlock").length
    for (let i = 0; i < 3; i++) expect((await backend.device({ type: "device-unlock", passphrase: "wrong" })).ok).toBe(false)
    expect(unlocks()).toBe(3)
    const refused = await backend.device({ type: "device-unlock", passphrase: "right" })
    expect(refused).toMatchObject({ ok: false, code: "backoff" })
    expect(unlocks()).toBe(3)
    // Kept across a service worker restart.
    const again = new StandaloneBackend()
    await again.connect()
    expect(await again.device({ type: "device-unlock", passphrase: "right" })).toMatchObject({ ok: false, code: "backoff" })
    setSystemTime(new Date(start.getTime() + 1000))
    expect((await again.device({ type: "device-unlock", passphrase: "right" })).ok).toBe(true)
    // Starting over: three more wrong ones before any wait.
    vault = "locked"
    for (let i = 0; i < 2; i++) await again.device({ type: "device-unlock", passphrase: "wrong" })
    expect(await again.device({ type: "device-unlock", passphrase: "wrong" })).toMatchObject({ ok: false, code: "wrong_passphrase" })
  })

  test("Strict's passphrase for a password counts too", async () => {
    fake.local["deadbolt.lockPreset"] = "strict"
    const backend = new StandaloneBackend()
    await backend.connect()
    for (let i = 0; i < 3; i++) await backend.device({ type: "device-secret", ref: "v:i", passphrase: "wrong" })
    expect(await backend.device({ type: "device-secret", ref: "v:i", passphrase: "right" })).toMatchObject({ ok: false, code: "backoff" })
  })

  test("Touch ID's passphrase check before enrolling counts too, and a right one starts over", async () => {
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    const checks = () => requests().filter((b) => b.type === "device-biometric-check").length
    expect(await backend.device({ type: "device-biometric-check", passphrase: "right" })).toMatchObject({ ok: true })
    for (let i = 0; i < 3; i++) expect(await backend.device({ type: "device-biometric-check", passphrase: "wrong" })).toMatchObject({ ok: false, code: "wrong_passphrase" })
    expect(checks()).toBe(4)
    // Refused during the wait without reaching the vault, and it holds unlocking back too.
    expect(await backend.device({ type: "device-biometric-check", passphrase: "right" })).toMatchObject({ ok: false, code: "backoff" })
    expect(await backend.device({ type: "device-unlock", passphrase: "right" })).toMatchObject({ ok: false, code: "backoff" })
    expect(checks()).toBe(4)
    setSystemTime(new Date(start.getTime() + 1000))
    expect(await backend.device({ type: "device-biometric-check", passphrase: "right" })).toMatchObject({ ok: true })
    // Starting over: three more wrong ones before any wait.
    for (let i = 0; i < 3; i++) expect(await backend.device({ type: "device-biometric-check", passphrase: "wrong" })).toMatchObject({ ok: false, code: "wrong_passphrase" })
  })
})

describe("a fill waiting on the passphrase", () => {
  const body = { type: "fill-form" as const, origin: "https://shop.test", ref: `${"a".repeat(64)}:${"1".repeat(32)}`, fields: ["number" as const] }
  const ask = { tabId: 1, title: "Visa •••• 4242", site: "shop.test" }
  const waiting = async (backend: StandaloneBackend) => {
    const r = await backend.device({ type: "device-reauth" })
    return r.ok ? (r.reply.reauth as { id: string; title: string; site: string } | null) : null
  }

  test("is asked in the popup, runs once with the passphrase, and keeps none of it", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    const fill = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    expect(fake.popups).toEqual([7])
    const r = await waiting(backend)
    expect(r).toMatchObject({ title: "Visa •••• 4242", site: "shop.test" })
    // A wrong passphrase leaves it waiting; the right one fills.
    const wrong = await backend.device({ type: "device-reauth-confirm", id: r!.id, passphrase: "wrong" })
    expect(!wrong.ok && wrong.code).toBe("wrong_passphrase")
    expect(await waiting(backend)).toEqual(r)
    expect((await backend.device({ type: "device-reauth-confirm", id: r!.id, passphrase: "right" })).ok).toBe(true)
    expect(await fill).toMatchObject({ values: { number: "4242424242424242" }, verified: true })
    expect(await waiting(backend)).toBeNull()
    const sent = requests().filter((b) => b.type === "fill-form")
    expect(sent.map((b) => b.passphrase)).toEqual(["wrong", "right"])
    // Answered once: the same id fills nothing more.
    const again = await backend.device({ type: "device-reauth-confirm", id: r!.id, passphrase: "right" })
    expect(!again.ok && again.code).toBe("expired")
    expect(requests().filter((b) => b.type === "fill-form")).toHaveLength(2)
  })

  /** Chrome's windows and Deadbolt's open pages, as this test has them; returns what the background did to tabs and windows, in order. */
  const browser = (contexts: Array<{ contextType: string; documentUrl: string; tabId?: number }>, focused: number[]) => {
    const c = (globalThis as unknown as { chrome: Record<string, any> }).chrome
    const log: string[] = []
    c.runtime.getContexts = async () => contexts
    c.windows = { get: async (id: number) => ({ id, focused: focused.includes(id) }), update: async (id: number) => void log.push(`focus ${id}`) }
    c.tabs.update = async (id: number) => {
      log.push(`activate ${id}`)
      return { id, ...fake.tabs[id] }
    }
    c.tabs.remove = async (id: number) => void log.push(`close ${id}`)
    return { c, log }
  }
  const answer = async (backend: StandaloneBackend, fill: Promise<unknown>, log: string[]) => {
    const done = fill.then(() => log.push("filled"))
    expect((await backend.device({ type: "device-reauth-confirm", id: (await waiting(backend))!.id, passphrase: "right" })).ok).toBe(true)
    await done
  }

  test("a device.html left in a background tab doesn't hide it: the popup opens over the page", async () => {
    // The user's Settings, in another tab of the same window and in a window behind.
    fake.tabs[5] = { active: false, windowId: 7 }
    fake.tabs[6] = { active: true, windowId: 8 }
    const { log } = browser(
      [
        { contextType: "TAB", documentUrl: `${DEVICE_URL}#settings`, tabId: 5 },
        { contextType: "TAB", documentUrl: DEVICE_URL, tabId: 6 },
      ],
      [7],
    )
    const backend = new StandaloneBackend()
    await backend.connect()
    const fill = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    expect(fake.popups).toEqual([7])
    await answer(backend, fill, log)
    // The page comes to the front before the fill goes on; the user's own tabs stay open.
    expect(log).toEqual(["activate 1", "focus 7", "filled"])
  })

  test("a device.html in front asks there, and the page comes back to the front before the fill goes on", async () => {
    fake.tabs[1] = { active: false, windowId: 7 }
    fake.tabs[5] = { active: true, windowId: 7 }
    const { log } = browser([{ contextType: "TAB", documentUrl: DEVICE_URL, tabId: 5 }], [7])
    const backend = new StandaloneBackend()
    await backend.connect()
    const fill = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    expect(fake.popups).toEqual([])
    expect(fake.opened).toEqual([])
    await answer(backend, fill, log)
    expect(log).toEqual(["activate 1", "focus 7", "filled"])
  })

  test("without the popup, device.html opens in a tab of its own, which alone is closed after", async () => {
    const { c, log } = browser([], [7])
    c.action.openPopup = async () => {
      throw new Error("no focused window")
    }
    c.tabs.create = async ({ url }: { url: string }) => {
      fake.opened.push(url)
      return { id: 9 }
    }
    const backend = new StandaloneBackend()
    await backend.connect()
    const fill = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    expect(fake.opened).toEqual([`${DEVICE_URL}#reauth`])
    await answer(backend, fill, log)
    expect(log).toEqual(["activate 1", "focus 7", "close 9", "filled"])
  })

  test("a newer fill never counts on the tab an older one opened, which is closing", async () => {
    const { c, log } = browser([], [7])
    c.action.openPopup = async () => {
      throw new Error("no focused window")
    }
    let next = 9
    c.tabs.create = async ({ url }: { url: string }) => {
      fake.opened.push(url)
      const id = next++
      // The new tab is in front of the focused window, and Chrome lists it.
      fake.tabs[id] = { active: true, windowId: 7 }
      c.runtime.getContexts = async () => [{ contextType: "TAB", documentUrl: `${DEVICE_URL}#reauth`, tabId: id }]
      return { id }
    }
    const backend = new StandaloneBackend()
    await backend.connect()
    const first = backend.reauth(body, ask, new AbortController().signal)
    first.catch(() => {})
    await settle()
    expect(fake.opened).toHaveLength(1)
    // Another pick before the first was answered: tab 9 goes with the first fill.
    const second = backend.reauth(body, ask, new AbortController().signal)
    await expect(first).rejects.toMatchObject({ code: "cancelled" })
    await settle()
    expect(fake.opened).toHaveLength(2)
    expect(log).toContain("close 9")
    await answer(backend, second, log)
    expect(log.filter((l) => l.startsWith("close"))).toEqual(["close 9", "close 10"])
    expect(log.at(-1)).toBe("filled")
  })

  test("a vault found locked when the passphrase is checked shows as locked", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    const fill = backend.reauth(body, ask, new AbortController().signal)
    fill.catch(() => {})
    await settle()
    const r = await backend.device({ type: "device-reauth-confirm", id: (await waiting(backend))!.id, passphrase: "discarded" })
    expect(!r.ok && r.code).toBe("locked")
    expect(r.status.state).toBe("locked")
    expect(backend.status.state).toBe("locked")
    await expect(fill).rejects.toMatchObject({ code: "locked" })
  })

  test("a fill that ends unanswered leaves the user where they are", async () => {
    fake.tabs[5] = { active: true, windowId: 7 }
    const { log } = browser([{ contextType: "TAB", documentUrl: DEVICE_URL, tabId: 5 }], [7])
    const backend = new StandaloneBackend()
    await backend.connect()
    const fill = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    await backend.device({ type: "device-reauth-cancel", id: (await waiting(backend))!.id })
    await expect(fill).rejects.toMatchObject({ code: "cancelled" })
    expect(log).toEqual([])
  })

  /**
   * A clock for timers of a second or more, moved by hand; shorter ones
   * (settle's) run for real.
   */
  const clock = () => {
    const g = globalThis as unknown as { setTimeout: (...a: unknown[]) => unknown; clearTimeout: (id: unknown) => void }
    const realSet = g.setTimeout
    const realClear = g.clearTimeout
    const timers = new Map<number, { at: number; run: () => void }>()
    let now = 0
    let next = 1
    g.setTimeout = (fn: unknown, ms = 0, ...args: unknown[]) => {
      if ((ms as number) < 1000) return realSet(fn, ms, ...args)
      const id = next++
      timers.set(id, { at: now + (ms as number), run: () => (fn as (...a: unknown[]) => void)(...args) })
      return id
    }
    g.clearTimeout = (id: unknown) => void (typeof id === "number" && timers.delete(id) ? null : realClear(id))
    return {
      advance(ms: number) {
        now += ms
        for (const [id, t] of [...timers]) if (t.at <= now && timers.delete(id)) t.run()
      },
      restore() {
        g.setTimeout = realSet
        g.clearTimeout = realClear
      },
    }
  }

  test("a slow passphrase check isn't dropped by the time left to answer, and a wrong one gets the time again", async () => {
    const time = clock()
    try {
      // The KDF answers "slow" only when the test lets it.
      let release!: () => void
      const answered = fake.runtimeAnswer
      fake.runtimeAnswer = (message) => {
        const m = message as VaultRequest
        if (m.type === VAULT_REQUEST && m.body.type === "fill-form" && m.body.passphrase === "slow") {
          return new Promise((resolve) => (release = () => resolve(answered({ ...m, body: { ...m.body, passphrase: "right" } }))))
        }
        return answered(message)
      }
      const backend = new StandaloneBackend()
      await backend.connect()
      const fill = backend.reauth(body, ask, new AbortController().signal)
      let ended: string | null = null
      fill.then(
        () => (ended = "filled"),
        (err) => (ended = err.code),
      )
      await settle()
      const id = (await waiting(backend))!.id
      // 90 s at the prompt, then a passphrase whose check takes 60 s: past the 2 minutes.
      time.advance(90_000)
      const confirm = backend.device({ type: "device-reauth-confirm", id, passphrase: "slow" })
      await settle()
      time.advance(60_000)
      await settle()
      expect(ended).toBeNull()
      release()
      expect((await confirm).ok).toBe(true)
      expect(await fill).toMatchObject({ values: { number: "4242424242424242" } })

      // A wrong passphrase leaves the next fill waiting with the full 2 minutes again, then it's dropped.
      const next = backend.reauth(body, ask, new AbortController().signal)
      next.catch(() => {})
      await settle()
      const again = (await waiting(backend))!.id
      time.advance(100_000)
      expect(await backend.device({ type: "device-reauth-confirm", id: again, passphrase: "wrong" })).toMatchObject({ ok: false, code: "wrong_passphrase" })
      time.advance(100_000)
      expect(await waiting(backend)).not.toBeNull()
      time.advance(20_000)
      await expect(next).rejects.toMatchObject({ code: "cancelled" })
      expect(await waiting(backend)).toBeNull()
    } finally {
      time.restore()
    }
  })

  test("a fill cancelled or replaced while its passphrase is checked gets nothing", async () => {
    let release!: () => void
    const answered = fake.runtimeAnswer
    fake.runtimeAnswer = (message) => {
      const m = message as VaultRequest
      if (m.type === VAULT_REQUEST && m.body.type === "fill-form" && m.body.passphrase === "slow") {
        return new Promise((resolve) => (release = () => resolve(answered({ ...m, body: { ...m.body, passphrase: "right" } }))))
      }
      return answered(message)
    }
    const backend = new StandaloneBackend()
    await backend.connect()
    const first = backend.reauth(body, ask, new AbortController().signal)
    first.catch(() => {})
    await settle()
    const confirm = backend.device({ type: "device-reauth-confirm", id: (await waiting(backend))!.id, passphrase: "slow" })
    await settle()
    await backend.device({ type: "device-reauth-cancel", id: (await waiting(backend))!.id })
    await expect(first).rejects.toMatchObject({ code: "cancelled" })
    release()
    expect(await confirm).toMatchObject({ ok: false, code: "expired" })

    const older = backend.reauth(body, ask, new AbortController().signal)
    older.catch(() => {})
    await settle()
    const replaced = backend.device({ type: "device-reauth-confirm", id: (await waiting(backend))!.id, passphrase: "slow" })
    await settle()
    const newer = backend.reauth(body, ask, new AbortController().signal)
    newer.catch(() => {})
    await expect(older).rejects.toMatchObject({ code: "cancelled" })
    release()
    expect(await replaced).toMatchObject({ ok: false, code: "expired" })
    // The newer fill still waits, untouched by the older one's answer.
    const left = await waiting(backend)
    expect(left).not.toBeNull()
    await backend.device({ type: "device-reauth-cancel", id: left!.id })
    await expect(newer).rejects.toMatchObject({ code: "cancelled" })
  })

  test("ends on cancel, on lock and when the page navigates", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    const cancelled = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    await backend.device({ type: "device-reauth-cancel", id: (await waiting(backend))!.id })
    await expect(cancelled).rejects.toMatchObject({ code: "cancelled" })

    const page = new AbortController()
    const navigated = backend.reauth(body, ask, page.signal)
    page.abort()
    await expect(navigated).rejects.toMatchObject({ code: "cancelled" })
    expect(await waiting(backend)).toBeNull()

    const locked = backend.reauth(body, ask, new AbortController().signal)
    await settle()
    const id = (await waiting(backend))!.id
    await backend.lock()
    await expect(locked).rejects.toMatchObject({ code: "locked" })
    expect(requests().filter((b) => b.type === "fill-form")).toHaveLength(0)
    const late = await backend.device({ type: "device-reauth-confirm", id, passphrase: "right" })
    expect(late.ok).toBe(false)
  })
})

describe("rate limits, as the native host's", () => {
  const origin = "https://shop.test"
  const ref = `${"a".repeat(64)}:${"1".repeat(32)}`
  const check = { type: "check" as const, origin, username: "kit", password: "pw" }
  const generateCheck = { type: "generate-check" as const, origin }
  const fill = { type: "fill" as const, origin, ref, want: ["password" as const] }
  const generate = { type: "generate" as const, origin }
  const fillForm = { type: "fill-form" as const, origin, ref, fields: ["given-name" as const] }
  const sentOf = (type: string) => requests().filter((b) => b.type === type).length
  const outcome = (p: Promise<unknown>) =>
    p.then(
      () => "ok",
      (err) => err.code,
    )

  beforeEach(() => {
    const answered = fake.runtimeAnswer
    fake.runtimeAnswer = (message) => {
      const m = message as VaultRequest
      if (m.type !== VAULT_REQUEST) return answered(message)
      if (m.body.type === "check") return { reply: { type: "check", status: "new", matches: [] } }
      if (m.body.type === "generate") return { reply: { type: "generate", password: "generated", generated: "g1" } }
      if (m.body.type === "fill-form") return { reply: { type: "fill-form", values: { "given-name": "Kit" }, verified: false } }
      return answered(message)
    }
  })

  test("checks: 20 at once, then one a second, refused before the vault sees them", async () => {
    const start = new Date("2026-10-29T12:00:00Z").getTime()
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    // Checks and generate-checks share one bucket.
    for (let i = 0; i < 20; i++) expect(await outcome(backend.send(i % 2 ? check : generateCheck))).toBe("ok")
    await expect(backend.send(check)).rejects.toMatchObject({ code: "rate_limited", message: "too many requests; try again in a moment" })
    expect(await outcome(backend.send(generateCheck))).toBe("rate_limited")
    expect(sentOf("check") + sentOf("generate-check")).toBe(20)
    // Fills have their own.
    expect(await outcome(backend.send(fill))).toBe("ok")
    setSystemTime(start + 999)
    expect(await outcome(backend.send(check))).toBe("rate_limited")
    setSystemTime(start + 1000)
    expect(await outcome(backend.send(check))).toBe("ok")
    expect(await outcome(backend.send(check))).toBe("rate_limited")
    // A long rest refills no more than the burst.
    setSystemTime(start + HOUR)
    for (let i = 0; i < 20; i++) expect(await outcome(backend.send(check))).toBe("ok")
    expect(await outcome(backend.send(check))).toBe("rate_limited")
  })

  test("fills: 60 at once, then four a second, and a refused one isn't use", async () => {
    const start = new Date("2026-10-29T12:00:00Z").getTime()
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    // Fills, generated passwords and form fills share one bucket.
    const kinds = [fill, generate, fillForm]
    for (let i = 0; i < 60; i++) expect(await outcome(backend.send(kinds[i % 3] as typeof fill))).toBe("ok")
    for (const body of kinds) expect(await outcome(backend.send(body as typeof fill))).toBe("rate_limited")
    expect(sentOf("fill") + sentOf("generate") + sentOf("fill-form")).toBe(60)
    expect(await outcome(backend.send(check))).toBe("ok")
    setSystemTime(start + 249)
    expect(await outcome(backend.send(fill))).toBe("rate_limited")
    setSystemTime(start + 250)
    expect(await outcome(backend.send(fill))).toBe("ok")
    expect(await outcome(backend.send(fill))).toBe("rate_limited")
    // A refused fill doesn't keep the vault unlocked.
    await settle()
    delete fake.session["deadbolt.lastUse"]
    expect(await outcome(backend.send(fillForm))).toBe("rate_limited")
    await settle()
    expect(fake.session["deadbolt.lastUse"]).toBeUndefined()
    // A minute refills the whole burst, and no more.
    setSystemTime(start + 250 + 60_000)
    for (let i = 0; i < 60; i++) expect(await outcome(backend.send(fill))).toBe("ok")
    expect(await outcome(backend.send(fill))).toBe("rate_limited")
  })
})

describe("the card menu's passphrase hint", () => {
  test("only Strict says the passphrase is asked for", async () => {
    for (const [preset, asks] of [
      ["strict", true],
      ["comfortable", false],
      ["relaxed", false],
    ] as const) {
      fake.local["deadbolt.lockPreset"] = preset
      expect(await new StandaloneBackend().asksPassphrase()).toBe(asks)
    }
    // Changing the preset changes it at once.
    fake.local["deadbolt.lockPreset"] = "comfortable"
    const backend = new StandaloneBackend()
    await backend.connect()
    await backend.device({ type: "device-preset", preset: "strict" })
    expect(await backend.asksPassphrase()).toBe(true)
  })
})

describe("clipboard", () => {
  const clears = () => fake.sent.filter((m): m is VaultClipboard => (m as { type: string }).type === VAULT_CLIPBOARD)

  test("a salted hash tells our copy from anything else, and keeps no value", async () => {
    const a = await record("Acme-demo-only-2026!")
    const b = await record("Acme-demo-only-2026!")
    expect(a.salt).not.toBe(b.salt)
    expect(a.hash).not.toBe(b.hash)
    expect(JSON.stringify(a)).not.toContain("Acme")
    expect(await holds(a, "Acme-demo-only-2026!")).toBe(true)
    expect(await holds(a, "something the user copied since")).toBe(false)
    expect(await digest(a.salt, "x")).toBe(await digest(a.salt, "x"))
  })

  test("without the clipboard permissions nothing is kept, nothing scheduled, nothing cleared", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    const r = await backend.device({ type: "device-copied", ...(await record("pw")) })
    expect(r.ok && r.reply.clears).toBe(false)
    expect(fake.alarms[CLIPBOARD_ALARM]).toBeUndefined()
    expect(fake.session[COPIED_KEY]).toBeUndefined()
    await backend.lock()
    expect(clears()).toEqual([])
  })

  test("with them, it's cleared 30 s later, if the clipboard still holds it", async () => {
    fake.granted = new Set(["clipboardRead", "clipboardWrite"])
    const start = new Date("2026-10-29T12:00:00Z")
    setSystemTime(start)
    const backend = new StandaloneBackend()
    await backend.connect()
    const r = await backend.device({ type: "device-copied", ...(await record("pw")) })
    expect(r.ok && r.reply.clears).toBe(true)
    expect(fake.alarms[CLIPBOARD_ALARM]).toEqual({ when: start.getTime() + 30_000 })
    const kept = fake.session[COPIED_KEY] as { salt: string; hash: string }
    expect(JSON.stringify(kept)).not.toContain("pw\"")
    expect(await holds(kept, "pw")).toBe(true)
    fireAlarm(CLIPBOARD_ALARM)
    await settle()
    expect(clears()).toEqual([{ type: VAULT_CLIPBOARD, salt: kept.salt, hash: kept.hash }])
    expect(fake.session[COPIED_KEY]).toBeUndefined()
    // Once.
    fireAlarm(CLIPBOARD_ALARM)
    await settle()
    expect(clears()).toHaveLength(1)
  })

  test("locking clears it at once, even after a service worker restart", async () => {
    fake.granted = new Set(["clipboardRead", "clipboardWrite"])
    const backend = new StandaloneBackend()
    await backend.connect()
    await backend.device({ type: "device-copied", ...(await record("pw")) })
    const restarted = new StandaloneBackend()
    await restarted.connect()
    await restarted.lock()
    expect(clears()).toHaveLength(1)
    expect(fake.alarms[CLIPBOARD_ALARM]).toBeUndefined()
  })
})
