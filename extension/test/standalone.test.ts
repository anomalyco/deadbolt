import { afterEach, beforeEach, describe, expect, setSystemTime, test } from "bun:test"
import { deviceCommand, deviceName, fromVaultPage, StandaloneBackend } from "../src/bg/standalone"
import { VAULT_CHANGED, VAULT_LOCK, VAULT_REQUEST, type VaultRequest } from "../src/bg/vault-messages"
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
      case "device-create":
      case "device-join-finish":
        vault = "ready"
        return { reply: { type: m.body.type, ok: true } }
      case "device-logins":
        return { reply: { type: "device-logins", accounts: [] } }
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
    expect(deviceCommand({ type: "device-logins", origin: "x" })).toEqual({ type: "device-logins" })
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
    expect(deviceCommand({ type: "device-remove", id })).toEqual({ type: "device-remove", id })
    expect(deviceCommand({ type: "device-remove", id: "AB".repeat(32) })).toBeNull()
    expect(deviceCommand({ type: "device-remove", id: "ab" })).toBeNull()
    expect(deviceCommand({ type: "device-rename", name: "work" })).toEqual({ type: "device-rename", name: "work" })
    expect(deviceCommand({ type: "device-rename", name: "Work" })).toBeNull()
    expect(deviceCommand({ type: "device-preset", preset: "strict" })).toEqual({ type: "device-preset", preset: "strict" })
    expect(deviceCommand({ type: "device-preset", preset: "toString" })).toBeNull()
    expect(deviceCommand({ type: "device-settings", preset: "relaxed" })).toEqual({ type: "device-settings" })
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
    expect(sent[finish]).toEqual({ type: "device-join-finish", passphrase: "browser pass", deviceName: expect.any(String) })
    expect(sent[finish + 1]?.type).toBe("hello")
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
    expect(sent[unlock]).toEqual({ type: "device-unlock", passphrase: "correct horse", deviceName: expect.any(String) })
    expect(sent[unlock + 1]?.type).toBe("hello")
    // No waiting for the five-minute sync alarm.
    expect(sent.slice(unlock + 2).some((b) => b.type === "device-sync")).toBe(true)
  })

  test("the page reading the vault isn't use, so an open page doesn't keep it unlocked", async () => {
    const backend = new StandaloneBackend()
    await backend.connect()
    await backend.device({ type: "device-logins" })
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
    expect(reply.ok && reply.reply).toEqual({ type: "device-settings", preset: "strict" })
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
