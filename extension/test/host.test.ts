import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { fillError, wantFor, menuAccounts } from "../src/bg/autofill"
import { Host, HostError } from "../src/bg/host"
import type { Status } from "../src/messages"
import { PROTOCOL, type Account } from "../src/protocol"

type Listener<T extends unknown[]> = (...args: T) => void

/** A native messaging port the test plays the host on. */
class FakePort {
  sent: Array<Record<string, unknown>> = []
  private messageListeners: Listener<[unknown]>[] = []
  private disconnectListeners: Listener<[]>[] = []
  onMessage = { addListener: (l: Listener<[unknown]>) => this.messageListeners.push(l) }
  onDisconnect = { addListener: (l: Listener<[]>) => this.disconnectListeners.push(l) }
  postMessage(message: Record<string, unknown>) {
    this.sent.push(structuredClone(message))
  }
  /** The host writes a message. */
  push(message: unknown) {
    for (const l of this.messageListeners) l(message)
  }
  /** The host exits, with the browser's reason in lastError. */
  exit(lastError?: string) {
    chromeStub.runtime.lastError = lastError ? { message: lastError } : undefined
    for (const l of this.disconnectListeners) l()
    chromeStub.runtime.lastError = undefined
  }
  last() {
    return this.sent[this.sent.length - 1]
  }
}

const chromeStub = { runtime: { lastError: undefined as { message: string } | undefined } }
;(globalThis as unknown as { chrome: unknown }).chrome = chromeStub

const tick = () => new Promise((r) => setTimeout(r, 0))
const hello = (id: unknown, status = "ready", extra: Record<string, unknown> = {}) => ({
  id,
  type: "hello",
  protocol: PROTOCOL,
  version: "0.4.0",
  status,
  capabilities: ["list", "fill", "check", "save", "generate"],
  ...extra,
})

let ports: FakePort[]
let host: Host
let statuses: Status[]

beforeEach(() => {
  ports = []
  host = new Host((name) => {
    expect(name).toBe("pw.deadbolt.browser")
    const port = new FakePort()
    ports.push(port)
    return port as unknown as chrome.runtime.Port
  })
  statuses = []
  host.onChange((s) => statuses.push(s))
})

afterEach(() => {
  // Stop any reconnect timer.
  ports.at(-1)?.exit()
})

describe("Host", () => {
  test("connect sends hello with a numeric id and follows its status", async () => {
    const ready = host.connect()
    expect(ports).toHaveLength(1)
    expect(ports[0].sent).toEqual([{ type: "hello", id: 1 }])
    ports[0].push(hello(1))
    await ready
    expect(host.status).toEqual({ state: "ready", version: "0.4.0" })
  })

  test("locked, not set up and unavailable come straight from hello", async () => {
    const ready = host.connect()
    ports[0].push(hello(1, "locked", { detail: "Unlock Deadbolt" }))
    await ready
    expect(host.status).toEqual({ state: "locked", detail: "Unlock Deadbolt" })
  })

  test("a different protocol version is unavailable, not ready", async () => {
    const ready = host.connect()
    ports[0].push(hello(1, "ready", { protocol: PROTOCOL + 1 }))
    await ready
    expect(host.status.state).toBe("unavailable")
  })

  test("requests are matched to replies by id, in any order", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const a = host.send({ type: "list", origin: "https://github.com" })
    const b = host.send({ type: "list", origin: "https://gitlab.com" })
    expect(ports[0].sent.slice(1)).toEqual([
      { type: "list", origin: "https://github.com", id: 2 },
      { type: "list", origin: "https://gitlab.com", id: 3 },
    ])
    ports[0].push({ id: 3, type: "list", site: "gitlab.com", accounts: [] })
    ports[0].push({ id: 2, type: "list", site: "github.com", accounts: [] })
    expect((await a).site).toBe("github.com")
    expect((await b).site).toBe("gitlab.com")
  })

  test("a passkey ceremony names its id for a cancel and takes its own reply type", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    let named = 0
    const get = host.send({ type: "passkey-get", origin: "https://example.com", ref: "r", challenge: "AA", userVerification: "preferred" }, { timeout: 1000, onId: (id) => (named = id) })
    expect(named).toBe(2)
    const cancel = host.send({ type: "passkey-cancel", request: named })
    ports[0].push({ id: 3, type: "passkey-cancelled", found: true })
    ports[0].push({ id: 2, type: "error", code: "cancelled", message: "the passkey request was cancelled" })
    expect(await cancel).toEqual({ type: "passkey-cancelled", found: true })
    expect(await get.catch((e: HostError) => e.code)).toBe("cancelled")
    const list = host.send({ type: "passkey-list", origin: "https://example.com" })
    ports[0].push({ id: 4, type: "list", site: "example.com", accounts: [] })
    expect(await list.catch((e: HostError) => e.message)).toBe("Expected a passkeys reply, got list.")
  })

  test("error replies reject with the host's code", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const fill = host.send({ type: "fill", origin: "https://github.com", ref: "x", want: ["password"] })
    ports[0].push({ id: 2, type: "error", code: "domain_mismatch", message: "That login is for another site." })
    const err = await fill.catch((e) => e)
    expect(err).toBeInstanceOf(HostError)
    expect(err.code).toBe("domain_mismatch")
  })

  test("rate_limited is its own code, and reads calmly when filling", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const fill = host.send({ type: "fill", origin: "https://github.com", ref: "x", want: ["password"] })
    ports[0].push({ id: 2, type: "error", code: "rate_limited", message: "too many fills" })
    const err = await fill.catch((e) => e)
    expect(err.code).toBe("rate_limited")
    expect(fillError(err)).toBe("Filling too quickly. Try again in a moment.")
    expect(host.status.state).toBe("ready")
    expect(ports[0].sent).toHaveLength(2)
  })

  test("a locked error while ready asks hello again", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const list = host.send({ type: "list", origin: "https://github.com" })
    ports[0].push({ id: 2, type: "error", code: "locked", message: "Deadbolt is locked." })
    await list.catch(() => {})
    expect(ports[0].last()).toEqual({ type: "hello", id: 3 })
    ports[0].push(hello(3, "locked"))
    await tick()
    expect(host.status.state).toBe("locked")
  })

  test("a request aborted while the port reconnects is never written", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    ports[0].exit("gone")
    const stop = new AbortController()
    let named: number | undefined
    const get = host.send({ type: "passkey-get", origin: "https://example.com", ref: "r", challenge: "AA", userVerification: "preferred" }, { onId: (id) => (named = id), signal: stop.signal })
    expect(ports).toHaveLength(2)
    expect(ports[1].sent.map((m) => m.type)).toEqual(["hello"])
    stop.abort()
    ports[1].push(hello(ports[1].sent[0].id))
    expect(await get.catch((e: HostError) => e.code)).toBe("cancelled")
    expect(ports[1].sent.map((m) => m.type)).toEqual(["hello"])
    expect(named).toBeUndefined()
    // Already aborted: not even a connect.
    expect(await host.send({ type: "passkey-cancel", request: 1 }, { signal: stop.signal }).catch((e: HostError) => e.code)).toBe("cancelled")
    expect(ports[1].sent.map((m) => m.type)).toEqual(["hello"])
  })

  test("requests time out", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const err = await host.send({ type: "list", origin: "https://github.com" }, { timeout: 5 }).catch((e) => e)
    expect(err.code).toBe("timeout")
  })

  test("changed pushes: locked, items, stopped, unlocked", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const changes: Array<string | undefined> = []
    host.onChange((_s, change) => changes.push(change))

    ports[0].push({ type: "changed", change: "locked" })
    expect(host.status.state).toBe("locked")

    ports[0].push({ type: "changed", change: "stopped" })
    expect(host.status).toEqual({ state: "locked", detail: "Deadbolt isn't running" })
    // Stopped must not send hello: hello would start the agent again.
    expect(ports[0].sent).toHaveLength(1)

    ports[0].push({ type: "changed", change: "unlocked" })
    expect(ports[0].last()).toEqual({ type: "hello", id: 2 })
    ports[0].push(hello(2))
    await tick()
    expect(host.status.state).toBe("ready")

    ports[0].push({ type: "changed", change: "items" })
    expect(changes).toEqual(["locked", "stopped", "unlocked", "items"])
  })

  test("a missing host manifest is not-installed, and reconnects back off", async () => {
    const ready = host.connect()
    ports[0].exit("Specified native messaging host not found.")
    await ready
    expect(host.status).toEqual({ state: "not-installed" })
    // Opening the popup tries again right away.
    void host.reconnectNow()
    expect(ports).toHaveLength(2)
    ports[1].push(hello(2))
    await tick()
    expect(host.status.state).toBe("ready")
  })

  test("the host exiting rejects pending requests and reports why", async () => {
    const ready = host.connect()
    ports[0].push(hello(1))
    await ready
    const list = host.send({ type: "list", origin: "https://github.com" })
    ports[0].exit("Native host has exited.")
    const err = await list.catch((e) => e)
    expect(err.code).toBe("disconnected")
    expect(host.status).toEqual({ state: "disconnected", message: "Native host has exited." })
    expect(statuses.map((s) => s.state)).toEqual(["ready", "disconnected"])
  })

  test("replies with ids nobody asked for, and junk, are ignored", async () => {
    const ready = host.connect()
    ports[0].push({ id: 99, type: "list", site: "x", accounts: [] })
    ports[0].push("garbage")
    ports[0].push(hello(1))
    await ready
    expect(host.status.state).toBe("ready")
  })
})

const account = (over: Partial<Account> = {}): Account => ({
  ref: "r",
  vault: "Personal",
  title: "GitHub",
  username: "octocat",
  hasPassword: true,
  hasTotp: false,
  urls: [],
  ...over,
})

describe("what a fill asks for", () => {
  test("only values the page has fields for", () => {
    expect(wantFor(["email"], account())).toEqual(["username"])
    expect(wantFor(["username", "password"], account())).toEqual(["username", "password"])
    expect(wantFor(["password"], account())).toEqual(["password"])
  })

  test("a code only when the login has one", () => {
    expect(wantFor(["otp"], account())).toEqual([])
    expect(wantFor(["otp"], account({ hasTotp: true }))).toEqual(["totp"])
  })

  test("new-password fields never get a saved password", () => {
    expect(wantFor(["email", "new-password"], account())).toEqual(["username"])
  })

  test("the menu on a code field lists only logins with codes", () => {
    const list = [account({ ref: "a" }), account({ ref: "b", hasTotp: true })]
    expect(menuAccounts(list, "otp").map((a) => a.ref)).toEqual(["b"])
    expect(menuAccounts(list, "email").map((a) => a.ref)).toEqual(["a", "b"])
    expect(menuAccounts([account({ hasPassword: false })], "password")).toEqual([])
  })
})
