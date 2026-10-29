import { beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { VAULT_CHANGED, VAULT_LOCK, VAULT_REQUEST, type VaultResponse, type WorkerRequest } from "../src/bg/vault-messages"
import { deliver, ID, installChrome, pageSender, POPUP_URL, settle, type FakeChrome } from "./chrome"

const BACKGROUND = { id: ID, url: `chrome-extension://${ID}/background.js` }

class FakeWorker {
  static all: FakeWorker[] = []
  posted: WorkerRequest[] = []
  terminated = false
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: ((event: { message: string; preventDefault(): void }) => void) | null = null
  constructor(readonly url: string) {
    FakeWorker.all.push(this)
  }
  postMessage(message: WorkerRequest) {
    this.posted.push(message)
  }
  terminate() {
    this.terminated = true
  }
  /** Answers the request whose body has this type. */
  answer(type: string, data: Record<string, unknown> = { reply: { type, ok: true } }) {
    const m = this.posted.find((p) => p.body.type === type)
    if (!m) throw new Error(`${type} never reached this worker`)
    this.onmessage?.({ data: { id: m.id, ...data } })
  }
}

let fake: FakeChrome
const ask = (type: string, sender: chrome.runtime.MessageSender = BACKGROUND) => deliver(fake, { type: VAULT_REQUEST, body: { type } }, sender) as Promise<VaultResponse | null>
const current = () => FakeWorker.all.at(-1)!
/** What reached the worker, in no particular order. */
const types = (w: FakeWorker) => w.posted.map((p) => p.body.type).sort()

beforeAll(async () => {
  fake = installChrome()
  ;(globalThis as unknown as { Worker: unknown }).Worker = FakeWorker
  await import("../src/offscreen")
})

beforeEach(async () => {
  // Each test starts with no worker, as after a lock.
  await deliver(fake, { type: VAULT_LOCK }, BACKGROUND)
  FakeWorker.all = []
  fake.sent.length = 0
})

describe("offscreen document", () => {
  test("takes requests from the service worker only", async () => {
    const others: chrome.runtime.MessageSender[] = [
      pageSender(),
      { id: ID, url: POPUP_URL },
      { id: ID, url: `chrome-extension://${ID}/device.html` },
      { id: ID, url: `chrome-extension://${ID}/menu.html`, tab: { id: 1 } as chrome.tabs.Tab },
      { ...BACKGROUND, tab: { id: 1 } as chrome.tabs.Tab },
      { ...BACKGROUND, id: "other" },
    ]
    for (const sender of others) expect(await ask("hello", sender)).toBeNull()
    for (const sender of others) expect(await deliver(fake, { type: VAULT_LOCK }, sender)).toBeNull()
    expect(FakeWorker.all).toHaveLength(0)
    const reply = ask("hello")
    await settle()
    current().answer("hello")
    expect(await reply).toEqual({ reply: { type: "hello", ok: true } })
  })

  test("a list doesn't wait behind a sync or a pairing", async () => {
    const sync = ask("device-sync")
    const pair = ask("device-pair")
    const list = ask("list")
    await settle()
    expect(types(current())).toEqual(["device-pair", "device-sync", "list"])
    current().answer("list")
    expect(await list).toEqual({ reply: { type: "list", ok: true } })
    current().answer("device-sync")
    current().answer("device-pair")
    await Promise.all([sync, pair])
  })

  test("a create or an unlock waits for the one before it; nothing else does", async () => {
    const first = ask("device-unlock")
    const second = ask("device-create")
    const hello = ask("hello")
    await settle()
    expect(types(current())).toEqual(["device-unlock", "hello"])
    current().answer("device-unlock")
    expect(await first).toEqual({ reply: { type: "device-unlock", ok: true } })
    await settle()
    expect(types(current())).toEqual(["device-create", "device-unlock", "hello"])
    current().answer("device-create")
    current().answer("hello")
    await Promise.all([second, hello])
  })

  test("lock fails what's in flight and waiting, and none of it reaches the next worker", async () => {
    const unlock = ask("device-unlock")
    const queued = ask("device-unlock")
    const sync = ask("device-sync")
    await settle()
    const old = current()
    expect(types(old)).toEqual(["device-sync", "device-unlock"])
    expect(await deliver(fake, { type: VAULT_LOCK }, BACKGROUND)).toBe(true)
    expect(old.terminated).toBe(true)
    for (const r of await Promise.all([unlock, queued, sync])) expect(r).toEqual({ error: "Deadbolt locked.", locked: true })
    // A late answer from the ended worker is ignored.
    old.answer("device-unlock")
    const after = ask("hello")
    await settle()
    expect(FakeWorker.all).toHaveLength(2)
    expect(types(current())).toEqual(["hello"])
    current().answer("hello")
    expect(await after).toEqual({ reply: { type: "hello", ok: true } })
  })

  test("an engine trap ends the worker, fails everything and starts fresh and locked", async () => {
    const list = ask("list")
    const sync = ask("device-sync")
    await settle()
    const old = current()
    old.answer("list", { error: "Deadbolt's vault stopped: unreachable.", fatal: true })
    expect(await list).toEqual({ error: "Deadbolt's vault stopped: unreachable.", locked: true })
    expect(await sync).toEqual({ error: "Deadbolt's vault stopped: unreachable.", locked: true })
    expect(old.terminated).toBe(true)
    expect(fake.sent).toContainEqual({ type: VAULT_CHANGED, change: "locked" })
    const hello = ask("hello")
    await settle()
    expect(current()).not.toBe(old)
    expect(types(current())).toEqual(["hello"])
    current().answer("hello")
    await hello
  })

  test("background changes reach the service worker, but stopped workers cannot publish", async () => {
    const hello = ask("hello")
    await settle()
    const old = current()
    old.answer("hello")
    await hello
    old.onmessage?.({ data: { change: "items" } })
    expect(fake.sent).toContainEqual({ type: VAULT_CHANGED, change: "items" })
    await deliver(fake, { type: VAULT_LOCK }, BACKGROUND)
    fake.sent.length = 0
    old.onmessage?.({ data: { change: "items" } })
    expect(fake.sent).toEqual([])
  })

  test("a background trap without a request id still releases the worker", async () => {
    const list = ask("list")
    await settle()
    const old = current()
    old.onmessage?.({ data: { error: "background trap", fatal: true } })
    expect(await list).toEqual({ error: "background trap", locked: true })
    expect(old.terminated).toBe(true)
    expect(fake.sent).toContainEqual({ type: VAULT_CHANGED, change: "locked" })
  })

  test("a request's own error leaves the worker running", async () => {
    const list = ask("list")
    await settle()
    current().answer("list", { error: "no such vault" })
    expect(await list).toEqual({ error: "no such vault" })
    expect(current().terminated).toBe(false)
    expect(fake.sent).toEqual([])
  })

  test("a worker that fails is ended the same way", async () => {
    const unlock = ask("device-unlock")
    await settle()
    const old = current()
    old.onerror?.({ message: "RuntimeError: unreachable", preventDefault() {} })
    expect(await unlock).toEqual({ error: "Deadbolt's vault stopped: RuntimeError: unreachable.", locked: true })
    expect(old.terminated).toBe(true)
    expect(fake.sent).toContainEqual({ type: VAULT_CHANGED, change: "locked" })
  })
})
