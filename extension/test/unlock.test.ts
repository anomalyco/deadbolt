import { beforeEach, describe, expect, test } from "bun:test"
import { Autofill } from "../src/bg/autofill"
import { HostError } from "../src/bg/backend"
import type { RequestBody } from "../src/protocol"
import { ACCOUNTS, fakeHost, installChrome, menuSender, pageSender, settle, SITE, type FakeChrome, type FakeHost } from "./chrome"

let fake: FakeChrome
let host: FakeHost
let autofill: Autofill
/** What the host answers `unlock-prompt` with, or throws. */
let prompted: () => unknown

beforeEach(() => {
  fake = installChrome()
  host = fakeHost()
  host.host.capabilities.push("unlock-prompt")
  const send = host.host.send.bind(host.host)
  prompted = () => ({ type: "unlock-prompt", app: false })
  host.host.send = (async (req: RequestBody, options?: unknown) => {
    if (req.type !== "unlock-prompt") return send(req as never, options as never)
    host.requests.push(req)
    return prompted()
  }) as typeof host.host.send
  autofill = new Autofill(host.host)
  host.setStatus({ state: "locked", touchId: true })
})

const prompts = () => host.requests.filter((r) => r.type === "unlock-prompt")
const lists = () => host.requests.filter((r) => r.type === "list")
const delivered = (type: string) => fake.delivered.filter((d) => d.message.type === type)

/** A locked login field's menu, open in the top page. */
async function lockedMenu(): Promise<string> {
  const { token, rows } = await autofill.query(pageSender(), ["email", "password"], "email", 1, true)
  expect(rows).toBe(1)
  return token!
}

describe("unlocking from the locked menu", () => {
  test("the locked menu offers to unlock with Touch ID; picking it asks the host and keeps the menu waiting", async () => {
    const token = await lockedMenu()
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toEqual({ kind: "status", status: { state: "locked", touchId: true }, unlock: true })
    expect(await autofill.menuUnlock(token, menuSender())).toEqual({ ok: true, app: false })
    expect(prompts()).toEqual([{ type: "unlock-prompt" }])
    expect(autofill.unlocker.pending).toMatchObject({ tabId: 1, frameId: 0, token })
  })

  test("once the vault is ready, the open menu lists the site's logins in place, with focus in it", async () => {
    const token = await lockedMenu()
    await autofill.menuLoad(token, menuSender(), SITE)
    // Deadbolt's window came forward; the passphrase is typed there, later.
    prompted = () => ({ type: "unlock-prompt", app: true })
    expect(await autofill.menuUnlock(token, menuSender())).toEqual({ ok: true, app: true })
    expect(fake.sent).toEqual([])
    host.setStatus({ state: "ready", version: "0" })
    await settle()
    expect(autofill.unlocker.pending).toBeNull()
    expect(lists().map((r) => r.origin)).toEqual([SITE])
    expect(fake.sent).toContainEqual({ type: "db:menu-refresh", token })
    expect(delivered("db:menu-resumed").map((d) => d.message)).toEqual([{ type: "db:menu-resumed", token }])
    // The same menu, its token unchanged, now loads the logins.
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toMatchObject({ kind: "accounts", site: "example.com", accounts: ACCOUNTS })
  })

  test("a site with nothing saved lists that in place, and keeps focus in its field", async () => {
    const token = await lockedMenu()
    await autofill.menuLoad(token, menuSender(), SITE)
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: RequestBody, options?: unknown) =>
      req.type === "list" ? (host.requests.push(req), { type: "list", site: "example.com", accounts: [] }) : send(req as never, options as never)) as typeof host.host.send
    expect(await autofill.menuUnlock(token, menuSender())).toEqual({ ok: true, app: false })
    host.setStatus({ state: "ready", version: "0" })
    await settle()
    expect(fake.sent).toContainEqual({ type: "db:menu-refresh", token })
    expect(delivered("db:menu-resumed")).toEqual([])
  })

  test("without Touch ID the row says Unlock Deadbolt, and the vault's later unlock still resumes it", async () => {
    host.setStatus({ state: "locked" })
    const token = await lockedMenu()
    const load = await autofill.menuLoad(token, menuSender(), SITE)
    expect(load).toEqual({ kind: "status", status: { state: "locked" }, unlock: true })
    expect(await autofill.menuUnlock(token, menuSender())).toEqual({ ok: true, app: false })
    host.setStatus({ state: "ready", version: "0" })
    await settle()
    expect(fake.sent).toContainEqual({ type: "db:menu-refresh", token })
  })

  test("Touch ID cancelled: the menu says so, and a later unlock elsewhere doesn't take it over", async () => {
    const token = await lockedMenu()
    await autofill.menuLoad(token, menuSender(), SITE)
    prompted = () => {
      throw new HostError("cancelled", "Touch ID was cancelled")
    }
    expect(await autofill.menuUnlock(token, menuSender())).toEqual({ ok: false, message: "Touch ID was cancelled." })
    expect(autofill.unlocker.pending).toBeNull()
    host.setStatus({ state: "ready", version: "0" })
    await settle()
    expect(fake.sent).toEqual([])
    expect(delivered("db:menu-resumed")).toEqual([])
  })

  test("another document's menu can't unlock, and a host that can't unlock from here is never asked", async () => {
    const token = await lockedMenu()
    await autofill.menuLoad(token, menuSender(), SITE)
    // Another document's menu can't use the token.
    expect(await autofill.menuUnlock(token, menuSender({ documentId: "other-menu" }))).toEqual({ ok: false, message: "This menu has expired." })
    expect(prompts()).toEqual([])
    // An older host: no row that unlocks, and nothing asked of it.
    host.host.capabilities = host.host.capabilities.filter((c) => c !== "unlock-prompt")
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toEqual({ kind: "status", status: { state: "locked", touchId: true } })
    expect(await autofill.menuUnlock(token, menuSender())).toEqual({ ok: false, message: "Unlock Deadbolt in its app, then come back." })
    expect(prompts()).toEqual([])
  })
})
