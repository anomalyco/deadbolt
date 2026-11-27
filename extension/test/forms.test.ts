import { beforeEach, describe, expect, test } from "bun:test"
import { Forms } from "../src/bg/forms"
import type { Status } from "../src/messages"
import { HOME_REF, SITE, fakeHost, installChrome, menuSender, pageSender, type FakeChrome, type FakeHost } from "./chrome"

let fake: FakeChrome, host: FakeHost, forms: Forms

beforeEach(() => {
  fake = installChrome()
  host = fakeHost()
  forms = new Forms(host.host)
  fake.answer = (m) => {
    if (m.type === "db:forms-approve") return { approval: "approval-1", roles: ["given-name"] }
    if (m.type === "db:forms-fill") return { filled: ["given-name"] }
    return true
  }
})

/** Opens the identity menu on the top page's name field; its token. */
async function menu(): Promise<string> {
  const reply = await forms.query(pageSender(), "identity", 0, "s0", true, undefined, ["given-name"])
  if (!reply.token) throw new Error("no menu")
  return reply.token
}

describe("locking", () => {
  test("drops every open menu's token and what each tab last filled", async () => {
    const picked = await menu()
    expect(await forms.menuLoad(picked, menuSender(), SITE)).toMatchObject({ kind: "forms" })
    expect(await forms.menuPick(picked, HOME_REF, menuSender())).toEqual({ ok: true })
    expect(forms.filledFrom(1)).toEqual({ card: undefined, identity: HOME_REF })
    const open = await menu()
    expect(forms.owns(open)).toBe(true)

    const sent = fake.delivered.length
    host.setStatus({ state: "locked", version: "0.0.0" } as Status)
    expect(forms.owns(open)).toBe(false)
    expect(forms.owns(picked)).toBe(false)
    await new Promise((resolve) => setTimeout(resolve, 0))
    // The open menu closes on the page rather than staying up locked.
    const closes = fake.delivered.slice(sent).filter((d) => d.message.type === "db:close-menu")
    expect(closes.map((d) => [d.message.token, (d.options as { documentId: string }).documentId])).toEqual([[picked, "top-doc"], [open, "top-doc"]])
    expect(forms.filledFrom(1)).toEqual({})
    expect(await forms.menuPick(open, HOME_REF, menuSender())).toEqual({ ok: false, message: "This menu has expired." })
  })

  test("a change that leaves the vault ready keeps them", async () => {
    const open = await menu()
    host.setStatus({ state: "ready", version: "0.0.1" } as Status)
    expect(forms.owns(open)).toBe(true)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(fake.delivered.some((d) => d.message.type === "db:close-menu")).toBe(false)
  })
})

test("a picked menu still resizes and dismisses until its owner closes it", async () => {
  const token = await menu()
  await forms.menuLoad(token, menuSender(), SITE)
  const release = host.holdFills()
  const picking = forms.menuPick(token, HOME_REF, menuSender())
  expect(await forms.menuPick(token, HOME_REF, menuSender())).toEqual({ ok: false, message: "This menu has expired." })
  expect(forms.owns(token)).toBe(true)
  expect(await forms.menuLoad(token, menuSender(), SITE)).toBeNull()
  await forms.menuResize(token, 42, menuSender(), 240, "pill")
  await forms.menuDismiss(token, menuSender())
  expect(fake.delivered.filter((d) => d.message.token === token).map((d) => d.message)).toContainEqual({ type: "db:resize-menu", token, height: 42, width: 240, mode: "pill" })
  expect(fake.delivered.some((d) => d.message.type === "db:close-menu" && d.message.token === token)).toBe(true)
  release()
  expect(await picking).toEqual({ ok: true })
  await forms.menuClose(token, pageSender())
  expect(forms.owns(token)).toBe(false)
})
