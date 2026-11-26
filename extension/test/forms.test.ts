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
    await new Promise((resolve) => setTimeout(resolve, 0))
    // The open menu closes on the page rather than staying up locked.
    const closes = fake.delivered.slice(sent).filter((d) => d.message.type === "db:close-menu")
    expect(closes.map((d) => [d.message.token, (d.options as { documentId: string }).documentId])).toEqual([[open, "top-doc"]])
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
