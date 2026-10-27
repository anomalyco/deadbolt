import { beforeEach, describe, expect, test } from "bun:test"
import { Autofill, nextStep } from "../src/bg/autofill"
import { ACCOUNTS, fakeHost, installChrome, menuSender, pageSender, POPUP_URL, SITE, type FakeChrome, type FakeHost } from "./chrome"

let fake: FakeChrome
let host: FakeHost
let autofill: Autofill

beforeEach(() => {
  fake = installChrome()
  host = fakeHost()
  autofill = new Autofill(host.host)
})

const fills = () => host.requests.filter((r) => r.type === "fill")
const delivered = (type: string) => fake.delivered.filter((d) => d.message.type === type)

async function waitFor(ok: () => boolean) {
  for (let i = 0; i < 100 && !ok(); i++) await Bun.sleep(1)
  expect(ok()).toBe(true)
}

async function menu(form = 1): Promise<string> {
  const reply = await autofill.query(pageSender(), ["email", "password"], "email", form)
  expect(reply.token).toBeString()
  return reply.token!
}

describe("menu tokens", () => {
  test("the menu frame handed the token by the asking page can use it", async () => {
    const token = await menu()
    expect((await autofill.menuLoad(token, menuSender(), SITE))?.kind).toBe("accounts")
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: true })
    expect(delivered("db:fill")[0].message).toEqual({ type: "db:fill", values: { username: "kit@example.com", password: "correct horse" }, form: 1, approval: "ok-1" })
  })

  test("a token used from another tab, another origin's frame, or another extension page is refused", async () => {
    const token = await menu()
    expect(await autofill.menuLoad(token, menuSender({ tab: { id: 2 } as chrome.tabs.Tab }), SITE)).toBeNull()
    expect(await autofill.menuLoad(token, menuSender(), "https://ads.example.net")).toBeNull()
    expect(await autofill.menuLoad(token, menuSender({ url: POPUP_URL }), SITE)).toBeNull()
    expect(await autofill.menuLoad(token, menuSender({ documentId: undefined }), SITE)).toBeNull()
    // A content script can't pose as the menu.
    expect(await autofill.menuLoad(token, pageSender(), SITE)).toBeNull()
    expect(fills()).toEqual([])
  })

  test("nothing works with a token before the menu loads it", async () => {
    const token = await menu()
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: false, message: "This menu has expired." })
    expect(fills()).toEqual([])
  })

  test("not once the asking document is gone", async () => {
    const token = await menu()
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "replaced-doc" }
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toBeNull()
  })

  test("a token is bound to the first menu document that loads it", async () => {
    const token = await menu()
    expect(await autofill.menuLoad(token, menuSender(), SITE)).not.toBeNull()
    const second = menuSender({ frameId: 8, documentId: "second" })
    expect(await autofill.menuLoad(token, second, SITE)).toBeNull()
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, second)).toEqual({ ok: false, message: "This menu has expired." })
    expect(fills()).toEqual([])
  })

  test("navigating the frame revokes its tokens", async () => {
    const token = await menu()
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/next", transitionType: "link" })
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toBeNull()
  })

  test("a form snapshot id is required", async () => {
    expect(await autofill.query(pageSender(), ["email"], "email", "x")).toEqual({ rows: 0 })
  })
})

describe("filling from the popup", () => {
  test("needs a login form the current document reported", async () => {
    expect(await autofill.popupFill(1, ACCOUNTS[0].ref)).toEqual({ ok: false, message: "No login form to fill on this page." })
    expect(fills()).toEqual([])
  })

  test("never for an opaque-origin page, which can't report one", async () => {
    await autofill.page(pageSender({ origin: "null" }), "login", ["email", "password"], 1)
    expect(await autofill.popupFill(1, ACCOUNTS[0].ref)).toEqual({ ok: false, message: "No login form to fill on this page." })
    expect(fills()).toEqual([])
  })

  test("fills the reported form, with its snapshot id", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")[0]).toMatchObject({ options: { documentId: "top-doc" }, message: { form: 4 } })
  })

  test("not after the reporting document went away", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "new-doc" }
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: false, message: "The page changed. Try again." })
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when the user cancels while the host is answering", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    const release = host.holdFills()
    const fill = autofill.popupFill(1, ACCOUNTS[1].ref)
    await waitFor(() => fills().length === 1)
    autofill.forgetTab(1)
    release()
    expect((await fill).ok).toBe(false)
    expect(delivered("db:fill")).toEqual([])
  })
})

/**
 * A page can make a field fillable after the check, such as a disabled
 * password it enables once the username is focused. The content script fixes
 * which fields may be filled before the host is asked; only those are asked
 * for and written.
 */
describe("filling only the fields approved before the host is asked", () => {
  const approve = (roles: string[] | null) => {
    fake.answer = (message) => (message.type === "db:approve" ? roles && { approval: "fixed", roles } : true)
  }

  test("a menu pick asks only for what was approved, and names the approval", async () => {
    approve(["email"])
    const token = await menu()
    await autofill.menuLoad(token, menuSender(), SITE)
    fake.fillAck = () => ({ filled: ["email"] })
    expect(await autofill.menuPick(token, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: true })
    expect(fills()).toMatchObject([{ want: ["username"] }])
    expect(delivered("db:approve")).toMatchObject([{ options: { documentId: "top-doc" }, message: { form: 1, measure: false } }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { username: "kit@example.com" }, approval: "fixed" } }])
    expect(delivered("db:fill")[0].message).not.toHaveProperty("values.password")
  })

  test("so does the popup", async () => {
    approve(["password"])
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    fake.fillAck = () => ({ filled: ["password"] })
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(fills()).toMatchObject([{ want: ["password"] }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { password: "correct horse" }, approval: "fixed" } }])
  })

  test("roles the form didn't report stay out, whatever the page approves", async () => {
    approve(["email", "password", "otp"])
    const reply = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(reply.token!, menuSender(), SITE)
    await autofill.menuPick(reply.token!, ACCOUNTS[1].ref, menuSender())
    expect(fills()).toMatchObject([{ want: ["username"] }])
  })

  test("nothing approved, or no answer: the host isn't asked", async () => {
    for (const answer of [null, { approval: "x", roles: [] }, { roles: ["email"] }, { approval: "x", roles: ["email"], boxes: "nope" }]) {
      fake.answer = (message) => (message.type === "db:approve" ? answer : true)
      const token = await menu()
      await autofill.menuLoad(token, menuSender(), SITE)
      expect(await autofill.menuPick(token, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: false, message: "The page changed. Try again." })
    }
    expect(fills()).toEqual([])
    expect(delivered("db:fill")).toEqual([])
  })
})

/**
 * Frames get no inline menu: a frame can't watch how the page around it shows
 * it. The popup fills a frame's form only when it and every frame above it
 * say it shows.
 */
describe("filling a frame's form from the popup", () => {
  const NOT_SHOWN = { ok: false, message: "That login form isn't fully visible. Nothing was filled." }
  const BOX = { left: 10, top: 20, right: 210, bottom: 50 }
  const LOW = { left: 40, top: 300, right: 240, bottom: 330 }
  /** Content scripts by document: `${documentId} ${type}` to the answer, or a function of the message. */
  let scripts: Record<string, unknown>
  const asked = (documentId: string) => fake.delivered.filter((d) => (d.options as { documentId: string }).documentId === documentId).map((d) => d.message)

  beforeEach(async () => {
    // top-doc > mid-doc (frame 2) > frame-doc (frame 3), all on the site.
    fake.frames["1:2"] = { url: "https://www.example.com/shell", documentId: "mid-doc", parentFrameId: 0 }
    fake.frames["1:3"] = { url: "https://www.example.com/embed", documentId: "frame-doc", parentFrameId: 2 }
    scripts = {
      "frame-doc db:approve": { approval: "framed", roles: ["email", "password"], boxes: [BOX] },
      "frame-doc db:approved": { boxes: [BOX] },
      "frame-doc db:frame-announce": true,
      "mid-doc db:frame-child": { boxes: [LOW] },
      "mid-doc db:frame-announce": true,
      "top-doc db:frame-child": { boxes: [LOW] },
    }
    fake.answer = (message, documentId) => {
      const key = `${documentId} ${message.type}`
      if (!(key in scripts)) throw new Error("no content script")
      const a = scripts[key]
      return typeof a === "function" ? a(message) : a
    }
    await autofill.page(pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" }), "login", ["email", "password"], 2)
  })

  test("fills once the frame and every frame above it say it shows", async () => {
    // An email-first form: the top page's would arm the password step.
    fake.fillAck = () => ({ filled: ["email"] })
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" }, message: { form: 2 } }])
    // Each frame up is asked about the boxes the one below gave, through the element the one below names.
    const [mid] = asked("mid-doc").filter((m) => m.type === "db:frame-child")
    const [named] = asked("frame-doc").filter((m) => m.type === "db:frame-announce")
    expect(mid).toMatchObject({ boxes: [BOX], nonce: named.nonce })
    const [top] = asked("top-doc").filter((m) => m.type === "db:frame-child")
    const [midNamed] = asked("mid-doc").filter((m) => m.type === "db:frame-announce")
    expect(top).toMatchObject({ boxes: [LOW], nonce: midNamed.nonce })
    expect(top.nonce).not.toBe(mid.nonce)
    // No email-first continuation from a frame.
    expect(fake.session).toEqual({})
  })

  test("asks only for the fields that showed, and checks those same fields again", async () => {
    scripts["frame-doc db:approve"] = { approval: "framed", roles: ["email"], boxes: [BOX] }
    fake.fillAck = () => ({ filled: ["email"] })
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(fills()).toMatchObject([{ want: ["username"] }])
    expect(asked("frame-doc").filter((m) => m.type === "db:approve")).toEqual([{ type: "db:approve", form: 2, measure: true }])
    expect(asked("frame-doc").filter((m) => m.type === "db:approved")).toEqual([{ type: "db:approved", approval: "framed" }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { username: "kit@example.com" }, approval: "framed" } }])
    expect(delivered("db:fill")[0].message).not.toHaveProperty("values.password")
  })

  test("not when the approved fields no longer all show once the values are in hand", async () => {
    scripts["frame-doc db:approved"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(fills()).toHaveLength(1)
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when the frame's own fields don't show, and the host isn't asked", async () => {
    scripts["frame-doc db:approve"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(fills()).toEqual([])
  })

  test("not when any frame above says it doesn't show it", async () => {
    scripts["mid-doc db:frame-child"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["mid-doc db:frame-child"] = { boxes: [LOW] }
    scripts["top-doc db:frame-child"] = { boxes: [] }
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when a frame above can't answer", async () => {
    delete scripts["top-doc db:frame-child"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["top-doc db:frame-child"] = { boxes: [LOW] }
    // An about:blank or sandboxed frame in between runs no content script.
    delete scripts["mid-doc db:frame-child"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["mid-doc db:frame-child"] = { boxes: [LOW] }
    // Nor one whose child can't name the element it's in.
    delete scripts["frame-doc db:frame-announce"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["frame-doc db:frame-announce"] = true
    // Nor one the tab doesn't list.
    delete fake.frames["1:2"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(delivered("db:fill")).toEqual([])
  })

  test("checked again once the values are in hand", async () => {
    const release = host.holdFills()
    const fill = autofill.popupFill(1, ACCOUNTS[1].ref)
    await waitFor(() => fills().length === 1)
    scripts["top-doc db:frame-child"] = null
    release()
    expect(await fill).toEqual(NOT_SHOWN)
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when more than one frame's form shows", async () => {
    fake.frames["1:4"] = { url: "https://www.example.com/other", documentId: "other-doc", parentFrameId: 0 }
    Object.assign(scripts, { "other-doc db:approve": { approval: "other", roles: ["password"], boxes: [BOX] }, "other-doc db:frame-announce": true })
    await autofill.page(pageSender({ frameId: 4, url: "https://www.example.com/other", documentId: "other-doc" }), "login", ["password"], 1)
    expect((await autofill.popupFill(1, ACCOUNTS[1].ref)).ok).toBe(false)
    // Only one of them showing is fine.
    scripts["other-doc db:approve"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("the top page's form wins, unchecked", async () => {
    scripts["top-doc db:approve"] = { approval: "top", roles: ["email", "password"] }
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "top-doc" }, message: { form: 4 } }])
    expect(fake.delivered.filter((d) => d.message.type.startsWith("db:frame-"))).toEqual([])
  })

  // A page can swap its form for a frame's without navigating.
  test("a top form that went away no longer wins", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    await autofill.page(pageSender(), null, [], 5)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("the top page is asked for a fresh report before choosing", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    // Its form went a moment ago; its next scan hasn't said so yet.
    scripts["top-doc db:report"] = async () => (await autofill.page(pageSender(), null, [], 5), true)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("a frame whose form went away isn't one to fill", async () => {
    await autofill.page(pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" }), null, [], 3)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: false, message: "No login form to fill on this page." })
    expect(fake.delivered.filter((d) => d.message.type.startsWith("db:frame-") || d.message.type === "db:approve")).toEqual([])
  })

  test("a frame gets no inline menu", async () => {
    const sender = pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" })
    expect(await autofill.query(sender, ["email", "password"], "email", 2)).toEqual({ rows: 0 })
  })
})

describe("email-first continuation", () => {
  const passwordPage = () => autofill.page(pageSender({ url: "https://www.example.com/password", documentId: "pw-doc" }), "login", ["password"], 1)
  const toPasswordPage = () => void (fake.frames["1:0"] = { url: "https://www.example.com/password", documentId: "pw-doc" })

  /** Holds the content script's answers to db:fill until released. */
  function holdFills(ack: string[]) {
    const held: Array<() => void> = []
    fake.fillAck = () => new Promise((resolve) => held.push(() => resolve({ filled: ack })))
    return held
  }

  beforeEach(() => {
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc" }
  })

  async function fillEmail(ack: string[], account = ACCOUNTS[1]) {
    fake.fillAck = () => ({ filled: ack })
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    return autofill.menuPick(token.token!, account.ref, menuSender())
  }

  test("nextStep follows what was actually filled", () => {
    expect(nextStep(["email"], { hasPassword: true, hasTotp: true })).toBe("password")
    expect(nextStep(["password"], { hasPassword: true, hasTotp: true })).toBe("otp")
    expect(nextStep(["password"], { hasPassword: true, hasTotp: false })).toBeUndefined()
    expect(nextStep([], { hasPassword: true, hasTotp: true })).toBeUndefined()
  })

  test("a fill the page didn't take arms nothing", async () => {
    expect(await fillEmail([])).toEqual({ ok: false, message: "The page changed. Try again." })
    expect(fake.session).toEqual({})
  })

  test("the next step fills once", async () => {
    await fillEmail(["email"])
    fake.frames["1:0"] = { url: "https://www.example.com/password", documentId: "pw-doc" }
    // The page doesn't take it this time.
    fake.fillAck = () => ({ filled: [] })
    await passwordPage()
    expect(fills().map((r) => (r as { want: string[] }).want)).toEqual([["username"], ["password"]])
    // Reporting the step again doesn't fill again.
    await passwordPage()
    expect(fills()).toHaveLength(2)
    expect(fake.session).toEqual({})
  })

  test("a page without the next step doesn't use it up, another step's page doesn't fill", async () => {
    await fillEmail(["email"])
    fake.frames["1:0"] = { url: "https://www.example.com/mfa", documentId: "mfa-doc" }
    await autofill.page(pageSender({ url: "https://www.example.com/mfa", documentId: "mfa-doc" }), "mfa", ["otp"], 1)
    expect(fills()).toHaveLength(1)
    expect(Object.keys(fake.session)).toEqual(["continue:1"])
  })

  test("typing an address, or going to another origin, ends it", async () => {
    await fillEmail(["email"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/password", transitionType: "typed" })
    expect(fake.session).toEqual({})
    await fillEmail(["email"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://accounts.example.com/password", transitionType: "form_submit" })
    expect(fake.session).toEqual({})
  })

  test("submitting to the next step on the same origin keeps it", async () => {
    await fillEmail(["email"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/password", transitionType: "form_submit" })
    expect(Object.keys(fake.session)).toEqual(["continue:1"])
  })

  test("a matching form in the same document isn't a step until the user submits or the filled fields go", async () => {
    await fillEmail(["email"])
    // The page shows a password box next to the email box it just got.
    await autofill.page(pageSender(), "login", ["email", "password"], 2)
    expect(fills()).toHaveLength(1)
    expect(Object.keys(fake.session)).toEqual(["continue:1"])
    await autofill.page(pageSender(), "login", ["password"], 3, true)
    expect(fills()).toHaveLength(2)
    expect(delivered("db:fill")[1]).toMatchObject({ options: { documentId: "top-doc" }, message: { form: 3 } })
  })

  test("two reports of the next step at once fill it once", async () => {
    await fillEmail(["email"])
    toPasswordPage()
    await Promise.all([passwordPage(), passwordPage(), passwordPage()])
    expect(fills()).toHaveLength(2)
  })

  test("a frame never continues", async () => {
    await fillEmail(["email"])
    fake.frames["1:3"] = { url: "https://www.example.com/embed", documentId: "frame-doc", parentFrameId: 0 }
    await autofill.page(pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" }), "login", ["password"], 1, true)
    expect(fills()).toHaveLength(1)
  })

  test("a pick cancelled while the host is answering fills nothing", async () => {
    const release = host.holdFills()
    const token = await autofill.query(pageSender(), ["email", "password"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const pick = autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    await waitFor(() => fills().length === 1)
    // Esc in the field's next menu.
    const other = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuClose(other.token!, true, pageSender())
    release()
    expect((await pick).ok).toBe(false)
    expect(delivered("db:fill")).toEqual([])
    expect(fake.session).toEqual({})
  })

  test("a fill that finishes after the menu was dismissed arms nothing", async () => {
    const acks = holdFills(["email"])
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const pick = autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    await waitFor(() => acks.length === 1)
    const other = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuClose(other.token!, true, pageSender())
    acks[0]()
    expect(await pick).toEqual({ ok: true })
    expect(fake.session).toEqual({})
  })

  test("a fill that finishes after the tab left the origin arms nothing", async () => {
    const acks = holdFills(["email"])
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const pick = autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    await waitFor(() => acks.length === 1)
    fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" }
    acks[0]()
    await pick
    expect(fake.session).toEqual({})
  })

  test("a step reported just before a cancel doesn't fill", async () => {
    await fillEmail(["email"])
    toPasswordPage()
    // Hold the report's read of the step, so the cancel lands while it's in progress.
    const session = (globalThis as unknown as { chrome: { storage: { session: { get: (key: string) => Promise<unknown> } } } }).chrome.storage.session
    const get = session.get
    let release = () => {}
    let reading = false
    session.get = async (key) => {
      reading = true
      await new Promise<void>((resolve) => (release = resolve))
      return get(key)
    }
    const report = passwordPage()
    await waitFor(() => reading)
    session.get = get
    const cancel = autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/password", transitionType: "link", transitionQualifiers: ["forward_back"] })
    release()
    await Promise.all([report, cancel])
    expect(fills()).toHaveLength(1)
    expect(fake.session).toEqual({})
  })

  test("the next step's fill, cancelled while on its way, arms no further step", async () => {
    // kit@example.com has a code too, so the password step would arm the code step.
    await fillEmail(["email"], ACCOUNTS[0])
    toPasswordPage()
    const acks = holdFills(["password"])
    const report = passwordPage()
    await waitFor(() => acks.length === 1)
    const cancel = autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/x", transitionType: "typed" })
    acks[0]()
    await Promise.all([report, cancel])
    expect(fills()).toHaveLength(2)
    expect(fake.session).toEqual({})
  })

  test("dismissing the menu cancels it", async () => {
    await fillEmail(["email"])
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuClose(token.token!, true, pageSender())
    expect(fake.session).toEqual({})
  })
})
