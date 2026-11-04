import { beforeEach, describe, expect, test } from "bun:test"
import { HostError } from "../src/bg/backend"
import { cardPlan, cleanCard, cleanFacts, identityPlan, judge, NEVER_KEY, NOT_NOW_MS, Saver, type Trust } from "../src/bg/save"
import type { RequestBody } from "../src/protocol"
import { CARDS, fakeHost, HOME_REF, HOME_VALUES, installChrome, menuSender, NO_FACTS, pageSender, SITE, VISA_REF, type FakeChrome, type FakeHost } from "./chrome"

let fake: FakeChrome
let host: FakeHost
let saver: Saver

beforeEach(() => {
  fake = installChrome()
  host = fakeHost()
  saver = new Saver(host.host, { capture: 60_000, offer: 60_000, reprobe: 5 })
})

const HOME = { url: "https://www.example.com/home", documentId: "home-doc" }

const signIn = async (username: string, password: string) => {
  await saver.capture(pageSender(), { username, password, title: "Sign in to Example" })
  fake.frames["1:0"] = HOME
  await saver.settled(pageSender(HOME))
}

const requests = (type: string) => host.requests.filter((r) => r.type === type)

/** Where offers showed by themselves: the save surface in a tab's page, or the popup over a window. */
const shown = () => [...fake.delivered.filter((d) => d.message.type === "db:surface").map((d) => `page:${d.tabId}`), ...fake.popups.map((w) => `popup:${w}`)]

/** Holds the host's replies to `type` until released, in order. */
function hold(type: RequestBody["type"]) {
  const held: Array<() => void> = []
  const send = host.host.send.bind(host.host)
  host.host.send = (async (req: RequestBody) => {
    if (req.type === type) await new Promise<void>((resolve) => held.push(resolve))
    return send(req)
  }) as typeof host.host.send
  return held
}

async function waitFor(ok: () => boolean) {
  for (let i = 0; i < 100 && !ok(); i++) await Bun.sleep(1)
  expect(ok()).toBe(true)
}

describe("offers", () => {
  test("a new login is offered in the toolbar, and in the page as Deadbolt's own surface", async () => {
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toMatchObject({ site: "example.com", username: "new@example.com", update: false })
    expect(saver.pending(1)?.id).toBeString()
    expect(fake.badges[1]).toBe("1")
    expect(shown()).toEqual(["page:1"])
    // The page's document got the question of what it shows and a token for the surface, nothing more;
    // the surface frame asks for the rest. Nothing was saved yet.
    expect(fake.delivered.map((d) => d.message.type)).toEqual(["db:probe", "db:surface"])
    expect(Object.keys(fake.delivered[1].message)).toEqual(["type", "token"])
    expect(fake.delivered.every((d) => (d.options as { documentId: string }).documentId === "home-doc")).toBe(true)
    expect(JSON.stringify(fake.delivered)).not.toContain("a new password")
    expect(host.requests.map((r) => r.type)).toEqual(["check"])
  })

  test("where the page doesn't take the surface, the popup opens, but never over another tab", async () => {
    fake.answer = (message) => (message.type === "db:probe" ? { ...NO_FACTS, account: true } : false)
    await signIn("new@example.com", "a new password")
    expect(fake.popups).toEqual([7])
    fake.popups = []
    fake.session = {}
    fake.tabs[1].active = false
    await signIn("other@example.com", "pw")
    expect(saver.pending(1)?.username).toBe("other@example.com")
    expect(fake.popups).toEqual([])
    expect(fake.badges[1]).toBe("1")
  })

  test("a changed password is offered as an update; an unchanged one isn't offered", async () => {
    await signIn("admin", "changed")
    expect(saver.pending(1)?.update).toBe(true)
    await saver.choose(1, saver.pending(1)!.id, "later")
    await signIn("admin", "hunter2")
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBe("")
  })

  test("save only after the user says so, then the offer is gone", async () => {
    await signIn("new@example.com", "a new password")
    const { id } = saver.pending(1)!
    expect(await saver.choose(1, id, "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    const save = requests("save")[0] as unknown as { entry: Record<string, string> }
    expect(save.entry).toEqual({ title: "Example", url: "https://www.example.com/login", username: "new@example.com", password: "a new password" })
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBe("")
    expect(await saver.choose(1, id, "save")).toEqual({ ok: false, message: "This offer has expired.", gone: true })
  })
})

describe("answering an offer", () => {
  test("Save and Not now answer only the offer the popup showed", async () => {
    await signIn("new@example.com", "a new password")
    const shown = saver.pending(1)!.id
    // Another sign-in in the tab replaces it while the popup still shows the first.
    await signIn("admin", "changed")
    const waiting = saver.pending(1)!
    expect(waiting.id).not.toBe(shown)
    expect(await saver.choose(1, shown, "save")).toMatchObject({ ok: false, gone: true })
    expect(await saver.choose(1, shown, "later")).toMatchObject({ ok: false, gone: true })
    expect(requests("save")).toEqual([])
    expect(saver.pending(1)).toEqual(waiting)
    expect(await saver.choose(1, waiting.id, "save")).toEqual({ ok: true, message: "Password updated" })
    expect((requests("save")[0] as { entry: { username: string } }).entry.username).toBe("admin")
  })

  test("a second Save while the first is on its way saves nothing more", async () => {
    const saves = hold("save")
    await signIn("new@example.com", "a new password")
    const { id } = saver.pending(1)!
    const first = saver.choose(1, id, "save")
    await waitFor(() => saves.length === 1)
    expect(await saver.choose(1, id, "save")).toEqual({ ok: false, message: "Saving…" })
    expect(await saver.choose(1, id, "later")).toEqual({ ok: false, message: "Saving…" })
    saves[0]()
    expect(await first).toMatchObject({ ok: true })
    expect(requests("save")).toHaveLength(1)
  })

  test("a save that finishes after a newer offer arrived leaves the newer one", async () => {
    const saves = hold("save")
    await signIn("new@example.com", "a new password")
    const first = saver.choose(1, saver.pending(1)!.id, "save")
    await waitFor(() => saves.length === 1)
    await signIn("admin", "changed")
    const newer = saver.pending(1)!
    saves[0]()
    expect(await first).toMatchObject({ ok: true })
    expect(saver.pending(1)).toEqual(newer)
    expect(fake.badges[1]).toBe("1")
  })

  test("Save checks the tab is still on the offer's site", async () => {
    await signIn("new@example.com", "a new password")
    // The tab has moved on and the navigation event hasn't arrived yet.
    fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" }
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toMatchObject({ ok: false, gone: true })
    expect(requests("save")).toEqual([])
  })
})

describe("a check that finishes late", () => {
  async function lateCheck(meanwhile: () => void) {
    const checks = hold("check")
    await saver.capture(pageSender(), { username: "new@example.com", password: "pw", title: "" })
    fake.frames["1:0"] = HOME
    const quiet = saver.settled(pageSender(HOME))
    await waitFor(() => checks.length === 1)
    meanwhile()
    checks[0]()
    await quiet
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBeUndefined()
    expect(shown()).toEqual([])
  }

  test("offers nothing once the tab is on another site", () =>
    lateCheck(() => {
      fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" }
      saver.navigated(1, "https://elsewhere.net/")
    }))

  test("or went to another site and came back", () =>
    lateCheck(() => {
      saver.navigated(1, "https://www.example.com/home")
      saver.navigated(1, "https://elsewhere.net/")
      saver.navigated(1, "https://www.example.com/home")
    }))

  test("or before the navigation event arrives", () => lateCheck(() => void (fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" })))

  test("or after Deadbolt locked, even once it's unlocked again", () =>
    lateCheck(() => {
      host.setStatus({ state: "locked" })
      host.setStatus({ state: "ready", version: "0" })
    }))

  test("or after the tab closed", () => lateCheck(() => saver.forgetTab(1)))

  test("a capture that lands after the tab left the site is dropped", async () => {
    const capture = saver.capture(pageSender(), { username: "new@example.com", password: "pw", title: "" })
    saver.navigated(1, "https://elsewhere.net/")
    await capture
    saver.navigated(1, "https://www.example.com/home")
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([])
  })
})

describe("opening the popup by itself", () => {
  // A page can see focus leave it when the popup opens, so this is the one bit
  // a check can leak: at most once per site every ten minutes, across tabs.
  test("happens once per site every ten minutes, across tabs; other offers only badge", async () => {
    let now = 1_000_000
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000 }, () => now)
    const signInOn = async (tabId: number, url: string) => {
      const tab = { id: tabId, incognito: false } as chrome.tabs.Tab
      const origin = new URL(url).origin
      fake.tabs[tabId] = { active: true, windowId: 7 }
      fake.frames[`${tabId}:0`] = { url, documentId: `login-${tabId}`, parentFrameId: -1 }
      await saver.capture(pageSender({ tab, url, origin, documentId: `login-${tabId}` }), { username: "new@example.com", password: "pw", title: "" })
      fake.frames[`${tabId}:0`] = { url: `${origin}/home`, documentId: `home-${tabId}`, parentFrameId: -1 }
      await saver.settled(pageSender({ tab, url: `${origin}/home`, origin, documentId: `home-${tabId}` }))
      expect(saver.pending(tabId)).toBeDefined()
    }

    await signInOn(1, "https://www.example.com/login")
    expect(shown()).toHaveLength(1)
    // Another tab on the same site (another subdomain too) a few minutes later: badge only.
    now += 4 * 60_000
    await signInOn(2, "https://app.example.com/login")
    expect(shown()).toHaveLength(1)
    expect(fake.badges[2]).toBe("1")
    // Another site has its own turn.
    await signInOn(3, "https://other.test/login")
    expect(shown()).toHaveLength(2)
    // Just under ten minutes after the first: still badge only.
    now += 6 * 60_000 - 1
    await signInOn(1, "https://www.example.com/login")
    expect(shown()).toHaveLength(2)
    // Ten minutes on, example.com gets its next turn.
    now += 1
    await signInOn(2, "https://app.example.com/login")
    expect(shown()).toHaveLength(3)
  })

  test("two tabs offering at once share one turn", async () => {
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000 }, () => 5_000_000)
    fake.tabs[2] = { active: true, windowId: 8 }
    fake.frames["2:0"] = { url: "https://www.example.com/login", documentId: "other-login", parentFrameId: -1 }
    const tab2 = { id: 2, incognito: false } as chrome.tabs.Tab
    await saver.capture(pageSender(), { username: "a@example.com", password: "x", title: "" })
    await saver.capture(pageSender({ tab: tab2, documentId: "other-login" }), { username: "b@example.com", password: "y", title: "" })
    fake.frames["1:0"] = HOME
    fake.frames["2:0"] = { url: "https://www.example.com/home", documentId: "other-home" }
    await Promise.all([saver.settled(pageSender(HOME)), saver.settled(pageSender({ tab: tab2, url: "https://www.example.com/home", documentId: "other-home" }))])
    expect([saver.pending(1), saver.pending(2)].every(Boolean)).toBe(true)
    expect(shown()).toHaveLength(1)
  })

  // Otherwise a page could submit guesses until the popup opens: every
  // "same" before the first opening would be free.
  test("a check that says the login is already saved uses the turn too", async () => {
    await signIn("admin", "hunter2")
    expect(saver.pending(1)).toBeUndefined()
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toBeDefined()
    expect(fake.badges[1]).toBe("1")
    expect(shown()).toEqual([])
  })

  test("so does a rate-limited check", async () => {
    const send = host.host.send.bind(host.host)
    let limited = true
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "check" && limited) {
        limited = false
        throw new HostError("rate_limited", "slow down")
      }
      return send(req)
    }) as typeof host.host.send
    await signIn("new@example.com", "first")
    expect(saver.pending(1)).toBeUndefined()
    await signIn("new@example.com", "second")
    expect(saver.pending(1)).toBeDefined()
    expect(shown()).toEqual([])
  })
})

describe("plaintext lifetime", () => {
  test("a capture expires on its own", async () => {
    saver = new Saver(host.host, { capture: 20, offer: 60_000 })
    await saver.capture(pageSender(), { username: "new@example.com", password: "x", title: "" })
    await Bun.sleep(40)
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(host.requests).toEqual([])
  })

  test("a username on its own doesn't keep an older password longer; a new password starts over", async () => {
    let now = 1_000_000
    saver = new Saver(host.host, { capture: 3 * 60_000, offer: 60_000 }, () => now)
    await saver.capture(pageSender(), { password: "old", title: "" })
    now += 2 * 60_000
    await saver.capture(pageSender(), { username: "new@example.com", title: "" })
    now += 90_000
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([])

    await saver.capture(pageSender(), { username: "new@example.com", password: "old", title: "" })
    now += 2 * 60_000
    await saver.capture(pageSender(), { password: "fresh", title: "" })
    now += 90_000
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toMatchObject([{ username: "new@example.com", password: "fresh" }])
  })

  test("an offer, and the password in it, expires on its own", async () => {
    saver = new Saver(host.host, { capture: 60_000, offer: 20 })
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toBeDefined()
    await Bun.sleep(40)
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBe("")
  })

  test("locking drops captures and offers", async () => {
    await signIn("new@example.com", "a new password")
    await saver.capture(pageSender(), { username: "b@example.com", password: "y", title: "" })
    host.setStatus({ state: "locked" })
    expect(saver.pending(1)).toBeUndefined()
    host.setStatus({ state: "ready", version: "0" })
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(1)
  })

  test("another site's page drops the capture and the offer; the same site's keeps them", async () => {
    await signIn("new@example.com", "a new password")
    saver.navigated(1, "https://app.example.com/dashboard")
    expect(saver.pending(1)).toBeDefined()
    saver.navigated(1, "https://elsewhere.net/")
    expect(saver.pending(1)).toBeUndefined()
    await saver.capture(pageSender(), { username: "b@example.com", password: "y", title: "" })
    saver.navigated(1, "https://elsewhere.net/")
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(1)
  })
})

describe("new passwords", () => {
  const submit = async (fields: Record<string, string>, kind: string) => {
    await saver.capture(pageSender(), { ...fields, title: "Example", kind, roles: ["email", "password", "new-password"] })
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
  }
  const on = (url: string, documentId: string) => pageSender({ url, origin: new URL(url).origin, documentId })

  test("a password goes to the origin it was submitted on, and is saved with that page; an email step's username carries across", async () => {
    // Email on one of the site's hosts, the generated password on another.
    await saver.capture(on("https://id.example.com/start", "id-doc"), { username: "new@example.com", title: "Example ID", kind: "login", roles: ["email"], submission: 1 })
    await saver.capture(on("https://accounts.example.com/signup", "accounts-doc"), { generated: "g4", title: "Create an account", kind: "signup", roles: ["new-password"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([{ type: "check", origin: "https://accounts.example.com", username: "new@example.com", generated: "g4" }])
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(requests("save")[0]).toMatchObject({
      origin: "https://accounts.example.com",
      entry: { title: "example.com", url: "https://accounts.example.com/signup", username: "new@example.com", generated: "g4" },
    })
  })

  test("only a sign-in's own username step on the top page carries to another host", async () => {
    const steps: Array<[chrome.runtime.MessageSender, Record<string, unknown>]> = [
      // A form that isn't a sign-in, such as a newsletter box.
      [on("https://news.example.com/", "n"), { username: "news@example.com", title: "News", kind: null, roles: ["email"], submission: 1 }],
      // A sign-in step in a frame.
      [pageSender({ url: "https://id.example.com/frame", origin: "https://id.example.com", documentId: "f", frameId: 2 }), { username: "framed@example.com", title: "", kind: "login", roles: ["email"], submission: 1 }],
    ]
    for (const [sender, step] of steps) {
      host.requests.length = 0
      fake.frames["1:0"] = { url: "https://www.example.com/", documentId: "top" }
      await saver.capture(sender, step)
      await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g7", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 1 })
      fake.frames["1:0"] = HOME
      await saver.settled(pageSender(HOME))
      expect(requests("check")).toEqual([])
    }
    // Nor to a password in a frame.
    fake.frames["1:0"] = { url: "https://id.example.com/start", documentId: "id-doc" }
    await saver.capture(on("https://id.example.com/start", "id-doc"), { username: "new@example.com", title: "", kind: "login", roles: ["email"], submission: 1 })
    await saver.capture(pageSender({ url: "https://accounts.example.com/pw", origin: "https://accounts.example.com", documentId: "f2", frameId: 2 }), { password: "framed", title: "", kind: "login", roles: ["password"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([])
  })

  test("a username joining a password from its own origin pairs with it, and the password's form still owns the failure check", async () => {
    await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g10", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 1 })
    await saver.capture(on("https://accounts.example.com/name", "a2"), { username: "new@example.com", title: "", kind: "signup", roles: ["email"], submission: 1 })
    saver.failed(on("https://accounts.example.com/signup", "a"), 1)
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([])

    await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g11", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 2 })
    await saver.capture(on("https://accounts.example.com/name", "a2"), { username: "new@example.com", title: "", kind: "signup", roles: ["email"], submission: 1 })
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([{ type: "check", origin: "https://accounts.example.com", username: "new@example.com", generated: "g11" }])
  })

  test("passwords held for one username never go with another's", async () => {
    // A sign-in as admin, then a sign-up as someone else on the same page.
    await saver.capture(pageSender(), { username: "admin", password: "hunter2", title: "", kind: "login", roles: ["username", "password"], submission: 1 })
    await saver.capture(pageSender(), { username: "new@example.com", generated: "g12", title: "", kind: "signup", roles: ["email", "new-password"], submission: 2 })
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([{ type: "check", origin: "https://www.example.com", username: "new@example.com", generated: "g12" }])
  })

  test("a password from another of the site's hosts replaces the earlier ones and their username, never mixes with them", async () => {
    // A generated sign-up on one host, then a sign-in with a typed password on another.
    await saver.capture(on("https://accounts.example.com/signup", "a"), { username: "new@example.com", generated: "g5", title: "Sign up", kind: "signup", roles: ["email", "new-password"], submission: 1 })
    await saver.capture(on("https://login.example.com/", "b"), { password: "typed", title: "Sign in", kind: "login", roles: ["password"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    // No username of its own: nothing to offer.
    expect(requests("check")).toEqual([])
    expect(JSON.stringify(host.requests)).not.toContain("g5")
  })

  test("a username from another host after the password never joins it, replaces its own, or takes over its failure check", async () => {
    // Without a username: one from another host doesn't join it.
    await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g6", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 1 })
    await saver.capture(on("https://profile.example.com/name", "p"), { username: "someone@example.com", title: "Profile", kind: "login", roles: ["email"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([])

    // With one: it stays, whatever another host or its own sends on its own.
    for (const later of ["https://profile.example.com/name", "https://accounts.example.com/invite"]) {
      host.requests.length = 0
      await saver.capture(on("https://accounts.example.com/signup", "a"), { username: "new@example.com", generated: "g8", title: "Sign up", kind: "signup", roles: ["email", "new-password"], submission: 2 })
      await saver.capture(on(later, "p"), { username: "someone@example.com", title: "", kind: "login", roles: ["email"], submission: 1 })
      await saver.settled(pageSender(HOME))
      expect(requests("check")).toEqual([{ type: "check", origin: "https://accounts.example.com", username: "new@example.com", generated: "g8" }])
      // Gone by hand (Not now would hold this login back for a day).
      saver.navigated(1, HOME.url, "typed")
    }

    // And the sign-up failing is still seen: the username's page didn't take over the failure check.
    host.requests.length = 0
    await saver.capture(on("https://accounts.example.com/signup", "a"), { username: "new@example.com", generated: "g9", title: "Sign up", kind: "signup", roles: ["email", "new-password"], submission: 3 })
    await saver.capture(on("https://profile.example.com/name", "p"), { username: "someone@example.com", title: "", kind: "login", roles: ["email"], submission: 1 })
    saver.failed(on("https://accounts.example.com/signup", "a"), 3)
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toEqual([])
  })
  const entry = () => (requests("save")[0] as unknown as { ref?: string; entry: Record<string, string> })

  test("a generated password is named by its id, never sent, and saved only when the user says so", async () => {
    await submit({ username: "new@example.com", generated: "g1", newPassword: "ignored" }, "signup")
    expect(requests("check")[0]).toMatchObject({ username: "new@example.com", generated: "g1" })
    expect(requests("check")[0]).not.toHaveProperty("password")
    expect(requests("save")).toEqual([])
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(entry().entry).toEqual({ title: "Example", url: "https://www.example.com/login", username: "new@example.com", generated: "g1" })
  })

  test("a change-password form with no username updates the login whose password is the current one", async () => {
    await submit({ password: "hunter2", generated: "g2" }, "change-password")
    expect(requests("check")[0]).not.toHaveProperty("username")
    expect(saver.pending(1)).toMatchObject({ username: "admin", update: true })
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(entry()).toMatchObject({ ref: "a".repeat(64) + ":" + "2".repeat(32), entry: { username: "admin", generated: "g2" } })
  })

  test("or the only login here, and nothing when there are several", async () => {
    await submit({ password: "forgotten", newPassword: "a new one" }, "change-password")
    expect(saver.pending(1)).toBeUndefined()
    expect(requests("save")).toEqual([])
    const list = host.host.send.bind(host.host)
    host.host.send = (async (req: RequestBody) =>
      req.type === "list" ? { type: "list", site: "example.com", accounts: [{ ...(await list(req) as { accounts: object[] }).accounts[0] }] } : list(req)) as typeof host.host.send
    await submit({ password: "forgotten", newPassword: "a new one" }, "change-password")
    expect(saver.pending(1)).toMatchObject({ username: "kit@example.com", update: true })
  })

  test("a change-password form with a username asks the host the same whether or not the current password matched", async () => {
    const changes: Array<[string, string, object]> = [
      // The saved password: an update of that login.
      ["admin", "hunter2", { username: "admin", update: true }],
      // Another current password: the saved login still updates.
      ["admin", "forgotten", { username: "admin", update: true }],
      // No login here for the username: a new one.
      ["new@example.com", "anything", { username: "new@example.com", update: false }],
    ]
    for (const [username, password, offer] of changes) {
      host.requests.length = 0
      await submit({ username, password, newPassword: "a new one" }, "change-password")
      expect(requests("check")).toEqual([
        { type: "check", origin: "https://www.example.com", username, password },
        { type: "check", origin: "https://www.example.com", username, password: "a new one" },
      ])
      expect(requests("list")).toEqual([])
      expect(saver.pending(1)).toMatchObject(offer)
      // Closing the tab, not Not now: Not now holds the username back for a day.
      saver.forgetTab(1)
    }
    host.requests.length = 0
    await submit({ username: "admin", password: "hunter2", newPassword: "a new one" }, "change-password")
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(entry()).toMatchObject({ ref: "a".repeat(64) + ":" + "2".repeat(32), entry: { username: "admin", password: "a new one" } })
  })

  test("a new password that's the current one offers nothing", async () => {
    const forms: Array<Record<string, string>> = [{ username: "admin", password: "hunter2", newPassword: "hunter2" }, { password: "hunter2", newPassword: "hunter2" }, { username: "admin", password: "other", newPassword: "other" }]
    for (const fields of forms) {
      await submit(fields, "change-password")
      expect(saver.pending(1)).toBeUndefined()
      expect(fake.badges[1] ?? "").toBe("")
    }
    expect(requests("save")).toEqual([])
  })

  test("a generated sign-up whose form still shows offers nothing", async () => {
    await saver.capture(pageSender(), { username: "new@example.com", generated: "g3", title: "", kind: "signup", roles: ["email", "new-password"], submission: 1 })
    saver.failed(pageSender(), 1)
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(host.requests).toEqual([])
  })
})

describe("failed and abandoned sign-ins", () => {
  const login = { username: "new@example.com", password: "wrong", title: "", kind: "login", roles: ["email", "password"], submission: 1 }

  test("the form still showing in place offers nothing", async () => {
    await saver.capture(pageSender(), login)
    saver.failed(pageSender(), 1)
    // Its username still narrows the next try's menu, on this site only.
    expect(saver.username(1, "example.com")).toBe("new@example.com")
    expect(saver.username(1, "elsewhere.net")).toBeUndefined()
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(0)
  })

  test("a failure counts only for the submit and document it's about", async () => {
    // A retry after a wrong password: the first submit's failure arrives after it.
    await saver.capture(pageSender(), login)
    await saver.capture(pageSender(), { ...login, password: "right", submission: 2 })
    saver.failed(pageSender(), 1)
    // Another document on the same page, such as a frame or a page posted back, can't fail it either.
    saver.failed(pageSender({ documentId: "other-doc" }), 2)
    saver.failed(pageSender(), "2")
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toMatchObject([{ username: "new@example.com", password: "right" }])
    // The retry's own failure does.
    await saver.capture(pageSender(), { ...login, submission: 3 })
    saver.failed(pageSender(), 3)
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(1)
  })

  test("the form posted back to its page offers nothing; the same document reporting it again doesn't count", async () => {
    await saver.capture(pageSender(), login)
    saver.page(pageSender(), "login", ["email", "password"])
    saver.page(pageSender({ url: "https://www.example.com/login/next", documentId: "next" }), "login", ["password"])
    saver.page(pageSender({ documentId: "mfa" }), "mfa", ["otp"])
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(1)

    await saver.capture(pageSender(), login)
    saver.page(pageSender({ documentId: "posted-back" }), "login", ["email", "password"])
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(1)
  })

  test("a typed address or a bookmark ends the sign-in; a link doesn't", async () => {
    await saver.capture(pageSender(), login)
    saver.navigated(1, "https://www.example.com/mfa", "form_submit")
    saver.navigated(1, HOME.url, "link")
    fake.frames["1:0"] = HOME
    await saver.settled(pageSender(HOME))
    expect(requests("check")).toHaveLength(1)
    for (const how of ["typed", "auto_bookmark"]) {
      await saver.capture(pageSender(), login)
      saver.navigated(1, HOME.url, how)
      await saver.settled(pageSender(HOME))
    }
    expect(requests("check")).toHaveLength(1)
  })

  test("so does one on the same site while the check is on its way, and an offer waiting", async () => {
    saver.navigated(1, "https://www.example.com/login", "link")
    const held = hold("check")
    await saver.capture(pageSender(), login)
    fake.frames["1:0"] = HOME
    const quiet = saver.settled(pageSender(HOME))
    await waitFor(() => held.length === 1)
    saver.navigated(1, "https://www.example.com/settings", "typed")
    held[0]()
    await quiet
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1] ?? "").toBe("")

    const signedIn = signIn("new@example.com", "a new password")
    await waitFor(() => held.length === 2)
    held[1]()
    await signedIn
    expect(saver.pending(1)).toBeDefined()
    saver.navigated(1, "https://www.example.com/settings", "auto_bookmark")
    expect(saver.pending(1)).toBeUndefined()
  })
})

describe("did the sign-in work", () => {
  const settleOn = async (url: string, documentId: string) => {
    fake.frames["1:0"] = { url, documentId }
    await saver.settled(pageSender({ url, documentId }))
  }
  const submit = (username: string, password: string) => saver.capture(pageSender(), { username, password, title: "Sign in to Example" })

  test("judge", () => {
    const f = (over: Partial<typeof NO_FACTS>) => ({ ...NO_FACTS, ...over })
    expect(judge(f({ error: true }), true, false)).toBe("failed")
    // A signed-in page with a stray error box is still signed in; the form back with an error isn't.
    expect(judge(f({ error: true, account: true }), false, false)).toBe("confirmed")
    expect(judge(f({ error: true, signOut: true }), false, false)).toBe("confirmed")
    expect(judge(f({ error: true, account: true, loginForm: true }), true, false)).toBe("failed")
    expect(judge(f({ loginForm: true, passwordEmpty: true }), false, false)).toBe("failed")
    expect(judge(f({ loginForm: true }), true, false)).toBe("undecided")
    expect(judge(f({ mfa: true }), true, false)).toBe("pending")
    expect(judge(f({ challenge: true, signOut: true }), true, false)).toBe("pending")
    expect(judge(f({ signOut: true, loginish: true }), false, false)).toBe("confirmed")
    expect(judge(f({}), false, false)).toBe("undecided")
    expect(judge(f({}), true, false)).toBe("likely")
    expect(judge(f({ loginish: true }), true, false)).toBe("undecided")
    // A sign-up's "verify your email" page.
    expect(judge(f({ loginish: true }), true, true)).toBe("likely")
  })

  test("a page with an error offers nothing and keeps the capture; the retry is offered", async () => {
    fake.facts = { error: true }
    await submit("new@example.com", "wrong")
    await settleOn("https://www.example.com/", "error-doc")
    expect(requests("check")).toEqual([])
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBeUndefined()
    fake.facts = { account: true }
    await submit("new@example.com", "right")
    await settleOn("https://www.example.com/home", "home-doc")
    expect(requests("check")).toMatchObject([{ password: "right" }])
    expect(saver.pending(1)).toBeDefined()
  })

  test("after a failure, a page without evidence offers nothing; one with the account does", async () => {
    fake.facts = { error: true }
    await submit("new@example.com", "pw")
    await settleOn("https://www.example.com/", "error-doc")
    fake.facts = {}
    await settleOn("https://www.example.com/home", "home-doc")
    expect(requests("check")).toEqual([])
    expect(saver.pending(1)).toBeUndefined()
    // A username alone doesn't clear it either.
    await saver.capture(pageSender(), { username: "new@example.com", title: "" })
    await settleOn("https://www.example.com/home", "home-doc")
    expect(requests("check")).toEqual([])
    fake.facts = { account: true }
    await settleOn("https://www.example.com/dashboard", "dash-doc")
    expect(requests("check")).toHaveLength(1)
    expect(saver.pending(1)).toBeDefined()
  })

  test("a username step isn't judged: the password step after it can still be offered on a page without evidence", async () => {
    let told: unknown[] = []
    saver.signedIn = (tabId, site) => (told = [tabId, site])
    // Step one: only the username, and the page shows the password box, empty.
    await saver.capture(pageSender(), { username: "new@example.com", title: "" })
    expect(saver.username(1, "example.com")).toBe("new@example.com")
    expect(saver.username(1, "elsewhere.net")).toBeUndefined()
    fake.facts = { loginForm: true, passwordEmpty: true }
    await settleOn("https://www.example.com/login", "step-doc")
    expect(fake.delivered.filter((d) => d.message.type === "db:probe")).toEqual([])
    fake.facts = {}
    await saver.capture(pageSender(), { password: "pw", title: "" })
    await settleOn("https://www.example.com/home", "home-doc")
    expect(saver.pending(1)).toMatchObject({ username: "new@example.com" })
    expect(told).toEqual([1, "example.com"])
  })

  test("a new password after a failure starts over", async () => {
    fake.facts = { error: true }
    await submit("new@example.com", "wrong")
    await settleOn("https://www.example.com/", "error-doc")
    fake.facts = {}
    await submit("new@example.com", "right")
    await settleOn("https://www.example.com/home", "home-doc")
    expect(requests("check")).toMatchObject([{ password: "right" }])
    expect(saver.pending(1)).toBeDefined()
  })

  test("of two settled pages at once in a tab, only the newer goes on", async () => {
    fake.facts = {}
    await submit("new@example.com", "pw")
    fake.frames["1:0"] = HOME
    const first = saver.settled(pageSender(HOME))
    const second = saver.settled(pageSender(HOME))
    await Promise.all([first, second])
    expect(requests("check")).toHaveLength(1)
    // Each looked once; only the newer looked a second time.
    expect(fake.delivered.filter((d) => d.message.type === "db:probe")).toHaveLength(3)
    expect(saver.pending(1)).toBeDefined()
  })

  test("only whole PageFacts replies count", () => {
    const full = { ...NO_FACTS, account: true }
    expect(cleanFacts(full)).toEqual(full)
    expect(cleanFacts({ ...full, text: "secret" })).toEqual(full)
    expect(cleanFacts(null)).toBeNull()
    expect(cleanFacts(true)).toBeNull()
    expect(cleanFacts({ account: true })).toBeNull()
    expect(cleanFacts({ ...full, error: "yes" })).toBeNull()
    expect(cleanFacts({ ...full, loginish: 1 })).toBeNull()
  })

  test("a captcha holds the capture past its time; the page after it is offered", async () => {
    let now = 1_000_000
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000, held: 120_000, reprobe: 5 }, () => now)
    fake.facts = { challenge: true, loginish: true }
    await submit("new@example.com", "pw")
    now += 30_000
    await settleOn("https://www.example.com/challenge", "challenge-doc")
    expect(requests("check")).toEqual([])
    expect(saver.pending(1)).toBeUndefined()
    // Past the capture's own minute, within the held two.
    now += 50_000
    fake.facts = { signOut: true }
    await settleOn("https://www.example.com/home", "home-doc")
    expect(requests("check")).toHaveLength(1)
    expect(saver.pending(1)).toBeDefined()
    expect(shown()).toEqual(["page:1"])
  })

  test("a code step waits for the page after it", async () => {
    fake.facts = (doc) => (doc === "mfa-doc" ? { mfa: true, loginish: true } : { account: true })
    await submit("new@example.com", "pw")
    await settleOn("https://www.example.com/mfa", "mfa-doc")
    expect(requests("check")).toEqual([])
    await settleOn("https://www.example.com/home", "home-doc")
    expect(saver.pending(1)).toBeDefined()
  })

  test("a page with no evidence is offered by badge only, after a second look, and leaves the turn", async () => {
    fake.facts = {}
    await submit("new@example.com", "pw")
    await settleOn("https://www.example.com/home", "home-doc")
    expect(fake.delivered.filter((d) => d.message.type === "db:probe")).toHaveLength(2)
    expect(saver.pending(1)).toBeDefined()
    expect(fake.badges[1]).toBe("1")
    expect(shown()).toEqual([])
    // The site's turn is still there for a confirmed sign-in.
    await saver.choose(1, saver.pending(1)!.id, "save")
    fake.facts = { account: true }
    await submit("other@example.com", "pw")
    await settleOn("https://www.example.com/home", "home-doc")
    expect(shown()).toEqual(["page:1"])
  })

  test("a sign-in URL without evidence offers nothing; with the account showing it's confirmed", async () => {
    fake.facts = { loginish: true }
    await submit("new@example.com", "pw")
    await settleOn("https://www.example.com/login?error=1", "again-doc")
    expect(requests("check")).toEqual([])
    fake.facts = { loginish: true, account: true }
    await settleOn("https://www.example.com/auth/complete", "complete-doc")
    expect(saver.pending(1)).toBeDefined()
    expect(shown()).toEqual(["page:1"])
  })

  test("a page that goes away before the second look offers nothing", async () => {
    fake.facts = {}
    await submit("new@example.com", "pw")
    fake.frames["1:0"] = HOME
    const settled = saver.settled(pageSender(HOME))
    fake.frames["1:0"] = { url: "https://www.example.com/next", documentId: "next-doc" }
    await settled
    expect(requests("check")).toEqual([])
  })
})

describe("quieter offers", () => {
  test("Never for this site stops captures and offers there until turned back on", async () => {
    await signIn("new@example.com", "a new password")
    expect(await saver.choose(1, saver.pending(1)!.id, "never")).toEqual({ ok: true, message: "" })
    expect(fake.local[NEVER_KEY]).toEqual(["example.com"])
    expect(await saver.savingOff(1)).toBe("example.com")
    await signIn("other@example.com", "pw")
    expect(requests("check")).toHaveLength(1)
    expect(saver.pending(1)).toBeUndefined()
    expect(await saver.savingOn(1)).toBe(true)
    expect(await saver.savingOff(1)).toBeUndefined()
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc" }
    await signIn("other@example.com", "pw")
    expect(saver.pending(1)).toBeDefined()
  })

  test("Not now holds back the same login on the site for a day, by hash", async () => {
    let now = 1_000_000
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000, reprobe: 5 }, () => now)
    await signIn("new@example.com", "a new password")
    await saver.choose(1, saver.pending(1)!.id, "later")
    expect(JSON.stringify(fake.session)).not.toContain("new@example.com")
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toBeUndefined()
    expect(requests("check")).toHaveLength(1)
    // Another username on the site is still offered.
    await signIn("b@example.com", "pw")
    expect(saver.pending(1)?.username).toBe("b@example.com")
    now += NOT_NOW_MS
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)?.username).toBe("new@example.com")
  })
})

describe("the save offer in the page", () => {
  const surfaceToken = () => fake.delivered.find((d) => d.message.type === "db:surface")?.message.token as string
  const closes = (token: string) => fake.delivered.filter((d) => d.message.type === "db:close-menu" && d.message.token === token)

  test("only the surface frame handed the token loads it, and it gets the site and username, never the password", async () => {
    await signIn("new@example.com", "a new password")
    const token = surfaceToken()
    expect(saver.ownsSurface(token)).toBe(true)
    // Not from another tab, an extension page that isn't the surface, a content script, or for another parent origin.
    expect(await saver.surfaceLoad(token, menuSender({ tab: { id: 2 } as chrome.tabs.Tab }), SITE)).toBeNull()
    expect(await saver.surfaceLoad(token, pageSender(HOME), SITE)).toBeNull()
    expect(await saver.surfaceLoad(token, menuSender(), "https://evil.test")).toBeNull()
    const reply = await saver.surfaceLoad(token, menuSender(), SITE)
    expect(reply).toEqual({ kind: "offer", site: "example.com", username: "new@example.com", update: false })
    // Bound to that frame's document from then on.
    expect(await saver.surfaceChoose(token, menuSender({ documentId: "other-menu" }), "save")).toMatchObject({ ok: false, gone: true })
    expect(requests("save")).toEqual([])
  })

  test("Save in the page saves once; the token answers once", async () => {
    await signIn("new@example.com", "a new password")
    const token = surfaceToken()
    await saver.surfaceLoad(token, menuSender(), SITE)
    expect(await saver.surfaceChoose(token, menuSender(), "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    expect(requests("save")).toHaveLength(1)
    expect(saver.pending(1)).toBeUndefined()
    // The surface shows its own answer: nothing closes it from here.
    expect(closes(token)).toEqual([])
    expect(await saver.surfaceChoose(token, menuSender(), "save")).toMatchObject({ ok: false, gone: true })
    expect(requests("save")).toHaveLength(1)
  })

  test("a save the host turns down for now may be pressed again", async () => {
    await signIn("new@example.com", "a new password")
    const token = surfaceToken()
    await saver.surfaceLoad(token, menuSender(), SITE)
    const send = host.host.send.bind(host.host)
    let locked = true
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "save" && locked) {
        locked = false
        throw new HostError("locked", "locked")
      }
      return send(req)
    }) as typeof host.host.send
    expect(await saver.surfaceChoose(token, menuSender(), "save")).toEqual({ ok: false, message: "Deadbolt is locked. Unlock it, then save again." })
    expect(await saver.surfaceChoose(token, menuSender(), "save")).toMatchObject({ ok: true })
  })

  test("Not now in the page leaves the offer in the toolbar", async () => {
    await signIn("new@example.com", "a new password")
    const token = surfaceToken()
    await saver.surfaceLoad(token, menuSender(), SITE)
    expect(await saver.surfaceChoose(token, menuSender(), "later")).toEqual({ ok: true, message: "" })
    expect(saver.pending(1)).toBeDefined()
    expect(fake.badges[1]).toBe("1")
    expect(saver.ownsSurface(token)).toBe(false)
    // The popup still answers it.
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toMatchObject({ ok: true })
  })

  test("answering in the popup, locking or the offer expiring closes the surface", async () => {
    await signIn("new@example.com", "a new password")
    let token = surfaceToken()
    await saver.choose(1, saver.pending(1)!.id, "later")
    await waitFor(() => closes(token).length === 1)
    expect(saver.ownsSurface(token)).toBe(false)

    fake.session = {}
    fake.delivered = []
    await signIn("other@example.com", "pw")
    token = surfaceToken()
    host.setStatus({ state: "locked" })
    await waitFor(() => closes(token).length === 1)
    host.setStatus({ state: "ready", version: "0" })

    saver = new Saver(host.host, { capture: 60_000, offer: 20, reprobe: 5 })
    fake.session = {}
    fake.delivered = []
    await signIn("third@example.com", "pw")
    token = surfaceToken()
    await Bun.sleep(40)
    await waitFor(() => closes(token).length === 1)
  })

  test("a surface that opens after its offer went is closed again", async () => {
    // The offer goes (here, Deadbolt locks) while the page is opening the surface: a close sent
    // before the page had it would be lost, so one follows the open.
    fake.answer = (message) => {
      if (message.type === "db:probe") return { ...NO_FACTS, account: true }
      if (message.type === "db:surface") {
        host.setStatus({ state: "locked" })
        host.setStatus({ state: "ready", version: "0" })
      }
      return true
    }
    await signIn("new@example.com", "a new password")
    const token = surfaceToken()
    // One close when the offer went, which can reach the page before the surface is open there,
    // and one once the page said it had opened it.
    await waitFor(() => closes(token).length === 2)
    expect(saver.ownsSurface(token)).toBe(false)
  })

  test("leaving the page forgets the surface", async () => {
    await signIn("new@example.com", "a new password")
    const token = surfaceToken()
    saver.navigated(1, "https://www.example.com/next")
    expect(saver.ownsSurface(token)).toBe(false)
    expect(saver.pending(1)).toBeDefined()
  })
})

describe("cards and identities typed into a form", () => {
  const CHECKOUT = { url: "https://www.example.com/checkout", documentId: "checkout-doc" }
  const top = (over: Partial<chrome.runtime.MessageSender> = {}) => pageSender({ url: CHECKOUT.url, documentId: CHECKOUT.documentId, ...over })
  const TYPED = { number: "4000056655665556", expiry: "2030-09", cardholder: "Ada Lovelace", brand: "Visa" }
  /**
   * The user submits a checkout on the top page, and its fields go away: the
   * submit went through. Every value typed by the user, unless `typed` says.
   */
  const checkout = async (got: { card?: Record<string, string>; identity?: Record<string, string>; typed?: string[]; filled?: string[] }, sender = top()) => {
    fake.frames["1:0"] = { ...CHECKOUT, parentFrameId: -1 }
    const typed = got.typed ?? [...Object.keys(got.card ?? {}), ...Object.keys(got.identity ?? {})]
    await saver.formCapture(sender, { ...got, typed, submission: 1 })
    await saver.formOutcome(sender, 1, true)
  }
  const saveForm = () => requests("save-form") as Array<Extract<RequestBody, { type: "save-form" }>>

  test("a card typed on a checkout is offered once the submit went through, as its brand and last four digits only", async () => {
    // With the security code it was typed with: never kept, never sent.
    fake.frames["1:0"] = { ...CHECKOUT, parentFrameId: -1 }
    await saver.formCapture(top(), { card: { ...TYPED, cvv: "737" }, submission: 1 })
    // Not before the outcome is judged.
    expect(saver.pending(1)).toBeUndefined()
    expect(host.requests).toEqual([])
    await saver.formOutcome(top(), 1, true)
    expect(saver.pending(1)).toMatchObject({ site: "example.com", username: "Visa •••• 5556", update: false, what: "card" })
    expect(shown()).toEqual(["page:1"])
    const token = fake.delivered.find((d) => d.message.type === "db:surface")!.message.token as string
    expect(await saver.surfaceLoad(token, menuSender(), SITE)).toEqual({ kind: "offer", site: "example.com", username: "Visa •••• 5556", update: false, what: "card" })
    // Nothing of the number but its last four digits went to a page, the popup or the surface.
    expect(JSON.stringify([fake.delivered, saver.pending(1)])).not.toContain("4000056655665556")
    expect(JSON.stringify([fake.delivered, saver.pending(1)])).not.toContain("737")
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    expect(saveForm()).toEqual([{ type: "save-form", origin: "https://www.example.com", kind: "card", fields: { number: "4000056655665556", expiry: "2030-09", cardholder: "Ada Lovelace", brand: "Visa" } }])
    expect(JSON.stringify(host.requests)).not.toContain("737")
  })

  test("a card typed in a payment provider's frame joins the name typed in the page, as one offer", async () => {
    fake.frames["1:3"] = { url: "https://js.stripe.com/v3/elements-inner-card", documentId: "stripe-doc", parentFrameId: 0 }
    saver.formFrames = () => [{ tabId: 1, frameId: 3, documentId: "stripe-doc", origin: "https://js.stripe.com", provider: "Stripe", kinds: ["card"], form: 1 }]
    fake.answer = (message, documentId) => (message.type === "db:forms-read" && documentId === "stripe-doc" ? { card: { number: TYPED.number, expiry: TYPED.expiry }, identity: { email: "frame@example.com" } } : true)
    await checkout({ card: { cardholder: "Ada Lovelace" } })
    expect(fake.delivered.filter((d) => d.message.type === "db:forms-read").map((d) => (d.options as { documentId: string }).documentId)).toEqual(["stripe-doc"])
    expect(saver.pending(1)?.username).toBe("Visa •••• 5556")
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(saveForm()[0].fields).toEqual({ number: TYPED.number, expiry: TYPED.expiry, cardholder: "Ada Lovelace", brand: "Visa" })
  })

  test("a provider's frame may give a card, never an identity; another site's frame gives nothing", async () => {
    fake.frames["1:0"] = { ...CHECKOUT, parentFrameId: -1 }
    fake.frames["1:3"] = { url: "https://js.stripe.com/v3/elements-inner-card", documentId: "stripe-doc", parentFrameId: 0 }
    fake.frames["1:4"] = { url: "https://evilpay.example.net/card", documentId: "evil-doc", parentFrameId: 0 }
    const evil = pageSender({ frameId: 4, url: "https://evilpay.example.net/card", origin: "https://evilpay.example.net", documentId: "evil-doc" })
    await saver.formCapture(evil, { card: TYPED, submission: 1 })
    await saver.formOutcome(evil, 1, true)
    expect(saver.pending(1)).toBeUndefined()
    const stripe = pageSender({ frameId: 3, url: "https://js.stripe.com/v3/elements-inner-card", origin: "https://js.stripe.com", documentId: "stripe-doc" })
    await saver.formCapture(stripe, { card: TYPED, identity: { "given-name": "Ada", "family-name": "Lovelace", email: "a@example.com", phone: "+15550100100" }, submission: 1 })
    await saver.formOutcome(stripe, 1, true)
    expect(saver.pending(1)?.what).toBe("card")
    expect(requests("fill-form")).toEqual([])
  })

  test("a changed expiry is an update of that card; an unchanged card, or one Deadbolt filled, offers nothing", async () => {
    await checkout({ card: { number: "4242424242424242", expiry: "2028-08", cardholder: "Kit Langton", brand: "Visa" } })
    expect(saver.pending(1)).toBeUndefined()
    expect(requests("forms")).toHaveLength(1)
    fake.session = {}
    await checkout({ card: { number: "4242424242424242", expiry: "2031-01", brand: "Visa" } })
    // The offer names the change, and may be saved as a new card instead.
    expect(saver.pending(1)).toMatchObject({ username: "Visa •••• 4242", update: true, what: "card", change: "Expires 08/28 → 01/31", saveNew: true })
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Card updated" })
    // Natively no number travels with an update: only the browser-only vault compares one.
    expect(saveForm()).toEqual([{ type: "save-form", origin: "https://www.example.com", kind: "card", ref: VISA_REF, fields: { expiry: "2031-01" } }])
    // An expiry the page put there (not typed) changes nothing.
    fake.session = {}
    await checkout({ card: { number: "4242424242424242", expiry: "2031-01" }, typed: ["number"] })
    expect(saver.pending(1)).toBeUndefined()
  })

  test("Save as new keeps an update's card as a new one, number and all", async () => {
    await checkout({ card: { number: "4242424242424242", expiry: "2031-01" } })
    expect(await saver.choose(1, saver.pending(1)!.id, "new")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    expect(saveForm()).toEqual([{ type: "save-form", origin: "https://www.example.com", kind: "card", fields: { number: "4242424242424242", expiry: "2031-01", brand: "Visa" } }])
    expect(saver.pending(1)).toBeUndefined()
  })

  test("the page's own brand never matches a card: same last four with another brand is a new card", async () => {
    // A Mastercard ending 4242, whatever brand the page claimed: a new card, not the saved Visa.
    await checkout({ card: { number: "5105105105104242", expiry: "2031-01", brand: "Visa" } })
    expect(saver.pending(1)).toMatchObject({ username: "Mastercard •••• 4242", update: false, what: "card" })
  })

  test("the browser-only vault compares a card update's typed number; another card is offered as new", async () => {
    ;(host.host as { capabilities: string[] }).capabilities.push("save-form-match")
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "save-form" && req.ref) {
        host.requests.push(req)
        throw new HostError("not_found", "no such card")
      }
      return send(req)
    }) as typeof host.host.send
    // Same last four and brand as the saved Visa, another number.
    await checkout({ card: { number: "4000000000004242", expiry: "2031-01" } })
    const update = saver.pending(1)!
    expect(update).toMatchObject({ update: true, username: "Visa •••• 4242" })
    expect(await saver.choose(1, update.id, "save")).toMatchObject({ ok: false, gone: true })
    expect(saveForm()[0]).toMatchObject({ ref: VISA_REF, fields: { expiry: "2031-01" }, match: { number: "4000000000004242" } })
    expect(saver.pending(1)).toMatchObject({ update: false, what: "card", username: "Visa •••• 4242" })
    expect(saver.pending(1)!.id).not.toBe(update.id)
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    expect(saveForm()[1]).toEqual({ type: "save-form", origin: "https://www.example.com", kind: "card", fields: { number: "4000000000004242", expiry: "2031-01", brand: "Visa" } })
  })

  test("a swapped or planted email isn't written into a saved identity: only what the user typed is", async () => {
    // The user typed a new phone; the page swapped the email (not typed) at submit.
    await checkout({ identity: { "given-name": "Kit", "family-name": "Langton", email: "attacker@example.net", phone: "(415) 555-0199" }, typed: ["given-name", "family-name", "phone"] })
    expect(saver.pending(1)).toMatchObject({ username: "Home", update: true, what: "details", changes: "phone", saveNew: true })
    // The page's email isn't even compared.
    expect(requests("fill-form")[0]).toMatchObject({ fields: ["given-name", "family-name", "phone"] })
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Details updated" })
    expect(saveForm()).toEqual([{ type: "save-form", origin: "https://www.example.com", kind: "identity", ref: HOME_REF, fields: { phone: "(415) 555-0199" } }])
  })

  test("a typed address is offered as a new identity, or as an update of the one it moved from", async () => {
    await checkout({ identity: { "given-name": "Ada", "family-name": "Lovelace", "address-line1": "1 Main St", city: "Springfield", "postal-code": "12345", country: "US" } })
    expect(saver.pending(1)).toMatchObject({ username: "1 Main St, Springfield", update: false, what: "address" })
    // Compared with the identities' values for the fields typed only.
    expect(requests("fill-form")).toEqual([{ type: "fill-form", origin: "https://www.example.com", ref: HOME_REF, fields: ["given-name", "family-name", "address-line1", "city", "postal-code", "country"] }])
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    expect(saveForm()[0]).toMatchObject({ kind: "identity", fields: { "given-name": "Ada", "address-line1": "1 Main St", country: "US" } })
    expect(saveForm()[0].ref).toBeUndefined()

    fake.session = {}
    await checkout({ identity: { "given-name": "Kit", "family-name": "Langton", email: "kit@example.com", "address-line1": "5 Oak Ave", city: "Brooklyn", "postal-code": "11215", country: "US" } })
    expect(saver.pending(1)).toMatchObject({ username: "Home", update: true, what: "address", changes: "address" })
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Address updated" })
    expect(saveForm()[1]).toEqual({ type: "save-form", origin: "https://www.example.com", kind: "identity", ref: HOME_REF, fields: { "address-line1": "5 Oak Ave", "postal-code": "11215" } })

    // Already saved: nothing.
    fake.session = {}
    await checkout({ identity: { ...HOME_VALUES } })
    expect(saver.pending(1)).toBeUndefined()
  })

  test("Never for this site keeps nothing; Not now holds back the same card for a day", async () => {
    fake.local[NEVER_KEY] = ["example.com"]
    await checkout({ card: TYPED })
    expect(saver.pending(1)).toBeUndefined()
    expect(host.requests).toEqual([])
    fake.local[NEVER_KEY] = []
    await checkout({ card: TYPED })
    await saver.choose(1, saver.pending(1)!.id, "later")
    fake.session = { notNow: fake.session.notNow, notNowSalt: fake.session.notNowSalt }
    await checkout({ card: TYPED })
    expect(saver.pending(1)).toBeUndefined()
    // Never from the offer turns the site off.
    await checkout({ card: { ...TYPED, number: "5555555555554444", brand: "Mastercard" } })
    await saver.choose(1, saver.pending(1)!.id, "never")
    expect(fake.local[NEVER_KEY]).toEqual(["example.com"])
  })

  test("a submit that was turned down, or posted back to its page, offers nothing", async () => {
    fake.frames["1:0"] = { ...CHECKOUT, parentFrameId: -1 }
    await saver.formCapture(top(), { card: TYPED, submission: 1 })
    await saver.formOutcome(top(), 1, false)
    await saver.formOutcome(top(), 1, true)
    expect(saver.pending(1)).toBeUndefined()
    // The same page back as a new document, its card fields showing again.
    await saver.formCapture(top(), { card: TYPED, submission: 2 })
    const again = { ...CHECKOUT, documentId: "checkout-doc-2" }
    fake.frames["1:0"] = { ...again, parentFrameId: -1 }
    saver.formFrames = () => [{ tabId: 1, frameId: 0, documentId: again.documentId, origin: SITE, kinds: ["card"], form: 1 }]
    await saver.settled(pageSender({ url: again.url, documentId: again.documentId }))
    await settleTimers()
    expect(saver.pending(1)).toBeUndefined()
    // Another page next: it went through.
    await saver.formCapture(pageSender({ url: again.url, documentId: again.documentId }), { card: TYPED, submission: 1 })
    fake.frames["1:0"] = { url: "https://www.example.com/thanks", documentId: "thanks-doc", parentFrameId: -1 }
    saver.formFrames = () => []
    await saver.settled(pageSender({ url: "https://www.example.com/thanks", documentId: "thanks-doc" }))
    await waitFor(() => saver.pending(1) !== undefined)
    expect(saver.pending(1)?.username).toBe("Visa •••• 5556")
  })

  test("an outcome from another document or for an older submit says nothing", async () => {
    fake.frames["1:0"] = { ...CHECKOUT, parentFrameId: -1 }
    await saver.formCapture(top(), { card: TYPED, submission: 2 })
    await saver.formOutcome(top({ documentId: "other" }), 2, true)
    await saver.formOutcome(top(), 1, true)
    expect(saver.pending(1)).toBeUndefined()
    // Leaving for another site forgets what was typed.
    saver.navigated(1, "https://elsewhere.net/")
    await saver.formOutcome(top(), 2, true)
    expect(host.requests).toEqual([])
  })

  test("a vault that can't save forms gets nothing kept", async () => {
    ;(host.host as { capabilities: string[] }).capabilities = ["list", "fill", "forms"]
    await checkout({ card: TYPED })
    expect(host.requests).toEqual([])
  })

  test("a save waiting on the passphrase ends when the tab closes, and holds nothing after", async () => {
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "save-form") throw new HostError("passphrase_needed", "Enter your passphrase.")
      return send(req)
    }) as typeof host.host.send
    let signal: AbortSignal | undefined
    host.host.reauth = ((_body: unknown, _ask: unknown, s: AbortSignal) => {
      signal = s
      return new Promise((_, reject) => s.addEventListener("abort", () => reject(new HostError("cancelled", "The request was cancelled."))))
    }) as typeof host.host.reauth
    await checkout({ card: TYPED })
    const saving = saver.choose(1, saver.pending(1)!.id, "save")
    await waitFor(() => signal !== undefined)
    expect(signal!.aborted).toBe(false)
    saver.forgetTab(1)
    expect(signal!.aborted).toBe(true)
    expect(await saving).toMatchObject({ ok: false })
    expect(saver.pending(1)).toBeUndefined()
  })

  test("the browser-only vault under Strict asks for the passphrase before saving a card", async () => {
    const asked: unknown[] = []
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "save-form") throw new HostError("passphrase_needed", "Enter your passphrase.")
      return send(req)
    }) as typeof host.host.send
    host.host.reauth = (async (body: unknown, ask: unknown) => {
      asked.push({ body, ask })
      return { type: "save-form", ref: "x", created: true }
    }) as typeof host.host.reauth
    await checkout({ card: TYPED })
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    expect(asked).toEqual([{ body: { type: "save-form", origin: "https://www.example.com", kind: "card", fields: { number: TYPED.number, expiry: TYPED.expiry, cardholder: TYPED.cardholder, brand: "Visa" } }, ask: { tabId: 1, title: "Visa •••• 5556", site: "example.com" } }])
    // Cancelled: nothing saved, and the offer can be answered again.
    host.host.reauth = (async () => {
      throw new HostError("cancelled", "The request was cancelled.")
    }) as typeof host.host.reauth
    fake.session = {}
    await checkout({ card: { ...TYPED, number: "5555555555554444", brand: "Mastercard" } })
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toEqual({ ok: false, message: "Deadbolt didn't get your passphrase. Nothing was saved." })
    expect(saver.pending(1)).toBeDefined()
  })
})

describe("what a form save offers", () => {
  test("a card: by last four digits and brand, with only what changed", () => {
    const visa = { number: "4242424242424242", brand: "Visa" }
    expect(cardPlan({ ...visa, expiry: "2028-08" }, CARDS)).toBeNull()
    expect(cardPlan({ ...visa, cardholder: "KIT  LANGTON" }, CARDS)).toBeNull()
    expect(cardPlan({ ...visa, cardholder: "Kit Lovelace" }, CARDS)).toMatchObject({ ref: VISA_REF, fields: { cardholder: "Kit Lovelace" }, label: "Visa •••• 4242", what: "card", change: "Name on card: Kit Lovelace", match: visa.number })
    // Another brand with the same last four is another card; so is one whose brand isn't known on either side.
    expect(cardPlan({ number: "5105105105104242", brand: "Mastercard" }, CARDS)?.ref).toBeUndefined()
    expect(cardPlan({ number: "4242424242424242" }, CARDS)?.ref).toBeUndefined()
    expect(cardPlan({ ...visa, expiry: "2031-01" }, [{ ...CARDS[0], brand: undefined }])?.ref).toBeUndefined()
    expect(cardPlan({ expiry: "2030-01" }, CARDS)).toBeNull()
    // Only what the user typed changes a card: an expiry the page put there doesn't.
    const typedNumber: Trust = { typed: new Set(["number"]), filled: new Set() }
    expect(cardPlan({ ...visa, expiry: "2031-01" }, CARDS, typedNumber)).toBeNull()
    // A label shows a long brand cut short.
    expect(cardPlan({ number: "4242424242424242", brand: "A".repeat(100) }, [])?.label).toBe(`${"A".repeat(20)} •••• 4242`)
  })

  test("a card's values never include a security code, and a number only as digits", () => {
    expect(cleanCard({ number: "4242424242424242", cvv: "123", pin: "1234", expiry: "2028-08" })).toEqual({ number: "4242424242424242", expiry: "2028-08", brand: "Visa" })
    expect(cleanCard({ number: "4242 4242", expiry: "08/28", cardholder: "Kit" })).toEqual({ cardholder: "Kit" })
    expect(cleanCard({ cvv: "123" })).toBeUndefined()
    // The brand only from the number: never what the page says.
    expect(cleanCard({ number: "4242424242424242", brand: "Mastercard" })?.brand).toBe("Visa")
    expect(cleanCard({ brand: "American Express" })).toBeUndefined()
  })

  test("an identity: one group changed is an update, two is a new identity, too little is nothing", () => {
    const home = { ref: HOME_REF, values: HOME_VALUES }
    expect(identityPlan({ "given-name": "Kit", "family-name": "Langton", email: "kit@example.com", phone: "(415) 555-0199" }, [{ ...home, title: "Home" }])).toMatchObject({ ref: HOME_REF, fields: { phone: "(415) 555-0199" }, label: "Home", what: "details", changes: "phone" })
    // A swapped email the user didn't type is neither compared nor written.
    const trust: Trust = { typed: new Set(["given-name", "family-name", "phone"]), filled: new Set() }
    expect(identityPlan({ "given-name": "Kit", "family-name": "Langton", email: "evil@example.net", phone: "(415) 555-0199" }, [home], trust)).toMatchObject({ ref: HOME_REF, fields: { phone: "(415) 555-0199" }, changes: "phone" })
    // Values Deadbolt filled from Home are written back to Home only, and only if changed.
    const fromHome: Trust = { typed: new Set(["phone"]), filled: new Set(["given-name", "family-name", "email"]), from: HOME_REF }
    expect(identityPlan({ "given-name": "Kit", "family-name": "Langton", email: "kit@example.com", phone: "(415) 555-0199" }, [home], fromHome)?.fields).toEqual({ phone: "(415) 555-0199" })
    // A phone written another way is the same phone.
    expect(identityPlan({ "given-name": "Kit", "family-name": "Langton", email: "kit@example.com", phone: "(415) 555-0123" }, [home])).toBeNull()
    expect(identityPlan({ "given-name": "Ada", "family-name": "Lovelace", "address-line1": "1 Main St", city: "Springfield" }, [home])?.ref).toBeUndefined()
    expect(identityPlan({ email: "kit@example.com" }, [home])).toBeNull()
    expect(identityPlan({ "given-name": "Kit", email: "kit@example.com" }, [])).toBeNull()
  })
})

/** Lets timers and promises run for a moment. */
const settleTimers = () => Bun.sleep(5)
