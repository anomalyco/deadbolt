import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { SIGNIN_SETTING } from "../src/auth-state"
import { Passkeys } from "../src/bg/passkeys"
import { ProviderChain, PROVIDER_CHAIN_ACTIONS, PROVIDER_CHAIN_TTL_MS } from "../src/bg/provider-chain"
import { provider, returnsTo } from "../src/signin"
import { SignInWith } from "../src/bg/signinwith"
import type { ProviderReport } from "../src/messages"
import { ACCOUNTS, fakeHost, installChrome, pageSender, SITE, type FakeChrome, type FakeHost } from "./chrome"

const GOOGLE = "https://accounts.google.com"
const home = { tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }
const providerAccount = { ...ACCOUNTS[0], urls: [GOOGLE] }
const linked = { ...ACCOUNTS[1], urls: [SITE], signIn: { provider: "google", account: providerAccount.username } }
let fake: FakeChrome, host: FakeHost, chain: ProviderChain, keys: Passkeys
let report: ProviderReport
let storageChanged: (changes: Record<string, chrome.storage.StorageChange>, area: string) => void
const actions = () => fake.delivered.filter((d) => d.message.type === "db:provider-act")
const fills = () => host.requests.filter((r) => r.type === "fill")

beforeEach(() => {
  fake = installChrome()
  Object.assign(chrome.storage, { onChanged: { addListener: (fn: typeof storageChanged) => { storageChanged = fn } } })
  fake.local[SIGNIN_SETTING] = true
  host = fakeHost()
  const send = host.host.send.bind(host.host)
  host.host.send = (async (req) => req.type === "list" ? { type: "list", site: "google.com", accounts: [providerAccount] } : send(req as never)) as typeof host.host.send
  keys = new Passkeys(host.host)
  chain = new ProviderChain(host.host, keys, new SignInWith(host.host))
  report = { kind: "entry", action: "entry" }
  fake.answer = (m) => m.type === "db:provider-probe" ? report : true
})
afterEach(() => chain.stop(1))

function commit(origin = GOOGLE, documentId = "provider-doc", tabId = 1, path = "/v3/signin/identifier") {
  fake.frames[`${tabId}:0`] = { url: `${origin}${path}`, documentId, parentFrameId: -1 }
  chain.navigated({ tabId, frameId: 0, url: `${origin}${path}`, documentId, transitionType: "link" })
  return pageSender({ tab: { id: tabId } as chrome.tabs.Tab, url: `${origin}${path}`, origin, documentId })
}
async function until(test: () => boolean) {
  for (let i = 0; i < 100 && !test(); i++) await Bun.sleep(1)
  expect(test()).toBe(true)
}

describe("provider chain authority", () => {
  test("setting off and a non-exact saved site do nothing", async () => {
    fake.local[SIGNIN_SETTING] = false
    await chain.start(home, linked)
    fake.local[SIGNIN_SETTING] = true
    await chain.start(home, { ...linked, urls: ["https://example.com"] })
    expect(actions()).toHaveLength(0)
    expect(chain.active(1)).toBe(false)
  })
  test("only the browser's committed provider document receives a credential", async () => {
    await chain.start(home, linked)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    // A sender cannot turn the site's current document into a provider page.
    await chain.check(pageSender({ origin: GOOGLE, url: GOOGLE + "/v3/signin/identifier" }))
    expect(fills()).toHaveLength(0)
    expect(actions()).toHaveLength(1)
  })
  test.each(["https://accounts.google.com.evil.test", "https://login.example.com", "http://accounts.google.com", "https://accounts.google.com:8443"])("unexpected origin %s ends it without disclosure", async (origin) => {
    await chain.start(home, linked)
    const sender = commit(origin)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(sender)
    // A host of the site's own (login.example.com) right after its button is a hop on the way to the provider: passed, never acted on.
    expect(chain.active(1)).toBe(origin === "https://login.example.com")
    expect(fills()).toHaveLength(0)
    expect(actions()).toHaveLength(1)
    expect(fake.delivered.filter((d) => d.message.account)).toHaveLength(0)
  })
  test("an auth hop: only a host of the home's site, right after the provider button, at most twice; its return URLs then count as home", async () => {
    const own = { ...providerAccount, signIn: { provider: "google", account: providerAccount.username! } }
    await chain.start(home, own, true)
    expect(actions()).toHaveLength(1)
    commit("https://sso.example.com", "hop", 1, "/__/auth/handler?apiKey=x")
    expect(chain.active(1)).toBe(true)
    // Google sends the person back to the hop host: an unlinked chain takes that as home now.
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "pwd", 1, `/v3/signin/challenge/pwd?redirect_uri=${encodeURIComponent("https://sso.example.com/__/auth/handler")}`))
    expect(chain.active(1)).toBe(true)
    expect(fills()).toHaveLength(1)
    expect(fake.delivered.filter((d) => d.message.type === "db:provider-probe").at(-1)?.message.home).toEqual(["www.example.com", "sso.example.com"])
    chain.stop(1)
    // Another site's handler (a project's firebaseapp.com) is no hop.
    fake.frames["1:0"] = { url: `${SITE}/login`, documentId: "top-doc", parentFrameId: -1 }
    report = { kind: "entry", action: "entry" }
    await chain.start(home, own, true)
    commit("https://acme-auth.firebaseapp.com", "other-site", 1, "/__/auth/handler?apiKey=x")
    expect(chain.active(1)).toBe(false)
  })
  test("email-first: with no provider button yet, the chain's account goes into the site's email step once, then the button", async () => {
    const sent: Array<[string, number]> = []
    chain.submitIdentifier = async (_, username, form) => (sent.push([username, form]), true)
    report = { kind: "identifier", form: 3, roles: ["email"] }
    await chain.start(home, linked)
    expect(sent).toEqual([[linked.signIn.account!, 3]])
    // The next step, a new document of the site: the provider's button now.
    report = { kind: "entry", action: "entry" }
    fake.frames["1:0"] = { url: `${SITE}/sso`, documentId: "step-2", parentFrameId: -1 }
    chain.navigated({ tabId: 1, frameId: 0, url: `${SITE}/sso`, documentId: "step-2", transitionType: "form_submit" })
    expect(chain.active(1)).toBe(true)
    await chain.check(pageSender({ documentId: "step-2", url: `${SITE}/sso` }))
    expect(actions()).toHaveLength(1)
    // Never twice: an email step again ends it.
    report = { kind: "identifier", form: 4, roles: ["email"] }
    chain.stop(1)
    fake.frames["1:0"] = { url: `${SITE}/login`, documentId: "top-doc", parentFrameId: -1 }
    await chain.start(home, linked)
    fake.frames["1:0"] = { url: `${SITE}/login`, documentId: "step-3", parentFrameId: -1 }
    chain.navigated({ tabId: 1, frameId: 0, url: `${SITE}/login`, documentId: "step-3", transitionType: "form_submit" })
    await chain.check(pageSender({ documentId: "step-3", url: `${SITE}/login` }))
    expect(sent).toHaveLength(2)
    expect(chain.active(1)).toBe(false)
  })
  test("provider iframe reports and unrelated tabs never inherit a pick", async () => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check({ ...sender, frameId: 2 })
    await chain.check({ ...sender, tab: { id: 9 } as chrome.tabs.Tab })
    expect(fills()).toHaveLength(0)
    await chain.check(sender)
    expect(fills()).toHaveLength(1)
    expect(actions().at(-1)?.message.values).toMatchObject({ password: "correct horse" })
  })
  test.each(["consent", "phone", "sms", "security-key", "captcha", "unknown"] as const)("%s stops before asking for values or acting", async (reason) => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "stop", reason }
    await chain.check(sender)
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(1)
    expect(fills()).toHaveLength(0)
  })
  test.each(["cancel", "lock", "setting", "navigate"])("%s revokes a delayed backend reply", async (stop) => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    const release = host.holdFills()
    const pending = chain.check(sender)
    await until(() => fills().length === 1)
    if (stop === "cancel") chain.stop(1)
    if (stop === "lock") host.setStatus({ state: "locked" })
    if (stop === "setting") {
      fake.local[SIGNIN_SETTING] = false
      storageChanged({ [SIGNIN_SETTING]: { newValue: false } }, "local")
    }
    if (stop === "navigate") commit("https://unrelated.test")
    release()
    await pending
    expect(actions()).toHaveLength(1)
    expect(chain.active(1)).toBe(false)
  })
  test("an unlearned code step is left completely untouched", async () => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["otp"], action: "code" }
    await chain.check(sender)
    expect(fills()).toHaveLength(0)
    expect(actions()).toHaveLength(1)
    expect(chain.active(1)).toBe(false)
  })
  test("entry and chooser actions share the eight-action cap", async () => {
    await chain.start(home, linked)
    report = { kind: "chooser", action: "tile" }
    for (let i = 0; i < PROVIDER_CHAIN_ACTIONS; i++) await chain.check(commit(GOOGLE, `chooser-${i}`))
    expect(actions()).toHaveLength(PROVIDER_CHAIN_ACTIONS)
    expect(chain.active(1)).toBe(false)
  })
  test("the original two-minute deadline is not renewed by a step", async () => {
    const now = Date.now()
    await chain.start(home, linked)
    report = { kind: "chooser", action: "tile" }
    const clock = spyOn(Date, "now").mockReturnValue(now + PROVIDER_CHAIN_TTL_MS + 1)
    try { await chain.check(commit()) } finally { clock.mockRestore() }
    expect(actions()).toHaveLength(1)
    expect(chain.active(1)).toBe(false)
  })
  test("only one popup from the opening top document follows the chain", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup", parentFrameId: -1 }
    await chain.opened({ sourceTabId: 1, sourceFrameId: 2, tabId: 2 })
    expect(chain.active(2)).toBe(false)
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
    expect(chain.active(2)).toBe(true)
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 3 })
    expect(chain.active(3)).toBe(false)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "popup", 2))
    expect(fills()).toHaveLength(1)
    expect(actions().at(-1)?.tabId).toBe(2)
  })
  test("an unloading acted document does not revoke the next committed step", async () => {
    await chain.start(home, linked)
    report = { kind: "chooser", action: "tile" }
    const chooser = commit()
    await chain.check(chooser)
    const answer = fake.answer
    fake.answer = (m, doc) => m.type === "db:provider-probe" ? null : answer(m, doc)
    await chain.check(chooser)
    expect(chain.active(1)).toBe(true)
    expect(actions()).toHaveLength(2)
    fake.answer = answer
    report = { kind: "form", form: 2, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "password-doc"))
    expect(fills()).toHaveLength(1)
  })
  // An unlinked chain's provider pages must lead back to its home's exact host.
  const BACK = `/v3/signin/challenge/pwd?redirect_uri=${encodeURIComponent(`${SITE}/oauth/callback`)}`
  const own = { ...providerAccount, signIn: { provider: "google", account: providerAccount.username! } }
  const signedInHome = () => {
    const answer = fake.answer
    fake.answer = (m, doc) => m.type === "db:auth-probe" ? { signOut: true, loginForm: false, uncertain: false, challenge: false } : answer(m, doc)
  }
  const saves = () => host.requests.filter((r) => r.type === "save")
  test.each([false, true])("one of the person's provider accounts: saved at the provider's own host, only that login fills, and the site is linked once signed in (already linked: %s)", async (already) => {
    // Saved for the site, or at a lookalike host, it isn't a provider account.
    await chain.start(home, { ...own, urls: [SITE] }, true)
    await chain.start(home, { ...own, urls: ["https://accounts.google.com.evil.test"] }, true)
    expect(chain.active(1)).toBe(false)
    const other = { ...providerAccount, ref: `${"c".repeat(64)}:${"3".repeat(32)}` }
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req) => req.type === "list"
      ? { type: "list", site: "example.com", accounts: (req as { origin: string }).origin === SITE ? (already ? [{ ...linked, signIn: { provider: "google", account: providerAccount.username } }] : []) : [other, providerAccount] }
      : send(req as never)) as typeof host.host.send
    await chain.start(home, own, true)
    expect(chain.active(1)).toBe(true)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    // Two logins of that username at the provider: only the one picked fills.
    await chain.check(commit(GOOGLE, "provider-doc", 1, BACK))
    expect(fills().map((r) => (r as { ref: string }).ref)).toEqual([own.ref])
    expect(fake.delivered.filter((d) => d.message.type === "db:provider-probe").at(-1)?.message.home).toEqual(["www.example.com"])
    const sender = commit(SITE, "returned", 1, "/oauth/callback")
    signedInHome()
    await chain.check(sender)
    await until(() => !chain.active(1))
    await Bun.sleep(5)
    expect(saves()).toEqual(already ? [] : [expect.objectContaining({ origin: SITE, entry: { title: "www.example.com", url: SITE, signIn: { provider: "google", account: own.ref } } })])
  })
  test.each(["sign-out before any provider page", "the popup coming back", "the popup closing", "no provider action"])("no link from %s", async (how) => {
    await chain.start(home, own, true)
    signedInHome()
    if (how === "sign-out before any provider page") {
      // The site shows a Sign out right after its button is clicked.
      report = { kind: "success" }
      await chain.check(pageSender())
    } else if (how === "no provider action") {
      commit(GOOGLE, "provider-doc", 1, BACK)
      await chain.check(commit(SITE, "returned", 1, "/oauth/callback"))
    } else {
      fake.frames["2:0"] = { url: GOOGLE + BACK, documentId: "popup", parentFrameId: -1 }
      await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
      report = { kind: "form", form: 1, roles: ["password"], action: "password" }
      await chain.check(commit(GOOGLE, "popup-pwd", 2, BACK))
      expect(fills()).toHaveLength(1)
      if (how === "the popup coming back") await chain.check(commit(SITE, "popup-home", 2, "/oauth/callback"))
      else await chain.closed(2)
    }
    await until(() => !chain.active(1) && !chain.active(2))
    await Bun.sleep(5)
    expect(saves()).toEqual([])
  })
  test.each([["github", "https://gist.github.com", "https://github.com"], ["google", "https://sites.google.com", GOOGLE]])("a %s account never signs in to %s, the provider's own site", async (id, site, at) => {
    await chain.start({ ...home, origin: site }, { ...own, urls: [at], signIn: { provider: id, account: own.username! } }, true)
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(0)
  })
  test("an unlinked chain needs every provider page to lead back to its exact host; a linked one only to its site", async () => {
    for (const [unlinked, path, live] of [
      [true, "/ServiceLogin", false],
      [false, "/ServiceLogin", true],
      [true, `/ServiceLogin?continue=${encodeURIComponent("https://accounts.example.com/cb")}`, false],
      [false, `/ServiceLogin?continue=${encodeURIComponent("https://accounts.example.com/cb")}`, true],
      [true, `/ServiceLogin?continue=${encodeURIComponent(`${SITE}/cb`)}`, true],
    ] as const) {
      fake.frames["1:0"] = { url: `${SITE}/login`, documentId: "top-doc", parentFrameId: -1 }
      await chain.start(home, unlinked ? own : linked, unlinked)
      commit(GOOGLE, "provider-doc", 1, path)
      expect([path, unlinked, chain.active(1)]).toEqual([path, unlinked, live])
      chain.stop(1)
    }
  })
  test("any parameter holding an absolute URL is a return URL, whatever its name or case; OAuth scopes aren't", () => {
    const google = provider("google")
    const at = (q: string) => returnsTo(google, `${GOOGLE}/o/oauth2/v2/auth?${q}`, "example.com")
    for (const q of ["wreply=https://evil.test/cb", "redir=https%3A%2F%2Fevil.test%2F", `Redirect_uri=${encodeURIComponent("https://evil.test/")}`, `RETURN_TO=${encodeURIComponent("https://evil.test/")}`]) expect([q, at(`redirect_uri=${encodeURIComponent(`${SITE}/cb`)}&${q}`)]).toEqual([q, "foreign"])
    expect(at(`scope=${encodeURIComponent("https://www.googleapis.com/auth/userinfo.email")}&redirect_uri=${encodeURIComponent(`${SITE}/cb`)}`)).toBe("home")
    expect(at("scope=openid")).toBe("none")
    // Exact host: another host of the site isn't home for an unlinked chain.
    expect(returnsTo(google, `${GOOGLE}/x?redirect_uri=${encodeURIComponent("https://cdn.example.com/cb")}`, "example.com", ["www.example.com"])).toBe("foreign")
    expect(returnsTo(google, `${GOOGLE}/x?redirect_uri=${encodeURIComponent("https://sso.example.com/cb")}`, "example.com", ["www.example.com", "sso.example.com"])).toBe("home")
  })
  test("an unlinked site's sharing notice waits for the person's own pick, then the chain goes on for the account shown", async () => {
    await chain.start(home, own, true)
    report = { kind: "stop", reason: "choose" }
    const chooser = commit(GOOGLE, "chooser", 1, BACK.replace("/v3/signin/challenge/pwd", "/o/oauth2/v2/auth"))
    await chain.check(chooser)
    expect(chain.active(1)).toBe(true)
    const statuses = fake.delivered.filter((d) => d.message.type === "db:provider-status" && (d.options as { documentId: string }).documentId === "chooser")
    expect(statuses.at(-1)?.message).toMatchObject({ label: "Choose your account", hold: true })
    // Scans of the same chooser ask nothing more.
    const probes = fake.delivered.filter((d) => d.message.type === "db:provider-probe").length
    await chain.check(chooser)
    expect(fake.delivered.filter((d) => d.message.type === "db:provider-probe").length).toBe(probes)
    expect(actions()).toHaveLength(1)
    // The person's tile leads to the password step: it fills.
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "pwd", 1, BACK))
    expect(fills()).toHaveLength(1)
    // An identifier step after their pick ("Use another account") ends it.
    report = { kind: "form", form: 2, roles: ["email"], action: "identifier" }
    await chain.check(commit(GOOGLE, "identifier", 1, BACK.replace("/challenge/pwd", "/identifier")))
    expect(chain.active(1)).toBe(false)
  })
  test("the return document receives a status before the confirmed success", async () => {
    await chain.start(home, linked)
    commit()
    const sender = commit(SITE, "returned")
    const answer = fake.answer
    fake.answer = (m, doc) => m.type === "db:auth-probe" ? { signOut: true, loginForm: false, uncertain: false, challenge: false } : answer(m, doc)
    await chain.check(sender)
    await until(() => fake.delivered.some((d) => d.message.label === "Signed in"))
    const statuses = fake.delivered.filter((d) => d.message.type === "db:provider-status" && (d.options as { documentId: string }).documentId === "returned")
    expect(statuses.map((d) => d.message.done ?? false)).toEqual([false, true])
    expect(chain.active(1)).toBe(false)
  })
  test("unowned WebAuthn calls keep their ordinary authority and behavior", async () => {
    await chain.start(home, linked)
    expect(keys.automaticSession!(home)).toBeUndefined()
    expect(await keys.automatic!(home, [])).toBeUndefined()
    commit()
    const target = { ...home, origin: GOOGLE, documentId: "provider-doc" }
    expect(keys.automaticSession!({ ...target, frameId: 2 })).toBeUndefined()
    expect(keys.automaticSession!({ ...target, documentId: "old" })).toBeUndefined()
    expect(await keys.automatic!({ ...target, frameId: 2 }, [])).toBeUndefined()
    expect(await keys.automatic!(target, [], true)).toBeUndefined()
    expect(chain.active(1)).toBe(true)
    expect(keys.automaticSession!(target)?.aborted).toBe(false)
  })
  test("concurrent popup events reserve only the first target", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup", parentFrameId: -1 }
    fake.frames["3:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup-other", parentFrameId: -1 }
    await Promise.all([
      chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 }),
      chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 3 }),
    ])
    expect(chain.active(2)).toBe(true)
    expect(chain.active(3)).toBe(false)
  })
  test("concurrent passkey calls can consume only one assertion", async () => {
    await chain.start(home, linked)
    commit()
    report = { kind: "passkey", action: "key" }
    const target = { ...home, origin: GOOGLE, documentId: "provider-doc" }
    const passkey = { ref: providerAccount.ref, vault: "Personal", credentialId: "YQ", username: providerAccount.username }
    const choices = await Promise.all([keys.automatic!(target, [passkey]), keys.automatic!(target, [passkey])])
    expect(choices.filter(Boolean)).toHaveLength(1)
    expect(choices.find(Boolean)?.ref).toBe(providerAccount.ref)
    chain.stop(1)
    expect(choices.find(Boolean)?.signal.aborted).toBe(true)
  })
  test("an incoming passkey cannot race a pending password fill", async () => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    const release = host.holdFills()
    const pending = chain.check(sender)
    await until(() => fills().length === 1)
    const choice = await keys.automatic!({ ...home, origin: GOOGLE, documentId: "provider-doc" }, [
      { ref: providerAccount.ref, vault: "Personal", credentialId: "YQ", username: providerAccount.username },
    ])
    release()
    await pending
    expect(choice).toBeNull()
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(1)
  })
  test.each([
    "/security/signinoptions/password",
    "/v3/signin/reauth/pwd",
    "/settings/passkeys",
    "/v3/signin/challenge/pwd?continue=https%3A%2F%2Fmyaccount.google.com%2Fsecurity",
    "/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fevil.test%2Fcb",
    "/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fwww.example.com.evil.test%2Fcb",
    "/v3/signin/identifier?continue=" + encodeURIComponent(GOOGLE + "/signin/oauth?redirect_uri=https://evil.test/cb"),
  ])("a site button pointing at %s ends it untouched", async (path) => {
    await chain.start(home, linked)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    const sender = commit(GOOGLE, "provider-doc", 1, path)
    await chain.check(sender)
    expect(chain.active(1)).toBe(false)
    expect(fills()).toHaveLength(0)
    expect(fake.delivered.filter((d) => d.message.type === "db:provider-probe" && d.message.account)).toHaveLength(0)
  })
  test.each([
    "/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
    "/v3/signin/challenge/pwd?continue=" + encodeURIComponent(GOOGLE + "/signin/oauth?redirect_uri=https://www.example.com/cb"),
  ])("a sign-in page whose return URL leads home, %s, goes on", async (path) => {
    await chain.start(home, linked)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "provider-doc", 1, path))
    expect(fills()).toHaveLength(1)
    expect(fake.delivered.find((d) => d.message.type === "db:provider-probe" && d.message.account)?.message.site).toBe("example.com")
  })
  test("a popup re-navigated off the sign-in path ends it before any value", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup", parentFrameId: -1 }
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
    expect(chain.active(2)).toBe(true)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "settings", 2, "/security/signinoptions/password"))
    expect(chain.active(2)).toBe(false)
    expect(fills()).toHaveLength(0)
  })
  test("a popup that opens straight onto a settings page is never followed", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/settings/security", documentId: "popup", parentFrameId: -1 }
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
    expect(chain.active(1)).toBe(false)
    expect(chain.active(2)).toBe(false)
  })
  test("only a linked pick of a provider with known hosts starts a chain", async () => {
    await chain.start(home, { ...providerAccount, urls: [SITE] })
    expect(chain.active(1)).toBe(false)
    await chain.start(home, { ...linked, signIn: { provider: "okta", account: providerAccount.username } })
    expect(chain.active(1)).toBe(false)
    await chain.start(home, { ...linked, signIn: { provider: "google" } })
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(0)
  })
  test("no state can restore authority after a worker restart", async () => {
    await chain.start(home, linked)
    const restarted = new ProviderChain(host.host, keys, new SignInWith(host.host))
    expect(restarted.active(1)).toBe(false)
    expect(fake.session).toEqual({})
    await restarted.check(commit())
    expect(actions()).toHaveLength(1)
  })
})
