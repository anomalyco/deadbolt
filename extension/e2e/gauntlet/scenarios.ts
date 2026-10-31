// The Gauntlet's e2e scenarios (see site.ts): what Deadbolt should do on
// each page, checked in a real browser against the fake host or the
// standalone vault. Each page is one unit of the table: it passes when every
// check on it does. e2e/run.ts mounts the site under /gauntlet and hands
// these its helpers.
//
// The e2e logins are the fake host's: kit@acme.test ("correct horse", with
// a one-time code) and admin ("hunter2"); the identity "Home" and the card
// "Personal Visa".

import type { BrowserContext, Frame, Page, Worker } from "playwright-core"
import { BACKUP_CODES, EMAIL_CODE, PAGES, SMS_CODE, type Account } from "./site"

export interface GauntletRun {
  context: BrowserContext
  worker: Worker
}

export interface Harness<R extends GauntletRun> {
  /** http://localhost:<port> */
  site: string
  port: number
  launch(options?: { record?: string; scale?: number }): Promise<R>
  close(run: R): Promise<void>
  check(ok: boolean, what: string): boolean
  settled(menu: Frame): Promise<void>
  hostLog(run: R): Promise<Array<Record<string, unknown>>>
  isCode(code: string): boolean
  diagnose(run: R, page: Page, what: string): Promise<void>
  /** Where --video wants recordings, if anywhere. */
  video?: string
}

export const KIT = "kit@acme.test"
export const KIT_PASSWORD = "correct horse"
export const E2E_PIN = "246810"

/** The fake host's logins, as the Gauntlet's accounts. */
export const gauntletAccounts = (totp: string): Account[] => [
  { username: KIT, password: KIT_PASSWORD, totp, aliases: ["kit", "+1 415 555 0123", "40021987"], pin: E2E_PIN, birthday: "1990-07-04" },
  { username: "admin", password: "hunter2" },
]

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** What `fn` gives once it gives something, or null after `timeout`. A wait, not a check: the page's checks say what failed. */
async function wait<T>(_what: string, fn: () => Promise<T | null | undefined | false> | T | null | undefined | false, timeout = 8000): Promise<T | null> {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    const v = await fn()
    if (v) return v
    await sleep(100)
  }
  return null
}

/**
 * Pages that fail on dev until the engine fix named here lands. Their
 * failures are reported, not counted; once one passes, it says so, and its
 * entry goes.
 */
export const PENDING: Record<string, string> = {}
const menuFrame = (page: Page) => page.frames().find((f) => f.url().includes("/menu.html")) ?? null

export function gauntletScenarios<R extends GauntletRun>(h: Harness<R>): { scenarios: Record<string, () => Promise<void>>; cost: Record<string, number> } {
  const g = (slug: string, host = "localhost") => `http://${host}:${h.port}/gauntlet/${slug}`

  interface Ctx {
    run: R
    page: Page
    /** One check of this page. */
    ok(cond: boolean, what: string): boolean
    /** How many vault requests the run had made when this page started. */
    before: number
  }

  /** Waits (at most `timeout`, quietly) for a frame of the page (0: the top) to report a login or forms page at `path`. */
  async function reported(run: R, path: string, frame: "top" | "any" = "top", timeout = 6000) {
    const end = Date.now() + timeout
    while (Date.now() < end) {
      const seen = await run.worker
        .evaluate(({ p, top }) => (globalThis as unknown as { __seen: string[] }).__seen.some((s) => /^db:(forms-)?page@/.test(s) && (!top || /@0:/.test(s)) && s.endsWith(p)), { p: path, top: frame === "top" })
        .catch(() => false)
      if (seen) return true
      await sleep(100)
    }
    return false
  }

  /** The open menu with rows, settled, after clicking `sel` in `target`. */
  async function menuOn(c: Ctx, sel: string, target: Page | Frame = c.page, timeout = 12_000) {
    await target.click(sel)
    const menu = await wait(
      `menu on ${sel}`,
      async () => {
        const f = menuFrame(c.page)
        return f && (await f.locator("button.row").count().catch(() => 0)) > 0 ? f : null
      },
      timeout,
    )
    if (menu) await h.settled(menu)
    return menu
  }

  /** No menu opens on `sel` within a beat (a click, as a person would). */
  async function quietOn(c: Ctx, sel: string, target: Page | Frame = c.page) {
    await target.click(sel)
    await sleep(1500)
    const f = menuFrame(c.page)
    const rows = f ? await f.locator("button.row .title").allTextContents().catch(() => []) : []
    if (f) await c.page.keyboard.press("Escape")
    return rows
  }

  /** Picks the login with `username` from the menu on `sel`, and waits for the pill to settle. */
  async function pick(c: Ctx, sel: string, username = KIT, target: Page | Frame = c.page) {
    const menu = await menuOn(c, sel, target)
    if (!menu) return false
    await menu.locator("button.row", { hasText: username }).first().click()
    const done = await wait(
      `the pick on ${sel} settles`,
      async () => {
        if (await menu.locator(".pill.ok").count().catch(() => 0)) return "ok"
        if (await menu.locator(".pill.failed").count().catch(() => 0)) return "failed"
        return !menuFrame(c.page) ? "gone" : null
      },
      12_000,
    )
    if (done !== "ok") console.log(`  the pick on ${sel} ended ${done}: ${(await menu.locator(".pill .pill-label").getAttribute("title").catch(() => "")) ?? ""}`)
    await wait("the pill goes", () => !menuFrame(c.page), 8000)
    return done === "ok"
  }

  /** Picks the row titled `title` from the forms menu on `sel` (an identity or card). */
  async function pickForm(c: Ctx, sel: string, title: string) {
    const menu = await menuOn(c, sel)
    if (!menu) return false
    await menu.locator("button.row", { hasText: title }).first().click()
    const done = await wait(
      `the form pick on ${sel} settles`,
      async () => ((await menu.locator(".pill.ok").count().catch(() => 0)) ? "ok" : (await menu.locator(".pill.failed").count().catch(() => 0)) ? "failed" : null),
      15_000,
    )
    await wait("the pill goes", () => !menuFrame(c.page), 8000)
    return done === "ok"
  }

  /** Types into `sel` by hand, as a person would: the menu that opens on the click is put away first. */
  async function typeInto(c: Ctx, sel: string, text: string) {
    await c.page.click(sel)
    const end = Date.now() + 4000
    while (Date.now() < end && !menuFrame(c.page)) await sleep(100)
    if (menuFrame(c.page)) {
      await c.page.keyboard.press("Escape")
      await wait("esc closes the menu", () => !menuFrame(c.page), 4000)
    }
    await c.page.locator(sel).pressSequentially(text)
  }

  const value = (target: Page | Frame, sel: string) => target.inputValue(sel, { timeout: 2000 }).catch(() => "")
  const filledWith = (target: Page | Frame, sel: string, want: string, timeout = 8000) => wait(`${sel} fills`, async () => (await value(target, sel)) === want, timeout).then(Boolean)
  /** The signed-in page: who it says. */
  const signedInAs = async (target: Page | Frame, timeout = 10_000) =>
    (await wait("the page says Signed in", async () => (await target.locator("#result[data-ok]").count().catch(() => 0)) > 0, timeout))
      ? ((await target.locator("#who").textContent().catch(() => "")) ?? "")
      : ""
  /** The fills this page asked the vault for. */
  const fills = async (c: Ctx) => (await h.hostLog(c.run)).slice(c.before).filter((r) => r.type === "fill")
  const codesAsked = async (c: Ctx) => (await fills(c)).filter((r) => (r.want as string[]).includes("totp")).length

  /** A two-step page's first step, picked and submitted. */
  async function passwordStep(c: Ctx, slug: string) {
    await c.page.goto(g(slug))
    await reported(c.run, `/gauntlet/${slug}`)
    c.ok(await pick(c, "#username"), "the menu fills the sign-in")
    c.ok((await value(c.page, "#password")) === KIT_PASSWORD, "with the password")
    await c.page.click("#submit")
  }

  /** A plain login on `slug` (top page): the menu fills both boxes, and submitting signs in. */
  async function plainLogin(c: Ctx, slug: string, o: { user?: string; pass?: string; host?: string; before?: () => Promise<void> } = {}) {
    const user = o.user ?? "#username"
    const pass = o.pass ?? "#password"
    await c.page.goto(g(slug, o.host))
    await o.before?.()
    await reported(c.run, `/gauntlet/${slug}`)
    c.ok(await pick(c, user), `picking a login on ${user} fills`)
    c.ok((await value(c.page, user)) === KIT, `${user} gets the username (${await value(c.page, user)})`)
    c.ok((await value(c.page, pass)) === KIT_PASSWORD, `${pass} gets the password`)
    await c.page.click("#submit")
    c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
  }

  const tests: Record<string, (c: Ctx) => Promise<void>> = {
    // ---- Sign-in ----
    basic: (c) => plainLogin(c, "basic"),
    "identifier-first": async (c) => {
      await c.page.goto(g("identifier-first"))
      await reported(c.run, "/gauntlet/identifier-first")
      c.ok(await pick(c, "#username"), "the identifier step fills from the menu")
      await c.page.click("#continue")
      await c.page.waitForURL("**/identifier-first/password")
      c.ok(await filledWith(c.page, "#password", KIT_PASSWORD), "the password page fills from the same pick")
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    "remember-device": async (c) => {
      await c.page.goto(g("remember-device"))
      await reported(c.run, "/gauntlet/remember-device")
      c.ok(await pick(c, "#username"), "the identifier step fills")
      await c.page.click("#continue")
      await c.page.waitForURL("**/remember-device/password")
      c.ok(await filledWith(c.page, "#password", KIT_PASSWORD), "the password page fills")
      await c.page.click("#submit")
      await c.page.waitForSelector("#yes")
      c.ok((await quietOn(c, "#trust")).length === 0, "the remember-device choice opens no menu")
      await c.page.click("#yes")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    pin: async (c) => {
      await c.page.goto(g("pin"))
      await reported(c.run, "/gauntlet/pin")
      c.ok(await pick(c, "#username"), "picking a login fills the username")
      const pin = await value(c.page, "#pin")
      c.ok(pin === "", `a 6-digit PIN box doesn't get a password that can't fit it (${pin.length} characters)`)
      await typeInto(c, "#pin", E2E_PIN)
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the PIN typed by hand signs in")
    },
    phone: async (c) => {
      await c.page.goto(g("phone"))
      await reported(c.run, "/gauntlet/phone")
      const rows = await quietOn(c, "#phone")
      c.ok(rows.length === 0, `a phone box offers no login whose username isn't a phone number (${rows.join(", ") || "none"})`)
      c.ok((await value(c.page, "#phone")) === "", "and gets nothing")
      await c.page.locator("#phone").pressSequentially("4155550123")
      await c.page.click("#continue")
      await c.page.waitForURL("**/phone/password")
      await reported(c.run, "/gauntlet/phone/password")
      await c.page.click("#password")
      await sleep(800)
      await c.page.keyboard.press("ArrowDown")
      const menu = await wait("↓ opens the list on the password", async () => {
        const f = menuFrame(c.page)
        return f && (await f.locator("button.row").count().catch(() => 0)) > 0 ? f : null
      })
      if (menu) {
        await h.settled(menu)
        await menu.locator("button.row", { hasText: KIT }).first().click()
      }
      c.ok(await filledWith(c.page, "#password", KIT_PASSWORD), "the password step fills from the list")
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    bank: async (c) => {
      await c.page.goto(g("bank"))
      await reported(c.run, "/gauntlet/bank")
      c.ok(await pick(c, "#customer"), "the menu on the customer number fills")
      c.ok((await value(c.page, "#customer")) === KIT && (await value(c.page, "#password")) === KIT_PASSWORD, "the customer number and password, nothing else")
      const dob = await Promise.all(["#dob-day", "#dob-month", "#dob-year"].map((s) => value(c.page, s)))
      c.ok(dob.every((v) => !v), `the birth date gets no part of the login (${dob.join("/")})`)
      for (const [s, v] of [["#dob-day", "04"], ["#dob-month", "07"], ["#dob-year", "1990"]]) await c.page.fill(s, v)
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    reveal: async (c) => {
      await c.page.goto(g("reveal"))
      await reported(c.run, "/gauntlet/reveal")
      c.ok(await pick(c, "#username"), "the username fills")
      await c.page.waitForSelector("#password", { state: "visible" })
      // The password box wasn't showing at the pick, so the pick can't fill it; its own menu, narrowed to the username, does.
      const menu = await menuOn(c, "#password")
      const rows = menu ? await menu.locator("button.row .sub").allTextContents() : []
      c.ok(rows.length === 1 && rows[0] === KIT, `the revealed password box's menu has just that login (${rows.join(", ")})`)
      if (menu) await menu.locator("button.row").first().click()
      c.ok(await filledWith(c.page, "#password", KIT_PASSWORD), "and fills it")
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },

    // ---- Codes and MFA ----
    totp: async (c) => {
      await passwordStep(c, "totp")
      await c.page.waitForSelector("#code")
      c.ok(!!(await wait("the code fills", async () => h.isCode(await value(c.page, "#code")))), "the authenticator code fills from the same pick")
      await c.page.click("#verify")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    "totp-split": async (c) => {
      await passwordStep(c, "totp-split")
      await c.page.waitForSelector("#d1")
      const digits = async () => (await Promise.all([1, 2, 3, 4, 5, 6].map((i) => value(c.page, `#d${i}`)))).join("")
      c.ok(!!(await wait("the six boxes fill", async () => h.isCode(await digits()))), "the six boxes fill with the code")
      await c.page.click("#verify")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    backup: async (c) => {
      await passwordStep(c, "backup")
      await c.page.waitForSelector("#backup-code")
      await sleep(2500)
      c.ok((await value(c.page, "#backup-code")) === "", "an 8-digit backup code box gets no TOTP")
      c.ok((await quietOn(c, "#backup-code")).length === 0, "and opens no menu")
      await c.page.click("#other-kind")
      await c.page.waitForURL("**/backup/step*")
      await sleep(2000)
      c.ok((await value(c.page, "#backup-code")) === "", "nor does the XXXX-XXXX one")
      await c.page.fill("#backup-code", BACKUP_CODES[1])
      await c.page.click("#verify")
      c.ok((await signedInAs(c.page)) === KIT, "and a backup code typed by hand signs in")
      c.ok((await codesAsked(c)) === 0, "the vault is never asked for a code")
    },
    sms: async (c) => sentCode(c, "sms", SMS_CODE),
    "email-code": async (c) => sentCode(c, "email-code", EMAIL_CODE),
    "mfa-picker": async (c) => {
      await passwordStep(c, "mfa-picker")
      await c.page.waitForSelector("#continue")
      c.ok((await quietOn(c, "#m-sms")).length === 0, "the method picker opens no menu")
      await c.page.click("#m-totp")
      await c.page.click("#continue")
      await c.page.waitForSelector("#code")
      await reported(c.run, "/gauntlet/mfa-picker/choose")
      await sleep(1500)
      let code = await value(c.page, "#code")
      if (!h.isCode(code)) {
        // Not carried through the picker: the code box's own menu fills it.
        const menu = await menuOn(c, "#code")
        if (menu) await menu.locator("button.row", { hasText: KIT }).first().click()
        await wait("the code fills", async () => h.isCode(await value(c.page, "#code")))
        code = await value(c.page, "#code")
      }
      c.ok(h.isCode(code), "after choosing the authenticator, the code fills")
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      await c.page.click("#verify")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    "number-match": async (c) => {
      await passwordStep(c, "number-match")
      await c.page.waitForSelector("#number")
      const before = (await fills(c)).length
      await sleep(1500)
      c.ok(!menuFrame(c.page), "the number-matching page shows no menu")
      c.ok((await signedInAs(c.page, 12_000)) === KIT, "and signs in once the phone approves")
      c.ok((await fills(c)).length === before, "with nothing asked of the vault meanwhile")
    },
    "security-questions": async (c) => {
      await passwordStep(c, "security-questions")
      await c.page.waitForSelector("#q1")
      await sleep(2500)
      c.ok((await value(c.page, "#q1")) === "" && (await value(c.page, "#q2")) === "", "the answers get nothing, not even the password in the masked one")
      const q1 = await quietOn(c, "#q1")
      const q2 = await quietOn(c, "#q2")
      c.ok(!q1.length && !q2.length, `and no menu opens on them (${[...q1, ...q2].join(", ") || "none"})`)
      await c.page.fill("#q1", "Biscuit")
      await c.page.fill("#q2", "maple")
      await c.page.click("#verify")
      c.ok((await signedInAs(c.page)) === KIT, "and the answers typed by hand sign in")
    },
    "magic-link": async (c) => {
      await c.page.goto(g("magic-link"))
      await reported(c.run, "/gauntlet/magic-link")
      c.ok(await pick(c, "#username"), "the email fills from the menu")
      await c.page.click("#continue")
      await c.page.waitForSelector("#magic")
      await sleep(1200)
      c.ok(!menuFrame(c.page), "the check-your-email page shows nothing")
      await c.page.click("#magic")
      c.ok((await signedInAs(c.page)) === KIT, "and the link signs in")
    },
    passkey: async (c) => {
      await c.page.goto(g("passkey"))
      await reported(c.run, "/gauntlet/passkey")
      await c.page.click("#use-password")
      await c.page.waitForSelector("#password", { state: "visible" })
      c.ok(await pick(c, "#username"), "with the password fallback open, the menu fills")
      c.ok((await value(c.page, "#username")) === KIT && (await value(c.page, "#password")) === KIT_PASSWORD, "both boxes")
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },

    // ---- Identity ----
    "dob-selects": async (c) => {
      await c.page.goto(g("dob-selects"))
      c.ok(await pickForm(c, "#first", "Home"), "the identity menu fills")
      const got = await Promise.all(["#first", "#last", "#dob-month", "#dob-day", "#dob-year", "#email"].map((s) => value(c.page, s)))
      c.ok(JSON.stringify(got) === JSON.stringify(["Kit", "Langton", "7", "4", "1990", KIT]), `names, the three birth-date selects and the email (${got.join(" | ")})`)
    },
    "dob-date": async (c) => {
      await c.page.goto(g("dob-date"))
      c.ok(await pickForm(c, "#fullname", "Home"), "the identity menu fills")
      const got = await Promise.all(["#fullname", "#birthday", "#tel"].map((s) => value(c.page, s)))
      c.ok(got[0] === "Kit Langton" && got[1] === "1990-07-04" && got[2].replace(/\D/g, "").endsWith("4155550123"), `full name, the date input and the phone (${got.join(" | ")})`)
    },
    "dob-masked": async (c) => {
      await c.page.goto(g("dob-masked"))
      c.ok(await pickForm(c, "#given", "Home"), "the identity menu fills")
      const got = await Promise.all(["#given", "#middle", "#family", "#dob"].map((s) => value(c.page, s)))
      c.ok(got[0] === "Kit" && got[1] === "" && got[2] === "Langton" && got[3] === "07/04/1990", `first, middle, last and MM/DD/YYYY (${got.join(" | ")})`)
    },
    "address-cascade": async (c) => {
      await c.page.goto(g("address-cascade"))
      c.ok(await pickForm(c, "#name", "Home"), "the identity menu fills")
      await sleep(800)
      const got = await Promise.all(["#name", "#country", "#line1", "#city", "#state", "#zip"].map((s) => value(c.page, s)))
      c.ok(JSON.stringify(got) === JSON.stringify(["Kit Langton", "US", "123 Main St", "Brooklyn", "NY", "11201"]), `the address, with the state picked once the country's states load (${got.join(" | ")})`)
    },

    // ---- Tricky DOM ----
    "shadow-open": (c) => plainLogin(c, "shadow-open"),
    "shadow-closed": async (c) => {
      await c.page.goto(g("shadow-closed"))
      // Playwright can't see into a closed root; the page's own script reports on it.
      await c.page.waitForFunction(() => !!(window as unknown as { __gauntletClosed?: unknown }).__gauntletClosed)
      await reported(c.run, "/gauntlet/shadow-closed")
      const box = await c.page.evaluate(() => (window as unknown as { __gauntletClosed: { rect(id: string): DOMRect } }).__gauntletClosed.rect("username"))
      const closedValue = (id: string) => c.page.evaluate((id) => (window as unknown as { __gauntletClosed: { value(id: string): string } }).__gauntletClosed.value(id), id)
      await c.page.mouse.click(box.x + box.width / 2, box.y + box.height / 2)
      const menu = await wait("menu on the closed root's username", async () => {
        const f = menuFrame(c.page)
        return f && (await f.locator("button.row").count().catch(() => 0)) > 0 ? f : null
      }, 12_000)
      if (menu) {
        await h.settled(menu)
        await menu.locator("button.row", { hasText: KIT }).first().click()
      }
      c.ok(!!(await wait("both fill", async () => (await closedValue("password")) === KIT_PASSWORD)), "the menu fills a form in a closed shadow root")
      c.ok((await closedValue("username")) === KIT, "username too")
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      const submit = await c.page.evaluate(() => (window as unknown as { __gauntletClosed: { rect(id: string): DOMRect } }).__gauntletClosed.rect("submit"))
      await c.page.mouse.click(submit.x + submit.width / 2, submit.y + submit.height / 2)
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    "web-component": async (c) => {
      await c.page.goto(g("web-component"))
      await reported(c.run, "/gauntlet/web-component")
      c.ok(await pick(c, "#user"), "the menu on a custom element's input fills")
      const got = await c.page.evaluate(() => ["user", "pass"].map((id) => (document.getElementById(id) as unknown as { value: string }).value))
      c.ok(got[0] === KIT && got[1] === KIT_PASSWORD, `both custom elements (${got[0]})`)
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    "iframe-same-origin": (c) => framedLogin(c, "iframe-same-origin", "localhost"),
    "iframe-same-site": (c) => framedLogin(c, "iframe-same-site", "www.acme.test"),
    "iframe-cross-site": async (c) => {
      await c.page.goto(g("iframe-cross-site"))
      const frame = await wait("the cross-site frame loads", () => c.page.frames().find((f) => f.url().includes("evilpay.test") && f.url().includes("/frame-login")))
      if (!frame) return void c.ok(false, "the frame loads")
      await frame.waitForSelector("#username")
      await sleep(1500)
      const rows = await quietOn(c, "#username", frame)
      c.ok(rows.length === 0, `a cross-site frame's login gets no menu (${rows.join(", ") || "none"})`)
      await frame.click("#password")
      await c.page.keyboard.press("ArrowDown")
      await sleep(1200)
      c.ok(!menuFrame(c.page), "not even on ↓")
      c.ok((await value(frame, "#username")) === "" && (await value(frame, "#password")) === "", "and nothing is filled")
      c.ok((await fills(c)).length === 0, "nor asked of the vault")
    },
    react: (c) => plainLogin(c, "react"),
    vue: (c) => plainLogin(c, "vue"),
    "clear-on-focus": (c) => plainLogin(c, "clear-on-focus"),
    late: (c) => plainLogin(c, "late", { before: async () => void (await c.page.waitForSelector("#username", { timeout: 6000 })) }),
    rerender: (c) => plainLogin(c, "rerender"),
    spa: async (c) => {
      await c.page.goto(g("spa"))
      await reported(c.run, "/gauntlet/spa")
      c.ok(await pick(c, "#username"), "the first route fills")
      await c.page.click("#continue")
      await c.page.waitForURL("**/spa/password")
      c.ok(await filledWith(c.page, "#password", KIT_PASSWORD), "the password route fills without a page load")
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      await c.page.click("#submit")
      await c.page.waitForURL("**/spa/code")
      c.ok(!!(await wait("the code route fills", async () => h.isCode(await value(c.page, "#code")))), "the code route fills too")
      await c.page.click("#verify")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    dialog: (c) => plainLogin(c, "dialog", { before: async () => void (await c.page.click("#open")) }),
    "many-forms": async (c) => {
      await c.page.goto(g("many-forms"))
      await reported(c.run, "/gauntlet/many-forms")
      const news = await quietOn(c, "#news-email")
      c.ok(!news.some((t) => t.startsWith("Acme")), `the newsletter box offers no logins (${news.join(", ") || "none"})`)
      c.ok((await quietOn(c, "#q")).length === 0, "the search box offers nothing")
      c.ok(await pick(c, "#username"), "the login form fills")
      c.ok((await value(c.page, "#password")) === KIT_PASSWORD, "with the password")
      c.ok((await value(c.page, "#news-email")) === "" && (await value(c.page, "#q")) === "", "and only it")
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    honeypot: async (c) => {
      await c.page.goto(g("honeypot"))
      await reported(c.run, "/gauntlet/honeypot")
      c.ok(await pick(c, "#username"), "the login fills")
      const traps = await Promise.all(["#hp-email", "#hp-login", "#hp-pass2", "#hp-website"].map((s) => value(c.page, s)))
      c.ok(traps.every((v) => !v), `every honeypot stays empty (${traps.join(" | ")})`)
      c.ok((await value(c.page, "#password")) === KIT_PASSWORD, "the real password box fills")
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the site signs in")
    },
    "autocomplete-off": (c) => plainLogin(c, "autocomplete-off", { user: "#user", pass: "#pass" }),
    misleading: (c) => plainLogin(c, "misleading", { user: "#password-field", pass: "#email-field" }),
    "css-masked": (c) => plainLogin(c, "css-masked", { pass: "#secret" }),
    "virtual-keyboard": async (c) => {
      await c.page.goto(g("virtual-keyboard"))
      await reported(c.run, "/gauntlet/virtual-keyboard")
      c.ok(await pick(c, "#username"), "the username fills")
      c.ok((await value(c.page, "#pin")) === "", "the keypad-only PIN box gets nothing")
      for (const d of E2E_PIN) await c.page.click(`#keypad button[data-key="${d}"]`)
      await c.page.click("#submit")
      c.ok((await signedInAs(c.page)) === KIT, "and the PIN tapped on the keypad signs in")
    },
    "no-paste": (c) => plainLogin(c, "no-paste"),
    rules: (c) => plainLogin(c, "rules"),

    // ---- Other flows ----
    signup: async (c) => {
      await c.page.goto(g("signup"))
      await reported(c.run, "/gauntlet/signup")
      await typeInto(c, "#email", "fresh@acme.test")
      const menu = await menuOn(c, "#new-password")
      const title = menu ? await menu.locator("button.row .title").first().textContent() : ""
      c.ok(title === "Use a strong password", `the new password offers the generator (${title})`)
      if (menu) await menu.locator("button.row").first().click()
      const made = await wait("both boxes fill", async () => {
        const v = await value(c.page, "#new-password")
        return v && v === (await value(c.page, "#confirm-password")) ? v : null
      })
      c.ok(!!made && made.length >= 14 && made.length <= 24 && /[a-z]/.test(made) && /[A-Z]/.test(made) && /\d/.test(made) && /[-_!@#]/.test(made) && !/[^A-Za-z0-9\-_!@#]/.test(made), `the generated password keeps the rules (${made?.length} characters)`)
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      await c.page.check("#terms")
      await c.page.click("#submit")
      c.ok(!!(await wait("account created", async () => (await c.page.locator("#result[data-ok]").count()) > 0)), `the site takes it (${(await c.page.locator("#error").textContent().catch(() => "")) ?? ""})`)
    },
    "change-password": async (c) => {
      await c.page.goto(g("change-password"))
      await reported(c.run, "/gauntlet/change-password")
      c.ok(await pick(c, "#current"), "the current password fills from the menu")
      c.ok((await value(c.page, "#current")) === KIT_PASSWORD, "with the saved password")
      c.ok((await value(c.page, "#new")) === "" && (await value(c.page, "#confirm")) === "", "and not into the new boxes")
      const menu = await menuOn(c, "#new")
      const title = menu ? await menu.locator("button.row .title").first().textContent() : ""
      c.ok(title === "Use a strong password", `the new password offers the generator (${title})`)
      if (menu) await menu.locator("button.row").first().click()
      const made = await wait("new and confirm fill", async () => {
        const v = await value(c.page, "#new")
        return v && v === (await value(c.page, "#confirm")) ? v : null
      })
      c.ok(!!made && made.length >= 12, "new and confirm get the same generated password")
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      await c.page.click("#submit")
      c.ok(!!(await wait("password changed", async () => (await c.page.locator("#result[data-ok]").count()) > 0)), `the site takes it (${(await c.page.locator("#error").textContent().catch(() => "")) ?? ""})`)
    },
    reset: async (c) => {
      await c.page.goto(g("reset"))
      await reported(c.run, "/gauntlet/reset")
      await typeInto(c, "#username", KIT)
      await c.page.click("#continue")
      await c.page.click("#reset-link")
      await c.page.waitForURL("**/reset/new*")
      await reported(c.run, "/gauntlet/reset/new")
      const menu = await menuOn(c, "#new-password")
      const title = menu ? await menu.locator("button.row .title").first().textContent() : ""
      c.ok(title === "Use a strong password", `the reset's new password offers the generator (${title})`)
      if (menu) await menu.locator("button.row").first().click()
      const made = await wait("both boxes fill", async () => {
        const v = await value(c.page, "#new-password")
        return v && v === (await value(c.page, "#confirm-password")) ? v : null
      })
      c.ok(!!made, "both boxes get it")
      await wait("the pill goes", () => !menuFrame(c.page), 8000)
      await c.page.click("#submit")
      c.ok(!!(await wait("password reset", async () => (await c.page.locator("#result[data-ok]").count()) > 0)), "the site takes it")
    },
    checkout: async (c) => {
      await c.page.goto(g("checkout"))
      c.ok(await pickForm(c, "#cc-number", "Visa"), "the card menu fills")
      const card = await Promise.all(["#cc-number", "#cc-month", "#cc-year", "#cc-csc", "#cc-name"].map((s) => value(c.page, s)))
      c.ok(card[0].replace(/\D/g, "") === "4242424242424242" && card[1] === "08" && card[2] === "2028" && card[3] === "123" && card[4] === "Kit Langton", `number, expiry selects, code and name (${card.join(" | ")})`)
      c.ok(await pickForm(c, "#bill-line1", "Home"), "the billing address fills from an identity")
      // An address goes only into fields on screen at the pick (docs/autofill.md): the rest, below the fold, take a second pick there.
      const below = await c.page.evaluate(() => document.getElementById("bill-country")!.getBoundingClientRect().top > innerHeight)
      if (below) {
        c.ok((await value(c.page, "#bill-country")) === "", "a field below the fold gets nothing")
        await c.page.locator("#bill-country").scrollIntoViewIfNeeded()
        c.ok(await pickForm(c, "#bill-city", "Home"), "a pick there fills the rest")
      }
      const bill = await Promise.all(["#bill-line1", "#bill-line2", "#bill-city", "#bill-state", "#bill-zip", "#bill-country"].map((s) => value(c.page, s)))
      c.ok(JSON.stringify(bill) === JSON.stringify(["123 Main St", "Apt 4", "Brooklyn", "NY", "11201", "US"]), `the whole billing address (${bill.join(" | ")})`)
      await c.page.click("#submit")
      c.ok(!!(await wait("saved", async () => (await c.page.locator("#result[data-ok]").count()) > 0)), "and the form submits")
    },
  }

  /** A code sent by text or email: never filled from the authenticator, Resend included. */
  async function sentCode(c: Ctx, slug: string, code: string) {
    await passwordStep(c, slug)
    await c.page.waitForSelector("#sent-code")
    await sleep(2500)
    c.ok((await value(c.page, "#code")) === "", "the sent code's box gets no TOTP")
    const rows = await quietOn(c, "#code")
    c.ok(!rows.length, `and opens no menu (${rows.join(", ") || "none"})`)
    await c.page.click("#resend")
    await c.page.waitForSelector("#resent")
    await sleep(2000)
    c.ok((await value(c.page, "#code")) === "", "nor after Resend")
    await c.page.fill("#code", code)
    await c.page.click("#verify")
    c.ok((await signedInAs(c.page)) === KIT, "and the code typed by hand signs in")
    c.ok((await codesAsked(c)) === 0, "the vault is never asked for a code")
  }

  /** A login in a frame of the page's own site: the menu opens on the frame's field and fills only it. */
  async function framedLogin(c: Ctx, slug: string, host: string) {
    await c.page.goto(g(slug, host))
    const frame = await wait("the login frame loads", () => c.page.frames().find((f) => f.url().includes("/gauntlet/frame-login")))
    if (!frame) return void c.ok(false, "the frame loads")
    await frame.waitForSelector("#username")
    await reported(c.run, "/gauntlet/frame-login", "any")
    c.ok(await pick(c, "#username", KIT, frame), "the menu on the frame's field fills")
    c.ok((await value(frame, "#username")) === KIT && (await value(frame, "#password")) === KIT_PASSWORD, "both boxes in the frame")
    await frame.click("#submit")
    c.ok((await signedInAs(frame)) === KIT, "and the frame signs in")
  }

  /** Runs `slugs` in one browser, one tab each, and prints a line per page. */
  async function runPages(all: string[]) {
    // GAUNTLET_PAGES=a,b runs just those pages; GAUNTLET_SHOTS=<dir> keeps a still of each failing page.
    const only = process.env.GAUNTLET_PAGES?.split(",").filter(Boolean)
    const slugs = only ? all.filter((s) => only.includes(s)) : all
    if (!slugs.length) return
    const run = await h.launch(h.video ? { record: h.video, scale: 1 } : {})
    try {
      for (const slug of slugs) {
        const page = await run.context.newPage()
        let fails = 0
        const pending = PENDING[slug]
        const c: Ctx = {
          run,
          page,
          before: (await h.hostLog(run)).length,
          ok: (cond, what) => {
            if (cond || !pending) h.check(cond, `gauntlet ${slug}: ${what}`)
            else console.log(`PEND gauntlet ${slug}: ${what}`)
            if (!cond) fails++
            return cond
          },
        }
        const start = Date.now()
        try {
          await tests[slug](c)
        } catch (err) {
          c.ok(false, `threw: ${(err as Error).message.split("\n")[0]}`)
          await h.diagnose(run, page, slug).catch(() => {})
        } finally {
          if (fails && process.env.GAUNTLET_SHOTS) await page.screenshot({ path: `${process.env.GAUNTLET_SHOTS}/${slug}.png` }).catch(() => {})
          const verdict = fails ? (pending ? `PENDING (${pending})` : "FAIL") : pending ? `PASS (now passes: drop it from PENDING)` : "PASS"
          console.log(`gauntlet-page ${slug} ${verdict} (${((Date.now() - start) / 1000).toFixed(1)} s)`)
          await page.close().catch(() => {})
          // With --video, each page's recording, for slowing down or stills.
          const recorded = h.video ? await page.video()?.path().catch(() => null) : null
          if (recorded) console.log(`gauntlet-video ${slug} ${recorded}`)
        }
      }
    } finally {
      await h.close(run)
    }
  }

  const byGroup = (group: string) => PAGES.filter((p) => p.group === group).map((p) => p.slug)
  const dom = byGroup("Tricky DOM")
  const half = Math.ceil(dom.length / 2)
  const units: Record<string, string[]> = {
    gauntletSignIn: byGroup("Sign-in"),
    gauntletCodes: byGroup("Codes and MFA"),
    gauntletIdentity: byGroup("Identity"),
    gauntletDom: dom.slice(0, half),
    gauntletDom2: dom.slice(half),
    gauntletFlows: byGroup("Other flows"),
  }
  const missing = PAGES.filter((p) => !tests[p.slug]).map((p) => p.slug)
  if (missing.length) throw new Error(`gauntlet pages without a scenario: ${missing.join(", ")}`)
  return {
    scenarios: Object.fromEntries(Object.entries(units).map(([name, slugs]) => [name, () => runPages(slugs)])),
    cost: { gauntletSignIn: 38, gauntletCodes: 80, gauntletIdentity: 19, gauntletDom: 52, gauntletDom2: 50, gauntletFlows: 55 },
  }
}
