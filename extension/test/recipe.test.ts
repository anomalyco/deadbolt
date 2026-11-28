import { afterAll, afterEach, beforeEach, describe, expect, test } from "bun:test"
import { Autofill } from "../src/bg/autofill"
import { Recipes } from "../src/bg/recipes"
import { scanPage } from "../src/content/detect"
import { scanGraph } from "../src/content/graph"
import { applySiteRecipes, buildSiteRecipe, MAX_RECIPE_BYTES, parseRecipe, pathMatches, pathPattern } from "../src/content/recipe"
import type { RequestBody } from "../src/protocol"
import { ACCOUNTS, fakeHost, installChrome, menuSender, pageSender, SITE, type FakeChrome, type FakeHost } from "./chrome"

// happy-dom doesn't read -webkit-text-security: a box with data-masked masks its text as a page's CSS would.
const realStyle = globalThis.getComputedStyle
globalThis.getComputedStyle = ((el: Element, pseudo?: string | null) => {
  const s = realStyle(el, pseudo)
  if (!el.hasAttribute?.("data-masked")) return s
  return new Proxy(s, {
    get(t, k) {
      if (k === "getPropertyValue") return (n: string) => (n === "-webkit-text-security" ? "disc" : t.getPropertyValue(n))
      const v = Reflect.get(t, k)
      return typeof v === "function" ? v.bind(t) : v
    },
  })
}) as typeof getComputedStyle
afterAll(() => void (globalThis.getComputedStyle = realStyle))

const ORIGIN = "https://portal.bank.example"
const PATH = "/banking/40213/signon"
/** A credit union's sign-in the scan passes over: one box, labelled by a span, a link for a button. */
const PORTAL = '<div class="box"><div>Member no.</div><input type="text" name="txt1" id="m"><a id="go">Continue</a></div>'
/** Its two-box form, the code masked by CSS. */
const PAIR = '<div class="box"><span>Member no.</span><input type="text" name="txt1"><span>Access code</span><input type="text" name="txt2" data-masked><a>Go</a></div>'

const page = (html: string) => void (document.body.innerHTML = html)
const input = (sel: string) => document.querySelector(sel) as HTMLInputElement

afterEach(() => void (document.body.innerHTML = ""))

/** What the user had filled by hand there: the fields ⌘⇧L made (content/manual.ts), as recipe fields. */
function teach(html: string, fields: Array<[string, "username" | "password"]>, values: string[] = []) {
  page(html)
  fields.forEach(([sel], i) => values[i] !== undefined && (input(sel).value = values[i]))
  const graph = scanGraph()
  const els = fields.map(([sel, role]) => ({ el: input(sel), role }))
  return buildSiteRecipe(ORIGIN, PATH, graph.clusterOf(els[0].el)!, els)
}

describe("learned forms", () => {
  test("a login the scan misses teaches a small recipe without values, which finds it on the next visit", () => {
    page(PORTAL)
    expect(scanPage(scanGraph()).kind).toBeNull()
    const recipe = teach(PORTAL, [["#m", "username"]], ["4411-2093"])!
    expect(new TextEncoder().encode(recipe).length).toBeLessThan(MAX_RECIPE_BYTES)
    expect(recipe).not.toContain("4411")
    expect(JSON.parse(recipe)).toEqual({ v: 1, origin: ORIGIN, pathPattern: "/banking/*/signon", clusterFingerprint: expect.stringMatching(/^[0-9a-f]{8}$/), slots: [{ role: "username", id: "m", name: "txt1", nthInput: 0 }] })
    // Visit 2: a fresh page, another account number in the path.
    page(PORTAL)
    const found = applySiteRecipes(scanGraph(), ORIGIN, "/banking/77001/signon", [recipe])
    expect(found).toEqual({ fields: [{ el: input("#m"), role: "username" }], stale: false })
  })

  test("a masked pair finds both boxes, and the password only goes into the box that masks it", () => {
    const recipe = teach(PAIR, [["[name=txt1]", "username"], ["[name=txt2]", "password"]], ["alex", "hunter22"])!
    for (const value of ["alex", "hunter22"]) expect(recipe).not.toContain(value)
    page(PAIR)
    expect(applySiteRecipes(scanGraph(), ORIGIN, PATH, [recipe]).fields.map((f) => [f.el.name, f.role])).toEqual([["txt1", "username"], ["txt2", "password"]])
    // The page stopped masking it, same shape otherwise: no field at all, not a password in plain text.
    page(PAIR.replace(" data-masked", ""))
    expect(applySiteRecipes(scanGraph(), ORIGIN, PATH, [recipe])).toEqual({ fields: [], stale: true })
  })

  test("a form that changed shape is stale and nothing of it is used", () => {
    const recipe = teach(PAIR, [["[name=txt1]", "username"], ["[name=txt2]", "password"]])!
    for (const changed of [
      PAIR.replace("<a>Go</a>", '<input type="text" name="captcha"><a>Go</a>'),
      PAIR.replace('type="text" name="txt1"', 'type="email" name="txt1"'),
      PAIR.replace('name="txt1"', 'name="txt1" maxlength="12"'),
    ]) {
      page(changed)
      expect(applySiteRecipes(scanGraph(), ORIGIN, PATH, [recipe])).toEqual({ fields: [], stale: true })
    }
    // Renamed in place: the shape matches, the field doesn't.
    page(PAIR.replace('name="txt1"', 'name="user"'))
    expect(applySiteRecipes(scanGraph(), ORIGIN, PATH, [recipe])).toEqual({ fields: [], stale: true })
  })

  test("a disabled, read-only, concealed or opted-out box resolves nothing", () => {
    const recipe = teach(PAIR, [["[name=txt1]", "username"], ["[name=txt2]", "password"]])!
    for (const attr of ["disabled", "readonly", 'aria-hidden="true" tabindex="-1"', "data-1p-ignore"]) {
      page(PAIR.replace('name="txt2"', `name="txt2" ${attr}`))
      const found = applySiteRecipes(scanGraph(), ORIGIN, PATH, [recipe])
      expect(found.fields, attr).toEqual([])
    }
  })

  test("only the exact origin and path it was taught on", () => {
    const recipe = teach(PORTAL, [["#m", "username"]])!
    page(PORTAL)
    const graph = scanGraph()
    for (const origin of ["https://bank.example", "https://portal.bank.example:8443", "http://portal.bank.example", "https://evil.example"])
      expect(applySiteRecipes(graph, origin, PATH, [recipe]), origin).toEqual({ fields: [], stale: false })
    for (const path of ["/banking/signon", "/banking/40213/signon/extra", "/other/40213/signon"]) expect(applySiteRecipes(graph, ORIGIN, path, [recipe]).fields).toEqual([])
    // A recipe naming another origin is never used here, whatever it says.
    const evil = recipe.replace(ORIGIN, "https://evil.example")
    expect(applySiteRecipes(graph, "https://evil.example", PATH, [evil]).fields).toHaveLength(1)
    expect(applySiteRecipes(graph, ORIGIN, PATH, [evil]).fields).toEqual([])
  })

  test("paths keep their words and lose their ids; recipes that don't read are skipped", () => {
    expect(pathPattern("/u/7f3a9c21e0/login")).toBe("/u/*/login")
    expect(pathPattern("/login")).toBe("/login")
    expect(pathPattern(`/${"a".repeat(200)}`)).toBeNull()
    expect(pathMatches("/u/*/login", "/u/abc/login")).toBe(true)
    expect(pathMatches("/u/*/login", "/u//login")).toBe(false)
    expect(parseRecipe("{")).toBeNull()
    expect(parseRecipe(JSON.stringify({ v: 2, origin: ORIGIN, pathPattern: "/", clusterFingerprint: "aa", slots: [{ role: "username", nthInput: 0 }] }))).toBeNull()
    expect(parseRecipe(JSON.stringify({ v: 1, origin: ORIGIN, pathPattern: "/", clusterFingerprint: "aa", slots: [{ role: "cvv", nthInput: 0 }] }))).toBeNull()
    expect(parseRecipe("x".repeat(MAX_RECIPE_BYTES + 1))).toBeNull()
  })

  test("a recipe too big with its attributes keeps only the fields' places", () => {
    const long = "n".repeat(64)
    const html = [0, 1, 2, 3].map((i) => `<input type="text" id="${long}${i}".slice(0, 64) name="${long}" autocomplete="${long}">`).join("")
    page(`<div>${html}</div>`)
    const graph = scanGraph()
    const els = Array.from(document.querySelectorAll("input")).map((el) => ({ el, role: "otp" as const }))
    const recipe = buildSiteRecipe(ORIGIN, PATH, graph.clusterOf(els[0].el)!, els)!
    expect(new TextEncoder().encode(recipe).length).toBeLessThanOrEqual(MAX_RECIPE_BYTES)
    expect(applySiteRecipes(graph, ORIGIN, PATH, [recipe]).fields).toHaveLength(4)
  })
})

describe("teaching and resetting a form (bg/recipes.ts)", () => {
  let fake: FakeChrome
  let host: FakeHost
  let autofill: Autofill
  let recipes: Recipes
  const saved = () => host.requests.filter((r): r is Extract<RequestBody, { type: "save-recipe" }> => r.type === "save-recipe")
  let stored: string | undefined

  beforeEach(() => {
    fake = installChrome()
    host = fakeHost()
    host.host.capabilities.push("site-recipe")
    stored = undefined
    const send = host.host.send.bind(host.host)
    // The daemon's side: the login keeps the recipe, and lists it back.
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "save-recipe") {
        host.requests.push(req)
        stored = req.recipe
        return { type: "save-recipe" }
      }
      if (req.type === "list") {
        host.requests.push(req)
        return { type: "list", site: "example.com", accounts: ACCOUNTS.map((a, i) => (i === 0 && stored ? { ...a, recipe: stored } : a)) }
      }
      return send(req as never)
    }) as typeof host.host.send
    autofill = new Autofill(host.host)
    recipes = new Recipes(host.host, (origin, fresh) => autofill.list(origin, fresh))
    autofill.taught = (target, ref, form) => void recipes.filled(target, ref, form)
  })

  const recipeFor = (origin = SITE) => JSON.stringify({ v: 1, origin, pathPattern: "/login", clusterFingerprint: "3dc018f4", slots: [{ role: "username", name: "txt1", nthInput: 0 }] })

  test("a hand fill teaches the form to the login picked, which lists it for the page; reset forgets it", async () => {
    expect(await recipes.forFrame(pageSender())).toEqual([])
    // ⌘⇧L on a field the scan passed over: the content script's recipe for it, then the user picks a login.
    await recipes.learned(pageSender(), recipeFor(), 4)
    expect(saved()).toEqual([])
    const { token } = await autofill.query(pageSender(), ["username"], "username", 4, true, undefined, true, null, undefined, undefined, undefined, undefined, true)
    // Its footer says the pick teaches the form.
    expect(await autofill.menuLoad(token!, menuSender(), SITE)).toMatchObject({ kind: "accounts", teach: true })
    expect(await autofill.menuPick(token!, ACCOUNTS[0].ref, menuSender())).toMatchObject({ ok: true })
    await new Promise((r) => setTimeout(r, 0))
    expect(saved()).toEqual([{ type: "save-recipe", origin: SITE, ref: ACCOUNTS[0].ref, recipe: recipeFor() }])
    // The daemon says its items changed (the cached lists go), and the next visit asks for its recipes: that one.
    host.setStatus({ state: "ready", version: "0.0.0" })
    expect(await recipes.forFrame(pageSender())).toEqual([recipeFor()])
    // "Reset learned form": the login forgets it, and the page is told.
    expect(await recipes.reset(1)).toBe(true)
    expect(saved().at(-1)).toEqual({ type: "save-recipe", origin: SITE, ref: ACCOUNTS[0].ref })
    expect(fake.delivered.filter((d) => d.message.type === "db:recipes-set").map((d) => d.message.recipes)).toEqual([[]])
    host.setStatus({ state: "ready", version: "0.0.0" })
    expect(await recipes.forFrame(pageSender())).toEqual([])
  })

  test("nothing is taught without a hand fill of that form, for another origin, or by a host that keeps no recipes", async () => {
    // A pick with no recipe waiting.
    await recipes.filled({ tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }, ACCOUNTS[0].ref, 1)
    // A recipe for another form snapshot than the one filled.
    await recipes.learned(pageSender(), recipeFor(), 2)
    await recipes.filled({ tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }, ACCOUNTS[0].ref, 3)
    // One that names another origin than the frame's.
    await recipes.learned(pageSender(), recipeFor("https://evil.example"), 5)
    await recipes.filled({ tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }, ACCOUNTS[0].ref, 5)
    expect(saved()).toEqual([])
    host.host.capabilities.splice(host.host.capabilities.indexOf("site-recipe"), 1)
    await recipes.learned(pageSender(), recipeFor(), 6)
    await recipes.filled({ tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }, ACCOUNTS[0].ref, 6)
    expect(saved()).toEqual([])
    expect(await recipes.forFrame(pageSender())).toEqual([])
  })

  test("a menu on a form the scan found doesn't say it teaches", async () => {
    const { token } = await autofill.query(pageSender(), ["username"], "username", 1, true, undefined, false, "login")
    expect(await autofill.menuLoad(token!, menuSender(), SITE)).not.toHaveProperty("teach")
  })

  test("locked, the page hears to ask again later", async () => {
    host.setStatus({ state: "locked" })
    expect(await recipes.forFrame(pageSender())).toBeNull()
  })
})
