import { afterEach, describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { clusterVerdicts, scanPage } from "../src/content/detect"
import { scanGraph } from "../src/content/graph"
import { loginOdds, notLogin } from "../src/content/rationalize"
import { WEIGHTS } from "../src/content/weights.gen"

const here = import.meta.dir
const FILE = join(here, "../src/content/weights.gen.ts")

function page(html: string, path = "/login", title = "") {
  history.replaceState(null, "", path)
  document.title = title
  document.body.innerHTML = html
}
const roles = () => Object.fromEntries(scanPage().fields.map((f) => [f.el.id, f.role]))

afterEach(() => {
  document.body.innerHTML = ""
  document.title = ""
  history.replaceState(null, "", "/login")
})

describe("weights.gen.ts", () => {
  test("is small, and every weight is finite, rounded, over the pruning floor and seen on two train clusters", () => {
    expect(readFileSync(FILE).length).toBeLessThan(20 * 1024)
    expect(Number.isFinite(WEIGHTS.bias)).toBe(true)
    expect(Number.isFinite(WEIGHTS.threshold)).toBe(true)
    const entries = Object.entries(WEIGHTS.features)
    expect(entries.length).toBeGreaterThan(0)
    for (const [, [weight, support]] of entries) {
      expect(Number.isFinite(weight)).toBe(true)
      expect(Math.abs(weight)).toBeGreaterThanOrEqual(0.05)
      expect(Math.abs(weight)).toBeLessThan(10)
      expect(Math.round(weight * 100) / 100).toBe(weight)
      expect(Number.isInteger(support) && support >= 2).toBe(true)
    }
  })

  test("names facts of a form, never a site: no feature is a corpus site's name", () => {
    const lock = JSON.parse(readFileSync(join(here, "../corpus/frozen.lock.json"), "utf8")) as { pages: Array<{ url: string }> }
    const GENERIC = new Set(["www", "com", "org", "net", "example", "login", "signin", "secure", "account", "accounts", "app", "id", "auth"])
    const sites = new Set(lock.pages.flatMap((p) => new URL(p.url).hostname.split(/[.-]/)).filter((part) => part.length >= 3 && !GENERIC.has(part)))
    for (const feature of Object.keys(WEIGHTS.features)) {
      expect(feature).toMatch(/^(role|shape|autocomplete|controls|unclaimed|words|button|path|title|signal|page):[a-z0-9+-]+$/)
      expect(sites.has(feature.split(":")[1])).toBe(false)
    }
  })

  test("is what the trainer writes from the corpus", () => {
    const run = Bun.spawnSync(["bun", join(here, "../corpus/train-weights.ts"), "--check"], { cwd: join(here, "..") })
    expect(run.stdout.toString()).toContain("weights.gen.ts: up to date")
    expect(run.exitCode).toBe(0)
  }, 30_000)

  test("scores a 20-field page in well under 0.2 ms", () => {
    const rows = Array.from({ length: 18 }, (_, i) => `<label for="f${i}">Field ${i}</label><input id="f${i}" name="f${i}">`).join("")
    page(`<form><label for="u">Email</label><input id="u" type="email" autocomplete="username"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password">${rows}<button type="submit">Sign in</button></form>`)
    const verdicts = clusterVerdicts(scanGraph())
    expect(verdicts.length).toBe(1)
    const runs = 2000
    const start = performance.now()
    let odds = 0
    for (let i = 0; i < runs; i++) for (const v of verdicts) odds += loginOdds(v.features)
    const perPage = (performance.now() - start) / runs
    expect(Number.isFinite(odds)).toBe(true)
    expect(perPage).toBeLessThan(0.2)
  })
})

describe("the cluster model", () => {
  test.each([
    ["de", "/anmelden", "Anmelden", `<h1>Anmelden</h1><form><label for="u">Benutzername</label><input id="u"><label for="p">Kennwort</label><input id="p" type="password"><button type="submit">Einloggen</button></form>`],
    ["fr", "/connexion", "Connexion", `<h1>Connexion</h1><form><label for="u">Adresse e-mail</label><input id="u" type="email"><label for="p">Mot de passe</label><input id="p" type="password"><button type="submit">Se connecter</button></form>`],
    ["es", "/acceso", "Acceso clientes", `<h1>Iniciar sesión</h1><form><label for="u">Usuario</label><input id="u"><label for="p">Contraseña</label><input id="p" type="password"><button type="submit">Ingresar</button></form>`],
    ["ja", "/member/login", "会員ログイン", `<h1>ログイン</h1><form><label for="u">メールアドレス</label><input id="u"><label for="p">パスワード</label><input id="p" type="password"><button type="submit">ログイン</button></form>`],
  ])("keeps a %s sign-in", (_, path, title, html) => {
    page(html, path, title)
    expect(scanPage().kind).toBe("login")
    expect(roles().p).toBe("password")
    for (const v of clusterVerdicts()) expect(notLogin(v.odds)).toBe(false)
  })

  test.each([
    ["a masked SSN on a payroll form", "/employee/w4", "Withholding – Payroll", `<h1>Federal withholding</h1><form><label for="ssn">Social Security number</label><input id="ssn" type="password" maxlength="11"><label for="dep">Dependents</label><input id="dep" type="number"><label for="st">Filing status</label><select id="st"><option>Single</option></select><button type="submit">Save</button></form>`],
    ["an environment variable's key and masked value", "/project/settings/env", "Environment", `<h1>Environment variables</h1><form><label for="k">Name</label><input id="k"><label for="v">Value</label><input id="v" type="password"><button type="submit">Add</button></form>`],
    ["a router's network name and Wi-Fi password", "/admin/wireless", "Router", `<h1>Wireless network</h1><form><label for="n">SSID</label><input id="n"><label for="w">Wi-Fi password</label><input id="w" type="password"><button type="submit">Apply</button></form>`],
    ["a hotel's six-character confirmation code", "/stays/lookup", "Look up a stay", `<h1>Look up your stay</h1><form><label for="c">Confirmation code</label><input id="c" maxlength="6"><label for="l">Last name</label><input id="l"><button type="submit">Look up</button></form>`],
    ["a password strength meter", "/blog/strong-passwords", "Strong passwords", `<article><h1>How strong is yours?</h1><p>Test a password here.</p><input id="t" type="password" aria-label="Password to test"></article>`],
  ])("sets aside %s", (_, path, title, html) => {
    page(html, path, title)
    const result = scanPage()
    expect(result.kind).toBeNull()
    expect(result.fields).toEqual([])
  })
})
