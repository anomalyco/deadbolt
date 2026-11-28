// Each pattern a blind audit of crawled live sign-in and decoy pages turned
// up, written small: the detector's fix for it, held in place.
import { afterEach, describe, expect, test } from "bun:test"
import { scoreField, type FieldFacts } from "../src/content/clues"
import { clusterVerdicts, scanPage } from "../src/content/detect"
import { scanForms } from "../src/content/forms"
import { scanGraph } from "../src/content/graph"
import { WEIGHTS } from "../src/content/weights.gen"

function page(html: string, path = "/login", title = "") {
  history.replaceState(null, "", path)
  document.title = title
  document.body.innerHTML = html
}

const byId = (result: ReturnType<typeof scanPage>) => Object.fromEntries(result.fields.map((f) => [f.el.id, f.role]))
const formRoles = () => Object.fromEntries(scanForms().map((f) => [f.el.id, f.role]))
const thin = (id: string, width: number, height: number) => {
  document.getElementById(id)!.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, right: width, bottom: height, width, height, toJSON() {} }) as DOMRect
}

afterEach(() => {
  document.body.innerHTML = ""
  document.title = ""
})

describe("class names", () => {
  test("a utility class that spells a clue inside it (opacity-100: city) costs the field nothing", () => {
    page(`<form>
      <label for="r0">Email</label><input id="r0" class="tw:box-border tw:placeholder:opacity-100 tw:focus:outline-none">
      <label for="r3">Password</label><input id="r3" type="password" class="tw:placeholder:opacity-100">
      <button type="submit">Log in</button></form>`)
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ r0: "email", r3: "password" })
  })

  test("a class that names the field still counts, word by word", () => {
    const facts = (classes: string): FieldFacts => ({ type: "text", autocomplete: [], display: " ", code: "", classes, maxLength: 0, inputMode: "" })
    expect(scoreField(facts(" login email input ")).email).toBeGreaterThan(3)
    expect(scoreField(facts(" opacity 100 ")).username).toBe(0)
  })

  test("phrases that squash to the same id token count once", () => {
    const facts: FieldFacts = { type: "text", autocomplete: [], display: " ", code: "username", maxLength: 0, inputMode: "" }
    // "username" and "user name" both squash to it: one clue, 5 × 0.8.
    expect(scoreField(facts).username).toBeCloseTo(4)
  })
})

describe("newsletters and providers", () => {
  test("SSO links in the main column don't make a footer newsletter box a sign-in", () => {
    page(
      `<main><h1>Welcome back!</h1><a href="https://sso.example/saml/login">Sign in with SSO</a><a href="https://sso.example/auth">Continue with SSO</a></main>
      <footer><form><input id="news" type="email" autocomplete="email" placeholder="Enter your business email now to subscribe!"><button type="submit">Sign up</button></form></footer>`,
      "/login",
      "Login - Example",
    )
    const result = scanPage()
    // No kind: no menu opens and nothing is offered.
    expect(result.kind).toBeNull()
    // The page still shows a provider: a sign-in may be under way.
    expect(result.provider).toBe(true)
  })

  test("a provider button beside a sign-in still counts for it", () => {
    page(`<main><div class="card"><form><label for="e">Email</label><input id="e" type="email"><button>Continue</button></form>
      <button>Continue with Google</button></div></main>`, "/start")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.provider).toBe(true)
  })

  test("a lone newsletter email marked autocomplete=email isn't an identity form", () => {
    page(`<footer><h2>Sign up for Example Emails</h2><form><label for="news">Email address</label><input id="news" type="email" autocomplete="email"><button>Sign up</button></form></footer>`, "/basket")
    expect(scanForms()).toEqual([])
  })

  test("a checkout's email with name and address beside it stays", () => {
    page(`<form><h2>Shipping</h2><input id="em" autocomplete="email"><input id="gn" autocomplete="given-name"><input id="a1" autocomplete="address-line1"></form>`, "/checkout")
    expect(formRoles()).toEqual({ em: "email", gn: "given-name", a1: "address-line1" })
  })

  test("a guest checkout's lone email marked autocomplete stays", () => {
    page(`<form><h2>Guest checkout</h2><label for="em">Email for your receipt</label><input id="em" type="email" autocomplete="email"><button>Continue</button></form>`, "/checkout")
    expect(formRoles()).toEqual({ em: "email" })
  })
})

describe("party games", () => {
  test("a room code and a player name are no code step and no sign-in", () => {
    page(`<form><label for="roomcode">Room code</label><input id="roomcode" maxlength="4" placeholder="ENTER 4-LETTER CODE">
      <label for="username">Name</label><input id="username" maxlength="12" placeholder="ENTER YOUR NAME"><button type="submit">Play</button></form>`, "/")
    const result = scanPage()
    expect(result.kind).toBeNull()
    expect(byId(result)).toEqual({})
  })
})

describe("hidden by an ancestor", () => {
  test("a step-two password in a faded-out wrapper isn't scanned", () => {
    page(`<form><label for="email">Email address</label><input id="email" type="email" autocomplete="email">
      <div style="opacity:0"><label for="password">Password</label><input id="password" type="password" autocomplete="current-password"></div>
      <button type="submit">Continue</button></form>`)
    expect(scanGraph().controls.map((c) => c.id)).toEqual(["email"])
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ email: "email" })
  })

  test("a honeypot password in a one-pixel clipping wrapper isn't scanned", () => {
    page(`<form><input id="user" autocomplete="username"><input id="pass" type="password" autocomplete="current-password">
      <div id="hp" style="overflow:hidden"><input id="hp-pass2" type="password"></div><button>Log in</button></form>`)
    thin("hp", 240, 1)
    expect(scanGraph().controls.map((c) => c.id)).toEqual(["user", "pass"])
    expect(byId(scanPage())).toEqual({ user: "username", pass: "password" })
  })

  test("a box fixed to the viewport escapes a thin wrapper's clip", () => {
    page(`<div id="bar" style="overflow:hidden"><form><input id="e" type="email" style="position:fixed"><button>Continue</button></form></div>`)
    thin("bar", 240, 0)
    expect(scanGraph().controls.map((c) => c.id)).toEqual(["e"])
  })
})

describe("sign-in or sign-up", () => {
  test("a Taiwanese bank's national ID, masked user ID and password are a sign-in", () => {
    page(`<form><label for="CustID">身分證字號</label><input id="CustID" maxlength="10">
      <label for="UserIdKeyin">使用者代號</label><input id="UserIdKeyin" type="password" maxlength="12" placeholder="請輸入6至12位用戶代號英數混合">
      <label for="PasswordKeyin">網銀密碼</label><input id="PasswordKeyin" type="password" maxlength="16">
      <button type="submit">登入</button></form>`, "/MyBank")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ CustID: "username", PasswordKeyin: "password" })
  })

  test("two password boxes under sign-in wording aren't a sign-up", () => {
    page(`<h1>Log in</h1><form><input id="u" name="username"><input id="p" type="password" name="password"><input id="pin" type="password" name="secondPassword"><button>Log in</button></form>`)
    expect(scanPage().kind).toBe("login")
  })

  test("one Create a password box beside a birthday is a sign-up, whatever the header's Log in link says", () => {
    page(`<header><a href="/login">Log in</a></header><form><label for="email">Email</label><input id="email" type="email" autocomplete="email">
      <label for="password">Password</label><input id="password" type="password" autocomplete="new-password" placeholder="Create a password">
      <input id="birthdate" type="date" autocomplete="bday"><button type="submit">Continue</button></form>`, "/")
    const result = scanPage()
    expect(result.kind).toBe("signup")
    expect(byId(result)).toEqual({ email: "email", password: "new-password" })
  })

  test("a login box with autocomplete=new-password (to block autofill) is still a sign-in", () => {
    page(`<h1>Sign in</h1><form><input id="u" autocomplete="username"><input id="p" type="password" autocomplete="new-password"><button>Sign in</button></form>`)
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ u: "username", p: "password" })
  })
})

describe("roles with no reason in their form", () => {
  test("a texted code's Verification code isn't a card's security code", () => {
    page(`<form><h1>Enter the code we texted you</h1><label for="sms">Verification code</label><input id="sms" maxlength="6"><button>Verify</button></form>`, "/verify")
    expect(scanForms()).toEqual([])
  })

  test("a share link's Link expires isn't a card's expiry", () => {
    page(`<form><h2>Protect this link</h2><label for="pw">Password</label><input id="pw" type="password"><label for="expires">Link expires</label><input id="expires"><button>Save</button></form>`, "/share")
    expect(scanForms()).toEqual([])
  })

  test("an SSO form's Data region isn't an address", () => {
    page(`<form><label for="ws">Workspace URL</label><input id="ws"><label for="region">Data region</label><select id="region"><option>US</option><option>EU</option></select>
      <label for="em">Work email</label><input id="em" type="email" autocomplete="email"><button>Continue</button></form>`, "/sso/start")
    expect(scanForms().map((f) => f.role)).not.toContain("address-level1")
  })

  test("a security code beside a card number stays a card's", () => {
    page(`<form><label for="n">Card number</label><input id="n"><label for="c">Security code</label><input id="c" maxlength="4"></form>`, "/pay")
    expect(formRoles()).toEqual({ n: "cc-number", c: "cc-csc" })
  })

  test("a state beside a street address stays an address", () => {
    page(`<form><label for="s">Street address</label><input id="s"><label for="st">State</label><input id="st"></form>`, "/checkout")
    expect(formRoles()).toEqual({ s: "address-line1", st: "address-level1" })
  })
})

describe("controls", () => {
  test("a page of long product cards and no login fields still finds a provider button", () => {
    const cards = Array.from({ length: 30 }, (_, i) => `<a href="/p/${i}">Cordless drill driver kit ${i} with two batteries, a charger, a carry case and a set of twenty-four bits for wood, metal and masonry</a>`).join("")
    page(`<main>${cards}<button>Continue with Google</button></main>`, "/")
    const result = scanPage()
    expect(result.kind).toBeNull()
    expect(result.provider).toBe(true)
  })
})

describe("card and identity fields in context", () => {
  const setURL = (url: string) => (window as unknown as { happyDOM: { setURL(u: string): void } }).happyDOM.setURL(url)
  // This window as a frame: its own top's descriptor, wherever happy-dom keeps it, put back after.
  const owner = (() => {
    for (let o: object | null = window; o; o = Object.getPrototypeOf(o)) if (Object.getOwnPropertyDescriptor(o, "top")) return o
    return window
  })()
  const topDescriptor = Object.getOwnPropertyDescriptor(owner, "top")
  afterEach(() => {
    delete (window as { top?: unknown }).top
    if (owner === window && topDescriptor) Object.defineProperty(window, "top", topDescriptor)
    setURL("https://example.com/login")
  })

  test("a payment provider's frame keeps its one security code or expiry box", () => {
    Object.defineProperty(window, "top", { configurable: true, get: () => ({}) })
    setURL("https://js.stripe.com/v3/elements-inner-cvc.html")
    document.body.innerHTML = `<form><label for="sc">Security code</label><input id="sc" maxlength="4"></form>`
    expect(formRoles()).toEqual({ sc: "cc-csc" })
    document.body.innerHTML = `<form><label for="ex">Expiration date</label><input id="ex" placeholder="MM / YY"></form>`
    expect(formRoles()).toEqual({ ex: "cc-exp" })
  })

  test("the same lone security code box outside a payment frame has no card role", () => {
    page(`<form><label for="sc">Security code</label><input id="sc" maxlength="4"></form>`, "/verify")
    expect(scanForms()).toEqual([])
  })

  test("a saved card's CVV prompt stands alone", () => {
    page(`<form><h2>Confirm your purchase</h2><label for="cvv">CVV</label><input id="cvv" maxlength="4"><button>Confirm</button></form>`, "/confirm")
    expect(formRoles()).toEqual({ cvv: "cc-csc" })
  })

  test("a guest checkout's email beside a newsletter checkbox stays", () => {
    page(`<form><h2>Guest checkout</h2><label for="em">Email</label><input id="em" type="email" autocomplete="email">
      <label><input type="checkbox" name="news"> Subscribe to our newsletter</label><button>Continue to shipping</button></form>`, "/checkout")
    expect(formRoles()).toEqual({ em: "email" })
  })
})

describe("controls with markup inside", () => {
  // An icon's stylesheet, 250 characters of it: no text of the button's.
  const style = `<style>
            .a { fill: #4285f4; } .b { fill: #34a853; } .c { fill: #fbbc05; } .d { fill: #ea4335; }
            .e { stroke: none; opacity: 1; } .f { fill-rule: evenodd; clip-rule: evenodd; } .g { transform: scale(1); }
          </style>`
  const indent = "\n" + " ".repeat(60)

  test("an indented button with an icon's inline style is still a provider's, and another still the submit", () => {
    page(`<main><form><label for="e">Email</label><input id="e" type="email">
        <button type="submit">${indent}<svg viewBox="0 0 24 24"><path d="M0 0h24v24H0z"></path></svg>${indent}Sign in${indent}${indent}</button>
        <button type="button">${indent}${style}${indent}<svg viewBox="0 0 24 24"><path d="M0 0h24v24H0z"></path></svg>${indent}Continue with Google${indent}</button>
      </form></main>`, "/start")
    expect(document.querySelector("button[type=submit]")!.textContent!.length).toBeGreaterThan(160)
    const result = scanPage()
    expect(result.provider).toBe(true)
    expect(result.submit?.textContent).toContain("Sign in")
  })

  test("an SSO link written over several lines is a provider's", () => {
    page(`<main><a href="https://example.com/sso/start">
        Single
        Sign-On
      </a></main>`, "/")
    expect(scanPage().provider).toBe(true)
  })
})

describe("clipping ancestors, as CSS positions boxes", () => {
  const ids = () => scanGraph().controls.map((c) => c.id)

  test("an absolute box escapes a collapsed wrapper that isn't its containing block", () => {
    page(`<div id="w" style="overflow:hidden"><form><input id="e" type="email" style="position:absolute"></form></div>`)
    thin("w", 240, 0)
    expect(ids()).toEqual(["e"])
  })

  test("a collapsed wrapper that is an absolute box's containing block clips it", () => {
    page(`<div id="w" style="overflow:hidden;position:relative"><form><input id="e" type="email" style="position:absolute"></form></div>`)
    thin("w", 240, 0)
    expect(ids()).toEqual([])
  })

  test("a box in a fixed modal escapes a collapsed wrapper around the modal", () => {
    page(`<div id="w" style="overflow:hidden"><div style="position:fixed"><form><input id="e" type="email"></form></div></div>`)
    thin("w", 240, 0)
    expect(ids()).toEqual(["e"])
  })

  test("a display: contents wrapper clips nothing", () => {
    page(`<div id="w" style="display:contents;overflow:hidden"><form><input id="e" type="email"></form></div>`)
    thin("w", 0, 0)
    expect(ids()).toEqual(["e"])
  })

  test("a fixed honeypot in a transformed one-pixel wrapper is clipped by it", () => {
    page(`<form><input id="u" autocomplete="username"><input id="p" type="password" autocomplete="current-password">
      <div id="hp" style="transform:translateY(0);overflow:hidden"><input id="hp2" type="password" style="position:fixed"></div></form>`)
    thin("hp", 240, 1)
    expect(ids()).toEqual(["u", "p"])
  })
})

describe("class names that share a code", () => {
  const facts = (classes: string): FieldFacts => ({ type: "text", autocomplete: [], display: " ", code: "", classes, maxLength: 0, inputMode: "" })

  test("user-name, userName and username each score a username once", () => {
    // What factsFor makes of class="user-name", class="userName" and class="username".
    for (const classes of [" user name ", " username "]) expect(scoreField(facts(classes)).username).toBeCloseTo(4)
  })

  test("userid scores a user id once", () => {
    expect(scoreField(facts(" userid ")).username).toBeCloseTo(3.2)
    expect(scoreField(facts(" user id ")).username).toBeCloseTo(3.2)
  })

  test("zip-code counts against a login field once", () => {
    expect(scoreField(facts(" zip code ")).username).toBeCloseTo(-4.8)
    expect(scoreField(facts(" zipcode ")).username).toBeCloseTo(-4.8)
  })

  test("camelCase and acronym class names split into their words", () => {
    page(`<form><input id="a" class="userName"><input id="b" type="password"><button>Sign in</button></form>`)
    expect(byId(scanPage())).toEqual({ a: "username", b: "password" })
    page(`<form><input id="c" class="OTPInput" maxlength="6"><button>Verify</button></form>`, "/verify")
    expect(byId(scanPage())).toEqual({ c: "otp" })
  })
})

describe("a newsletter's features", () => {
  test("a magic-link sign-in on /login keeps its path and title, well above the threshold", () => {
    page(`<header><h1>Acme</h1></header><main><form><label for="e">Email</label><input id="e" type="email"><button>Send magic link</button></form></main>`, "/login", "Log in – Acme")
    const result = scanPage()
    expect(result.kind).toBe("login")
    const [verdict] = clusterVerdicts()
    expect(verdict.features).toContain("path:login")
    expect(verdict.features).toContain("title:login")
    expect(verdict.odds).toBeGreaterThan(WEIGHTS.threshold + 1)
  })

  test("a footer newsletter box on /login doesn't take the page's path or title", () => {
    page(`<main><h1>Welcome back!</h1></main><footer><form><input id="news" type="email" placeholder="Enter your email to subscribe to our newsletter"><button>Sign up</button></form></footer>`, "/login", "Login - Example")
    const features = clusterVerdicts().flatMap((v) => v.features)
    expect(features.some((f) => f.startsWith("path:") || f.startsWith("title:"))).toBe(false)
  })
})
