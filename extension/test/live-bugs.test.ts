// Each pattern a blind audit of crawled live sign-in and decoy pages turned
// up, written small: the detector's fix for it, held in place.
import { afterEach, describe, expect, test } from "bun:test"
import { scoreField, type FieldFacts } from "../src/content/clues"
import { clusterVerdicts, masked, scanPage } from "../src/content/detect"
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

describe("buttons, verbs and headings a sign-in may use", () => {
  const library = `<h1>Login</h1><div><form name="patform" method="POST"><fieldset><legend>Please enter the following information:</legend>
    <label for="code">Bar Code</label><input autocomplete="off" name="code" id="code" type="PASSWORD" maxlength="40">
    <label for="pin">Enter your 4-digit PIN</label><input autocomplete="off" name="pin" id="pin" type="PASSWORD" maxlength="64">
    <input type="image" name="submit" value="submit"></fieldset></form></div>`

  test("a library's masked bar code and PIN with an image submit button are a sign-in", () => {
    page(library, "/patroninfo", "Town Library / All Locations")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ code: "username", pin: "password" })
    expect((result.submit as HTMLInputElement).type).toBe("image")
    const [verdict] = clusterVerdicts()
    expect(verdict.features).not.toContain("button:none")
    expect(verdict.features).toContain("button:proceed")
  })

  test("a generic legend inside the form doesn't hide the Login heading above it", () => {
    page(library, "/patroninfo")
    const graph = scanGraph()
    expect(graph.context(graph.clusters[0])).toContain(" login ")
  })

  test("a masked library card number, a PIN and a name are a sign-in", () => {
    page(`<form><label for="name">Your Name:</label><input name="name" id="name" maxlength="40">
      <label for="card">Library Card Number:</label><input autocomplete="off" name="code" id="card" type="PASSWORD" maxlength="40">
      <label for="pin">Enter your PIN:</label><input autocomplete="off" name="pin" id="pin" type="PASSWORD" maxlength="64">
      <input type="image" name="submit" value="submit"></form>`, "/patroninfo")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ card: "username", pin: "password" })
  })

  test("a bank's Logon page wrapped in one form, its footer's Contact Us inside it, is a sign-in", () => {
    page(`<form id="logonAction" method="POST" autocomplete="off"><header><a href="#">Close Window</a></header><section><h1>Internet Banking Logon</h1>
      <label for="access">Card / Customer access number</label><input id="access" name="userId" maxlength="19" aria-label="Enter your Card or Access Number">
      <label for="sec">Security Number</label><input id="sec" name="securityNumber" type="password" maxlength="6">
      <label><input type="checkbox" name="rememberMe"> Remember me</label>
      <label for="pw">Internet Password</label><input id="pw" name="password" type="password" maxlength="12">
      <input type="submit" id="logon" value="Logon"></section>
      <footer><a href="#">Help</a> | <a href="#">Contact Us</a> | <a href="#">FAQs</a></footer></form>`, "/ibank/loginPage.action", "Example Bank Internet Banking - Logon")
    const [verdict] = clusterVerdicts()
    expect(verdict.features).not.toContain("words:non-login")
    expect(verdict.features).toContain("button:login")
    expect(verdict.features).toContain("title:login")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ access: "username", sec: "password", pw: "password" })
    expect(result.submit?.id).toBe("logon")
  })

  test("a card's own footer inside a section still speaks for its form", () => {
    page(`<section><form><input id="e" type="email"><input id="p" type="password"><footer>Need help? Contact us</footer><button>Log in</button></form></section>`)
    expect(clusterVerdicts()[0].features).toContain("words:contact")
  })

  test("an IdP's username step with a Proceed button under /idp/ and a card titled User Login is a sign-in", () => {
    page(`<header><h1>Member Portal</h1></header><mat-card><mat-card-header><div><mat-card-title><span>User Login</span></mat-card-title></div></mat-card-header>
      <mat-card-content><div><div><form autocomplete="off"><label for="mat-input-0">Username</label><input id="mat-input-0" name="loginName" autocomplete="off" aria-label="Username">
      <button type="submit"> Proceed </button><a role="button" tabindex="0">Trouble signing in?</a></form></div></div></mat-card-content></mat-card>`, "/idp/members/", "Member Portal")
    const [verdict] = clusterVerdicts()
    expect(verdict.features).toEqual(expect.arrayContaining(["button:proceed", "path:login", "words:login"]))
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ "mat-input-0": "username" })
    expect(result.submit?.textContent?.trim()).toBe("Proceed")
  })

  test("a card title over some other form says nothing of a login form elsewhere", () => {
    page(`<div class="product-card"><div class="card-title">Log in to save</div><form><input id="q" type="search"></form></div>
      <form><input id="e" type="email"><button>Continue</button></form>`, "/")
    const graph = scanGraph()
    expect(graph.context(graph.clusterOf(document.getElementById("e")!))).not.toContain("log in")
  })
})

describe("which form is the page's", () => {
  test("a sign-up above the sign-in on /login: the sign-in is the login form", () => {
    page(`<main><section><h2>Create an Account</h2><form><input id="fn" name="first_name"><input id="ln" name="last_name">
      <label for="se">Email</label><input id="se" type="email"><label for="sp">Password</label><input id="sp" type="password"><button type="submit">Create an Account</button></form></section>
      <section><h2>Log In</h2><form><label for="le">Email</label><input id="le" type="email"><label for="lp">Password</label><input id="lp" type="password">
      <label><input type="checkbox"> Remember me</label><button type="submit">Log In</button></form></section></main>`, "/login/")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ le: "email", lp: "password" })
    expect(result.submit?.textContent).toBe("Log In")
  })

  test("a sign-in above the sign-up on /signup: the sign-up is the form", () => {
    page(`<header><form><input id="le" type="email"><input id="lp" type="password"><button type="submit">Log in</button></form></header>
      <main><h1>Create your account</h1><form><input id="se" type="email" autocomplete="email"><input id="sp" type="password" autocomplete="new-password">
      <input id="sc" type="password" autocomplete="new-password"><button type="submit">Sign up</button></form></main>`, "/signup")
    const result = scanPage()
    expect(result.kind).toBe("signup")
    expect(byId(result)).toEqual({ se: "email", sp: "new-password", sc: "new-password" })
  })

  test("a login link button before Log in: Log in is the submit button", () => {
    page(`<form><input id="e" type="email" autocomplete="username"><input id="p" type="password" autocomplete="current-password">
      <button type="submit" id="onetime">E-mail a login link</button><button type="submit" id="login">Log in</button></form>`)
    expect(scanPage().submit?.id).toBe("login")
  })
})

describe("Sign up with a provider", () => {
  test("a sidebar's one-box sign-up beside Sign up with Google is no sign-in", () => {
    page(`<main><a href="/jobs/1">Revenue Analyst</a><button type="button">Apply</button></main>
      <aside><div><div><form action="/jobs/signup" method="GET"><input name="email" maxlength="100" placeholder="Your Email"><input type="submit" value="Sign up"></form>
      <span>or</span><a href="https://www.example.com/auth/google_oauth2/with_callback"><span>Sign up with Google</span></a></div>
      <div>Already have an account? <button type="button">Log In</button></div></div></aside>`, "/jobs", "Startup jobs")
    const result = scanPage()
    expect(result.kind).toBeNull()
    expect(result.provider).toBe(true)
  })

  test("an email-first step beside Sign in with Google is still a sign-in", () => {
    page(`<main><div><form><label for="e">Email</label><input id="e" type="email"><button>Continue</button></form>
      <a href="https://www.example.com/auth/google">Sign in with Google</a></div></main>`, "/start")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ e: "email" })
  })

  test("a full sign-up page with Sign up with Google stays a sign-up", () => {
    page(`<main><h1>Create your account</h1><form><label for="e">Email</label><input id="e" type="email" autocomplete="email">
      <label for="p">Create a password</label><input id="p" type="password" autocomplete="new-password"><button type="submit">Sign up</button>
      <a href="https://www.example.com/auth/google">Sign up with Google</a></form></main>`, "/signup")
    const result = scanPage()
    expect(result.kind).toBe("signup")
    expect(byId(result)).toEqual({ e: "email", p: "new-password" })
  })
})

describe("email and text marketing popups", () => {
  test("a 10%-off popup's email and mobile number are no identity form", () => {
    page(`<div role="dialog"><form><h2>Take 10% off your first order*</h2><div>Be the first to hear about new arrivals.</div>
      <label for="email">Email Address</label><input id="email" name="email" type="text"><label for="cell">Mobile Phone Number</label><input id="cell" name="cellPhone" type="tel">
      <div>By signing up via text, you agree to receive recurring automated marketing text messages.</div><button type="submit">Continue</button></form></div>`, "/")
    expect(scanForms()).toEqual([])
  })

  test("a newsletter's email and phone boxes marked by autocomplete are no identity form either", () => {
    page(`<footer><form><h2>Subscribe for exclusive offers</h2><input id="em" autocomplete="email"><input id="tel" autocomplete="tel"><button>Subscribe</button></form></footer>`, "/")
    expect(scanForms()).toEqual([])
  })

  test("a contact form's email and phone stay", () => {
    page(`<form><h2>Contact details</h2><label for="em">Email</label><input id="em" type="email"><label for="tel">Phone</label><input id="tel" type="tel"><button>Save</button></form>`, "/account")
    expect(formRoles()).toEqual({ em: "email", tel: "tel" })
  })

  test("a checkout's email and phone beside a text-offers checkbox stay", () => {
    page(`<form><h2>Checkout: contact for delivery</h2><label for="em">Email</label><input id="em" type="email"><label for="tel">Phone</label><input id="tel" type="tel">
      <label><input type="checkbox"> Text me exclusive offers</label><button>Continue to shipping</button></form>`, "/checkout")
    expect(formRoles()).toEqual({ em: "email", tel: "tel" })
  })
})

describe("masked boxes and boxes for either", () => {
  const style = (security: string) => () => ({ getPropertyValue: (name: string) => (name === "-webkit-text-security" ? security : "") }) as unknown as CSSStyleDeclaration
  const input = (type: string) => Object.assign(document.createElement("input"), { type })

  test("a tel, number or email box masked with -webkit-text-security is masked; a checkbox never is", () => {
    for (const type of ["text", "tel", "number", "email"]) expect(masked(input(type), style("disc"))).toBe(true)
    expect(masked(input("tel"), style("none"))).toBe(false)
    expect(masked(input("checkbox"), style("disc"))).toBe(false)
  })

  test("a PIN in a tel box masked with CSS is the sign-in's password, not a code", () => {
    // happy-dom drops vendor-prefixed properties: the inline declaration stands in for the computed one, as Chromium reads it.
    const computed = globalThis.getComputedStyle
    const withSecurity = (el: Element) => {
      const s = computed(el)
      const security = /-webkit-text-security:\s*(\w+)/.exec(el.getAttribute("style") ?? "")?.[1]
      return security ? new Proxy(s, { get: (t, k) => (k === "getPropertyValue" ? (n: string) => (n === "-webkit-text-security" ? security : t.getPropertyValue(n)) : Reflect.get(t, k)) }) : s
    }
    globalThis.getComputedStyle = withSecurity as typeof getComputedStyle
    try {
      maskedPin()
    } finally {
      globalThis.getComputedStyle = computed
    }
  })

  const maskedPin = () => {
    page(`<main><h1>Sign In to your account</h1><form id="login-form"><label for="u">Mobile service or account number</label><input id="u" name="user_name" type="tel">
      <label for="pw">PIN</label><input id="pw" name="user_password" type="tel" maxlength="6" placeholder="******" style="-webkit-text-security:disc">
      <button type="submit">SIGN IN</button><p>Forgot your PIN?</p></form></main>`, "/customer/login", "Secure PIN Entry")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(byId(result)).toEqual({ u: "phone", pw: "password" })
  }

  test("a plain text box labelled Password, unmasked, is never the password", () => {
    page(`<form><label for="u">Username</label><input id="u" name="username"><label for="pw">Password</label><input id="pw" name="password" type="text" autocomplete="off"><button>Log in</button></form>`)
    expect(byId(scanPage()).pw).toBeUndefined()
  })

  test("ID or phone number, and Телефон / Логин, are one box for either: a username", () => {
    page(`<form><input id="id" name="id" placeholder="ID or phone number"><input id="pw" type="password" placeholder="Password"><button>Sign in</button></form>`)
    expect(byId(scanPage())).toEqual({ id: "username", pw: "password" })
    page(`<form><label for="sign">Телефон / Логин</label><input id="sign" name="sign"><label for="pw">Пароль</label><input id="pw" type="password"><button>Войти с паролем</button></form>`, "/sign")
    expect(byId(scanPage())).toEqual({ sign: "username", pw: "password" })
  })

  test("a phone number box alone stays a phone box", () => {
    page(`<form><label for="ph">Phone number</label><input id="ph" name="phone"><button>Continue</button></form>`)
    expect(byId(scanPage())).toEqual({ ph: "phone" })
  })

  test("an access number or library card is who you are; a payment card's number is no username", () => {
    const facts = (display: string, type = "text"): FieldFacts => ({ type, autocomplete: [], display, code: "", maxLength: 0, inputMode: "" })
    expect(scoreField(facts(" card customer access number ")).username).toBeGreaterThanOrEqual(3)
    expect(scoreField(facts(" library card number ", "password")).username).toBeGreaterThanOrEqual(3)
    expect(scoreField(facts(" library card number ", "password")).password).toBeLessThan(3)
    expect(scoreField(facts(" card number ")).username).toBeLessThan(0)
  })
})
