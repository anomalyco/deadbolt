// The Gauntlet's trap pages (see site.ts): patterns that real pages use and
// that have caught password managers out. Google's email-first step with its
// hiddenPassword box, a React form with no action, two six-box code groups,
// concealed inputs (the ACSAC 2024 concealment tricks), decoy fields that are
// no sign-in at all, a checkout whose fields all sit below the fold, code
// boxes that take a code only as a paste, a card form behind a strict mask,
// and a single-page app that signs in without a page load.
// Every account, code and answer here is made up.

import type { Account, PageInfo } from "./site"

export const TRAP_PAGES: PageInfo[] = [
  { slug: "google-hidden-password", group: "Traps", title: "Email first, with a hidden password box", blurb: "Google's hiddenPassword: tabindex=-1, aria-hidden, 1 px." },
  { slug: "react-onsubmit-form", group: "Traps", title: "React form with no action", blurb: "onSubmit only; a native submit would GET the password into the URL." },
  { slug: "dual-otp-boxes", group: "Traps", title: "Two six-box code groups", blurb: "An authenticator code and a texted code, in two forms." },
  { slug: "concealed-traps", group: "Traps", title: "Concealed inputs", blurb: "Opacity 0, clip-path, off-screen, 1 px, inert, covered." },
  { slug: "decoy-zoo", group: "Traps", title: "Decoy fields", blurb: "Search, promo code, newsletter and invite: no sign-in." },
  { slug: "below-fold-checkout", group: "Traps", title: "Checkout below the fold", blurb: "Shipping address and card under a tall summary." },
  { slug: "paste-otp-boxes", group: "Traps", title: "Paste-only code boxes", blurb: "Six boxes that turn a written digit down and take the code only as a paste." },
  { slug: "masked-card", group: "Traps", title: "Strictly masked card", blurb: "Card number and expiry masks that take a character at a time." },
  { slug: "spa-shell-save", group: "Traps", title: "Single-page sign-in", blurb: "No page load: the form goes and an avatar menu shows. No Sign out link." },
]

/** The one password the single-page sign-in takes, for an account the vault doesn't have. */
export const SPA_USER = "newbie@acme.test"
export const SPA_PASSWORD = "spa shell 42"

type Handler = (req: Request, u: URL, rest: string, form: () => Promise<Record<string, string>>) => Response | Promise<Response>

/** What the trap pages borrow from site.ts. */
export interface TrapKit {
  h(title: string, body: string, slug?: string, script?: string, more?: { style?: string; wide?: boolean }): Response
  url(slug: string, rest?: string): string
  login(id: string | undefined, password: string | undefined): Account | undefined
  find(id: string | undefined): Account | undefined
  ticket(...parts: string[]): string
  signedIn(who: string, extra?: string): string
  errorLine(error?: string): string
  esc(s: unknown): string
  savedProfile(req: Request, slug: string): Promise<Response>
  plainFields(): string
  clientLogin(formSel: string, user: string, pass: string): string
  regions: Array<[string, string]>
  smsCode: string
  codeOk(a: Account | undefined, code: string): boolean
}

/** The script that makes a row of one-digit boxes advance, go back and take a paste. */
const digitScript = (sel: string) => `for(const group of document.querySelectorAll(${JSON.stringify(sel)})){const boxes=[...group.querySelectorAll("input")]
boxes.forEach((b,i)=>{b.addEventListener("input",()=>{b.value=b.value.replace(/\\D/g,"").slice(-1);if(b.value&&boxes[i+1])boxes[i+1].focus()})
b.addEventListener("keydown",(e)=>{if(e.key==="Backspace"&&!b.value&&boxes[i-1])boxes[i-1].focus()})
b.addEventListener("paste",(e)=>{const t=(e.clipboardData.getData("text")||"").replace(/\\D/g,"");if(!t)return;e.preventDefault();t.split("").slice(0,6).forEach((c,j)=>{if(boxes[j])boxes[j].value=c})})})}`

/** One-digit boxes that keep only a digit typed by a person or a paste: a written one (an untrusted input event) is put back. */
const pasteOnlyScript = (sel: string) => `for(const group of document.querySelectorAll(${JSON.stringify(sel)})){const boxes=[...group.querySelectorAll("input")];const state=boxes.map(()=>"")
const take=(t)=>{t.replace(/\\D/g,"").split("").slice(0,6).forEach((c,j)=>{state[j]=c;boxes[j].value=c})}
boxes.forEach((b,i)=>{b.addEventListener("input",(e)=>{if(!e.isTrusted){b.value=state[i];return}state[i]=b.value=b.value.replace(/\\D/g,"").slice(-1);if(b.value&&boxes[i+1])boxes[i+1].focus()})
b.addEventListener("paste",(e)=>{e.preventDefault();take(e.clipboardData.getData("text")||"")})})}`

/** A mask that takes a character at a time and formats, and turns a whole value written at once down. */
const strictMaskScript = `const mask=(el,format)=>{let kept="";el.addEventListener("input",(e)=>{if(e.inputType==="insertReplacementText"||(e.data||"").length>1){el.value=kept;return}el.value=kept=format(el.value.replace(/\\D/g,""))})}
mask(document.getElementById("cc-number"),(d)=>d.slice(0,16).replace(/(\\d{4})(?=\\d)/g,"$1 "))
mask(document.getElementById("cc-exp"),(d)=>d.length>2?d.slice(0,2)+" / "+d.slice(2,4):d)`

/** Names of the concealed inputs on the concealed-traps page, by id. */
export const CONCEALED = ["t-opacity", "t-clip", "t-offscreen", "t-tiny", "t-inert", "t-covered"]
/** The decoy fields on the decoy-zoo page. */
export const DECOYS = ["#q", "#promo", "#news-email", "#invite-email"]

export function trapPages(k: TrapKit): Record<string, Handler> {
  const { h, url, esc } = k
  const digits = (prefix: string, label: string) =>
    `<div class="digits" role="group" aria-label="${label}">${[1, 2, 3, 4, 5, 6].map((i) => `<input id="${prefix}${i}" name="${prefix}${i}" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="${i === 1 ? "one-time-code" : "off"}" aria-label="${label}, digit ${i}">`).join("")}</div>`

  const dualStep = (who: string, error?: string) =>
    h(
      "Verify it's you",
      `<h1>Verify it's you</h1><p class="lede">Use either code.</p>
      <form method="post" action="${url("dual-otp-boxes", "/code")}" novalidate id="totp-form"><input type="hidden" name="username" value="${esc(who)}"><input type="hidden" name="ticket" value="${k.ticket("dual-otp-boxes", who)}"><input type="hidden" name="via" value="totp">
        <h2 style="font-size:15px;margin:12px 0 4px">Authenticator app</h2><p class="muted">Enter the 6-digit code from your authenticator app.</p>${digits("a", "Authenticator code")}
        <button type="submit" id="verify-totp">Verify</button></form>
      <form method="post" action="${url("dual-otp-boxes", "/code")}" novalidate id="sms-form" style="margin-top:24px"><input type="hidden" name="username" value="${esc(who)}"><input type="hidden" name="ticket" value="${k.ticket("dual-otp-boxes", who)}"><input type="hidden" name="via" value="sms">
        <h2 style="font-size:15px;margin:12px 0 4px">Text message</h2><p class="muted">Or enter the code we texted to your phone ending in 0123.</p>${digits("s", "Texted code")}
        ${k.errorLine(error)}<button type="submit" id="verify-sms">Verify</button></form>
      <div class="inbox">Demo phone: your code is <strong id="sent-code">${k.smsCode}</strong></div>`,
      "dual-otp-boxes",
      digitScript(".digits"),
    )

  return {
    // Google's identifier step carries a password box no one can see or reach
    // (tabindex=-1, aria-hidden, a 1 px box): a bot or a careless password
    // manager fills it, a person never does. The server refuses the sign-in if it has anything.
    "google-hidden-password": async (req, _u, rest, form) => {
      const first = (error?: string) =>
        h(
          "Sign in",
          `<h1>Sign in</h1><p class="lede">to continue to Gauntlet Mail</p><form method="post" action="${url("google-hidden-password", "/password")}" novalidate>
            <label for="username">Email or phone</label><input id="username" name="identifier" type="email" autocomplete="username webauthn" spellcheck="false" autocapitalize="none">
            <div aria-hidden="true" style="position:absolute;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none"><input type="password" id="hidden-password" name="hiddenPassword" autocomplete="off" spellcheck="false" tabindex="-1" aria-hidden="true"></div>
            ${k.errorLine(error)}<button type="submit" id="continue">Next</button></form>`,
          "google-hidden-password",
        )
      if (req.method !== "POST") return first()
      const f = await form()
      if (f.hiddenPassword) return h("Blocked", `<h1>Blocked</h1><p id="trapped">Something filled the hidden password box (${f.hiddenPassword.length} characters).</p>`, "google-hidden-password")
      if (rest === "/password") {
        if (!k.find(f.identifier)) return first("Couldn't find your account.")
        return h(
          "Welcome",
          `<h1>Welcome</h1><p class="lede" id="account">${esc(f.identifier)}</p><form method="post" action="${url("google-hidden-password", "/signin")}" novalidate>
            <input type="hidden" name="identifier" value="${esc(f.identifier)}" autocomplete="username"><label for="password">Enter your password</label><input id="password" name="Passwd" type="password" autocomplete="current-password">
            <button type="submit" id="submit">Next</button></form>`,
          "google-hidden-password",
        )
      }
      const a = k.login(f.identifier, f.Passwd)
      return a ? h("Signed in", k.signedIn(a.username), "google-hidden-password") : first("Wrong password. Try again.")
    },

    // A React form: no action, no method (so a native submit is a GET of
    // this URL with every field in the query), onSubmit preventing it. The
    // identifier step re-renders into the password step in the same form.
    "react-onsubmit-form": () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">One form, re-rendered by script for each step.</p><form id="f" novalidate><div id="step"></div><button type="submit" id="next">Continue</button></form>`,
        "react-onsubmit-form",
        `const step=document.getElementById("step"),next=document.getElementById("next");let who=""
const one=()=>{step.innerHTML='<label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username">';next.textContent="Continue";next.id="next"}
const two=()=>{step.innerHTML='<p class="lede" id="account"></p><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">';document.getElementById("account").textContent=who;next.textContent="Sign in";next.id="submit"}
one()
document.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault()
  if(!who){const v=document.getElementById("username").value;const r=await G.post("exists",{username:v});if(!r.ok)return G.show(r);who=v;two();return}
  G.show(await G.post("login",{username:who,password:document.getElementById("password").value}))})`,
      ),

    "dual-otp-boxes": async (req, _u, rest, form) => {
      const first = (error?: string) =>
        h(
          "Sign in",
          `<h1>Sign in</h1><form method="post" action="${url("dual-otp-boxes")}" novalidate>${k.plainFields()}${k.errorLine(error)}<button type="submit" id="submit">Sign in</button></form>`,
          "dual-otp-boxes",
        )
      if (req.method !== "POST") return first()
      const f = await form()
      if (rest === "/code") {
        if (f.ticket !== k.ticket("dual-otp-boxes", f.username)) return first("Your sign-in expired. Start again.")
        const code = (p: string) => [1, 2, 3, 4, 5, 6].map((i) => f[`${p}${i}`] ?? "").join("")
        const ok = f.via === "sms" ? code("s") === k.smsCode : k.codeOk(k.find(f.username), code("a"))
        return ok ? h("Signed in", k.signedIn(f.username), "dual-otp-boxes") : dualStep(f.username, "That code isn't right.")
      }
      const a = k.login(f.username, f.password)
      return a ? dualStep(a.username) : first("That email or password isn't right.")
    },

    // The real boxes, and around them one input per concealment trick: each
    // is in the form and posted, and the server refuses a sign-in that
    // carries anything in one.
    "concealed-traps": async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const trapped = CONCEALED.filter((id) => f[id.replace("-", "_")])
        if (trapped.length) return h("Blocked", `<h1>Blocked</h1><p id="trapped">Concealed inputs were filled: ${esc(trapped.join(", "))}.</p>`, "concealed-traps")
        const a = k.login(f.username, f.password)
        return a ? h("Signed in", k.signedIn(a.username), "concealed-traps") : h("Sign in", `<h1>Sign in</h1>${k.errorLine("That email or password isn't right.")}`, "concealed-traps")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Six concealed inputs sit in this form.</p><form method="post" action="${url("concealed-traps")}" novalidate style="position:relative">
          <input id="t-clip" name="t_clip" type="text" autocomplete="username" tabindex="-1" style="position:absolute;top:0;left:0;width:120px;height:20px;clip-path:inset(50%)">
          <label for="username">Email or username</label><input id="username" name="username" autocomplete="username">
          <input id="t-offscreen" name="t_offscreen" type="email" autocomplete="username" tabindex="-1" style="position:absolute;left:-9999px;top:0">
          <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
          <input id="t-opacity" name="t_opacity" type="password" autocomplete="current-password" tabindex="-1" style="opacity:0;height:20px;margin-top:6px">
          <input id="t-tiny" name="t_tiny" type="password" autocomplete="current-password" tabindex="-1" style="width:1px;height:1px;padding:0;border:0">
          <div style="position:relative;margin-top:6px"><input id="t-covered" name="t_covered" type="text" autocomplete="username" tabindex="-1"><div style="position:absolute;inset:-2px;background:var(--card);z-index:2"></div></div>
          <div inert style="height:0;overflow:hidden"><input id="t-inert" name="t_inert" type="email" autocomplete="username"></div>
          <button type="submit" id="submit">Sign in</button></form>`,
        "concealed-traps",
      )
    },

    // Fields that ask for an email or a code but are no sign-in: none should open a menu.
    "decoy-zoo": () =>
      h(
        "Acme Store",
        `<form role="search" action="${url("decoy-zoo")}" style="margin-bottom:18px"><label for="q">Search the store</label><input id="q" name="q" type="text" placeholder="Search" autocomplete="off"></form>
        <h1>Your cart</h1><p class="lede">1 item, $24.00.</p>
        <form id="promo-form" novalidate><label for="promo">Promo code</label><input id="promo" name="promo" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit code" autocomplete="off"><button type="submit" class="secondary" id="apply">Apply</button></form>
        <hr style="border:0;border-top:1px solid var(--line);margin:24px 0"><h2 style="font-size:16px;margin:0">Invite a teammate</h2>
        <form id="invite-form" novalidate><label for="invite-email">Teammate's email</label><input id="invite-email" name="invite" type="email" placeholder="teammate@example.com"><label for="invite-role">Role</label><select id="invite-role" name="role"><option>Member</option><option>Admin</option></select><button type="submit" class="secondary" id="invite">Send invite</button></form>
        <hr style="border:0;border-top:1px solid var(--line);margin:24px 0"><h2 style="font-size:16px;margin:0">Newsletter</h2><p class="muted">Subscribe to our newsletter for monthly deals.</p>
        <form id="news-form" novalidate><label for="news-email">Email address</label><input id="news-email" name="news" type="email" placeholder="you@example.com"><button type="submit" class="secondary" id="subscribe">Subscribe</button></form>`,
        "decoy-zoo",
        `for(const id of ["promo-form","invite-form","news-form"])document.getElementById(id).addEventListener("submit",(e)=>{e.preventDefault();e.target.insertAdjacentHTML("beforeend",'<p class="muted">Done.</p>')})`,
      ),

    "below-fold-checkout": async (req) => {
      if (req.method === "POST") return k.savedProfile(req, "below-fold-checkout")
      const mm = `<option value="">MM</option>${Array.from({ length: 12 }, (_, i) => `<option value="${String(i + 1).padStart(2, "0")}">${String(i + 1).padStart(2, "0")}</option>`).join("")}`
      const yy = `<option value="">YYYY</option>${Array.from({ length: 12 }, (_, i) => `<option value="${2026 + i}">${2026 + i}</option>`).join("")}`
      return h(
        "Checkout",
        `<h1>Checkout</h1><section id="summary" style="height:1400px"><h2 style="font-size:15px">Order summary</h2><p class="lede">Gauntlet Pro, $12.00 a month.</p><p class="muted">Scroll down for shipping and payment.</p></section>
        <form method="post" action="${url("below-fold-checkout")}">
          <h2 style="font-size:15px;margin:16px 0 0">Shipping address</h2>
          <label for="ship-name">Full name</label><input id="ship-name" name="ship-name" autocomplete="shipping name">
          <label for="ship-line1">Address</label><input id="ship-line1" name="ship-line1" autocomplete="shipping address-line1">
          <label for="ship-line2">Apartment, suite, etc.</label><input id="ship-line2" name="ship-line2" autocomplete="shipping address-line2">
          <div class="row"><div><label for="ship-city">City</label><input id="ship-city" name="ship-city" autocomplete="shipping address-level2"></div>
          <div><label for="ship-state">State</label><select id="ship-state" name="ship-state" autocomplete="shipping address-level1"><option value="">State</option>${k.regions.map(([v, n]) => `<option value="${v}">${n}</option>`).join("")}</select></div>
          <div><label for="ship-zip">ZIP</label><input id="ship-zip" name="ship-zip" autocomplete="shipping postal-code"></div></div>
          <label for="ship-country">Country</label><select id="ship-country" name="ship-country" autocomplete="shipping country"><option value="">Country</option><option value="CA">Canada</option><option value="US">United States</option></select>
          <h2 style="font-size:15px;margin:20px 0 0">Card</h2>
          <label for="cc-number">Card number</label><input id="cc-number" name="cc-number" autocomplete="cc-number" inputmode="numeric" placeholder="1234 1234 1234 1234">
          <div class="row"><div><label for="cc-month">Expiry month</label><select id="cc-month" name="cc-month" autocomplete="cc-exp-month">${mm}</select></div>
          <div><label for="cc-year">Expiry year</label><select id="cc-year" name="cc-year" autocomplete="cc-exp-year">${yy}</select></div>
          <div><label for="cc-csc">CVC</label><input id="cc-csc" name="cc-csc" autocomplete="cc-csc" inputmode="numeric" maxlength="4"></div></div>
          <label for="cc-name">Name on card</label><input id="cc-name" name="cc-name" autocomplete="cc-name">
          <button type="submit" id="submit">Pay $12.00</button></form>`,
        "below-fold-checkout",
      )
    },

    // A code step whose six boxes keep only what a person types or pastes.
    "paste-otp-boxes": async (req, _u, rest, form) => {
      const first = (error?: string) =>
        h("Sign in", `<h1>Sign in</h1><form method="post" action="${url("paste-otp-boxes")}" novalidate>${k.plainFields()}${k.errorLine(error)}<button type="submit" id="submit">Sign in</button></form>`, "paste-otp-boxes")
      const step = (who: string, error?: string) =>
        h(
          "Verify it's you",
          `<h1>Verify it's you</h1><p class="lede">Enter the 6-digit code from your authenticator app.</p>
          <form method="post" action="${url("paste-otp-boxes", "/code")}" novalidate><input type="hidden" name="username" value="${esc(who)}"><input type="hidden" name="ticket" value="${k.ticket("paste-otp-boxes", who)}">
            ${digits("p", "Authenticator code")}${k.errorLine(error)}<button type="submit" id="verify">Verify</button></form>`,
          "paste-otp-boxes",
          pasteOnlyScript(".digits"),
        )
      if (req.method !== "POST") return first()
      const f = await form()
      if (rest === "/code") {
        if (f.ticket !== k.ticket("paste-otp-boxes", f.username)) return first("Your sign-in expired. Start again.")
        const code = [1, 2, 3, 4, 5, 6].map((i) => f[`p${i}`] ?? "").join("")
        return k.codeOk(k.find(f.username), code) ? h("Signed in", k.signedIn(f.username), "paste-otp-boxes") : step(f.username, "That code isn't right.")
      }
      const a = k.login(f.username, f.password)
      return a ? step(a.username) : first("That email or password isn't right.")
    },

    "masked-card": async (req) => {
      if (req.method === "POST") return k.savedProfile(req, "masked-card")
      return h(
        "Payment",
        `<h1>Payment</h1><form method="post" action="${url("masked-card")}">
          <label for="cc-name">Name on card</label><input id="cc-name" name="cc-name" autocomplete="cc-name">
          <label for="cc-number">Card number</label><input id="cc-number" name="cc-number" autocomplete="cc-number" inputmode="numeric" placeholder="1234 1234 1234 1234">
          <div class="row"><div><label for="cc-exp">Expiry</label><input id="cc-exp" name="cc-exp" autocomplete="cc-exp" inputmode="numeric" placeholder="MM / YY"></div>
          <div><label for="cc-csc">CVC</label><input id="cc-csc" name="cc-csc" autocomplete="cc-csc" inputmode="numeric" maxlength="4"></div></div>
          <button type="submit" id="submit">Pay $12.00</button></form>`,
        "masked-card",
        strictMaskScript,
      )
    },

    // Signs in without a page load: a wrong password shows an alert and
    // clears the box; the right one swaps the form for an app shell whose
    // only sign of the account is an avatar menu.
    "spa-shell-save": () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><form id="f" novalidate><label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username">
          <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password"><button type="submit" id="submit">Sign in</button></form>`,
        "spa-shell-save",
        `const f=document.getElementById("f")
f.addEventListener("submit",(e)=>{e.preventDefault();const pw=document.getElementById("password")
  if(pw.value!==${JSON.stringify(SPA_PASSWORD)}){let a=document.getElementById("error");if(!a){a=document.createElement("p");a.id="error";a.className="error";a.setAttribute("role","alert");f.append(a)}a.textContent="Incorrect password. Try again.";pw.value="";return}
  history.pushState({},"",G.base+"/spa-shell-save/dashboard");document.title="Projects"
  document.querySelector("main").innerHTML='<header style="display:flex;justify-content:flex-end"><button type="button" id="avatar" aria-label="Account menu" aria-haspopup="menu" style="width:36px;height:36px;margin:0;border-radius:50%;padding:0"><svg viewBox="0 0 10 10" width="20" height="20"><circle cx="5" cy="5" r="4" fill="currentColor"/></svg></button></header><h1>Projects</h1><p class="lede">No projects yet.</p>'})`,
      ),
  }
}
