// The Gauntlet: one page per sign-in, MFA and form pattern a password
// manager meets in the wild, each a working demo that validates its fields,
// steps through its flow and says "Signed in" (#result[data-ok]) only for
// the right fake credentials and codes. The e2e run (e2e/run.ts) mounts it
// under /gauntlet on its test hosts; e2e/gauntlet/server.ts hosts it on its
// own. Every account, code and answer here is made up.

import { createHmac, randomBytes } from "node:crypto"

export interface Account {
  /** What the login is saved under: an email or a plain username. */
  username: string
  password: string
  /** Base32 TOTP secret (RFC 6238, SHA-1, 30 s, 6 digits). */
  totp?: string
  /** Other identifiers the account signs in with: a phone number, a customer number, a short username. */
  aliases?: string[]
  /** A numeric PIN, for the PIN and on-screen keypad pages (the password works on the PIN page too). */
  pin?: string
  /** Birth date, YYYY-MM-DD, for the bank page. */
  birthday?: string
}

export interface GauntletOptions {
  /** Path prefix the pages live under, without a trailing slash ("" or "/gauntlet"). */
  base: string
  accounts: Account[]
  /** Codes accepted on top of each account's current TOTP (the e2e fake host's fixed code). */
  fixedCodes?: string[]
  /** The origin a same-site (different-origin) frame comes from, for this request. */
  sameSiteOrigin?: (url: URL) => string | null
  /** The origin a cross-site frame comes from, for this request. */
  crossSiteOrigin?: (url: URL) => string | null
  /** A line for the index about which login to use. */
  hint?: string
}

export interface PageInfo {
  slug: string
  group: "Sign-in" | "Codes and MFA" | "Identity" | "Tricky DOM" | "Other flows"
  title: string
  blurb: string
}

/** Every page, in the index's order. */
export const PAGES: PageInfo[] = [
  { slug: "basic", group: "Sign-in", title: "Username and password", blurb: "Both on one page." },
  { slug: "identifier-first", group: "Sign-in", title: "Email, then password", blurb: "Identifier first; the password on a second page." },
  { slug: "remember-device", group: "Sign-in", title: "Email, password, remember device", blurb: "Then a “trust this device?” choice." },
  { slug: "pin", group: "Sign-in", title: "Username and PIN", blurb: "A numeric PIN instead of a password." },
  { slug: "phone", group: "Sign-in", title: "Phone number, then password", blurb: "A country-code select beside the number." },
  { slug: "bank", group: "Sign-in", title: "Customer number, birth date, password", blurb: "As some banks do." },
  { slug: "reveal", group: "Sign-in", title: "Password revealed after the username", blurb: "The password box appears once you type." },
  { slug: "totp", group: "Codes and MFA", title: "Authenticator code", blurb: "Password, then a TOTP in one box." },
  { slug: "totp-split", group: "Codes and MFA", title: "Authenticator code in six boxes", blurb: "Auto-advance and paste." },
  { slug: "backup", group: "Codes and MFA", title: "Backup codes", blurb: "8 digits or XXXX-XXXX; never a TOTP." },
  { slug: "sms", group: "Codes and MFA", title: "SMS code", blurb: "Sent to a phone, with Resend; never a TOTP." },
  { slug: "email-code", group: "Codes and MFA", title: "Email code", blurb: "Sent by email, with Resend; never a TOTP." },
  { slug: "mfa-picker", group: "Codes and MFA", title: "Choose a method", blurb: "Authenticator, SMS or email." },
  { slug: "number-match", group: "Codes and MFA", title: "Number matching", blurb: "Tap the number in your app." },
  { slug: "security-questions", group: "Codes and MFA", title: "Security questions", blurb: "Answers you know; nothing to fill." },
  { slug: "magic-link", group: "Codes and MFA", title: "Magic link", blurb: "“Check your email.”" },
  { slug: "passkey", group: "Codes and MFA", title: "Passkey first", blurb: "With a password fallback." },
  { slug: "dob-selects", group: "Identity", title: "Birth date in three selects", blurb: "Month, day, year; first and last name." },
  { slug: "dob-date", group: "Identity", title: "Birth date in a date input", blurb: "And one full-name box." },
  { slug: "dob-masked", group: "Identity", title: "Masked MM/DD/YYYY", blurb: "First, middle and last name." },
  { slug: "address-cascade", group: "Identity", title: "Country and state cascade", blurb: "States load after the country." },
  { slug: "shadow-open", group: "Tricky DOM", title: "Open shadow root", blurb: "The form inside an open shadow root." },
  { slug: "shadow-closed", group: "Tricky DOM", title: "Closed shadow root", blurb: "The form inside a closed shadow root." },
  { slug: "web-component", group: "Tricky DOM", title: "Web components", blurb: "A custom input element per field." },
  { slug: "iframe-same-origin", group: "Tricky DOM", title: "Same-origin frame", blurb: "The login in a frame of this origin." },
  { slug: "iframe-same-site", group: "Tricky DOM", title: "Same-site frame", blurb: "From another origin of this site." },
  { slug: "iframe-cross-site", group: "Tricky DOM", title: "Cross-site frame", blurb: "Another site's frame: must be refused." },
  { slug: "react", group: "Tricky DOM", title: "React-style controlled inputs", blurb: "Ignore .value without real events." },
  { slug: "vue", group: "Tricky DOM", title: "Vue-style v-model", blurb: "State only from input events." },
  { slug: "clear-on-focus", group: "Tricky DOM", title: "Clears itself on focus", blurb: "Both boxes empty when focused." },
  { slug: "late", group: "Tricky DOM", title: "Rendered late", blurb: "The form appears after 2 s." },
  { slug: "rerender", group: "Tricky DOM", title: "Re-rendered on each keystroke", blurb: "New input elements every time." },
  { slug: "spa", group: "Tricky DOM", title: "SPA route changes", blurb: "Email, password, code; no page loads." },
  { slug: "dialog", group: "Tricky DOM", title: "Login in a modal dialog", blurb: "A <dialog> opened with showModal()." },
  { slug: "many-forms", group: "Tricky DOM", title: "Several forms", blurb: "Login, newsletter and search." },
  { slug: "honeypot", group: "Tricky DOM", title: "Honeypot fields", blurb: "Hidden traps that must stay empty." },
  { slug: "autocomplete-off", group: "Tricky DOM", title: "autocomplete=off everywhere", blurb: "On the form and both fields." },
  { slug: "misleading", group: "Tricky DOM", title: "Misleading names", blurb: "name=email on the password, and so on." },
  { slug: "css-masked", group: "Tricky DOM", title: "Password masked by CSS", blurb: "type=text with -webkit-text-security." },
  { slug: "virtual-keyboard", group: "Tricky DOM", title: "On-screen keypad", blurb: "The PIN box takes only keypad taps." },
  { slug: "no-paste", group: "Tricky DOM", title: "Paste disabled", blurb: "onpaste is blocked." },
  { slug: "rules", group: "Tricky DOM", title: "maxlength and pattern", blurb: "Constraint validation on both boxes." },
  { slug: "signup", group: "Other flows", title: "Sign up with password rules", blurb: "Use the generator." },
  { slug: "change-password", group: "Other flows", title: "Change password", blurb: "Current, new and confirm." },
  { slug: "reset", group: "Other flows", title: "Password reset", blurb: "Email, link, new password." },
  { slug: "checkout", group: "Other flows", title: "Checkout", blurb: "Card and billing address." },
]

// ---- One-time codes ---------------------------------------------------------------

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
function base32(secret: string): Buffer {
  let bits = ""
  for (const c of secret.replace(/[\s=]/g, "").toUpperCase()) {
    const i = B32.indexOf(c)
    if (i >= 0) bits += i.toString(2).padStart(5, "0")
  }
  return Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)))
}
export function totpAt(secret: string, seconds: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(seconds / 30)))
  const mac = createHmac("sha1", base32(secret)).update(counter).digest()
  const at = mac[mac.length - 1] & 0xf
  return String((mac.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, "0")
}

/** The made-up codes the SMS and email pages "send", shown in their demo inbox. */
export const SMS_CODE = "314159"
export const EMAIL_CODE = "271828"
export const BACKUP_CODES = ["40218867", "K7QX-M2PD"]
export const ANSWERS: Record<string, string> = { pet: "biscuit", street: "maple", city: "lisbon" }
/** What the on-screen keypad page takes when an account has no PIN of its own. */
export const KEYPAD_PIN = "246810"

// ---- Pages ---------------------------------------------------------------------------

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

const STYLE = `
:root{color-scheme:light dark;--bg:#f5f5f4;--fg:#1c1917;--muted:#78716c;--card:#fff;--line:#e7e5e4;--accent:#4f46e5;--ok:#15803d;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--fg:#e7e5e4;--muted:#a8a29e;--card:#1c1917;--line:#292524;--accent:#818cf8;--ok:#4ade80;--bad:#f87171}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,-apple-system,system-ui,sans-serif}
.top{display:flex;justify-content:space-between;align-items:center;max-width:720px;margin:0 auto;padding:14px 20px;font-size:13px;color:var(--muted)}
.top a{color:inherit;text-decoration:none}
main{max-width:400px;margin:24px auto 64px;padding:28px;border-radius:14px;background:var(--card);border:1px solid var(--line)}
main.wide{max-width:560px}
h1{font-size:22px;margin:0 0 6px}
p.lede{margin:0 0 16px;color:var(--muted)}
label{display:block;font-size:13px;margin:12px 0 4px}
input,select{width:100%;height:38px;padding:0 10px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit}
input[type=checkbox],input[type=radio]{width:auto;height:auto}
button,.button{display:block;width:100%;margin-top:18px;height:38px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;cursor:pointer;text-align:center;line-height:38px;text-decoration:none}
button.secondary,.button.secondary{background:transparent;color:var(--accent);border:1px solid var(--line)}
.row{display:flex;gap:8px}.row>*{flex:1}
.digits{display:flex;gap:6px}.digits input{width:44px;text-align:center;font-size:20px;padding:0}
.error{color:var(--bad);font-size:14px;margin:8px 0 0}
.inbox{margin-top:20px;padding:12px 14px;border:1px dashed var(--line);border-radius:10px;font-size:13px;color:var(--muted)}
.inbox strong{color:var(--fg);font-family:ui-monospace,monospace;font-size:15px}
.result h1{color:var(--ok)}
.muted{color:var(--muted);font-size:13px}
ul.index{list-style:none;padding:0;margin:0}ul.index li{padding:8px 0;border-top:1px solid var(--line)}ul.index a{color:var(--accent);text-decoration:none;font-weight:500}
`

/** A step's HTML page. */
function page(o: { title: string; body: string; slug?: string; script?: string; style?: string; wide?: boolean; base: string }) {
  const info = o.slug ? PAGES.find((p) => p.slug === o.slug) : undefined
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(o.title)}</title><style>${STYLE}${o.style ?? ""}</style></head><body>
<div class="top"><a href="${o.base}/">← The Gauntlet</a><span>${info ? esc(info.group + " · " + info.title) : ""}</span></div>
<main${o.wide ? ` class="wide"` : ""}>${o.body}</main>
<script>window.G={base:${JSON.stringify(o.base)},slug:${JSON.stringify(o.slug ?? "")},async post(path,data){const r=await fetch(this.base+"/api/"+path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(data)});return r.json()},show(res){const m=document.querySelector("main");if(res.ok){m.innerHTML=res.html}else{let e=document.getElementById("error");if(!e){e=document.createElement("p");e.id="error";e.className="error";e.setAttribute("role","alert");(document.querySelector("form")||m).append(e)}e.textContent=res.error}}}</script>
${o.script ? `<script>${o.script}</script>` : ""}</body></html>`,
    { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } },
  )
}

/** What a signed-in page says. */
const signedIn = (who: string, extra = "") =>
  `<div class="result" id="result" data-ok="1"><h1>Signed in</h1><p>Signed in as <strong id="who">${esc(who)}</strong>.</p>${extra}</div>`

const errorLine = (error?: string) => (error ? `<p class="error" id="error" role="alert">${esc(error)}</p>` : "")

export function gauntlet(opts: GauntletOptions): (req: Request) => Promise<Response | null> {
  const base = opts.base
  const key = randomBytes(32)
  const ticket = (...parts: string[]) => createHmac("sha256", key).update(parts.join("\0")).digest("base64url").slice(0, 22)
  const norm = (s: unknown) => String(s ?? "").trim().toLowerCase()
  const digitsOf = (s: unknown) => String(s ?? "").replace(/\D/g, "")
  const find = (id: string | undefined) => {
    const n = norm(id)
    if (!n) return undefined
    return opts.accounts.find((a) => {
      if (norm(a.username) === n) return true
      return (a.aliases ?? []).some((x) => norm(x) === n || (digitsOf(x).length >= 7 && digitsOf(x) === digitsOf(n)) || (digitsOf(x).length >= 7 && digitsOf(n).endsWith(digitsOf(x))))
    })
  }
  const passwordOk = (a: Account | undefined, p: string) => !!a && (p === a.password || (!!a.pin && p === a.pin))
  const codeOk = (a: Account | undefined, code: string) => {
    if (!a) return false
    const c = code.replace(/\s/g, "")
    if (opts.fixedCodes?.includes(c)) return true
    if (!a.totp) return false
    const now = Date.now() / 1000
    return [-30, 0, 30].some((d) => totpAt(a.totp!, now + d) === c)
  }
  const login = (id: string | undefined, p: string | undefined) => {
    const a = find(id)
    return passwordOk(a, p ?? "") ? a : undefined
  }
  const h = (title: string, body: string, slug?: string, script?: string, more: { style?: string; wide?: boolean } = {}) => page({ title, body, slug, script, base, ...more })
  const url = (slug: string, rest = "") => `${base}/${slug}${rest}`

  // ---- Shared step builders ----

  /** A username and password on one form, posted to `action`. */
  const loginForm = (action: string, o: { user?: string; userLabel?: string; userType?: string; userAc?: string; extra?: string; formAttrs?: string; pwAttrs?: string; userAttrs?: string; button?: string } = {}) =>
    `<form method="post" action="${action}" novalidate ${o.formAttrs ?? ""}>
      <label for="username">${o.userLabel ?? "Email or username"}</label><input id="username" name="username" type="${o.userType ?? "text"}" autocomplete="${o.userAc ?? "username"}" value="${esc(o.user ?? "")}" ${o.userAttrs ?? ""}>
      <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" ${o.pwAttrs ?? ""}>
      ${o.extra ?? ""}<button type="submit" id="submit">${o.button ?? "Sign in"}</button></form>`

  /** The code step after a password, with what it carries. */
  const codeCarry = (who: string, slug: string) => `<input type="hidden" name="username" value="${esc(who)}"><input type="hidden" name="ticket" value="${ticket(slug, who)}">`

  const totpStep = (slug: string, who: string, split: boolean, error?: string) =>
    h(
      "Two-step verification",
      `<h1>Two-step verification</h1><p class="lede">Enter the 6-digit code from your authenticator app.</p>
      <form method="post" action="${url(slug, "/code")}" novalidate id="code-form">${codeCarry(who, slug)}
      ${
        split
          ? `<label id="code-label">Authentication code</label><div class="digits" role="group" aria-labelledby="code-label">${[1, 2, 3, 4, 5, 6].map((i) => `<input id="d${i}" name="d${i}" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="${i === 1 ? "one-time-code" : "off"}" aria-label="Digit ${i}">`).join("")}</div>`
          : `<label for="code">Authentication code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456">`
      }
      ${errorLine(error)}<button type="submit" id="verify">Verify</button></form>
      <p class="muted"><a href="${url("mfa-picker", "/methods?u=" + encodeURIComponent(who) + "&t=" + ticket("mfa-picker", who))}">Try another way</a></p>`,
      slug,
      split
        ? `const boxes=[...document.querySelectorAll(".digits input")]
boxes.forEach((b,i)=>{b.addEventListener("input",()=>{b.value=b.value.replace(/\\D/g,"").slice(-1);if(b.value&&boxes[i+1])boxes[i+1].focus()})
b.addEventListener("keydown",(e)=>{if(e.key==="Backspace"&&!b.value&&boxes[i-1])boxes[i-1].focus()})
b.addEventListener("paste",(e)=>{const t=(e.clipboardData.getData("text")||"").replace(/\\D/g,"");if(!t)return;e.preventDefault();t.split("").slice(0,6).forEach((c,j)=>{if(boxes[j])boxes[j].value=c});(boxes[Math.min(t.length,6)-1]||b).focus()})})`
        : undefined,
    )

  /** A code sent somewhere (not an authenticator): the code is shown in a demo inbox. */
  const sentStep = (slug: string, who: string, via: "sms" | "email", error?: string, resent = false) => {
    const code = via === "sms" ? SMS_CODE : EMAIL_CODE
    const where = via === "sms" ? "your phone ending in 0123" : "k•••@" + (who.split("@")[1] ?? "example.com")
    return h(
      via === "sms" ? "Check your phone" : "Check your email",
      `<h1>${via === "sms" ? "Check your phone" : "Check your email"}</h1><p class="lede">We sent a 6-digit code ${via === "sms" ? "by text message" : "by email"} to ${esc(where)}. It expires in 10 minutes.</p>
      <form method="post" action="${url(slug, "/code")}" novalidate>${codeCarry(who, slug)}
      <label for="code">${via === "sms" ? "Code from the text message" : "Code from the email"}</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6">
      ${errorLine(error)}${resent ? `<p class="muted" id="resent">We sent a new code.</p>` : ""}
      <button type="submit" id="verify">Verify</button>
      <button type="submit" class="secondary" id="resend" name="resend" value="1" formnovalidate>Resend code</button></form>
      <div class="inbox">Demo ${via === "sms" ? "phone" : "inbox"}: your code is <strong id="sent-code">${code}</strong></div>`,
      slug,
    )
  }

  /** Where each two-step page goes after the password. */
  const afterPassword = (slug: string, who: string): Response => {
    switch (slug) {
      case "totp":
        return totpStep(slug, who, false)
      case "totp-split":
        return totpStep(slug, who, true)
      case "sms":
        return sentStep(slug, who, "sms")
      case "email-code":
        return sentStep(slug, who, "email")
      case "backup":
        return backupStep(who, false)
      case "mfa-picker":
        return pickerStep(who)
      case "number-match":
        return numberStep(who)
      case "security-questions":
        return questionsStep(who)
      case "remember-device":
        return rememberStep(who)
    }
    return h("Signed in", signedIn(who), slug)
  }

  const backupStep = (who: string, alnum: boolean, error?: string) =>
    h(
      "Use a backup code",
      `<h1>Use a backup code</h1><p class="lede">Enter one of the ${alnum ? "8-character" : "8-digit"} backup codes you saved when you turned on two-step verification. Each works once.</p>
      <form method="post" action="${url("backup", "/code")}" novalidate>${codeCarry(who, "backup")}<input type="hidden" name="alnum" value="${alnum ? 1 : 0}">
      <label for="backup-code">Backup code</label>${
        alnum
          ? `<input id="backup-code" name="code" maxlength="9" autocomplete="off" placeholder="XXXX-XXXX" autocapitalize="characters" spellcheck="false">`
          : `<input id="backup-code" name="code" maxlength="8" inputmode="numeric" autocomplete="one-time-code" placeholder="8-digit code">`
      }
      ${errorLine(error)}<button type="submit" id="verify">Verify</button></form>
      <p class="muted"><a id="other-kind" href="${url("backup", `/step?u=${encodeURIComponent(who)}&t=${ticket("backup", who)}&alnum=${alnum ? 0 : 1}`)}">${alnum ? "Use an 8-digit code" : "Use a code with letters"}</a></p>
      <div class="inbox">Demo backup codes: <strong>${BACKUP_CODES[0]}</strong> and <strong>${BACKUP_CODES[1]}</strong></div>`,
      "backup",
    )

  const pickerStep = (who: string) =>
    h(
      "Choose a verification method",
      `<h1>Choose a verification method</h1><p class="lede">How do you want to verify it's you?</p>
      <form method="post" action="${url("mfa-picker", "/choose")}">${codeCarry(who, "mfa-picker")}
        <label><input type="radio" name="method" value="totp" id="m-totp" checked> Authenticator app</label>
        <label><input type="radio" name="method" value="sms" id="m-sms"> Text message to •••• 0123</label>
        <label><input type="radio" name="method" value="email" id="m-email"> Email to k•••@${esc(who.split("@")[1] ?? "example.com")}</label>
        <button type="submit" id="continue">Continue</button></form>`,
      "mfa-picker",
    )

  const numberStep = (who: string) => {
    const n = 10 + Math.floor(Math.random() * 89)
    const t = ticket("number-match", who, "approved")
    return h(
      "Approve the sign-in",
      `<h1>Approve the sign-in</h1><p class="lede">Open the Gauntlet app on your phone and tap the number below.</p>
      <div style="font-size:64px;font-weight:700;text-align:center;letter-spacing:2px" id="number">${n}</div>
      <p class="muted" id="waiting" role="status">Waiting for your phone…</p>
      <div class="inbox">Demo phone: <button type="button" class="secondary" id="approve" style="display:inline-block;width:auto;padding:0 14px;margin:0 0 0 6px;height:30px;line-height:28px">Tap ${n}</button> (or wait 6 s)</div>`,
      "number-match",
      `const go=()=>location.assign(${JSON.stringify(url("number-match", "/approved"))}+"?u="+encodeURIComponent(${JSON.stringify(who)})+"&t="+${JSON.stringify(t)})
document.getElementById("approve").addEventListener("click",go);setTimeout(go,6000)`,
    )
  }

  const questionsStep = (who: string, error?: string) =>
    h(
      "Security questions",
      `<h1>Answer your security questions</h1><p class="lede">We don't recognise this device. Answer two of your security questions.</p>
      <form method="post" action="${url("security-questions", "/answers")}" novalidate>${codeCarry(who, "security-questions")}
        <label for="q1">What was the name of your first pet?</label><input id="q1" name="q1" type="text" autocomplete="off">
        <label for="q2">On what street did you grow up?</label><input id="q2" name="q2" type="password" autocomplete="off">
        ${errorLine(error)}<button type="submit" id="verify">Continue</button></form>
      <div class="inbox">Demo answers: <strong>Biscuit</strong> and <strong>Maple</strong> (any case)</div>`,
      "security-questions",
    )

  const rememberStep = (who: string) =>
    h(
      "Remember this device?",
      `<h1>Remember this device?</h1><p class="lede">Skip the code next time you sign in on this browser.</p>
      <form method="post" action="${url("remember-device", "/remember")}">${codeCarry(who, "remember-device")}
        <label><input type="checkbox" name="trust" id="trust" checked> Trust this browser for 30 days</label>
        <button type="submit" name="choice" value="yes" id="yes">Remember</button>
        <button type="submit" name="choice" value="no" class="secondary" id="no">Not now</button></form>`,
      "remember-device",
    )

  /** Step one of an identifier-first sign-in: the identifier alone. */
  const identifierStep = (slug: string, o: { label?: string; type?: string; ac?: string; error?: string; lede?: string; before?: string; value?: string } = {}) =>
    h(
      "Sign in",
      `<h1>Sign in</h1><p class="lede">${o.lede ?? "Use your Gauntlet account."}</p>
      <form method="post" action="${url(slug, "/password")}" novalidate>${o.before ?? ""}
        <label for="username">${o.label ?? "Email"}</label><input id="username" name="username" type="${o.type ?? "email"}" autocomplete="${o.ac ?? "username"}" value="${esc(o.value ?? "")}">
        ${errorLine(o.error)}<button type="submit" id="continue">Continue</button></form>`,
      slug,
    )

  /** Step two: the password for the identifier step one sent (shown, and carried in a hidden box). */
  const passwordStep = (slug: string, who: string, error?: string) =>
    h(
      "Enter your password",
      `<h1>Enter your password</h1><p class="lede" id="account">${esc(who)}</p>
      <form method="post" action="${url(slug, "/signin")}" novalidate>
        <input type="hidden" name="username" value="${esc(who)}" autocomplete="username">
        <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
        ${errorLine(error)}<button type="submit" id="submit">Sign in</button></form>
      <p class="muted"><a id="other" href="${url(slug)}">Use a different account</a></p>`,
      slug,
    )

  // ---- Client-side pages: shared login script ----

  /** Posts {username,password} from the given getters to /api/login and shows the result. */
  const clientLogin = (formSel: string, user: string, pass: string) =>
    `document.querySelector(${JSON.stringify(formSel)}).addEventListener("submit",async(e)=>{e.preventDefault();G.show(await G.post("login",{username:${user},password:${pass}}))})`

  const plainFields = (o: { userLabel?: string; userType?: string; userAc?: string; pwAc?: string; userAttrs?: string; pwAttrs?: string } = {}) =>
    `<label for="username">${o.userLabel ?? "Email or username"}</label><input id="username" name="username" type="${o.userType ?? "text"}" autocomplete="${o.userAc ?? "username"}" ${o.userAttrs ?? ""}>
     <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="${o.pwAc ?? "current-password"}" ${o.pwAttrs ?? ""}>`

  // ---- Index ----

  const index = () => {
    const groups = [...new Set(PAGES.map((p) => p.group))]
    return h(
      "The Gauntlet",
      `<h1>The Gauntlet</h1><p class="lede">One page per sign-in, MFA and form pattern. Each one works: it checks what you enter and says <em>Signed in</em> only for the right login and codes.</p>
      ${opts.hint ? `<p class="muted">${opts.hint}</p>` : ""}
      ${groups.map((g) => `<h2 style="font-size:15px;margin:22px 0 6px">${g}</h2><ul class="index">${PAGES.filter((p) => p.group === g).map((p) => `<li><a href="${url(p.slug)}">${esc(p.title)}</a> <span class="muted">${esc(p.blurb)}</span></li>`).join("")}</ul>`).join("")}`,
      undefined,
      undefined,
      { wide: true },
    )
  }

  // ---- Pages ----

  const months = `<option value="">Month</option>${["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"].map((m, i) => `<option value="${i + 1}">${m}</option>`).join("")}`
  const days = `<option value="">Day</option>${Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("")}`
  const years = `<option value="">Year</option>${Array.from({ length: 90 }, (_, i) => 2010 - i).map((y) => `<option value="${y}">${y}</option>`).join("")}`
  const REGIONS: Record<string, Array<[string, string]>> = {
    US: [["CA", "California"], ["NY", "New York"], ["TX", "Texas"], ["WA", "Washington"]],
    CA: [["BC", "British Columbia"], ["ON", "Ontario"], ["QC", "Quebec"]],
    AU: [["NSW", "New South Wales"], ["VIC", "Victoria"]],
  }

  /** A saved-profile page: echoes what was posted. */
  const savedProfile = async (req: Request, slug: string) => {
    const form = await req.formData()
    const rows = [...form.entries()].filter(([k]) => !k.startsWith("_")).map(([k, v]) => `<tr><td class="muted">${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")
    return h("Saved", `<div class="result" id="result" data-ok="1"><h1>Saved</h1><table>${rows}</table></div>`, slug)
  }

  const shadowLogin = (mode: "open" | "closed") =>
    h(
      "Sign in",
      `<h1>Sign in</h1><p class="lede">This form lives in a ${mode} shadow root.</p><div id="host"></div>`,
      `shadow-${mode}`,
      `const root=document.getElementById("host").attachShadow({mode:${JSON.stringify(mode)}})
root.innerHTML=\`<style>${STYLE.replace(/`/g, "")}</style><form id="f" novalidate>${plainFields().replace(/`/g, "")}<button type="submit" id="submit">Sign in</button></form>\`
root.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault();const r=await G.post("login",{username:root.getElementById("username").value,password:root.getElementById("password").value});if(r.ok)document.querySelector("main").innerHTML=r.html;else{const p=document.createElement("p");p.id="error";p.className="error";p.textContent=r.error;root.getElementById("f").append(p)}})
// Tests can't reach into a closed root; the page's own script answers for it.
window.__gauntletClosed={value:(id)=>root.getElementById(id).value,rect:(id)=>root.getElementById(id).getBoundingClientRect().toJSON()}`,
    )

  const pages: Record<string, (req: Request, u: URL, rest: string, form: () => Promise<Record<string, string>>) => Response | Promise<Response>> = {
    // ---- Sign-in ----
    basic: async (req, _u, _r, form) => {
      if (req.method !== "POST") return h("Sign in", `<h1>Sign in</h1><p class="lede">Use your Gauntlet account.</p>${loginForm(url("basic"), { extra: `<label style="display:flex;gap:8px;align-items:center"><input type="checkbox" name="remember"> Remember me</label>` })}<p class="muted"><a href="${url("reset")}">Forgot your password?</a></p>`, "basic")
      const f = await form()
      const a = login(f.username, f.password)
      if (a) return h("Signed in", signedIn(a.username), "basic")
      return h("Sign in", `<h1>Sign in</h1>${loginForm(url("basic"), { user: f.username })}${errorLine("That email or password isn't right.")}`, "basic")
    },
    "identifier-first": (req, u, rest, form) => idFirst("identifier-first", req, u, rest, form),
    "remember-device": async (req, u, rest, form) => {
      if (rest === "/remember" && req.method === "POST") {
        const f = await form()
        if (f.ticket !== ticket("remember-device", f.username)) return h("Sign in", `<h1>Session expired</h1><a href="${url("remember-device")}">Start again</a>`, "remember-device")
        return h("Signed in", signedIn(f.username, `<p class="muted" id="trusted">${f.choice === "yes" ? "This browser is remembered." : "This browser isn't remembered."}</p>`), "remember-device")
      }
      return idFirst("remember-device", req, u, rest, form)
    },
    pin: async (req, _u, _r, form) => {
      const body = (user = "", error?: string) =>
        `<h1>Sign in with your PIN</h1><p class="lede">Your username and 6-digit PIN.</p><form method="post" action="${url("pin")}" novalidate>
          <label for="username">Username</label><input id="username" name="username" autocomplete="username" value="${esc(user)}">
          <label for="pin">PIN</label><input id="pin" name="pin" type="password" inputmode="numeric" maxlength="6" autocomplete="current-password">
          ${errorLine(error)}<button type="submit" id="submit">Sign in</button></form>`
      if (req.method !== "POST") return h("Sign in", body(), "pin")
      const f = await form()
      const a = login(f.username, f.pin)
      return a ? h("Signed in", signedIn(a.username), "pin") : h("Sign in", body(f.username, "That username or PIN isn't right."), "pin")
    },
    phone: async (req, _u, rest, form) => {
      const codes = `<option value="+1" selected>🇺🇸 +1</option><option value="+44">🇬🇧 +44</option><option value="+49">🇩🇪 +49</option><option value="+81">🇯🇵 +81</option>`
      const first = (error?: string) =>
        h(
          "Sign in",
          `<h1>Sign in</h1><p class="lede">With your mobile number.</p><form method="post" action="${url("phone", "/password")}" novalidate>
            <label for="phone">Mobile number</label><div class="row" style="gap:8px"><select id="country-code" name="cc" aria-label="Country code" style="flex:0 0 96px">${codes}</select>
            <input id="phone" name="phone" type="tel" autocomplete="tel-national" inputmode="tel" placeholder="(415) 555-0123"></div>
            ${errorLine(error)}<button type="submit" id="continue">Continue</button></form>`,
          "phone",
        )
      if (req.method !== "POST") return first()
      const f = await form()
      if (rest === "/password") {
        const who = `${f.cc ?? ""} ${f.phone ?? ""}`.trim()
        const a = find(who) ?? find(f.phone ?? "")
        if (!a) return first("We can't find an account with that number.")
        return passwordStep("phone", who)
      }
      const a = login(f.username, f.password)
      return a ? h("Signed in", signedIn(a.username), "phone") : passwordStep("phone", f.username, "That password isn't right.")
    },
    bank: async (req, _u, _r, form) => {
      const body = (error?: string) =>
        `<h1>Online banking</h1><p class="lede">Log on with your customer number.</p><form method="post" action="${url("bank")}" novalidate>
          <label for="customer">Customer number</label><input id="customer" name="customer" inputmode="numeric" autocomplete="username" placeholder="8 digits">
          <label id="dob-label">Date of birth</label><div class="row" role="group" aria-labelledby="dob-label">
            <input id="dob-day" name="dob-day" inputmode="numeric" maxlength="2" placeholder="DD" aria-label="Day of birth" autocomplete="bday-day">
            <input id="dob-month" name="dob-month" inputmode="numeric" maxlength="2" placeholder="MM" aria-label="Month of birth" autocomplete="bday-month">
            <input id="dob-year" name="dob-year" inputmode="numeric" maxlength="4" placeholder="YYYY" aria-label="Year of birth" autocomplete="bday-year"></div>
          <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
          ${errorLine(error)}<button type="submit" id="submit">Log on</button></form>`
      if (req.method !== "POST") return h("Online banking", body(), "bank")
      const f = await form()
      const a = login(f.customer, f.password)
      const dob = `${f["dob-year"]}-${String(f["dob-month"]).padStart(2, "0")}-${String(f["dob-day"]).padStart(2, "0")}`
      if (a && (!a.birthday || a.birthday === dob)) return h("Signed in", signedIn(a.username), "bank")
      return h("Online banking", body(a ? "That date of birth doesn't match." : "Those details don't match our records."), "bank")
    },
    reveal: async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const a = login(f.username, f.password)
        return a ? h("Signed in", signedIn(a.username), "reveal") : h("Sign in", `<h1>Sign in</h1>${errorLine("That email or password isn't right.")}<a href="${url("reveal")}">Try again</a>`, "reveal")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">The password box shows once you start typing.</p><form method="post" action="${url("reveal")}" novalidate>
          <label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username">
          <div id="pw" style="display:none"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password"></div>
          <button type="submit" id="submit">Sign in</button></form>`,
        "reveal",
        `const u=document.getElementById("username");const show=()=>{document.getElementById("pw").style.display=u.value?"block":"none"};u.addEventListener("input",show);u.addEventListener("change",show)`,
      )
    },

    // ---- Codes and MFA ----
    totp: (req, u, rest, form) => twoStep("totp", req, u, rest, form),
    "totp-split": (req, u, rest, form) => twoStep("totp-split", req, u, rest, form),
    backup: (req, u, rest, form) => twoStep("backup", req, u, rest, form),
    sms: (req, u, rest, form) => twoStep("sms", req, u, rest, form),
    "email-code": (req, u, rest, form) => twoStep("email-code", req, u, rest, form),
    "mfa-picker": async (req, u, rest, form) => {
      if (rest === "/methods") {
        const who = u.searchParams.get("u") ?? ""
        return u.searchParams.get("t") === ticket("mfa-picker", who) ? pickerStep(who) : h("Sign in", `<a href="${url("mfa-picker")}">Start again</a>`, "mfa-picker")
      }
      if (rest === "/choose" && req.method === "POST") {
        const f = await form()
        if (f.ticket !== ticket("mfa-picker", f.username)) return h("Sign in", `<a href="${url("mfa-picker")}">Start again</a>`, "mfa-picker")
        const to = f.method === "sms" ? "sms" : f.method === "email" ? "email-code" : "totp"
        return to === "totp" ? totpStep("totp", f.username, false) : sentStep(to, f.username, to === "sms" ? "sms" : "email")
      }
      return twoStep("mfa-picker", req, u, rest, form)
    },
    "number-match": async (req, u, rest, form) => {
      if (rest === "/approved") {
        const who = u.searchParams.get("u") ?? ""
        return u.searchParams.get("t") === ticket("number-match", who, "approved") ? h("Signed in", signedIn(who), "number-match") : h("Sign in", `<a href="${url("number-match")}">Start again</a>`, "number-match")
      }
      return twoStep("number-match", req, u, rest, form)
    },
    "security-questions": async (req, u, rest, form) => {
      if (rest === "/answers" && req.method === "POST") {
        const f = await form()
        if (f.ticket !== ticket("security-questions", f.username)) return h("Sign in", `<a href="${url("security-questions")}">Start again</a>`, "security-questions")
        if (norm(f.q1 ?? "") === ANSWERS.pet && norm(f.q2 ?? "") === ANSWERS.street) return h("Signed in", signedIn(f.username), "security-questions")
        return questionsStep(f.username, "Those answers don't match.")
      }
      return twoStep("security-questions", req, u, rest, form)
    },
    "magic-link": async (req, u, rest, form) => {
      if (rest === "/open") {
        const who = u.searchParams.get("u") ?? ""
        return u.searchParams.get("t") === ticket("magic-link", who) ? h("Signed in", signedIn(who), "magic-link") : h("Link expired", `<h1>That link has expired</h1><a href="${url("magic-link")}">Send a new one</a>`, "magic-link")
      }
      if (req.method === "POST") {
        const f = await form()
        const a = find(f.username)
        if (!a) return identifierStep("magic-link", { error: "We can't find that account.", lede: "We'll email you a link to sign in. No password needed." })
        const link = url("magic-link", `/open?u=${encodeURIComponent(a.username)}&t=${ticket("magic-link", a.username)}`)
        return h(
          "Check your email",
          `<h1>Check your email</h1><p class="lede">We sent a sign-in link to <strong>${esc(a.username)}</strong>. Open it on this device to finish signing in.</p>
          <p class="muted">Didn't get it? Check your spam folder, or <a href="${url("magic-link")}">send another</a>.</p>
          <div class="inbox">Demo inbox: <a id="magic" href="${link}">Sign in to the Gauntlet</a></div>`,
          "magic-link",
        )
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">We'll email you a link to sign in. No password needed.</p>
        <form method="post" action="${url("magic-link")}" novalidate><label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username">
        <button type="submit" id="continue">Email me a link</button></form>`,
        "magic-link",
      )
    },
    passkey: () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Passkeys first; a password if you don't have one.</p>
        <form id="f" novalidate>
          <label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username webauthn">
          <div id="pw" hidden><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password"></div>
          <button type="button" id="passkey">Sign in with a passkey</button>
          <button type="submit" id="submit" class="secondary" hidden>Sign in</button>
          <p class="muted" id="status" role="status"></p></form>
        <p class="muted"><a href="#" id="use-password">Use your password instead</a></p>`,
        "passkey",
        `const pw=document.getElementById("pw"),submit=document.getElementById("submit"),status=document.getElementById("status")
const usePassword=()=>{pw.hidden=false;submit.hidden=false;document.getElementById("use-password").hidden=true;submit.classList.remove("secondary")}
document.getElementById("use-password").addEventListener("click",(e)=>{e.preventDefault();usePassword();document.getElementById("password").focus()})
document.getElementById("passkey").addEventListener("click",async()=>{
  if(!window.PublicKeyCredential||!isSecureContext){status.textContent="Passkeys need a secure page. Use your password instead.";usePassword();return}
  try{await navigator.credentials.get({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),timeout:60000,userVerification:"preferred",allowCredentials:[]}});status.textContent="This demo has no passkeys registered. Use your password instead."}catch(e){status.textContent="No passkey was used. Use your password instead."}
  usePassword()})
${clientLogin("#f", 'document.getElementById("username").value', 'document.getElementById("password").value')}`,
      ),

    // ---- Identity ----
    "dob-selects": async (req) => {
      if (req.method === "POST") return savedProfile(req, "dob-selects")
      return h(
        "Your profile",
        `<h1>Your profile</h1><p class="lede">We need a few details to open your account.</p><form method="post" action="${url("dob-selects")}">
          <div class="row"><div><label for="first">First name</label><input id="first" name="first" autocomplete="given-name"></div><div><label for="last">Last name</label><input id="last" name="last" autocomplete="family-name"></div></div>
          <label id="dob">Date of birth</label><div class="row" role="group" aria-labelledby="dob">
            <select id="dob-month" name="dob-month" aria-label="Month" autocomplete="bday-month">${months}</select>
            <select id="dob-day" name="dob-day" aria-label="Day" autocomplete="bday-day">${days}</select>
            <select id="dob-year" name="dob-year" aria-label="Year" autocomplete="bday-year">${years}</select></div>
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email">
          <button type="submit" id="submit">Save</button></form>`,
        "dob-selects",
      )
    },
    "dob-date": async (req) => {
      if (req.method === "POST") return savedProfile(req, "dob-date")
      return h(
        "Your profile",
        `<h1>Your profile</h1><p class="lede">Tell us about yourself.</p><form method="post" action="${url("dob-date")}">
          <label for="fullname">Full name</label><input id="fullname" name="fullname" autocomplete="name">
          <label for="birthday">Birthday</label><input id="birthday" name="birthday" type="date">
          <label for="tel">Phone</label><input id="tel" name="tel" type="tel" autocomplete="tel">
          <button type="submit" id="submit">Save</button></form>`,
        "dob-date",
      )
    },
    "dob-masked": async (req) => {
      if (req.method === "POST") return savedProfile(req, "dob-masked")
      return h(
        "Your profile",
        `<h1>Your profile</h1><p class="lede">As it appears on your ID.</p><form method="post" action="${url("dob-masked")}">
          <label for="given">First name</label><input id="given" name="given">
          <label for="middle">Middle name</label><input id="middle" name="middle">
          <label for="family">Last name</label><input id="family" name="family">
          <label for="dob">Date of birth</label><input id="dob" name="dob" inputmode="numeric" placeholder="MM/DD/YYYY" maxlength="10">
          <button type="submit" id="submit">Save</button></form>`,
        "dob-masked",
        `const d=document.getElementById("dob");d.addEventListener("input",()=>{const n=d.value.replace(/\\D/g,"").slice(0,8);d.value=[n.slice(0,2),n.slice(2,4),n.slice(4)].filter(Boolean).join("/")})`,
      )
    },
    "address-cascade": async (req) => {
      if (req.method === "POST") return savedProfile(req, "address-cascade")
      return h(
        "Shipping address",
        `<h1>Shipping address</h1><p class="lede">Pick the country first; its states load after.</p><form method="post" action="${url("address-cascade")}">
          <label for="name">Full name</label><input id="name" name="name" autocomplete="name">
          <label for="country">Country</label><select id="country" name="country" autocomplete="country"><option value="">Choose…</option><option value="AU">Australia</option><option value="CA">Canada</option><option value="US">United States</option></select>
          <label for="line1">Address</label><input id="line1" name="line1" autocomplete="address-line1">
          <label for="city">City</label><input id="city" name="city" autocomplete="address-level2">
          <div class="row"><div><label for="state">State / province</label><select id="state" name="state" autocomplete="address-level1" disabled><option value="">Choose a country first</option></select></div>
          <div><label for="zip">ZIP / postal code</label><input id="zip" name="zip" autocomplete="postal-code"></div></div>
          <button type="submit" id="submit">Save</button></form>`,
        "address-cascade",
        `const REGIONS=${JSON.stringify(REGIONS)};const c=document.getElementById("country"),s=document.getElementById("state")
c.addEventListener("change",()=>{s.disabled=true;s.innerHTML='<option value="">Loading…</option>';setTimeout(()=>{const list=REGIONS[c.value]||[];s.innerHTML='<option value="">Choose…</option>'+list.map(([v,n])=>'<option value="'+v+'">'+n+'</option>').join("");s.disabled=!list.length},300)})`,
      )
    },

    // ---- Tricky DOM ----
    "shadow-open": () => shadowLogin("open"),
    "shadow-closed": () => shadowLogin("closed"),
    "web-component": () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Each field is its own custom element with a shadow root.</p>
        <form id="f" novalidate><g-field id="user" label="Email" type="email" autocomplete="username" name="username"></g-field>
        <g-field id="pass" label="Password" type="password" autocomplete="current-password" name="password"></g-field>
        <button type="submit" id="submit">Sign in</button></form>`,
        "web-component",
        `class GField extends HTMLElement{static formAssociated=true
constructor(){super();this.internals=this.attachInternals();const r=this.attachShadow({mode:"open",delegatesFocus:true})
r.innerHTML='<style>label{display:block;font-size:13px;margin:12px 0 4px}input{box-sizing:border-box;width:100%;height:38px;padding:0 10px;border:1px solid #d6d3d1;border-radius:8px;font:inherit;background:transparent;color:inherit}</style><label for="i"></label><input id="i">'
const i=r.getElementById("i");r.querySelector("label").textContent=this.getAttribute("label");i.type=this.getAttribute("type")||"text";i.autocomplete=this.getAttribute("autocomplete")||"";i.name=this.getAttribute("name")||""
i.addEventListener("input",()=>this.internals.setFormValue(i.value));this.input=i}
get value(){return this.input.value}}
customElements.define("g-field",GField)
${clientLogin("#f", 'document.getElementById("user").value', 'document.getElementById("pass").value')}`,
      ),
    "iframe-same-origin": (_req, u) => framed("iframe-same-origin", u.origin, u),
    "iframe-same-site": (_req, u) => framed("iframe-same-site", opts.sameSiteOrigin?.(u) ?? null, u),
    "iframe-cross-site": (_req, u) => framed("iframe-cross-site", opts.crossSiteOrigin?.(u) ?? null, u),
    "frame-login": (req, _u, _r, form) => frameLogin(req, form),
    react: () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Controlled inputs: state changes only through the value tracker, as React's do.</p><form id="f" novalidate>${plainFields()}<p class="muted">State: <code id="state">{}</code></p><button type="submit" id="submit">Sign in</button></form>`,
        "react",
        `// React keeps the last value it rendered on the node (its "value tracker"): an input event whose value matches it is ignored, and every render writes the state back.
const state={username:"",password:""};const show=()=>document.getElementById("state").textContent=JSON.stringify({username:state.username,password:state.password?"•".repeat(state.password.length):""})
for(const id of ["username","password"]){const el=document.getElementById(id);const proto=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value");let tracked=""
Object.defineProperty(el,"value",{configurable:true,get(){return proto.get.call(this)},set(v){tracked=String(v);proto.set.call(this,v)}})
const render=()=>{if(proto.get.call(el)!==state[id]){tracked=state[id];proto.set.call(el,state[id])}}
el.addEventListener("input",()=>{const now=proto.get.call(el);if(now===tracked)return;tracked=now;state[id]=now;show()})
el.addEventListener("change",()=>{});el.addEventListener("blur",render);setInterval(render,250)}
show()
document.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault();G.show(await G.post("login",state))})`,
      ),
    vue: () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">v-model style: state from input events only, written back on each tick.</p><form id="f" novalidate>${plainFields()}<p class="muted">State: <code id="state">{}</code></p><button type="submit" id="submit">Sign in</button></form>`,
        "vue",
        `const state={username:"",password:""};let composing=false
const show=()=>document.getElementById("state").textContent=JSON.stringify({username:state.username,password:state.password?"•".repeat(state.password.length):""})
for(const id of ["username","password"]){const el=document.getElementById(id)
el.addEventListener("compositionstart",()=>composing=true);el.addEventListener("compositionend",()=>{composing=false;el.dispatchEvent(new Event("input"))})
el.addEventListener("input",()=>{if(composing)return;state[id]=el.value;show()})}
const tick=()=>{for(const id of ["username","password"]){const el=document.getElementById(id);if(el.value!==state[id]&&document.activeElement!==el)el.value=state[id]}requestAnimationFrame(tick)};tick();show()
document.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault();G.show(await G.post("login",state))})`,
      ),
    "clear-on-focus": () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Both boxes empty themselves whenever they're focused.</p><form id="f" novalidate>${plainFields()}<button type="submit" id="submit">Sign in</button></form>`,
        "clear-on-focus",
        `for(const id of ["username","password"])document.getElementById(id).addEventListener("focus",(e)=>{e.target.value=""})
${clientLogin("#f", 'document.getElementById("username").value', 'document.getElementById("password").value')}`,
      ),
    late: () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede" id="loading" role="status">Loading…</p><div id="slot"></div>`,
        "late",
        `setTimeout(()=>{document.getElementById("loading").textContent="Use your Gauntlet account.";document.getElementById("slot").innerHTML='<form id="f" novalidate>'+${JSON.stringify(plainFields())}+'<button type="submit" id="submit">Sign in</button></form>';${clientLogin("#f", 'document.getElementById("username").value', 'document.getElementById("password").value')}},2000)`,
      ),
    rerender: () =>
      h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Every keystroke re-renders the form with new input elements.</p><form id="f" novalidate><div id="fields"></div><button type="submit" id="submit">Sign in</button></form>`,
        "rerender",
        `const state={username:"",password:""};let renders=0
const render=(focus,caret)=>{renders++;const box=document.getElementById("fields");box.innerHTML=${JSON.stringify(plainFields())}+'<p class="muted">Renders: <span id="renders">'+renders+'</span></p>'
for(const id of ["username","password"]){const el=document.getElementById(id);el.value=state[id];el.addEventListener("input",()=>{state[id]=el.value;const at=el.selectionStart;queueMicrotask(()=>render(id,at))})}
if(focus){const el=document.getElementById(focus);el.focus();try{el.setSelectionRange(caret,caret)}catch{}}}
render();document.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault();G.show(await G.post("login",state))})`,
      ),
    spa: () =>
      h(
        "Sign in",
        `<div id="app"></div>`,
        "spa",
        `const app=document.getElementById("app");let who="";const base=G.base+"/spa"
const views={
  "":()=>'<h1>Sign in</h1><p class="lede">One document; each step is a route.</p><form id="f" novalidate><label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username"><p class="error" id="error" role="alert"></p><button type="submit" id="continue">Continue</button></form>',
  "/password":()=>'<h1>Enter your password</h1><p class="lede">'+who.replace(/[<>&]/g,"")+'</p><form id="f" novalidate><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password"><p class="error" id="error" role="alert"></p><button type="submit" id="submit">Sign in</button></form>',
  "/code":()=>'<h1>Two-step verification</h1><p class="lede">Enter the code from your authenticator app.</p><form id="f" novalidate><label for="code">Authentication code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><p class="error" id="error" role="alert"></p><button type="submit" id="verify">Verify</button></form>'}
const go=(route,push=true)=>{if(push)history.pushState({route},"",base+route);document.title=route==="/code"?"Two-step verification":route==="/password"?"Enter your password":"Sign in";app.innerHTML=views[route]();bind(route)}
const fail=(m)=>{document.getElementById("error").textContent=m}
const bind=(route)=>document.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault()
  if(route===""){who=document.getElementById("username").value;const r=await G.post("exists",{username:who});r.ok?go("/password"):fail(r.error)}
  else if(route==="/password"){const r=await G.post("password",{username:who,password:document.getElementById("password").value});if(!r.ok)return fail(r.error);r.code?(window.__t=r.ticket,go("/code")):(app.innerHTML=r.html)}
  else{const r=await G.post("code",{username:who,code:document.getElementById("code").value,ticket:window.__t});r.ok?(history.pushState({},"",base+"/home"),app.innerHTML=r.html):fail(r.error)}})
addEventListener("popstate",(e)=>go(e.state&&e.state.route||"",false));go("",false)`,
      ),
    dialog: () =>
      h(
        "Welcome",
        `<h1>Welcome to the Gauntlet</h1><p class="lede">The sign-in form opens in a modal dialog.</p><button type="button" id="open">Sign in</button>
        <dialog id="d" style="border:1px solid var(--line);border-radius:14px;padding:24px;width:340px;background:var(--card);color:var(--fg)"><h2 style="margin:0 0 8px;font-size:18px">Sign in</h2><form id="f" novalidate>${plainFields()}<button type="submit" id="submit">Sign in</button><button type="button" class="secondary" id="close">Cancel</button></form></dialog>`,
        "dialog",
        `const d=document.getElementById("d");document.getElementById("open").addEventListener("click",()=>d.showModal());document.getElementById("close").addEventListener("click",()=>d.close())
document.getElementById("f").addEventListener("submit",async(e)=>{e.preventDefault();const r=await G.post("login",{username:document.getElementById("username").value,password:document.getElementById("password").value});if(r.ok){d.close();document.querySelector("main").innerHTML=r.html}else{let p=document.getElementById("error");if(!p){p=document.createElement("p");p.id="error";p.className="error";document.getElementById("f").append(p)}p.textContent=r.error}})`,
      ),
    "many-forms": () =>
      h(
        "Gauntlet",
        `<form id="search" role="search" action="${url("many-forms")}" style="margin-bottom:18px"><label for="q">Search the docs</label><input id="q" name="q" type="search" placeholder="Search"></form>
        <h1>Sign in</h1><form id="login" novalidate>${plainFields()}<button type="submit" id="submit">Sign in</button></form>
        <hr style="border:0;border-top:1px solid var(--line);margin:24px 0"><h2 style="font-size:16px;margin:0">Newsletter</h2><p class="muted">Subscribe to our newsletter for monthly updates.</p>
        <form id="news" novalidate><label for="news-email">Email address</label><input id="news-email" name="email" type="email" autocomplete="email" placeholder="you@example.com"><button type="submit" id="subscribe" class="secondary">Subscribe</button></form>`,
        "many-forms",
        `${clientLogin("#login", 'document.getElementById("username").value', 'document.getElementById("password").value')}
document.getElementById("news").addEventListener("submit",(e)=>{e.preventDefault();e.target.innerHTML='<p id="subscribed">Thanks for subscribing.</p>'})`,
      ),
    honeypot: async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const trapped = ["email", "website", "login", "pass2"].filter((k) => f[k])
        if (trapped.length) return h("Blocked", `<h1>Blocked</h1><p id="trapped">A bot filled the honeypot fields: ${esc(trapped.join(", "))}.</p>`, "honeypot")
        const a = login(f.username, f.password)
        return a ? h("Signed in", signedIn(a.username), "honeypot") : h("Sign in", `<h1>Sign in</h1>${errorLine("That email or password isn't right.")}`, "honeypot")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Four hidden traps sit around the real boxes.</p><form method="post" action="${url("honeypot")}" novalidate>
          <div style="position:absolute;left:-9999px" aria-hidden="true"><label for="hp-email">Email</label><input id="hp-email" name="email" type="email" autocomplete="username" tabindex="-1"></div>
          <label for="username">Username</label><input id="username" name="username" autocomplete="username">
          <input id="hp-login" name="login" type="text" style="display:none" autocomplete="username">
          <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
          <div style="opacity:0;height:1px;overflow:hidden"><input id="hp-pass2" name="pass2" type="password" autocomplete="current-password" tabindex="-1"></div>
          <input id="hp-website" name="website" type="text" style="width:1px;height:1px;border:0;padding:0" tabindex="-1" aria-hidden="true">
          <button type="submit" id="submit">Sign in</button></form>`,
        "honeypot",
      )
    },
    "autocomplete-off": async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const a = login(f.user, f.pass)
        return a ? h("Signed in", signedIn(a.username), "autocomplete-off") : h("Sign in", `<h1>Sign in</h1>${errorLine("That username or password isn't right.")}`, "autocomplete-off")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">This site asks browsers not to autofill.</p><form method="post" action="${url("autocomplete-off")}" autocomplete="off" novalidate>
          <label for="user">Username</label><input id="user" name="user" autocomplete="off">
          <label for="pass">Password</label><input id="pass" name="pass" type="password" autocomplete="off">
          <button type="submit" id="submit">Sign in</button></form>`,
        "autocomplete-off",
      )
    },
    misleading: async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        // The names lie: "password" holds the username and "email" the password.
        const a = login(f.password, f.email)
        return a ? h("Signed in", signedIn(a.username), "misleading") : h("Sign in", `<h1>Sign in</h1>${errorLine("That username or password isn't right.")}`, "misleading")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">The ids and names lie; the labels and types don't.</p><form method="post" action="${url("misleading")}" novalidate>
          <label for="password-field">Username</label><input id="password-field" name="password" class="pw-input" autocomplete="username">
          <label for="email-field">Password</label><input id="email-field" name="email" type="password" class="email-input">
          <button type="submit" id="submit">Sign in</button></form>`,
        "misleading",
      )
    },
    "css-masked": async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const a = login(f.username, f.secret)
        return a ? h("Signed in", signedIn(a.username), "css-masked") : h("Sign in", `<h1>Sign in</h1>${errorLine("That username or password isn't right.")}`, "css-masked")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">The password box is type=text, masked by CSS.</p><form method="post" action="${url("css-masked")}" novalidate>
          <label for="username">Username</label><input id="username" name="username" autocomplete="username">
          <label for="secret">Password</label><input id="secret" name="secret" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" style="-webkit-text-security:disc;text-security:disc">
          <button type="submit" id="submit">Sign in</button></form>`,
        "css-masked",
      )
    },
    "virtual-keyboard": async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const a = find(f.username)
        const pin = a?.pin ?? KEYPAD_PIN
        return a && f.pin === pin ? h("Signed in", signedIn(a.username), "virtual-keyboard") : h("Sign in", `<h1>Sign in</h1>${errorLine("That username or PIN isn't right.")}<a href="${url("virtual-keyboard")}">Try again</a>`, "virtual-keyboard")
      }
      // The keypad is shuffled, as banks do, so a recorded click pattern doesn't replay.
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Your username, then your PIN on the keypad. The PIN box takes no typing.</p><form method="post" action="${url("virtual-keyboard")}" novalidate>
          <label for="username">Username</label><input id="username" name="username" autocomplete="username">
          <label for="pin">PIN</label><input id="pin" name="pin" type="password" readonly autocomplete="off" placeholder="Use the keypad">
          <div id="keypad" style="display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin-top:10px"></div>
          <button type="submit" id="submit">Sign in</button></form>
          <p class="muted">Demo PIN: ${KEYPAD_PIN}</p>`,
        "virtual-keyboard",
        `const pin=document.getElementById("pin"),pad=document.getElementById("keypad");const keys=[..."0123456789"].sort(()=>Math.random()-.5)
for(const k of [...keys,"⌫"]){const b=document.createElement("button");b.type="button";b.textContent=k;b.dataset.key=k;b.style.cssText="margin:0;height:40px";b.className="secondary";b.addEventListener("click",()=>{pin.value=k==="⌫"?pin.value.slice(0,-1):(pin.value+k).slice(0,6)});pad.append(b)}`,
      )
    },
    "no-paste": async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const a = login(f.username, f.password)
        return a ? h("Signed in", signedIn(a.username), "no-paste") : h("Sign in", `<h1>Sign in</h1>${errorLine("That username or password isn't right.")}`, "no-paste")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">Pasting is blocked on both boxes. <span id="blocked"></span></p>${loginForm(url("no-paste"), { userAttrs: `onpaste="return false" ondrop="return false"`, pwAttrs: `onpaste="return false" ondrop="return false" oncopy="return false"` })}`,
        "no-paste",
        `for(const id of ["username","password"])document.getElementById(id).addEventListener("paste",(e)=>{e.preventDefault();document.getElementById("blocked").textContent="(Paste blocked.)"})`,
      )
    },
    rules: async (req, _u, _r, form) => {
      if (req.method === "POST") {
        const f = await form()
        const a = login(f.username, f.password)
        return a ? h("Signed in", signedIn(a.username), "rules") : h("Sign in", `<h1>Sign in</h1>${errorLine("That username or password isn't right.")}<a href="${url("rules")}">Try again</a>`, "rules")
      }
      return h(
        "Sign in",
        `<h1>Sign in</h1><p class="lede">The browser checks maxlength, minlength and pattern before it submits.</p><form method="post" action="${url("rules")}">
          <label for="username">Email or username</label><input id="username" name="username" autocomplete="username" required maxlength="40" pattern="[A-Za-z0-9@._+\\-]{3,40}" title="3 to 40 letters, digits or @._+-">
          <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required minlength="6" maxlength="64">
          <button type="submit" id="submit">Sign in</button></form>`,
        "rules",
      )
    },

    // ---- Other flows ----
    signup: async (req, _u, _r, form) => {
      const RULES = "minlength: 14; maxlength: 24; required: lower; required: upper; required: digit; required: [-_!@#];"
      const body = (email = "", error?: string) =>
        `<h1>Create your account</h1><p class="lede">14 to 24 characters with upper and lower case, a digit and one of - _ ! @ #.</p><form method="post" action="${url("signup")}" novalidate>
          <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" value="${esc(email)}">
          <label for="new-password">Password</label><input id="new-password" name="password" type="password" autocomplete="new-password" minlength="14" maxlength="24" passwordrules="${RULES}">
          <label for="confirm-password">Confirm password</label><input id="confirm-password" name="confirm" type="password" autocomplete="new-password" maxlength="24">
          <ul class="muted" id="checks" style="padding-left:18px;margin:8px 0 0"></ul>
          <label style="display:flex;gap:8px;align-items:center"><input type="checkbox" name="terms" id="terms"> I agree to the terms of service</label>
          ${errorLine(error)}<button type="submit" id="submit">Create account</button></form><p class="muted">Already have an account? <a href="${url("basic")}">Sign in</a></p>`
      if (req.method === "POST") {
        const f = await form()
        const p = f.password ?? ""
        const why =
          !/^\S+@\S+\.\S+$/.test(f.email ?? "") ? "Enter an email address."
          : p.length < 14 || p.length > 24 ? "Use 14 to 24 characters."
          : !/[a-z]/.test(p) || !/[A-Z]/.test(p) || !/\d/.test(p) || !/[-_!@#]/.test(p) ? "Use upper and lower case, a digit and one of - _ ! @ #."
          : /[^A-Za-z0-9\-_!@#]/.test(p) ? "Only letters, digits and - _ ! @ # are allowed."
          : p !== f.confirm ? "The passwords don't match."
          : null
        if (why) return h("Create your account", body(f.email, why), "signup", signupScript)
        return h("Welcome", `<div class="result" id="result" data-ok="1"><h1>Account created</h1><p>Welcome, <strong id="who">${esc(f.email)}</strong>. (Demo: nothing is stored.)</p></div>`, "signup")
      }
      return h("Create your account", body(), "signup", signupScript)
    },
    "change-password": async (req, _u, _r, form) => {
      const body = (error?: string) =>
        `<h1>Change your password</h1><p class="lede">Signed in as ${esc(opts.accounts[0]?.username)}.</p><form method="post" action="${url("change-password")}" novalidate>
          <input type="text" name="username" autocomplete="username" value="${esc(opts.accounts[0]?.username)}" hidden>
          <label for="current">Current password</label><input id="current" name="current" type="password" autocomplete="current-password">
          <label for="new">New password</label><input id="new" name="new" type="password" autocomplete="new-password" minlength="12">
          <label for="confirm">Confirm new password</label><input id="confirm" name="confirm" type="password" autocomplete="new-password">
          ${errorLine(error)}<button type="submit" id="submit">Change password</button></form>`
      if (req.method !== "POST") return h("Change password", body(), "change-password")
      const f = await form()
      const why = !opts.accounts.some((a) => a.password === f.current) ? "Your current password isn't right." : (f.new ?? "").length < 12 ? "Use at least 12 characters." : f.new !== f.confirm ? "The new passwords don't match." : f.new === f.current ? "Choose a password you haven't used." : null
      if (why) return h("Change password", body(why), "change-password")
      return h("Password changed", `<div class="result" id="result" data-ok="1"><h1>Password changed</h1><p>(Demo: nothing is stored; your old password still works here.)</p></div>`, "change-password")
    },
    reset: async (req, u, rest, form) => {
      if (rest === "/new") {
        const who = u.searchParams.get("u") ?? (req.method === "POST" ? "" : "")
        if (req.method === "POST") {
          const f = await form()
          if (f.ticket !== ticket("reset", f.username)) return h("Link expired", `<h1>That link has expired</h1>`, "reset")
          const why = (f.password ?? "").length < 12 ? "Use at least 12 characters." : f.password !== f.confirm ? "The passwords don't match." : null
          if (!why) return h("Password reset", `<div class="result" id="result" data-ok="1"><h1>Password reset</h1><p>You can sign in with your new password. (Demo: nothing is stored.)</p></div>`, "reset")
          return h("Choose a new password", resetNew(f.username, why), "reset")
        }
        if (u.searchParams.get("t") !== ticket("reset", who)) return h("Link expired", `<h1>That link has expired</h1><a href="${url("reset")}">Start again</a>`, "reset")
        return h("Choose a new password", resetNew(who), "reset")
      }
      if (req.method === "POST") {
        const f = await form()
        const a = find(f.username)
        const link = a ? url("reset", `/new?u=${encodeURIComponent(a.username)}&t=${ticket("reset", a.username)}`) : null
        return h(
          "Check your email",
          `<h1>Check your email</h1><p class="lede">If an account uses that address, we sent it a link to reset the password.</p>${link ? `<div class="inbox">Demo inbox: <a id="reset-link" href="${link}">Reset your password</a></div>` : ""}`,
          "reset",
        )
      }
      return h(
        "Reset your password",
        `<h1>Reset your password</h1><p class="lede">Enter your email and we'll send you a reset link.</p><form method="post" action="${url("reset")}" novalidate>
          <label for="username">Email</label><input id="username" name="username" type="email" autocomplete="username">
          <button type="submit" id="continue">Send reset link</button></form>`,
        "reset",
      )
    },
    checkout: async (req) => {
      if (req.method === "POST") return savedProfile(req, "checkout")
      const mm = `<option value="">MM</option>${Array.from({ length: 12 }, (_, i) => `<option value="${String(i + 1).padStart(2, "0")}">${String(i + 1).padStart(2, "0")}</option>`).join("")}`
      const yy = `<option value="">YYYY</option>${Array.from({ length: 12 }, (_, i) => `<option value="${2026 + i}">${2026 + i}</option>`).join("")}`
      return h(
        "Checkout",
        `<h1>Checkout</h1><p class="lede">Gauntlet Pro, $12.00 a month.</p><form method="post" action="${url("checkout")}">
          <h2 style="font-size:15px;margin:16px 0 0">Card</h2>
          <label for="cc-number">Card number</label><input id="cc-number" name="cc-number" autocomplete="cc-number" inputmode="numeric" placeholder="1234 1234 1234 1234">
          <div class="row"><div><label for="cc-month">Expiry month</label><select id="cc-month" name="cc-month" autocomplete="cc-exp-month">${mm}</select></div>
          <div><label for="cc-year">Expiry year</label><select id="cc-year" name="cc-year" autocomplete="cc-exp-year">${yy}</select></div>
          <div><label for="cc-csc">CVC</label><input id="cc-csc" name="cc-csc" autocomplete="cc-csc" inputmode="numeric" maxlength="4"></div></div>
          <label for="cc-name">Name on card</label><input id="cc-name" name="cc-name" autocomplete="cc-name">
          <h2 style="font-size:15px;margin:20px 0 0">Billing address</h2>
          <label for="bill-line1">Address</label><input id="bill-line1" name="bill-line1" autocomplete="billing address-line1">
          <label for="bill-line2">Apartment, suite, etc.</label><input id="bill-line2" name="bill-line2" autocomplete="billing address-line2">
          <div class="row"><div><label for="bill-city">City</label><input id="bill-city" name="bill-city" autocomplete="billing address-level2"></div>
          <div><label for="bill-state">State</label><select id="bill-state" name="bill-state" autocomplete="billing address-level1"><option value="">State</option>${REGIONS.US.map(([v, n]) => `<option value="${v}">${n}</option>`).join("")}</select></div>
          <div><label for="bill-zip">ZIP</label><input id="bill-zip" name="bill-zip" autocomplete="billing postal-code"></div></div>
          <label for="bill-country">Country</label><select id="bill-country" name="bill-country" autocomplete="billing country"><option value="">Country</option><option value="CA">Canada</option><option value="US">United States</option></select>
          <button type="submit" id="submit">Pay $12.00</button></form>`,
        "checkout",
      )
    },
  }

  const signupScript = `const p=document.getElementById("new-password"),c=document.getElementById("confirm-password"),list=document.getElementById("checks")
const rules=[["14 to 24 characters",(v)=>v.length>=14&&v.length<=24],["Upper and lower case",(v)=>/[a-z]/.test(v)&&/[A-Z]/.test(v)],["A digit",(v)=>/\\d/.test(v)],["One of - _ ! @ #",(v)=>/[-_!@#]/.test(v)],["Passwords match",(v)=>v&&v===c.value]]
const draw=()=>{list.innerHTML=rules.map(([t,f])=>'<li style="color:'+(f(p.value)?"var(--ok)":"inherit")+'">'+t+'</li>').join("")};p.addEventListener("input",draw);c.addEventListener("input",draw);draw()`

  const resetNew = (who: string, error?: string) =>
    `<h1>Choose a new password</h1><p class="lede">For ${esc(who)}.</p><form method="post" action="${url("reset", "/new")}" novalidate>
      <input type="hidden" name="username" value="${esc(who)}" autocomplete="username"><input type="hidden" name="ticket" value="${ticket("reset", who)}">
      <label for="new-password">New password</label><input id="new-password" name="password" type="password" autocomplete="new-password" minlength="12">
      <label for="confirm-password">Confirm new password</label><input id="confirm-password" name="confirm" type="password" autocomplete="new-password">
      ${errorLine(error)}<button type="submit" id="submit">Reset password</button></form>`

  /** A page with the login in a frame from `origin` (null: none configured for this host). */
  const framed = (slug: string, origin: string | null, u: URL) => {
    if (!origin) return h("Not available", `<h1>Not available here</h1><p>This server has no ${slug === "iframe-cross-site" ? "cross-site" : "same-site"} origin configured for frames.</p>`, slug)
    const src = `${origin}${base}/frame-login?from=${encodeURIComponent(u.origin)}`
    const what = slug === "iframe-cross-site" ? "another site" : slug === "iframe-same-site" ? "another origin of this site" : "this origin"
    return h(
      "Sign in",
      `<h1>Sign in</h1><p class="lede">The form is in a frame from ${what}${slug === "iframe-cross-site" ? ". A password manager must not fill it." : "."}</p>
      <iframe id="login-frame" src="${esc(src)}" title="Sign in" style="width:100%;height:300px;border:1px solid var(--line);border-radius:10px"></iframe>
      <p class="muted" id="frame-origin">Frame: ${esc(origin)}</p>`,
      slug,
    )
  }

  const frameLogin = async (req: Request, form: () => Promise<Record<string, string>>) => {
    const inner = (body: string) =>
      new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title><style>${STYLE}body{background:var(--card)}main{border:0;margin:0;max-width:none;padding:14px}</style></head><body><main>${body}</main></body></html>`, {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      })
    if (req.method === "POST") {
      const f = await form()
      const a = login(f.username, f.password)
      return inner(a ? signedIn(a.username) : `${loginForm(`${base}/frame-login`, { user: f.username })}${errorLine("That email or password isn't right.")}`)
    }
    return inner(loginForm(`${base}/frame-login`))
  }

  /** Identifier first: the identifier, then a password page. */
  async function idFirst(slug: string, req: Request, _u: URL, rest: string, form: () => Promise<Record<string, string>>): Promise<Response> {
    if (req.method !== "POST") return identifierStep(slug)
    const f = await form()
    if (rest === "/password") {
      const a = find(f.username)
      if (!a) return identifierStep(slug, { error: "We can't find an account with that email.", value: f.username })
      return passwordStep(slug, f.username)
    }
    const a = login(f.username, f.password)
    if (!a) return passwordStep(slug, f.username, "That password isn't right.")
    return afterPassword(slug, f.username)
  }

  /** A username and password, then the page's own second step. */
  async function twoStep(slug: string, req: Request, u: URL, rest: string, form: () => Promise<Record<string, string>>): Promise<Response> {
    const first = (error?: string, user?: string) => h("Sign in", `<h1>Sign in</h1><p class="lede">Use your Gauntlet account.</p>${loginForm(url(slug), { user })}${errorLine(error)}`, slug)
    if (rest === "/step") {
      const who = u.searchParams.get("u") ?? ""
      if (u.searchParams.get("t") !== ticket(slug, who)) return first()
      return slug === "backup" ? backupStep(who, u.searchParams.get("alnum") === "1") : afterPassword(slug, who)
    }
    if (req.method !== "POST") return first()
    const f = await form()
    if (rest === "/code") {
      if (f.ticket !== ticket(slug, f.username)) return first("Your sign-in expired. Start again.")
      const a = find(f.username)
      if (f.resend) return slug === "sms" || slug === "email-code" ? sentStep(slug, f.username, slug === "sms" ? "sms" : "email", undefined, true) : first()
      const code = f.code ?? [1, 2, 3, 4, 5, 6].map((i) => f[`d${i}`] ?? "").join("")
      let ok = false
      if (slug === "totp" || slug === "totp-split") ok = codeOk(a, code)
      else if (slug === "sms") ok = code.trim() === SMS_CODE
      else if (slug === "email-code") ok = code.trim() === EMAIL_CODE
      else if (slug === "backup") ok = BACKUP_CODES.map((c) => c.replace(/-/g, "").toUpperCase()).includes(code.replace(/[\s-]/g, "").toUpperCase())
      if (ok) return h("Signed in", signedIn(f.username), slug)
      const why = "That code isn't right."
      if (slug === "totp" || slug === "totp-split") return totpStep(slug, f.username, slug === "totp-split", why)
      if (slug === "backup") return backupStep(f.username, f.alnum === "1", why)
      return sentStep(slug, f.username, slug === "sms" ? "sms" : "email", why)
    }
    const a = login(f.username, f.password)
    if (!a) return first("That email or password isn't right.", f.username)
    return afterPassword(slug, a.username)
  }

  /** The JSON API the client-side pages post to. */
  async function api(req: Request, what: string): Promise<Response> {
    const body = (await req.json().catch(() => ({}))) as Record<string, string>
    const json = (v: unknown) => Response.json(v, { headers: { "cache-control": "no-store" } })
    if (what === "login") {
      const a = login(String(body.username ?? ""), String(body.password ?? ""))
      return json(a ? { ok: true, html: signedIn(a.username) } : { ok: false, error: "That email or password isn't right." })
    }
    if (what === "exists") return json(find(String(body.username ?? "")) ? { ok: true } : { ok: false, error: "We can't find an account with that email." })
    if (what === "password") {
      const a = login(String(body.username ?? ""), String(body.password ?? ""))
      if (!a) return json({ ok: false, error: "That password isn't right." })
      return json(a.totp || opts.fixedCodes?.length ? { ok: true, code: true, ticket: ticket("spa", a.username) } : { ok: true, html: signedIn(a.username) })
    }
    if (what === "code") {
      const a = find(String(body.username ?? ""))
      if (!a || body.ticket !== ticket("spa", a.username)) return json({ ok: false, error: "Your sign-in expired. Start again." })
      return json(codeOk(a, String(body.code ?? "")) ? { ok: true, html: signedIn(a!.username) } : { ok: false, error: "That code isn't right." })
    }
    return json({ ok: false, error: "Unknown request." })
  }

  return async (req: Request) => {
    const u = new URL(req.url)
    if (base && u.pathname !== base && !u.pathname.startsWith(`${base}/`)) return null
    const path = u.pathname.slice(base.length) || "/"
    if (path === "/") return index()
    if (path.startsWith("/api/") && req.method === "POST") return api(req, path.slice(5))
    const [, slug, ...more] = path.split("/")
    const handler = pages[slug]
    if (!handler) return new Response("not found", { status: 404 })
    const rest = more.length ? `/${more.join("/")}` : ""
    // The SPA's routes all load the same document.
    if (slug === "spa") return handler(req, u, "", async () => ({}))
    let parsed: Record<string, string> | null = null
    const form = async () => (parsed ??= Object.fromEntries([...(await req.formData().catch(() => new FormData())).entries()].map(([k, v]) => [k, String(v)])))
    return handler(req, u, rest, form)
  }
}
