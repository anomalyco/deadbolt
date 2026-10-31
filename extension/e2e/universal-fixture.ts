// Deliberately separate from the forms gauntlet. Synthetic accounts only.
import { createHmac } from "node:crypto"
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type WebAuthnCredential } from "@simplewebauthn/server"
export const USER = "universal@example.test"
export const PASSWORD = "synthetic-universal-password-83219"
export const OTP = "JBSWY3DPEHPK3PXP"

function currentCode(at: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)))
  // The fixture's public synthetic base32 seed above, decoded.
  const digest = createHmac("sha1", Buffer.from("48656c6c6f21deadbeef", "hex")).update(counter).digest()
  const offset = digest[digest.length - 1] & 15
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0")
}

const email = '<label>Email<input id="email" name="email" type="email" autocomplete="username"></label>'
const password = '<label>Password<input id="password" name="password" type="password" autocomplete="current-password"></label>'
const code = '<label>Verification code<input id="code" name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6"></label>'
const form = (action: string, fields: string, button = "Continue") => `<form method="post" action="${action}">${fields}<button type="submit">${button}</button></form>`
function html(body: string) {
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Universal sign-in fixture</title>
    <style>body{font:16px system-ui;margin:0;color:#202024;background:#fafafa}header{padding:24px;border-bottom:1px solid #ddd}main{max-width:440px;margin:90px auto}input,button{display:block;padding:12px;margin:12px 0;font:inherit}input{width:320px}a{color:#4545a0}dialog{border:1px solid #ccc;border-radius:12px;padding:32px}small{color:#666}</style></head>
    <body><header>Acme · universal sign-in lab</header><main>${body}</main></body></html>`, { headers: { "content-type": "text/html", "cache-control": "no-store" } })
}

export async function universalFixture(req: Request): Promise<Response> {
  const url = new URL(req.url)
  if (url.hostname.endsWith(".test")) return providerFixture(req, url)
  const data = req.method === "POST" ? await req.formData() : null
  const redirect = (path: string) => Response.redirect(`${url.origin}${path}`, 303)
  switch (url.pathname) {
    case "/": return html('<h1>Your workspace, ready.</h1><p>A signed-out home page.</p><a href="/login">Sign in</a>')
    case "/login":
      if (data) return data.get("email") === USER ? redirect("/password") : html("<h1>Incorrect email</h1>")
      return html(`<h1>Sign in</h1>${form("/login", email)}`)
    case "/password":
      if (data) return data.get("password") === PASSWORD ? redirect("/code") : html("<h1>Incorrect password</h1>")
      return html(`<h1>Enter your password</h1>${form("/password", password, "Sign in")}`)
    case "/code":
      if (data) return [currentCode(Date.now()), currentCode(Date.now() - 30_000)].includes(String(data.get("code"))) ? redirect("/dashboard") : html("<h1>Incorrect code</h1>")
      return html(`<h1>Two-factor authentication</h1>${form("/code", code, "Verify")}`)
    case "/sms-login":
    case "/email-login":
    case "/auto-login":
      if (data) return data.get("email") === USER && data.get("password") === PASSWORD ? redirect(url.pathname.replace("-login", "-code")) : html("<h1>Incorrect password</h1>")
      return html(`<h1>Sign in</h1>${form(url.pathname, email + password, "Sign in")}`)
    case "/sms-code":
    case "/email-code":
    case "/auto-code":
      if (data) return [currentCode(Date.now()), currentCode(Date.now() - 30_000)].includes(String(data.get("code"))) ? redirect("/dashboard") : html("<h1>Incorrect code</h1>")
      return html(`<h1>Verification code</h1><p>${url.pathname === "/sms-code" ? "Enter the code we sent in a text message." : url.pathname === "/email-code" ? "Check your email for the code." : "Use your authenticator app."}</p><div><div>${form(url.pathname, code, "Verify")}</div></div>${url.pathname === "/auto-code" ? '<script>document.querySelector("#code").addEventListener("input", e => { if (e.target.value.length === 6) e.target.form.requestSubmit() })</script>' : ""}`)
    case "/dashboard": return html(`<h1>Your dashboard</h1><p>Signed in as ${USER}</p><a href="/logout">Sign out</a><hr><small>Connect another service</small><button>Sign in with Google</button>`)
    case "/email": return html(`<h1>Workspace</h1><p>${USER}</p><a href="/login">Sign in</a>`)
    case "/logout": return redirect("/")
    case "/modal": return html(`<h1>Welcome</h1><button id="open" type="button">Sign in</button><dialog id="login"><h2>Sign in</h2>${form("/password", email + password, "Sign in")}</dialog><script>document.querySelector('#open').onclick=()=>document.querySelector('dialog').showModal()</script>`)
    case "/delayed": return html(`<h1>Welcome</h1><button id="open" type="button">Sign in</button><dialog id="login"><h2>Sign in</h2>${form("/password", email + password, "Sign in")}</dialog><script>document.querySelector('#open').onclick=()=>setTimeout(()=>document.querySelector('dialog').showModal(),2000)</script>`)
    case "/override": return html(`<h1>Sign in</h1><form method="post" action="/password">${email + password}<button type="submit" formaction="http://127.0.0.1:${url.port}/password">Sign in</button></form>`)
    case "/spa": return html(`<div id="app"><h1>Dashboard</h1><p>${USER}</p><button id="out">Sign out</button><button>Sign in with Google</button></div><script>
      document.querySelector('#out').onclick=()=>{history.pushState({},'', '/spa?out');document.querySelector('#app').innerHTML='<h1>Welcome back</h1><a href="/login">Sign in</a>'}
      </script>`)
    case "/wrapped-logout":
    case "/large-logout":
    case "/overflow-logout": {
      const tag = url.pathname === "/wrapped-logout" ? "div" : "button"
      const overflow = url.pathname === "/overflow-logout"
      return html(`<a href="/logout">Sign out</a><${tag} id="out" role="button" aria-label="Sign out" style="display:block;box-sizing:border-box;width:${overflow ? 300 : 440}px;height:${overflow ? 40 : 200}px">${overflow ? '<span style="position:fixed;inset:0">Switch workspace</span>' : "Switch workspace"}</${tag}><script>
        document.querySelector('#out').onclick=()=>{history.pushState({},'',location.pathname+'?out');document.querySelector('main').innerHTML='<h1>Welcome</h1><a href="/login">Sign in</a>'}
        </script>`)
    }
    case "/frame": return html(`<h1>Embedded login</h1><iframe title="Other site's login" width="400" height="380" src="http://127.0.0.1:${url.port}/login"></iframe>`)
    case "/failed": return html(`<h1>Sign in</h1><p role="alert">Incorrect password. Try again.</p>${form("/failed", email + password, "Sign in")}`)
    case "/cross-action": return html(`<h1>Sign in</h1>${form(`http://127.0.0.1:${url.port}/password`, email + password, "Sign in")}`)
    default: return new Response("Not found", { status: 404 })
  }
}

// ---- Sign in with a provider (e2e/universal-providers.ts) -----------------------
// acme.test is the site; accounts.google.test is a fake Google, both mapped to
// this server, and any other accounts.*.test host (a lookalike) serves the same
// pages. The fake Google keeps no state: each step carries the run's options
// in its query (flow, mode, chooser, pk, uv, phone, consent, loop, delay, frame,
// redirect_uri, continue). Every request is logged under its `flow`, so a run
// counts exactly what was clicked or submitted. Synthetic accounts only.
export const GOOGLE_USER = "universal.google@example.test"
export const GOOGLE_OTHER = "someone.else@example.test"
export const GOOGLE_PASSWORD = "synthetic-google-password-51027"
export interface ProviderHit { host: string; path: string; method: string; flow: string; frame: boolean; value?: string }
export const providerLog: ProviderHit[] = []
/**
 * The fake Google's relying-party side, checked with @simplewebauthn/server:
 * the passkey registered on /v3/signin/passkey/enroll (made by Deadbolt in a
 * real ceremony), and each ceremony's challenge by flow.
 */
export const googlePasskey: { credential?: WebAuthnCredential; aaguid?: string; challenges: Map<string, string>; verified: number } = { challenges: new Map(), verified: 0 }
const FOOTER = '<footer><p><small>To continue, Google will share your name, email address, language preference and profile picture with Acme.</small></p></footer>'
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } })

const clean = (v: string | null | undefined) => (v ?? "").replace(/[<>&"']/g, "")
const validCode = (v: unknown) => [currentCode(Date.now()), currentCode(Date.now() - 30_000)].includes(String(v))
const page = (title: string, body: string) =>
  new Response(`<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>${body}</html>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } })

function google(title: string, body: string) {
  return page(title, `<style>body{font:14px system-ui,sans-serif;margin:0;background:#f0f4f9;color:#1f1f1f}.card{max-width:420px;margin:80px auto;background:#fff;border-radius:28px;padding:36px}h1{font-weight:400;font-size:28px;margin:12px 0}.logo{font-size:22px;color:#4285f4}input{display:block;box-sizing:border-box;width:100%;padding:14px;margin:16px 0;border:1px solid #747775;border-radius:4px;font:inherit}.row{display:flex;justify-content:space-between;align-items:center;margin-top:24px}button{font:inherit;padding:10px 24px;border-radius:20px;border:0;background:#0b57d0;color:#fff;cursor:pointer}button.text{background:none;color:#0b57d0;padding:10px 0}ul{padding:0}li{list-style:none;border-top:1px solid #e3e3e3}[role=link]{display:flex;gap:12px;align-items:center;padding:12px 8px;cursor:pointer}.chip{display:inline-block;border:1px solid #747775;border-radius:16px;padding:4px 12px}</style></head>
    <body><div class="card"><div class="logo">Google</div>${body}</div></body>`)
}

async function googleFixture(req: Request, url: URL, hit: ProviderHit): Promise<Response> {
  const q = url.searchParams
  const data = req.method === "POST" && !url.pathname.startsWith("/pk/") ? await req.formData() : null
  const step = (path: string) => {
    const s = new URLSearchParams(q)
    s.delete("id")
    s.delete("another")
    return `${path}?${s}`
  }
  const go = (path: string) => Response.redirect(`${url.origin}${step(path)}`, 303)
  const form = (path: string, fields: string, button = "Next", extra = "<span></span>") =>
    `<form method="post" action="${step(path)}">${fields}<div class="row">${extra}<button type="submit">${button}</button></div></form>`
  const chip = `<p><span class="chip" data-profile-identifier="" translate="no">${GOOGLE_USER}</span></p>`
  const password = () => go(q.get("pk") === "1" ? "/v3/signin/challenge/pk" : "/v3/signin/challenge/pwd")
  const done = () => {
    const back = new URL(q.get("redirect_uri") ?? "http://acme.test/")
    back.searchParams.set("as", GOOGLE_USER)
    return Response.redirect(back.href, 303)
  }
  const chooser = () =>
    google("Sign in - Google Accounts", `<h1>Choose an account</h1><p>to continue to Acme</p><ul>${[["Universal Google", GOOGLE_USER], ["Someone Else", GOOGLE_OTHER]]
      .map(([name, email]) => `<li><div role="link" tabindex="0" data-identifier="${email}" data-authuser="-1"><span>${name[0]}</span><span><b>${name}</b><br><small>${email}</small></span></div></li>`)
      .join("")}<li><div role="link" tabindex="0" id="another">Use another account</div></li></ul>${FOOTER}
      <script>for (const t of document.querySelectorAll("[role=link]")) t.addEventListener("click", () => location.assign(${JSON.stringify(step("/signin/select"))} + (t.dataset.identifier ? "&id=" + encodeURIComponent(t.dataset.identifier) : "&another=1")))</script>`)
  switch (url.pathname) {
    case "/o/oauth2/v2/auth":
      return q.get("chooser") === "0" ? go("/v3/signin/identifier") : chooser()
    case "/signin/select":
      hit.value = q.get("id") ?? "another"
      // Held open to outlast the chain's lifetime without a page that could end it.
      await Bun.sleep(Math.min(Number(q.get("delay")) || 0, 150_000))
      if (q.get("loop") === "1") return chooser()
      if (q.has("another")) return go("/v3/signin/identifier")
      return q.get("id") === GOOGLE_USER ? password() : google("Sign in - Google Accounts", "<h1>This account isn't available</h1>")
    case "/v3/signin/identifier":
      if (data) {
        hit.value = String(data.get("identifier") ?? "")
        return hit.value === GOOGLE_USER ? password() : google("Sign in - Google Accounts", "<h1>Couldn't find your Google Account</h1>")
      }
      return google("Sign in - Google Accounts", `<h1>Sign in</h1><p>to continue to Acme</p>${form("/v3/signin/identifier", '<input type="email" name="identifier" id="identifierId" autocomplete="username" aria-label="Email or phone">', "Next", '<button class="text" type="button">Create account</button>')}`)
    case "/v3/signin/challenge/pk":
      return google("Sign in - Google Accounts", `<h1>Use your passkey to confirm it's really you</h1>${chip}<p>Your device will ask for your fingerprint, face or screen lock.</p><div class="row"><a href="${step("/v3/signin/challenge/selection")}">Try another way</a><button id="pk-go" type="button">Use your passkey</button></div><p id="pk-status" role="status"></p>
        <script>
          document.querySelector("#pk-go").addEventListener("click", async () => {
            const status = document.querySelector("#pk-status")
            try {
              const options = await (await fetch(${JSON.stringify(step("/pk/auth-options"))})).json()
              const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) })
              const reply = await (await fetch(${JSON.stringify(step("/pk/auth"))}, { method: "POST", body: JSON.stringify(credential.toJSON()) })).json()
              if (reply.next) location.assign(reply.next)
              else status.textContent = "Couldn't verify your passkey"
            } catch (e) { status.textContent = e.name + ": " + e.message }
          })
        </script>`)
    case "/pk/auth-options": {
      const options = await generateAuthenticationOptions({ rpID: url.hostname, userVerification: q.get("uv") === "discouraged" ? "discouraged" : "preferred" })
      googlePasskey.challenges.set(`auth:${hit.flow}`, options.challenge)
      return json(options)
    }
    case "/pk/auth": {
      const expectedChallenge = googlePasskey.challenges.get(`auth:${hit.flow}`)
      googlePasskey.challenges.delete(`auth:${hit.flow}`)
      const credential = googlePasskey.credential
      if (req.method !== "POST") return json({ error: "POST" }, 405)
      const response = await req.json().catch(() => null)
      if (!expectedChallenge || !credential || !response) return json({ verified: false })
      const v = await verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin: url.origin, expectedRPID: url.hostname, credential, requireUserVerification: false }).catch(() => null)
      hit.value = v?.verified && response.id === credential.id ? "verified" : "rejected"
      if (hit.value !== "verified") return json({ verified: false })
      googlePasskey.verified++
      credential.counter = v!.authenticationInfo.newCounter
      const s = new URLSearchParams(q)
      return json({ verified: true, next: q.get("consent") === "1" ? `${url.origin}/signin/oauth/consent?${s}` : (() => { const back = new URL(q.get("redirect_uri") ?? "http://acme.test/"); back.searchParams.set("as", GOOGLE_USER); return back.href })() })
    }
    // Passkey enrollment, as Google's "Create a passkey" page: a real WebAuthn create.
    case "/v3/signin/passkey/enroll":
      return google("Create a passkey", `<h1>Create a passkey</h1>${chip}<p>With passkeys, you can sign in with your fingerprint, face or screen lock.</p><p id="enroll-status" role="status"></p>
        <script>
          window.enroll = async () => {
            const status = document.querySelector("#enroll-status")
            try {
              const options = await (await fetch(${JSON.stringify(step("/pk/register-options"))})).json()
              const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
              const reply = await (await fetch(${JSON.stringify(step("/pk/register"))}, { method: "POST", body: JSON.stringify(credential.toJSON()) })).json()
              status.textContent = reply.verified ? "Passkey created" : "Couldn't create a passkey"
            } catch (e) { status.textContent = e.name + ": " + e.message }
          }
        </script>`)
    case "/pk/register-options": {
      const options = await generateRegistrationOptions({ rpName: "Google", rpID: url.hostname, userName: GOOGLE_USER, attestationType: "none", authenticatorSelection: { residentKey: "required", userVerification: "preferred" }, supportedAlgorithmIDs: [-7, -257] })
      googlePasskey.challenges.set(`register:${hit.flow}`, options.challenge)
      return json(options)
    }
    case "/pk/register": {
      const expectedChallenge = googlePasskey.challenges.get(`register:${hit.flow}`)
      googlePasskey.challenges.delete(`register:${hit.flow}`)
      const response = await req.json().catch(() => null)
      if (!expectedChallenge || !response) return json({ verified: false })
      const v = await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: url.origin, expectedRPID: url.hostname, requireUserVerification: false }).catch(() => null)
      if (!v?.verified) return json({ verified: false })
      googlePasskey.credential = v.registrationInfo!.credential
      googlePasskey.aaguid = v.registrationInfo!.aaguid
      return json({ verified: true })
    }
    case "/v3/signin/challenge/pk/start":
    case "/v3/signin/challenge/selection":
      return google("Sign in - Google Accounts", "<h1>Choose how you want to sign in</h1>")
    case "/v3/signin/challenge/pwd":
      if (data) return data.get("Passwd") === GOOGLE_PASSWORD ? go(q.get("phone") === "1" ? "/v3/signin/challenge/ipp" : "/v3/signin/challenge/totp") : google("Sign in - Google Accounts", "<h1>Wrong password</h1>")
      return google("Sign in - Google Accounts", `<h1>Welcome</h1>${chip}<p>To continue, first verify it's you</p>${form("/v3/signin/challenge/pwd", '<input type="password" name="Passwd" autocomplete="current-password" aria-label="Enter your password">', "Next", `<button class="text" id="passkey" type="button" onclick='location.assign(${JSON.stringify(step("/v3/signin/challenge/pk/start"))})'>Use your passkey</button>`)}${FOOTER}`)
    case "/v3/signin/challenge/ipp":
      if (data) return google("Sign in - Google Accounts", "<h1>Code sent</h1>")
      return google("Sign in - Google Accounts", `<h1>Verify it's you</h1>${chip}<p>Enter a phone number to get a text message with a verification code.</p>${form("/v3/signin/challenge/ipp", '<input type="tel" name="phoneNumberId" autocomplete="tel" aria-label="Phone number">', "Send")}`)
    case "/v3/signin/challenge/totp":
      if (data) return validCode(data.get("totpPin")) ? (q.get("consent") === "1" ? go("/signin/oauth/consent") : done()) : google("Sign in - Google Accounts", "<h1>Wrong code</h1>")
      return google("Sign in - Google Accounts", `<h1>2-Step Verification</h1>${chip}<p>Get a verification code from the Google Authenticator app.</p>${form("/v3/signin/challenge/totp", '<input type="tel" name="totpPin" id="totpPin" autocomplete="one-time-code" inputmode="numeric" maxlength="6" aria-label="Enter code">')}`)
    case "/signin/oauth/consent":
      return google("Sign in - Google Accounts", `<h1>Acme wants access to your Google Account</h1>${chip}<p>This will allow Acme to:</p><ul><li>See your primary email address</li><li>See your personal info</li></ul>${form("/signin/oauth/consent/approve", "", "Continue", '<button class="text" type="button" id="cancel">Cancel</button>')}`)
    case "/signin/oauth/consent/approve":
      return data ? done() : new Response("Method not allowed", { status: 405 })
    // A re-authentication page, as before changing a setting: a password form that is no sign-in.
    case "/security/signinoptions/password":
      if (data) return google("Google Account", "<h1>Verified</h1>")
      return google("Google Account", `<h1>Confirm it's you</h1>${chip}<p>To continue, first verify it's you</p>${form("/security/signinoptions/password", '<input type="password" name="Passwd" autocomplete="current-password" aria-label="Enter your password">')}`)
    default:
      return new Response("Not found", { status: 404 })
  }
}

function acmeFixture(req: Request, url: URL): Response {
  const q = url.searchParams
  switch (url.pathname) {
    case "/signin": {
      // The site's own "Continue with Google": same tab, a popup, or an embedded
      // (cross-site) chooser, on accounts.google.test or the host `gh` names.
      // A hostile site's variants: `foreign` returns to another site, `entry=settings`
      // points the button at Google's re-authentication page, and `renav()`
      // re-navigates the popup there. `okta` adds an Okta button.
      const options = new URLSearchParams(q)
      for (const k of ["gh", "foreign", "entry", "okta"]) options.delete(k)
      const callback = new URL(q.get("foreign") === "1" ? `http://evil.test:${url.port}/oauth/callback` : `${url.origin}/oauth/callback`)
      for (const k of ["flow", "mode"]) if (q.has(k)) callback.searchParams.set(k, q.get(k)!)
      options.set("redirect_uri", callback.href)
      const provider = `http://${clean(q.get("gh")) || "accounts.google.test"}:${url.port}`
      const settings = `${provider}/security/signinoptions/password?${options}`
      const auth = q.get("entry") === "settings" ? settings : `${provider}/o/oauth2/v2/auth?${options}`
      return page("Sign in to Acme", `<style>body{font:16px system-ui;margin:0;background:#fafafa}main{max-width:440px;margin:90px auto}input,button{display:block;padding:12px;margin:12px 0;font:inherit;width:320px}</style></head><body><main>
        <h1>Sign in to Acme</h1><form method="post" action="/signin"><label>Email<input name="email" type="email" autocomplete="username"></label><label>Password<input name="password" type="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form>
        <p>or</p><button id="google" type="button">Continue with Google</button>${q.get("okta") === "1" ? '<button id="okta" type="button" onclick="document.title = \'Okta clicked\'">Continue with Okta</button>' : ""}<div id="slot"></div></main>
        <script>
          const auth = ${JSON.stringify(auth)}, settings = ${JSON.stringify(settings)}, mode = ${JSON.stringify(q.get("mode") ?? "tab")}, framed = ${q.get("frame") === "1"}
          let popup = null
          window.renav = () => { popup.location.href = settings }
          document.querySelector("#google").addEventListener("click", () => {
            if (framed) document.querySelector("#slot").innerHTML = '<iframe title="Sign in with Google" width="440" height="520" src="' + auth + '&frame=1"></iframe>'
            else if (mode === "popup") popup = window.open(auth, "google-signin", "popup,width=480,height=640")
            else location.assign(auth)
          })
          addEventListener("message", (e) => { if (e.origin === location.origin && typeof e.data?.as === "string") location.assign("/account?as=" + encodeURIComponent(e.data.as)) })
        </script></body>`)
    }
    case "/oauth/callback":
      if (q.get("mode") === "popup")
        return page("Signing in", `</head><body><p>Signing in…</p><script>opener?.postMessage({ as: ${JSON.stringify(clean(q.get("as")))} }, location.origin); window.close()</script></body>`)
      return Response.redirect(`${url.origin}/account?as=${encodeURIComponent(clean(q.get("as")))}`, 303)
    case "/account":
      return page("Acme", `</head><body><main><h1>Your dashboard</h1><p id="who">Signed in as ${clean(q.get("as"))} with Google</p><a href="/signin">Sign out</a></main></body>`)
    default:
      return new Response("Not found", { status: 404 })
  }
}

async function providerFixture(req: Request, url: URL): Promise<Response> {
  const hit: ProviderHit = { host: url.hostname, path: url.pathname, method: req.method, flow: url.searchParams.get("flow") ?? "", frame: url.searchParams.get("frame") === "1" }
  providerLog.push(hit)
  if (url.hostname === "acme.test") return acmeFixture(req, url)
  if (url.hostname.startsWith("accounts.")) return googleFixture(req, url, hit)
  return new Response("Not found", { status: 404 })
}
