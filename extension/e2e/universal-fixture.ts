// Deliberately separate from the forms gauntlet. Synthetic accounts only.
import { createHmac } from "node:crypto"
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
    case "/dashboard": return html(`<h1>Your dashboard</h1><p>Signed in as ${USER}</p><a href="/logout">Sign out</a><hr><small>Connect another service</small><button>Sign in with Google</button>`)
    case "/email": return html(`<h1>Workspace</h1><p>${USER}</p><a href="/login">Sign in</a>`)
    case "/logout": return redirect("/")
    case "/modal": return html(`<h1>Welcome</h1><button id="open" type="button">Sign in</button><dialog id="login"><h2>Sign in</h2>${form("/password", email + password, "Sign in")}</dialog><script>document.querySelector('#open').onclick=()=>document.querySelector('dialog').showModal()</script>`)
    case "/delayed": return html(`<h1>Welcome</h1><button id="open" type="button">Sign in</button><dialog id="login"><h2>Sign in</h2>${form("/password", email + password, "Sign in")}</dialog><script>document.querySelector('#open').onclick=()=>setTimeout(()=>document.querySelector('dialog').showModal(),2000)</script>`)
    case "/override": return html(`<h1>Sign in</h1><form method="post" action="/password">${email + password}<button type="submit" formaction="http://127.0.0.1:${url.port}/password">Sign in</button></form>`)
    case "/spa": return html(`<div id="app"><h1>Dashboard</h1><p>${USER}</p><button id="out">Sign out</button><button>Sign in with Google</button></div><script>
      document.querySelector('#out').onclick=()=>{history.pushState({},'', '/spa?out');document.querySelector('#app').innerHTML='<h1>Welcome back</h1><a href="/login">Sign in</a>'}
      </script>`)
    case "/frame": return html(`<h1>Embedded login</h1><iframe title="Other site's login" width="400" height="380" src="http://127.0.0.1:${url.port}/login"></iframe>`)
    case "/failed": return html(`<h1>Sign in</h1><p role="alert">Incorrect password. Try again.</p>${form("/failed", email + password, "Sign in")}`)
    case "/cross-action": return html(`<h1>Sign in</h1>${form(`http://127.0.0.1:${url.port}/password`, email + password, "Sign in")}`)
    default: return new Response("Not found", { status: 404 })
  }
}
