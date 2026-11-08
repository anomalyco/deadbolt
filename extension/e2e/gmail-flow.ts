// A Gmail-style sign-in, for the extension's one-pick sign-in (see
// googleSignIn in run.ts): Google's own page shapes, served on the test site.
// One document for every step, as accounts.google.com is: no <form> anywhere,
// <button type="button"> controls whose clicks a delegated jsaction handler
// on the document reads, and each step a history.pushState swap of the view.
// The password and code views start hidden and fade in, beside a hidden email
// box and the account chip ([data-profile-identifier]) the real pages carry.
// Each Next posts its step with fetch to /flow/gmail/<step>, which the test
// server records (flowPosts) and answers {ok} or {error}: the Acme login's
// username, password and current code are the right ones.
//
// ?new: an address with no account goes on to "Create a password" (two
// new-password boxes), a sign-up step. ?captcha: the password step shows a
// reCAPTCHA. ?sms: the code step says Google texted a code.

const BUTTON = 'class="VfPpkd-LgbsSe VfPpkd-LgbsSe-OWXEXe-k8QpJ nCP5yc AjY5Oe DuMIQc LQeN7" jsname="LgbsSe" type="button"'
const LINK_BUTTON = 'class="VfPpkd-LgbsSe ksBjEc lKxP2d LQeN7" jsname="LgbsSe" type="button"'

const next = (step: string) =>
  `<div class="JYXaTc" jsname="DH6Rkf"><div class="O1Slxf" jsname="k77Iif"><div jscontroller="f8Gu1e" jsaction="click:cOuCgd;JIbuQc:JIbuQc;" jsname="Njthtb" class="FliLIb" data-is-touch-wrapper="true"><button ${BUTTON} id="next" data-step="${step}"><span class="VfPpkd-vQzf8d" jsname="V67aGc">Next</span></button></div></div></div>`

export function gmailPage(query: URLSearchParams): string {
  const flags = JSON.stringify({ new: query.has("new"), captcha: query.has("captcha"), sms: query.has("sms") })
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in - Google Accounts</title>
<style>
  body{margin:0;font:14px/1.4 Roboto,system-ui,sans-serif;background:#f0f4f9;color:#1f1f1f}
  .Hvu6D{display:none}
  main.Svhjgc{max-width:1040px;margin:80px auto;padding:36px;background:#fff;border-radius:28px;display:flex;gap:40px;min-height:300px}
  .side{flex:1}.view{flex:1}
  h1{font:400 36px/44px "Google Sans",system-ui,sans-serif;margin:16px 0 12px}
  .view{transition:opacity .25s ease,transform .25s ease}
  .view.entering{opacity:0;transform:translateX(24px);visibility:hidden}
  input.whsOnd{display:block;width:100%;box-sizing:border-box;height:56px;padding:13px 15px;border:1px solid #747775;border-radius:4px;font:16px system-ui}
  .JYXaTc{display:flex;justify-content:flex-end;gap:8px;margin-top:32px}
  button{font:500 14px system-ui;border:0;border-radius:20px;height:40px;padding:0 24px;cursor:pointer}
  #next{background:#0b57d0;color:#fff}
  .ksBjEc{background:none;color:#0b57d0;padding:0 12px}
  .chip{display:inline-flex;align-items:center;gap:8px;border:1px solid #747775;border-radius:16px;padding:4px 12px;margin:8px 0 16px}
  .o6cuMc{color:#b3261e;margin-top:8px}
  .g-recaptcha{width:302px;height:76px;border:1px solid #d3d3d3;background:#f9f9f9;margin-top:16px}
</style></head><body>
<div class="S7xv8 LZgQXe">
<c-wiz jsrenderer="chA7fe" class="A77ntc" data-view-id="hm18Ec" data-locale="en" jsshadow>
<main class="Svhjgc" jsname="bN97Pc" jscontroller="SD8Jgb" jsaction="rcuQ6b:npT2md;">
  <div class="side"><svg width="48" height="48" aria-hidden="true"><circle cx="24" cy="24" r="20" fill="#4285f4"/></svg><h1 id="headingText"><span jsslot>Sign in</span></h1><div id="headingSubtext"><span jsslot>to continue to Gmail</span></div><div id="chipslot"></div></div>
  <div class="view" id="view" jsname="rEuO1b">
    <div jscontroller="ziZ8Mc" jsname="Vsb5Ub"><div class="rFrNMe" jscontroller="pxq3x">
      <input type="email" class="whsOnd zHQkBf" jsname="YPqjbf" autocomplete="username webauthn" spellcheck="false" tabindex="0" aria-label="Email or phone" name="identifier" autocapitalize="none" id="identifierId" dir="ltr" data-initial-dir="ltr" data-initial-value="">
    </div></div>
    <div class="PrDSKc"><button ${LINK_BUTTON}>Forgot email?</button></div>
    <div class="o6cuMc" id="error" role="alert" aria-live="assertive"></div>
    <input type="password" name="hiddenPassword" jsname="Ki5Xbb" class="Hvu6D" tabindex="-1" aria-hidden="true">
    <div class="JYXaTc"><button ${LINK_BUTTON} id="create">Create account</button></div>
    ${next("identifier")}
  </div>
</main>
</c-wiz></div>
<script>
(() => {
  const flags = ${flags}
  let who = ""
  const view = () => document.getElementById("view")
  const chip = (email) => '<div class="chip" jsname="bQIQze" data-profile-identifier translate="no">' + email + '</div>'
  const esc = (s) => s.replace(/[<>&"']/g, "")
  // A step's view swaps in hidden and fades in, as Google's do.
  function show(path, heading, sub, html) {
    history.pushState({}, "", path)
    document.title = heading + " - Google Accounts"
    document.getElementById("headingText").innerHTML = "<span jsslot>" + heading + "</span>"
    document.getElementById("headingSubtext").innerHTML = sub ? "<span jsslot>" + sub + "</span>" : ""
    document.getElementById("chipslot").innerHTML = chip(esc(who))
    const v = view()
    v.classList.add("entering")
    v.innerHTML = html
    setTimeout(() => requestAnimationFrame(() => v.classList.remove("entering")), 250)
  }
  const hiddenEmail = () => '<input type="email" name="identifier" class="Hvu6D" tabindex="-1" aria-hidden="true" spellcheck="false" jsname="KKx9x" autocomplete="off" id="hiddenEmail" value="' + esc(who) + '">'
  const error = '<div class="o6cuMc" id="error" role="alert" aria-live="assertive"></div>'
  async function post(step, values) {
    const body = new FormData()
    for (const [k, v] of Object.entries(values)) body.set(k, v)
    const res = await fetch("/flow/gmail/" + step, { method: "POST", body })
    return res.json()
  }
  const steps = {
    async identifier() {
      const email = document.getElementById("identifierId").value
      const reply = await post("identifier", { identifier: email })
      if (reply.error) return void (document.getElementById("error").textContent = reply.error)
      who = email
      if (flags.new)
        return show("/flow/gmail/signup/password", "Create a strong password", "Create a strong password with a mix of letters, numbers and symbols",
          hiddenEmail() +
          '<input type="password" class="whsOnd zHQkBf" autocomplete="new-password" aria-label="Password" name="Passwd" id="newPasswd">' +
          '<input type="password" class="whsOnd zHQkBf" autocomplete="new-password" aria-label="Confirm" name="PasswdAgain" id="confirmPasswd" style="margin-top:12px">' +
          error + ${JSON.stringify(next("signup"))})
      show("/flow/gmail/challenge/pwd", "Welcome", "",
        hiddenEmail() +
        '<div jscontroller="Iy4Rwd"><input type="password" class="whsOnd zHQkBf" jsname="YPqjbf" autocomplete="current-password webauthn" spellcheck="false" tabindex="0" aria-label="Enter your password" name="Passwd" autocapitalize="off" data-initial-value=""></div>' +
        '<label style="display:flex;gap:8px;margin-top:12px"><input type="checkbox" jsname="YPqjbf"> Show password</label>' +
        error + (flags.captcha ? '<div class="g-recaptcha" data-sitekey="x"></div>' : "") +
        '<div class="JYXaTc"><button ${LINK_BUTTON}>Forgot password?</button></div>' + ${JSON.stringify(next("pwd"))})
    },
    async pwd() {
      const reply = await post("pwd", { identifier: who, Passwd: document.querySelector("input[name=Passwd]").value })
      if (reply.error) return void (document.getElementById("error").textContent = reply.error)
      if (reply.done) return done()
      show("/flow/gmail/challenge/totp", "2-Step Verification", "To help keep your account safe, Google wants to make sure it’s really you trying to sign in",
        (flags.sms ? "<p>A text message with a 6-digit verification code was just sent to •••• ••• 0123</p>" : "<p>Get a verification code from the <strong>Google Authenticator</strong> app</p>") +
        '<input type="tel" class="whsOnd zHQkBf" jsname="YPqjbf" autocomplete="off" spellcheck="false" tabindex="0" aria-label="Enter code" name="totpPin" id="totpPin" pattern="[0-9 ]*" dir="ltr" data-initial-value="">' +
        '<label style="display:flex;gap:8px;margin-top:12px"><input type="checkbox" checked> Don’t ask again on this device</label>' +
        error + '<div class="JYXaTc"><button ${LINK_BUTTON}>Try another way</button></div>' + ${JSON.stringify(next("totp"))})
    },
    async totp() {
      const reply = await post("totp", { identifier: who, totpPin: document.getElementById("totpPin").value })
      if (reply.error) return void (document.getElementById("error").textContent = reply.error)
      done()
    },
    async signup() {
      await post("signup", { identifier: who })
      done()
    },
  }
  function done() {
    history.pushState({}, "", "/flow/gmail/inbox")
    document.title = "Inbox - " + who + " - Gmail"
    document.body.innerHTML = '<header style="padding:16px 24px;background:#fff">Gmail · <span id="account">' + esc(who) + '</span></header><main style="padding:40px"><h2>Inbox</h2><p id="signed-in">Signed in as ' + esc(who) + '</p></main>'
  }
  // Google's jsaction: one listener on the document reads the clicked
  // control's handler, instead of a listener on each button.
  document.addEventListener("click", (e) => {
    const button = e.target instanceof Element ? e.target.closest("button[data-step]") : null
    const owner = button?.closest("[jsaction]")
    if (!button || !owner || !/click:/.test(owner.getAttribute("jsaction") || "")) return
    void steps[button.dataset.step]?.()
  })
  // Enter in a box is Next, as on Google's pages.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target instanceof HTMLInputElement) document.getElementById("next")?.click()
  })
})()
</script></body></html>`
}
