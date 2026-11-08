import { beforeAll, describe, expect, test } from "bun:test"
import { initLearn, learnScanned, learning } from "../src/content/learn"
import type { LearnSession, LearnStep } from "../src/learn"

// The content side of "Learn this site", in one frame shaped like Apple's
// sign-in widget: the username box shows, the password box waits hidden.

const session: LearnSession = { id: "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b", salt: "pepper", until: Date.now() + 60_000 }
const sent: Array<{ type: string; session?: string; step?: LearnStep }> = []
const listeners: Array<(m: unknown) => void> = []
/** What the background answers to a step. */
let stepReply: unknown = true
const settle = () => new Promise((r) => setTimeout(r, 30))
const steps = () => sent.filter((m) => m.type === "db:learn-step").map((m) => m.step!)

function trusted<E extends Event>(event: E): E {
  Object.defineProperty(event, "isTrusted", { value: true })
  return event
}

function type(el: HTMLInputElement, value: string) {
  el.value = value
  el.dispatchEvent(trusted(new Event("input", { bubbles: true, composed: true })))
}

const $ = <E extends Element>(selector: string) => document.querySelector<E>(selector)!

beforeAll(async () => {
  ;(globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      sendMessage: async (m: { type: string }) => {
        sent.push(m)
        return m.type === "db:learn-ask" ? session : stepReply
      },
      onMessage: { addListener: (f: (m: unknown) => void) => listeners.push(f) },
    },
  }
  history.replaceState(null, "", "/appleauth/auth/signin?widgetKey=secret-ish&language=US-EN")
  document.title = "Sign In - Apple"
  document.body.innerHTML = `
    <h1>Sign in with Apple Account</h1>
    <input id="account_name_text_field" type="text" autocomplete="username webauthn" aria-label="Email or Phone Number">
    <div hidden><input id="password_text_field" type="password" autocomplete="current-password" tabindex="-1"></div>
    <button id="continue">Continue</button>`
  initLearn()
  await settle()
})

describe("a learning frame", () => {
  test("joins the tab's session and records where it starts", () => {
    expect(learning()).toBe(true)
    const [start] = steps()
    expect(start.trigger).toBe("start")
    expect(start.frame).toEqual({ top: true, depth: 0, origin: "https://example.com", path: "/appleauth/auth/signin", queryKeys: ["widgetKey", "language"] })
    expect(JSON.stringify(start)).not.toContain("secret-ish")
    const ids = start.inputs.map((i) => [i.id, i.visible, i.autocomplete])
    expect(ids).toEqual([
      ["account_name_text_field", true, "username webauthn"],
      ["password_text_field", false, "current-password"],
    ])
  })

  test("a submit records the typed field's shape, never its value", async () => {
    type($("#account_name_text_field"), "kit@example.com")
    $("#continue").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    await settle()
    const submit = steps().find((s) => s.trigger === "submit")!
    expect(submit.submitted).toMatchObject({ by: "click", text: "Continue" })
    const typed = submit.inputs.find((i) => i.id === "account_name_text_field")!.typed!
    expect(typed).toMatchObject({ order: 1, shape: "email", length: "9-16", truth: "email" })
    expect(typed.digest).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(sent)).not.toContain("kit@example.com")
  })

  test("the next step's text has the typed username taken out, and a password box gets no digest", async () => {
    document.body.innerHTML = `
      <p>kit@example.com</p>
      <label for="pw">Password for kit@example.com</label><input id="pw" type="password" autocomplete="current-password">
      <label for="again">Confirm</label><input id="again" type="password">
      <button>Sign In</button>`
    learnScanned()
    await settle()
    const change = steps().findLast((s) => s.trigger === "change")!
    expect(change.inputs[0].label).toBe("Password for <typed>")

    type($("#pw"), "correct horse")
    type($("#again"), "correct horse")
    // Past the window in which a click, Enter and the submit event that follows are one submit.
    await new Promise((r) => setTimeout(r, 850))
    $<HTMLInputElement>("#again").dispatchEvent(trusted(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true })))
    await settle()
    const submit = steps().findLast((s) => s.trigger === "submit")!
    expect(submit.submitted?.by).toBe("enter")
    const [pw, again] = submit.inputs.map((i) => i.typed!)
    expect(pw).toMatchObject({ order: 2, shape: "secret", truth: "password" })
    expect(pw.digest).toBeUndefined()
    expect(pw.length).toBeUndefined()
    expect(again).toMatchObject({ order: 3, sameAs: 2, truth: "password" })
    expect(JSON.stringify(sent)).not.toContain("correct horse")
  })

  test("a password shown as text by a toggle stays secret", async () => {
    for (const f of listeners) f({ type: "db:learn", session: { ...session, id: "1b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b" } })
    document.body.innerHTML = `<input id="user" type="text" autocomplete="username"><input id="pw" type="password"><button>Sign In</button>`
    learnScanned()
    await settle()
    const pw = $<HTMLInputElement>("#pw")
    pw.type = "text"
    type(pw, "hunter2-plain")
    await new Promise((r) => setTimeout(r, 850))
    $("button").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    await settle()
    const typed = steps().findLast((s) => s.trigger === "submit")!.inputs.find((i) => i.id === "pw")!.typed!
    expect(typed).toEqual({ order: 1, shape: "secret", truth: "password" })
    expect(JSON.stringify(sent)).not.toContain("hunter2-plain")
  })

  test("a page that echoes a password into text doesn't get it logged", async () => {
    for (const f of listeners) f({ type: "db:learn", session: { ...session, id: "3b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b" } })
    document.body.innerHTML = `
      <label for="pw">Password</label><input id="pw" type="password">
      <button>Sign In</button>`
    learnScanned()
    await settle()
    type($("#pw"), "hunter2-plain")
    // The page reads the password back out of the field and echoes it, as a
    // "show password" mirror or a page that logs what it was given can.
    document.title = "hunter2-plain"
    $("label").textContent = "Re-enter hunter2-plain"
    await new Promise((r) => setTimeout(r, 850))
    $("button").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    await settle()
    const submit = steps().findLast((s) => s.trigger === "submit")!
    expect(submit.title).toBe("<typed>")
    expect(submit.inputs.find((i) => i.id === "pw")!.label).toBe("Re-enter <typed>")
    expect(JSON.stringify(sent)).not.toContain("hunter2-plain")
    document.title = "Sign In - Apple"
  })

  test("page attributes and the address lose what may be the user's", async () => {
    history.replaceState(null, "", "/u/kit@example.com/login?kit@example.com&token123456=1")
    // happy-dom loads no iframe pages, and says so on the console.
    const quiet = console.error
    console.error = () => {}
    document.body.innerHTML = `
      <form action="https://kit@example.com/x"><input id="field-kit@example.com" name="otp-48151623" autocomplete="one-time-code" inputmode="numeric"></form>
      <iframe src="https://chat.example.net/w/kit@example.com/9876543"></iframe>`
    console.error = quiet
    for (const f of listeners) f({ type: "db:learn", session: { ...session, id: "2b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b" } })
    await settle()
    const start = steps().findLast((s) => s.trigger === "start")!
    expect(start.frame).toMatchObject({ path: "/u/<email>/login", queryKeys: ["<email>", "token<n>"] })
    expect(start.inputs[0]).toMatchObject({ id: "<email>", name: "otp-<n>", autocomplete: "one-time-code", inputMode: "numeric" })
    expect(start.iframes[0]).toMatchObject({ host: "chat.example.net", path: "/w/<email>/<n>" })
    expect(JSON.stringify(start)).not.toContain("kit@")
  })

  test("ends here when the background no longer has the session", async () => {
    expect(learning()).toBe(true)
    stepReply = null
    document.body.innerHTML = `<input id="next" type="text"><button>Next</button>`
    learnScanned()
    await settle()
    expect(learning()).toBe(false)
    stepReply = true
  })

  test("leaves when the session ends", async () => {
    for (const f of listeners) f({ type: "db:learn", session })
    for (const f of listeners) f({ type: "db:learn", session: null })
    expect(learning()).toBe(false)
    const before = sent.length
    $("button").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    await settle()
    expect(sent.length).toBe(before)
  })
})
