import { beforeAll, describe, expect, test } from "bun:test"
import { initLearn, learnScanned, learning } from "../src/content/learn"
import type { LearnSession, LearnStep, TimelineEvent } from "../src/learn"

// The content side of Record, in one frame shaped like Apple's sign-in
// widget: the username box shows, the password box waits hidden.

const session: LearnSession = { id: "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b", salt: "pepper", startedAt: Date.now(), until: Date.now() + 60_000 }
const sent: Array<{ type: string; session?: string; step?: LearnStep; events?: TimelineEvent[] }> = []
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

  test("the timeline: clicks, named keys and typing by shape, never a typed or pasted value", async () => {
    for (const f of listeners) f({ type: "db:learn", session: { ...session, id: "3b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b", startedAt: Date.now() } })
    document.body.innerHTML = `
      <form id="login"><label for="email">Email</label><input id="email" name="email" autocomplete="username">
      <input id="pw" type="password" name="pw"><button id="go" type="submit">Sign in <span>now</span></button></form>`
    const email = $<HTMLInputElement>("#email")
    const pw = $<HTMLInputElement>("#pw")
    const down = (el: Element, key: string, init: KeyboardEventInit = {}) => el.dispatchEvent(trusted(new KeyboardEvent("keydown", { key, bubbles: true, composed: true, ...init })))
    const focus = (el: Element) => el.dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
    focus(email)
    for (const c of "kit@example.com") down(email, c)
    type(email, "kit@example.com")
    down(email, "Tab")
    focus(pw)
    // A password box's capitals and length stay its own.
    down(pw, "Shift")
    down(pw, "C", { shiftKey: true })
    pw.value = "correct horse battery"
    pw.dispatchEvent(trusted(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertFromPaste" })))
    down(pw, "Enter")
    down(document.body, "k")
    $("#go span").dispatchEvent(trusted(new MouseEvent("pointerdown", { bubbles: true, composed: true, clientX: 40, clientY: 12 })))
    $("#go span").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true, clientX: 40, clientY: 12 })))
    await new Promise((r) => setTimeout(r, 650))
    const timeline = sent.filter((m) => m.type === "db:learn-events" && m.session?.startsWith("3b5d")).flatMap((m) => m.events!)
    const brief = timeline.map((e) => [e.type, e.key ?? e.target?.id ?? e.target?.tag, e.shape ?? null])
    expect(brief).toEqual([
      ["focus", "email", null],
      ["input", "email", "email"],
      ["key", "Tab", "email"],
      ["focus", "pw", null],
      ["input", "pw", "secret"],
      ["key", "Enter", "secret"],
      ["key", "char", null],
      ["pointerdown", "go", null],
      ["click", "go", null],
    ])
    expect(timeline[0].target).toMatchObject({ tag: "input", id: "email", name: "email", label: "Email", autocomplete: "username", path: "input#email" })
    expect(timeline[1]).toMatchObject({ length: "9-16" })
    expect(timeline[4]).toMatchObject({ inputType: "insertFromPaste" })
    expect(timeline[4].length).toBeUndefined()
    // Merged typing keeps no count: that would be the value's length.
    expect(JSON.stringify(timeline)).not.toContain("count")
    expect(timeline[7]).toMatchObject({ x: 40, y: 12, target: { tag: "button", type: "submit", text: "Sign in now", path: "button#go" } })
    expect(timeline.every((e, i) => e.t >= 0 && (i === 0 || e.t >= timeline[i - 1].t))).toBe(true)
    const all = JSON.stringify(sent)
    for (const never of ["kit@example.com", "correct horse battery", "kit@"]) expect(all).not.toContain(never)
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
    // Only this frame's messages: other test files' timers share the process and the chrome stub.
    const ours = () => sent.filter((m) => m.type.startsWith("db:learn")).length
    const before = ours()
    // Not recording, the frame doesn't listen at all.
    $("button").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    $("button").dispatchEvent(trusted(new MouseEvent("pointerdown", { bubbles: true, composed: true })))
    $("button").dispatchEvent(trusted(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 600))
    expect(ours()).toBe(before)
  })
})
