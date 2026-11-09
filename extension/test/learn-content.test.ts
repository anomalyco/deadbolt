import { beforeAll, describe, expect, test } from "bun:test"
import { initLearn, learnScanned, learning } from "../src/content/learn"
import { wordDigest, type LearnSession, type LearnStep, type TimelineEvent } from "../src/learn"

// The content side of Record, in one frame shaped like Apple's sign-in
// widget: the username box shows, the password box waits hidden.

const session: LearnSession = { id: "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b", salt: "pepper", startedAt: Date.now(), until: Date.now() + 60_000, words: [] }
const sent: Array<{ type: string; session?: string; step?: LearnStep; events?: TimelineEvent[]; words?: string[] }> = []
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
        return stepReply
      },
      onMessage: { addListener: (f: (m: unknown) => void) => listeners.push(f) },
    },
    // Other test files' timers share this process and this global: an
    // autofill session's expiry writes chrome.storage.session while these
    // tests wait. Give it somewhere to write.
    storage: { session: { get: async () => ({}), set: async () => {}, remove: async () => {} }, local: { get: async () => ({}), set: async () => {}, remove: async () => {} } },
  }
  history.replaceState(null, "", "/appleauth/auth/signin?widgetKey=secret-ish&language=US-EN")
  document.title = "Sign In - Apple"
  document.body.innerHTML = `
    <h1>Sign in with Apple Account</h1>
    <input id="account_name_text_field" type="text" autocomplete="username webauthn" aria-label="Email or Phone Number">
    <div hidden><input id="password_text_field" type="password" autocomplete="current-password" tabindex="-1"></div>
    <button id="continue">Continue</button>`
  initLearn()
  // A frame asks nothing: it waits to be told.
  await settle()
  expect(sent).toEqual([])
  join(session)
  await settle()
})

/** The background tells the frame its tab records (on DOMContentLoaded, or as it starts). */
const join = (s: LearnSession | null) => {
  for (const f of listeners) f({ type: "db:learn", session: s })
}
let next = 0x40
/** A new recording, each with its own id. */
const fresh = (over: Partial<LearnSession> = {}): LearnSession => ({ ...session, id: `${(next++).toString(16)}5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b`, startedAt: Date.now(), ...over })
/** This recording's timeline as the frame sent it. */
const timelineOf = (id: string) => sent.filter((m) => m.type === "db:learn-events" && m.session === id).flatMap((m) => m.events!)
const down = (el: Element, key: string, init: KeyboardEventInit = {}) => el.dispatchEvent(trusted(new KeyboardEvent("keydown", { key, bubbles: true, composed: true, ...init })))

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
    expect(start.frame).toMatchObject({ path: "/u/<seg>/login", queryKeys: ["<email>", "token<n>"] })
    expect(start.inputs[0]).toMatchObject({ id: "<email>", name: "otp-<n>", autocomplete: "one-time-code", inputMode: "numeric" })
    expect(start.iframes[0]).toMatchObject({ host: "chat.example.net", path: "/w/<seg>/<seg>" })
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

  test("a PIN pad's keys log no digits, text or place", async () => {
    const s = fresh()
    join(s)
    document.body.innerHTML = `<div id="pad">${[1, 2, 3, 4, 5, 6, 7, 8, 9, 0].map((n) => `<button class="key key-${n}" aria-label="${n}">${n}</button>`).join("")}</div>
      <div id="imgs">${[1, 9, 8, 4].map((n) => `<div class="k" role="button" tabindex="0"><img src="/k${n}.png" alt=""></div>`).join("")}</div>`
    // happy-dom lays nothing out: the image keys are four small same-size controls.
    const rects = new Map<Element, DOMRect>()
    for (const el of Array.from(document.querySelectorAll("#imgs .k"))) rects.set(el, { x: 0, y: 0, width: 48, height: 48, top: 0, left: 0, right: 48, bottom: 48, toJSON: () => ({}) } as DOMRect)
    const real = Element.prototype.getBoundingClientRect
    Element.prototype.getBoundingClientRect = function (this: Element) {
      return rects.get(this) ?? real.call(this)
    }
    try {
      for (const n of [1, 9, 8, 4]) {
        const key = $(`#pad .key-${n}`)
        for (const type of ["pointerdown", "pointerup", "click"]) key.dispatchEvent(trusted(new MouseEvent(type, { bubbles: true, composed: true, clientX: 10 * n, clientY: 20 })))
      }
      for (const key of Array.from(document.querySelectorAll("#imgs .k img"))) key.dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true, clientX: 5, clientY: 5 })))
      await new Promise((r) => setTimeout(r, 650))
    } finally {
      Element.prototype.getBoundingClientRect = real
    }
    const timeline = timelineOf(s.id)
    expect(timeline.length).toBe(16)
    expect(timeline.every((e) => e.target?.keypad === true && e.x === undefined && e.y === undefined && !e.target.text && !e.target.label)).toBe(true)
    expect(timeline[0].target).toEqual({ tag: "button", path: "html > body > div > button", keypad: true })
    expect(JSON.stringify(timeline.map((e) => e.target))).not.toMatch(/\d/)
    expect(JSON.stringify(sent.filter((m) => m.session === s.id))).not.toMatch(/"(text|label)":"[^"]*\d/)
  })

  test("a phone pad's 2580 logs no digit or letters on focus, blur or click", async () => {
    const s = fresh()
    join(s)
    const keys = ["1", "2 ABC", "3 DEF", "4 GHI", "5 JKL", "6 MNO", "7 PQRS", "8 TUV", "9 WXYZ", "0 +"]
    document.body.innerHTML = `<div class="pad">${keys.map((k, i) => `<button id="key-${k[0]}" name="digit${k[0]}" class="k${i}">${k.replace(" ", "<br>")}</button>`).join("")}</div>`
    for (const d of "2580") {
      const key = $(`#key-${d}`)
      key.dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
      for (const type of ["pointerdown", "pointerup", "click"]) key.dispatchEvent(trusted(new MouseEvent(type, { bubbles: true, composed: true, clientX: 10, clientY: 10 })))
      down(key, "Enter")
      key.dispatchEvent(trusted(new FocusEvent("focusout", { bubbles: true, composed: true })))
    }
    await new Promise((r) => setTimeout(r, 650))
    const timeline = timelineOf(s.id)
    expect(new Set(timeline.map((e) => e.type))).toEqual(new Set(["focus", "pointerdown", "pointerup", "click", "key", "blur"]))
    expect(timeline.every((e) => e.target === undefined || (e.target.keypad && !e.target.id && !e.target.name && !e.target.text && !e.target.label))).toBe(true)
    const all = JSON.stringify(timeline.map((e) => e.target))
    expect(all).not.toMatch(/\d|ABC|JKL|TUV|key-|digit/)
  })

  test("spelled-out keys nested a wrapper deeper, three to a row, are a keypad's", async () => {
    const s = fresh()
    join(s)
    const rows = [["sieben", "acht", "neun"], ["vier", "fünf", "sechs"]]
    document.body.innerHTML = `<div id="pad">${rows.map((r) => `<div class="row">${r.map((w) => `<span class="cell"><span class="wrap"><button id="k-${w}">${w}</button></span></span>`).join("")}</div>`).join("")}</div>
      <button id="pay">Pay seven dollars</button>`
    const real = Element.prototype.getBoundingClientRect
    Element.prototype.getBoundingClientRect = function (this: Element) {
      return this.tagName === "BUTTON" && this.id.startsWith("k-") ? ({ x: 0, y: 0, width: 56, height: 56, top: 0, left: 0, right: 56, bottom: 56, toJSON: () => ({}) } as DOMRect) : real.call(this)
    }
    try {
      for (const w of ["sieben", "neun", "vier"]) {
        $(`#k-${w}`).dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
        $(`#k-${w}`).dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
      }
      $("#pay").dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
      await new Promise((r) => setTimeout(r, 650))
    } finally {
      Element.prototype.getBoundingClientRect = real
    }
    const targets = timelineOf(s.id).map((e) => e.target!)
    expect(targets.slice(0, 6).every((t) => t.keypad && t.path === "div > span > span > button" && !t.text && !t.id)).toBe(true)
    expect(targets[6]).toMatchObject({ tag: "button", id: "pay", text: "Pay <n> dollars" })
    expect(JSON.stringify(targets)).not.toMatch(/sieben|neun|vier/)
  })

  test("a letter keyboard's keys keep no id or class: they would spell the word", async () => {
    const s = fresh()
    join(s)
    document.body.innerHTML = `<div id="kb">${"qwertyuiop".split("").map((c) => `<button id="key-${c}" class="key key-${c}" data-k="${c}">${c}</button>`).join("")}</div>`
    for (const c of "hunter".split("").filter((c) => document.getElementById(`key-${c}`)))
      for (const type of ["focusin", "click"]) $(`#key-${c}`).dispatchEvent(trusted(type === "click" ? new MouseEvent(type, { bubbles: true, composed: true }) : new FocusEvent(type, { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    const targets = timelineOf(s.id).map((e) => e.target!)
    expect(targets.length).toBeGreaterThan(0)
    expect(targets.every((t) => t.keypad && !t.id && !t.name && t.path === "html > body > div > button")).toBe(true)
    expect(JSON.stringify(targets)).not.toMatch(/key-/)
  })

  test("an echo cut short, or of a typed value's start, is scrubbed, past 256 characters too", async () => {
    const s = fresh()
    join(s)
    document.body.innerHTML = `<textarea id="msg"></textarea><input id="name">
      <button id="send">Send kit vogel secr…</button><button id="hi">Hello kitt</button><button id="tail">Mention zanzib…</button>`
    const msg = $<HTMLTextAreaElement>("#msg")
    msg.value = `kit vogel secret message ${"filler words ".repeat(30)}zanzibar`
    msg.dispatchEvent(trusted(new Event("input", { bubbles: true, composed: true })))
    type($<HTMLInputElement>("#name"), "kittens")
    for (const b of ["send", "hi", "tail"]) $(`#${b}`).dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    const texts = timelineOf(s.id).filter((e) => e.type === "focus").map((e) => e.target?.text)
    expect(texts).toEqual(["Send <typed> <typed> <typed>…", "Hello <typed>", "Mention <typed>…"])
  })

  test("a password box in a closed shadow root logs only Enter, Tab and Escape", async () => {
    const s = fresh()
    join(s)
    document.body.innerHTML = `<pw-box id="host"></pw-box><input id="after">`
    const host = $("#host")
    const root = host.attachShadow({ mode: "closed" })
    root.innerHTML = `<input type="password" id="inner">`
    for (const [key, init] of [["Shift", { shiftKey: true }], ["C", { shiftKey: true }], ["o", {}], ["Backspace", {}], ["v", { ctrlKey: true }], ["ArrowLeft", {}], ["Enter", {}], ["Tab", {}], ["Escape", {}], ["Enter", { ctrlKey: true }]] as const) down(host, key, init)
    host.dispatchEvent(trusted(new Event("input", { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    const timeline = timelineOf(s.id)
    expect(timeline.map((e) => [e.type, e.key, e.mods ?? ""])).toEqual([
      ["key", "Enter", ""],
      ["key", "Tab", ""],
      ["key", "Escape", ""],
    ])
    expect(timeline.some((e) => e.length)).toBe(false)
  })

  test("Ctrl+Alt+Q and other chords in a password box log nothing, and its typing stays one event", async () => {
    const s = fresh()
    join(s)
    document.body.innerHTML = `<input id="pw" type="password"><input id="user">`
    const pw = $<HTMLInputElement>("#pw")
    pw.dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
    type(pw, "ab")
    down(pw, "q", { ctrlKey: true, altKey: true })
    down(pw, "@", { altKey: true, ctrlKey: true })
    down(pw, "Enter", { altKey: true })
    down(pw, "Tab", { metaKey: true })
    type(pw, "abcd")
    pw.dispatchEvent(trusted(new FocusEvent("focusout", { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    expect(timelineOf(s.id).map((e) => e.type)).toEqual(["focus", "input", "blur"])
  })

  test("textarea and editable text, and labels that show it, are scrubbed", async () => {
    const s = fresh()
    join(s)
    document.body.innerHTML = `
      <label>Note <textarea id="note"></textarea></label>
      <div id="live" aria-live="polite"></div>
      <label for="reply" id="lab">Reply</label><input id="reply" aria-labelledby="live lab">
      <button id="send">Send</button>`
    const note = $<HTMLTextAreaElement>("#note")
    note.value = "meet me at the blue door"
    note.dispatchEvent(trusted(new Event("input", { bubbles: true, composed: true })))
    $("#live").textContent = "Saved meet me at the blue door"
    document.body.insertAdjacentHTML("beforeend", `<label for="x">Re: meet me at the blue door</label><input id="x">`)
    learnScanned()
    $("#reply").dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
    $("#note").dispatchEvent(trusted(new FocusEvent("focusin", { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    const all = JSON.stringify(sent.filter((m) => m.session === s.id))
    expect(all).not.toContain("blue door")
    expect(all).toContain("Re: <typed>")
    const focus = timelineOf(s.id).filter((e) => e.type === "focus")
    expect(focus.map((e) => e.target?.label)).toEqual(["Reply", "Note"])
    // The typed words go to the background as salted digests, never as words.
    const words = sent.filter((m) => m.session === s.id).flatMap((m) => m.words ?? [])
    expect(words).toContain(await wordDigest(s.salt, "door"))
    expect(all).not.toMatch(/"meet"|"door"/)
  })

  test("a later page's address and title are scrubbed of words typed before it", async () => {
    history.replaceState(null, "", "/search/Kittens/results?kittens=1")
    document.title = "Kittens - Example Search"
    document.body.innerHTML = `<input id="q">`
    const s = fresh({ words: [await wordDigest(session.salt, "kittens")] })
    join(s)
    await settle()
    const start = steps().findLast((st) => st.trigger === "start")!
    expect(start.frame).toMatchObject({ path: "/search/<seg>/results", queryKeys: ["<typed>"] })
    expect(start.title).toBe("<typed> - Example Search")
    history.replaceState(null, "", "/search/kittens")
    $<HTMLInputElement>("#q").dispatchEvent(trusted(new Event("input", { bubbles: true, composed: true })))
    document.body.innerHTML = `<input id="q2">`
    learnScanned()
    await settle()
    const change = steps().findLast((st) => st.trigger === "change")!
    expect(change.frame.path).toBe("/search/<typed>")
    // Only a page's first step has its title.
    expect(change.title).toBeUndefined()
  })

  test("a pagehide a page dispatches itself isn't an unload", async () => {
    const s = fresh()
    join(s)
    window.dispatchEvent(new Event("pagehide"))
    window.dispatchEvent(trusted(new Event("pagehide")))
    await new Promise((r) => setTimeout(r, 50))
    expect(timelineOf(s.id).filter((e) => e.type === "unload").length).toBe(1)
  })

  test("a full recording doesn't end the frame: it stops sending, the tab still records", async () => {
    const s = fresh()
    join(s)
    stepReply = "full"
    document.body.innerHTML = `<button id="b">Go</button>`
    $("#b").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    expect(learning()).toBe(true)
    const before = sent.filter((m) => m.type === "db:learn-events").length
    $("#b").dispatchEvent(trusted(new MouseEvent("click", { bubbles: true, composed: true })))
    await new Promise((r) => setTimeout(r, 650))
    expect(sent.filter((m) => m.type === "db:learn-events").length).toBe(before)
    expect(learning()).toBe(true)
    stepReply = true
  })

  test("ends here when the background no longer has the session", async () => {
    join(fresh())
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
