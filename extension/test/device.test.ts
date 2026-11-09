import { afterEach, beforeEach, describe, expect, jest, spyOn, test } from "bun:test"
import type { ActivityEntry, DeviceReply, Status } from "../src/messages"
import { describePreset, quitKeys } from "../src/device-rules"
import { activityDetail, activitySection, activityWords } from "../src/vault/activity"
import type { App } from "../src/vault/app"
import { installChrome, type FakeChrome } from "./chrome"

// device.html's first run (src/vault, as the popup shows it too): choosing
// between pairing and a new vault, joining a vault another device has, and
// what survives a reload, a cancel and a poll.

const CODE = "dress-garment-tiger-strategy"
const POLL_MS = 1500
type Command = { type: string; [k: string]: unknown }

let fake: FakeChrome
let status: Status
/** What the vault says about the join, as device-join-status. */
let phase: Record<string, unknown>
/** Holds the next answer to a command type until the returned function is called. */
let held: Record<string, Promise<void>>
let loads = 0
/** The vault's Activity, newest first, as device-activity pages it. */
let activity: ActivityEntry[]
/** What device-settings answers (the preset, and why it locked). */
let settings: Record<string, unknown>
/** Touch ID's enrollment as device-biometric-info answers it, when it's set up. */
let touchToken: string | undefined
const NOW = 1_800_000_000

const ok = (reply: Record<string, unknown>): DeviceReply => ({ ok: true, reply, ms: 1, status })

async function answer(c: Command): Promise<DeviceReply> {
  await held[c.type]
  switch (c.type) {
    case "device-status":
      return ok({ type: "hello" })
    case "device-join-status":
      return ok({ type: "device-join-status", ...phase })
    case "device-join-start":
      phase = { phase: "waiting", code: CODE }
      return ok({ type: "device-join-start", code: CODE, phase: "waiting" })
    case "device-join-cancel":
      phase = { phase: "idle" }
      return ok({ type: "device-join-cancel", ok: true })
    case "device-join-finish":
      phase = { phase: "idle" }
      status = { state: "ready", version: "test" }
      return ok({ type: "device-join-finish", ok: true })
    case "device-items":
      return ok({ type: "device-items", items: [] })
    case "device-devices":
      return ok({ type: "device-devices", devices: [{ id: "d".repeat(64), name: "Chrome on macOS", current: true }] })
    case "device-settings":
      return ok({ type: "device-settings", retryAt: 0, ...settings })
    case "device-biometric-info":
      return ok({ type: "device-biometric-info", token: touchToken })
    case "device-preset":
      // As the service worker: Until you quit takes the passphrase, which the vault checks.
      if (c.preset === "until-quit" && settings.preset !== "until-quit") {
        if (!c.passphrase) return { ok: false, message: "Enter your passphrase.", code: "passphrase_needed", status }
        if (c.passphrase === "wrong") return { ok: false, message: "That passphrase isn't right.", code: "wrong_passphrase", status }
      }
      settings = { ...settings, preset: c.preset }
      return ok({ type: "device-settings", retryAt: 0, ...settings })
    case "device-pair":
      // As the vault: admitting a device takes the passphrase.
      if (!c.passphrase && !c.prf) return { ok: false, message: "Enter your passphrase to continue.", code: "passphrase_needed", status }
      if (c.passphrase === "wrong") return { ok: false, message: "That passphrase isn't right.", code: "wrong_passphrase", status }
      return ok({ type: "device-pair", ok: true })
    case "device-activity": {
      const before = typeof c.before === "number" ? c.before : Infinity
      const entries = activity.filter((e) => e.id < before).slice(0, typeof c.limit === "number" ? c.limit : 50)
      return ok({ type: "device-activity", now: NOW, entries })
    }
  }
  return ok({ type: c.type, ok: true })
}

function hold(type: string): () => void {
  let release = () => {}
  held[type] = new Promise<void>((resolve) => (release = resolve))
  return () => {
    delete held[type]
    release()
  }
}

const commands = () => fake.sent.filter((m) => (m as { type: string }).type === "db:device").map((m) => (m as { command: Command }).command)
const sentTypes = () => commands().map((c) => c.type)
const app = () => document.getElementById("app")!
const headings = () => [...app().querySelectorAll(".stage h1, .stage h2")].map((h) => h.textContent).filter(Boolean)
/** A button's name: its label if it has one (icon buttons, the first-run choices), else its text. */
/** A button's accessible name, near enough: its aria-label, what aria-labelledby points at, or its text. */
const nameOf = (b: Element) => b.getAttribute("aria-label") ?? (b.hasAttribute("aria-labelledby") ? document.getElementById(b.getAttribute("aria-labelledby")!)?.textContent : null) ?? b.textContent
const buttons = () => [...app().querySelectorAll(".stage button")].map(nameOf)
const buttonNamed = (name: string) => [...app().querySelectorAll<HTMLButtonElement>(".stage button")].find((b) => nameOf(b) === name)!
const input = (label: string) => {
  const l = [...app().querySelectorAll("label")].find((l) => l.textContent === label)
  return (l ? document.getElementById(l.htmlFor) : app().querySelector(`input[aria-label="${label}"]`)) as HTMLInputElement
}
const shownError = () => app().querySelector(".error:not([hidden])")

/** Lets the page's message round trips finish (they're promises, not timers). */
async function flush() {
  for (let i = 0; i < 30; i++) await Promise.resolve()
}

/** Opens device.html afresh: a new page, as after a reload. */
async function open() {
  document.getElementById("app")?.remove()
  document.body.append(Object.assign(document.createElement("main"), { id: "app" }))
  await import(`../src/device.ts?page=${loads++}`)
  await flush()
}

function submit(form: Element) {
  form.dispatchEvent(new Event("submit", { cancelable: true }))
}

let logs: Array<ReturnType<typeof spyOn>>

beforeEach(() => {
  jest.useFakeTimers()
  fake = installChrome()
  status = { state: "not-set-up" }
  phase = { phase: "idle" }
  held = {}
  activity = []
  settings = { preset: "comfortable" }
  touchToken = undefined
  fake.runtimeAnswer = (m) => ((m as { type: string }).type === "db:device" ? answer((m as { command: Command }).command) : undefined)
  logs = (["log", "info", "debug", "warn", "error"] as const).map((k) => spyOn(console, k))
})

afterEach(() => {
  // No page ever logs a pairing code (or anything else).
  for (const spy of logs) {
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  }
  // The old page goes away, as a closed tab does: its timers stop.
  window.dispatchEvent(new Event("pagehide"))
  jest.useRealTimers()
})

describe("first run", () => {
  test("offers pairing first and a new vault second; creating opens the existing form", async () => {
    await open()
    expect(headings()).toEqual(["Set up Deadbolt"])
    expect(buttons()).toEqual(["Pair with an existing device", "Create a new vault"])
    buttonNamed("Create a new vault").click()
    expect(headings()).toEqual(["Create a vault"])
    expect(buttons()).toContain("Create vault")
    expect(sentTypes()).toEqual(["device-status", "device-join-status"])
  })

  test("pairing shows the code to type on the other device, and waits", async () => {
    await open()
    buttonNamed("Pair with an existing device").click()
    await flush()
    expect(commands().at(-1)).toEqual({ type: "device-join-start" })
    expect(app().querySelector("#join-code")!.textContent).toBe(CODE)
    expect(app().textContent).toContain("On a device that has your vault, run deadbolt approve with this code, or choose Approve in the Deadbolt app.")
    expect(app().querySelector("code")!.textContent).toBe("deadbolt approve")
    expect(buttons()).toEqual(["Back", "Copy code", "Copy command", "Cancel"])

    const writes: string[] = []
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (t: string) => void writes.push(t) } })
    buttonNamed("Copy code").click()
    await flush()
    expect(writes).toEqual([CODE])
    expect(buttons()).toEqual(["Back", "Copied", "Copy command", "Cancel"])
    buttonNamed("Copy command").click()
    await flush()
    expect(writes).toEqual([CODE, `deadbolt approve ${CODE}`])
  })

  test("a poll that changes nothing redraws nothing; admission asks this browser's passphrase", async () => {
    await open()
    buttonNamed("Pair with an existing device").click()
    await flush()
    const card = app().querySelector(".code-box")
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    expect(sentTypes().filter((t) => t === "device-join-status")).toHaveLength(2)
    expect(app().querySelector(".code-box")).toBe(card)

    phase = { phase: "admitted", vault: "personal" }
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    expect(headings()).toEqual(["Joined the personal vault"])
    expect(app().textContent).toContain("It unlocks Deadbolt here only")
    expect(buttons()).toEqual(["Finish", "Cancel"])
    // Admitted, nothing more to wait for: no more polls.
    const polls = sentTypes().length
    jest.advanceTimersByTime(POLL_MS * 4)
    await flush()
    expect(sentTypes()).toHaveLength(polls)

    // A status push that changes nothing keeps what's typed.
    input("Passphrase").value = "typed"
    fake.listeners.forEach((l) => l({ type: "db:status", status }, {}, () => {}))
    expect(input("Passphrase").value).toBe("typed")
  })

  test("finishing sends only the passphrase, then shows the vault", async () => {
    phase = { phase: "admitted", vault: "personal" }
    await open()
    input("Passphrase").value = "browser pass"
    input("Passphrase again").value = "something else"
    submit(app().querySelector("form")!)
    await flush()
    expect(shownError()!.textContent).toBe("The passphrases don't match.")
    expect(sentTypes()).not.toContain("device-join-finish")

    input("Passphrase").value = "browser pass"
    input("Passphrase again").value = "browser pass"
    submit(app().querySelector("form")!)
    await flush()
    expect(commands().find((c) => c.type === "device-join-finish")).toEqual({ type: "device-join-finish", passphrase: "browser pass" })
    // The vault: its (empty) logins, and the footer saying no other device shares it yet.
    expect(app().querySelector('input[type="search"]')).not.toBeNull()
    expect(app().textContent).toContain("Nothing saved yet")
    expect(app().querySelector(".bottom")!.textContent).toContain("Only on this browser")
  })

  test("a failure says why, and can be tried again or cancelled", async () => {
    await open()
    buttonNamed("Pair with an existing device").click()
    await flush()
    phase = { phase: "failed", message: "The pairing code expired." }
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    expect(headings()).toEqual(["Pairing didn't work"])
    expect(app().querySelector(".error")!.textContent).toBe("The pairing code expired.")
    expect(buttons()).toEqual(["Back", "Cancel", "Try again"])

    buttonNamed("Try again").click()
    await flush()
    expect(sentTypes().filter((t) => t === "device-join-start")).toHaveLength(2)
    expect(app().querySelector("#join-code")!.textContent).toBe(CODE)

    phase = { phase: "failed", message: "The other device refused." }
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    buttonNamed("Cancel").click()
    await flush()
    expect(sentTypes().at(-1)).toBe("device-join-cancel")
    expect(buttons()).toEqual(["Pair with an existing device", "Create a new vault"])
    expect(sentTypes()).not.toContain("device-create")
  })

  test("a start the vault refuses shows its message", async () => {
    await open()
    fake.runtimeAnswer = (m) => {
      const c = (m as { command: Command }).command
      return c.type === "device-join-start" ? ({ ok: false, message: "Deadbolt couldn't reach its relay.", status } satisfies DeviceReply) : answer(c)
    }
    buttonNamed("Pair with an existing device").click()
    await flush()
    expect(headings()).toEqual(["Pairing didn't work"])
    expect(app().querySelector(".error")!.textContent).toBe("Deadbolt couldn't reach its relay.")
  })

  test("losing a waiting worker explains the interruption", async () => {
    await open()
    buttonNamed("Pair with an existing device").click()
    await flush()
    phase = { phase: "idle" }
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    expect(headings()).toEqual(["Pairing didn't work"])
    expect(app().querySelector(".error")!.textContent).toBe("The pairing was interrupted. Start again.")
  })

  test("screen lock discarding admission explains why the passphrase form went away", async () => {
    phase = { phase: "admitted", vault: "personal" }
    await open()
    phase = { phase: "idle" }
    fake.listeners.forEach((l) => l({ type: "db:status", status }, {}, () => {}))
    await flush()
    expect(headings()).toEqual(["Pairing didn't work"])
    expect(buttons()).toEqual(["Back", "Cancel", "Try again"])
  })
})

describe("cancel", () => {
  test("goes back to the choice, and a poll answered after it can't bring the code back", async () => {
    await open()
    buttonNamed("Pair with an existing device").click()
    await flush()
    const release = hold("device-join-status")
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    buttonNamed("Cancel").click()
    await flush()
    expect(buttons()).toEqual(["Pair with an existing device", "Create a new vault"])
    // The stale poll answers "waiting" with its code.
    phase = { phase: "waiting", code: CODE }
    release()
    await flush()
    expect(app().querySelector("#join-code")).toBeNull()
    expect(buttons()).toEqual(["Pair with an existing device", "Create a new vault"])
    // And nothing polls any more.
    const sent = sentTypes().length
    jest.advanceTimersByTime(POLL_MS * 4)
    await flush()
    expect(sentTypes()).toHaveLength(sent)
  })

  test("while the code is still coming, a late start can't bring it back", async () => {
    await open()
    const release = hold("device-join-start")
    buttonNamed("Pair with an existing device").click()
    await flush()
    expect(app().textContent).toContain("Getting a code…")
    buttonNamed("Cancel").click()
    await flush()
    release()
    await flush()
    expect(app().querySelector("#join-code")).toBeNull()
    expect(buttons()).toEqual(["Pair with an existing device", "Create a new vault"])
  })

  test("a finish answered after a cancel doesn't open a vault", async () => {
    phase = { phase: "admitted" }
    await open()
    const release = hold("device-join-finish")
    input("Passphrase").value = "p"
    input("Passphrase again").value = "p"
    submit(app().querySelector("form")!)
    await flush()
    buttonNamed("Cancel").click()
    await flush()
    // The cancel ended the worker, so the finish fails as locked.
    fake.runtimeAnswer = (m) => {
      const c = (m as { command: Command }).command
      return c.type === "device-join-finish" ? ({ ok: false, message: "Deadbolt locked.", status } satisfies DeviceReply) : answer(c)
    }
    release()
    await flush()
    expect(buttons()).toEqual(["Pair with an existing device", "Create a new vault"])
    expect(shownError()).toBeNull()
  })
})

describe("reload", () => {
  test("a reloaded page shows the code it was waiting with, and keeps polling", async () => {
    phase = { phase: "waiting", code: CODE }
    await open()
    expect(app().querySelector("#join-code")!.textContent).toBe(CODE)
    expect(sentTypes()).toEqual(["device-status", "device-join-status"])
    jest.advanceTimersByTime(POLL_MS)
    await flush()
    expect(sentTypes()).toEqual(["device-status", "device-join-status", "device-join-status"])
  })

  test("closing the page stops its polls", async () => {
    phase = { phase: "waiting", code: CODE }
    await open()
    window.dispatchEvent(new Event("pagehide"))
    jest.advanceTimersByTime(POLL_MS * 4)
    await flush()
    expect(sentTypes()).toEqual(["device-status", "device-join-status"])
  })

  test("a vault set up under the page ends the join's view and its polls", async () => {
    phase = { phase: "waiting", code: CODE }
    await open()
    status = { state: "locked", detail: "Unlock Deadbolt to fill passwords" }
    fake.listeners.forEach((l) => l({ type: "db:status", status }, {}, () => {}))
    await flush()
    expect(headings()).toContain("Unlock Deadbolt")
    const sent = sentTypes().length
    jest.advanceTimersByTime(POLL_MS * 4)
    await flush()
    expect(sentTypes()).toHaveLength(sent)
  })
})

describe("lock", () => {
  const reason = () => app().querySelector<HTMLElement>(".lock-reason")!

  test("the locked page says quietly why it locked", async () => {
    status = { state: "locked" }
    settings = { preset: "relaxed", lockedBy: { reason: "idle", idleMs: 12 * 60 * 60_000 } }
    await open()
    expect(headings()).toContain("Unlock Deadbolt")
    expect(reason().textContent).toBe("Locked · 12 h idle")
    // The lock setting itself is Settings' to say, not the locked page's.
    expect(app().textContent).not.toContain("Relaxed")
    settings = { preset: "until-quit", lockedBy: { reason: "quit" } }
    await open()
    expect(reason().textContent).toBe("Locked · browser restarted")
    for (const [why, line] of [["screen", "screen locked"], ["worker", "vault worker stopped"], ["offscreen", "browser closed the vault's page"], ["update", "extension updated"], ["removed", "removed from vault"]]) {
      settings = { preset: "comfortable", lockedBy: { reason: why } }
      await open()
      expect(reason().textContent).toBe(`Locked · ${line}`)
    }
    // A lock the user made needs no telling.
    settings = { preset: "comfortable", lockedBy: { reason: "manual" } }
    await open()
    expect(reason().textContent).toBe("")
    // Nothing known, or something that isn't a reason: nothing said.
    for (const lockedBy of [undefined, { reason: "password123" }]) {
      settings = { preset: "comfortable", lockedBy }
      await open()
      expect(reason().textContent).toBe("")
    }
  })

  describe("with Touch ID set up", () => {
    const credentials = Object.getOwnPropertyDescriptor(navigator, "credentials")
    // What the label says now (its text swaps over a moment: ui/unlock.ts swapText).
    const touchLabel = () => app().querySelector<HTMLElement>(".unlock-touch-label")!.dataset.text
    const errorLine = () => app().querySelector(".unlock-under.wrong")
    /** The browser's prompt: `get` is the platform authenticator's. */
    const prompt = (get: (o: CredentialRequestOptions) => Promise<Credential | null>) => Object.defineProperty(navigator, "credentials", { configurable: true, value: { get } })
    beforeEach(() => {
      status = { state: "locked" }
      touchToken = JSON.stringify({ id: "ab".repeat(16), salt: "cd".repeat(32) })
    })
    afterEach(() => {
      if (credentials) Object.defineProperty(navigator, "credentials", credentials)
      else delete (navigator as unknown as { credentials?: unknown }).credentials
    })

    test("a prompt the user cancels is no error: the panel is as it opened, the passphrase field ready", async () => {
      prompt(() => Promise.reject(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError")))
      await open()
      expect(document.activeElement).toBe(input("Passphrase"))
      buttonNamed("Unlock with Touch ID").click()
      await flush()
      expect(touchLabel()).toBe("Unlock with Touch ID")
      expect(errorLine()).toBeNull()
      expect(document.activeElement).toBe(input("Passphrase"))
      expect(sentTypes()).not.toContain("device-unlock")
    })

    test("Return on the empty field asks Touch ID, and the passphrase ends its prompt", async () => {
      const asked: AbortSignal[] = []
      prompt((o) => new Promise((_, reject) => {
        asked.push(o.signal!)
        o.signal!.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")))
      }))
      await open()
      const form = app().querySelector("form.unlock")!
      submit(form)
      await flush()
      expect(asked).toHaveLength(1)
      // The system's prompt says what to do; the panel only says it's waiting.
      expect(touchLabel()).toBe("Waiting for macOS…")
      expect(document.activeElement).toBe(input("Passphrase"))
      input("Passphrase").value = "browser pass"
      submit(form)
      await flush()
      expect(commands().find((c) => c.type === "device-unlock")).toMatchObject({ passphrase: "browser pass" })
      expect(asked[0]!.aborted).toBe(true)
      expect(errorLine()).toBeNull()
    })
  })

  test("a wrong passphrase is said in the line that says why it locked, and typing again gives the line back", async () => {
    status = { state: "locked" }
    settings = { preset: "comfortable", lockedBy: { reason: "idle", idleMs: 60 * 60_000 } }
    fake.runtimeAnswer = (m) => {
      const c = (m as { command?: Command }).command
      if (c?.type === "device-unlock") return Promise.resolve({ ok: false, code: "wrong_passphrase", message: "That passphrase isn't right.", status } as DeviceReply)
      return (m as { type: string }).type === "db:device" ? answer(c!) : undefined
    }
    await open()
    const under = app().querySelector(".unlock-under")!
    expect(reason().textContent).toBe("Locked · 1 h idle")
    expect(under.classList.contains("wrong")).toBe(false)
    input("Passphrase").value = "nope"
    submit(app().querySelector("form.unlock")!)
    await flush()
    // The same line, in the room it always has: nothing under the field moves.
    expect(under.classList.contains("wrong")).toBe(true)
    expect(under.querySelector(".unlock-line")!.textContent).toBe("That passphrase isn't right.")
    expect(reason().textContent).toBe("Locked · 1 h idle")
    input("Passphrase").value = "n"
    input("Passphrase").dispatchEvent(new Event("input"))
    expect(under.classList.contains("wrong")).toBe(false)
  })

  test("choosing Until you quit asks for the passphrase first", async () => {
    status = { state: "ready", version: "test" }
    await open()
    const settingsButton = [...app().querySelectorAll<HTMLButtonElement>("button")].find((b) => nameOf(b) === "Settings")!
    settingsButton.click()
    await flush()
    const radio = (p: string) => app().querySelector<HTMLInputElement>(`input[name="preset"][value="${p}"]`)!
    const sub = [...app().querySelectorAll(".preset")].find((l) => l.contains(radio("until-quit")))!.querySelector(".sub")!.textContent
    expect(sub).toBe(describePreset("until-quit"))
    expect(sub).toContain("Stays unlocked, even through sleep and screen lock, until you quit the browser (")
    expect(sub).toEndWith("). Anyone using this computer can see and fill your passwords, cards and codes meanwhile.")
    radio("until-quit").checked = true
    radio("until-quit").dispatchEvent(new Event("change"))
    await flush()
    // Asked, not chosen yet.
    expect(commands().filter((c) => c.type === "device-preset")).toEqual([])
    expect(radio("comfortable").checked).toBe(true)
    const pass = input("Passphrase to stay unlocked")
    pass.value = "wrong"
    submit(pass.closest("form")!)
    await flush()
    expect(shownError()!.textContent).toBe("That passphrase isn't right.")
    expect(radio("comfortable").checked).toBe(true)
    pass.value = "right"
    submit(pass.closest("form")!)
    await flush()
    expect(commands().filter((c) => c.type === "device-preset").at(-1)).toEqual({ type: "device-preset", preset: "until-quit", passphrase: "right" })
    expect(radio("until-quit").checked).toBe(true)
    expect(input("Passphrase to stay unlocked")).toBeNull()
    // A stricter one again takes nothing.
    radio("relaxed").checked = true
    radio("relaxed").dispatchEvent(new Event("change"))
    await flush()
    expect(commands().filter((c) => c.type === "device-preset").at(-1)).toEqual({ type: "device-preset", preset: "relaxed" })
    expect(radio("relaxed").checked).toBe(true)
  })
})

describe("quitting", () => {
  test("is ⌘Q on a Mac, and closing every window (or Ctrl+Shift+Q on Linux) elsewhere", () => {
    expect(quitKeys({ platform: "MacIntel" })).toBe("⌘Q")
    expect(quitKeys({ userAgentData: { platform: "macOS" } })).toBe("⌘Q")
    expect(quitKeys({ userAgentData: { platform: "Windows" }, platform: "Win32" })).toBe("close every window, or Ctrl+Shift+Q on Linux")
    expect(quitKeys({ platform: "Linux x86_64" })).toBe("close every window, or Ctrl+Shift+Q on Linux")
    expect(describePreset("until-quit", "⌘Q")).toBe("Stays unlocked, even through sleep and screen lock, until you quit the browser (⌘Q). Anyone using this computer can see and fill your passwords, cards and codes meanwhile.")
  })
})

describe("pairing", () => {
  test("approving a device asks for the passphrase with the code", async () => {
    status = { state: "ready", version: "test" }
    await open()
    ;[...app().querySelectorAll<HTMLButtonElement>("button")].find((b) => nameOf(b) === "Settings")!.click()
    await flush()
    ;[...app().querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent === "Pair another device")!.click()
    await flush()
    const code = input("Pairing code")
    const pass = input("Passphrase to approve")
    code.value = "apple-river-stone-lamp-zoo"
    // Without the passphrase nothing is sent.
    submit(code.closest("form")!)
    await flush()
    expect(commands().filter((c) => c.type === "device-pair")).toEqual([])
    pass.value = "wrong"
    submit(code.closest("form")!)
    await flush()
    expect(shownError()!.textContent).toBe("That passphrase isn't right.")
    expect(pass.value).toBe("")
    pass.value = "right"
    submit(code.closest("form")!)
    await flush()
    expect(commands().filter((c) => c.type === "device-pair").at(-1)).toEqual({ type: "device-pair", code: "apple-river-stone-lamp-zoo", passphrase: "right" })
    expect(input("Pairing code")).toBeNull()
  })
})

describe("activity", () => {
  const fill = (id: number): ActivityEntry => ({ id, time: NOW - id * 60, caller: "autofill", command: "site-fill", items: [{ id: "v:i", title: "GitHub" }], fields: ["username", "password"], site: "https://github.com", outcome: "allowed", more: 0 })

  /** Settings' Activity section on its own, asking the fake vault. */
  async function section() {
    status = { state: "ready", version: "test" }
    const asked: Command[] = []
    const { el } = activitySection({ ask: (c: Command) => (asked.push(c), answer(c)) } as unknown as App)
    document.body.replaceChildren(el)
    const named = (name: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === name)!
    const rows = () => [...el.querySelectorAll<HTMLElement>(".vrow.activity")]
    const olderShown = () => !named("Show older").closest<HTMLElement>(".buttons")!.hidden
    await flush()
    // Closed until asked for, as in the native app: the vault page reads none of it.
    expect(asked).toHaveLength(0)
    named("Show").click()
    await flush()
    return { el, asked, named, rows, olderShown }
  }

  test("lists what happened in plain words, newest first, a page at a time", async () => {
    activity = Array.from({ length: 120 }, (_, i) => fill(120 - i))
    const { asked, named, rows, olderShown } = await section()
    expect(rows()).toHaveLength(50)
    expect(rows()[0]!.querySelector(".title")!.textContent).toBe("Filled username and password")
    expect(rows()[0]!.querySelector(".sub")!.textContent).toBe("GitHub · github.com · 2 h ago")
    named("Show older").click()
    await flush()
    expect(asked.at(-1)).toEqual({ type: "device-activity", before: 71, limit: 50 })
    expect(rows()).toHaveLength(100)
    named("Show older").click()
    await flush()
    // The oldest page is short: nothing older to ask for.
    expect(rows().map((r) => Number(r.dataset.id))).toEqual(activity.map((e) => e.id))
    expect(olderShown()).toBe(false)
    named("Hide").click()
    await flush()
    expect(rows()).toHaveLength(0)
  })

  test("an empty log says so quietly", async () => {
    const { el, rows, olderShown } = await section()
    expect(rows()).toHaveLength(0)
    expect(el.querySelector(".activity-list")!.textContent).toBe("Nothing yet")
    expect(olderShown()).toBe(false)
  })

  test("names fields, copies, reveals and what went to keep the log small in words", () => {
    const base = fill(1)
    expect(activityWords({ ...base, fields: ["username", "password", "otp"] })).toBe("Filled username, password and one-time code")
    expect(activityWords({ ...base, command: "form-fill", items: [{ title: "Visa •••• 4242" }], fields: ["number", "cvv"] })).toBe("Filled card number and security code")
    expect(activityWords({ ...base, command: "form-fill", fields: ["number"], outcome: "refused" })).toBe("Filled card number: refused")
    const copy: ActivityEntry = { ...base, caller: "vault", command: "copy", fields: ["private-key"], site: undefined }
    expect(activityWords(copy)).toBe("Copied private key")
    expect(activityDetail(copy, NOW)).toBe("GitHub · in this vault · 1 min ago")
    expect(activityWords({ ...base, command: "reveal", fields: ["password"] })).toBe("Showed password")
    expect(activityWords({ ...base, command: "site-save", fields: ["password"] })).toBe("Updated a password")
    expect(activityWords({ ...base, command: "more-past-budget", caller: "deadbolt", items: [], fields: [], more: 12 })).toBe("12 older entries removed to keep the log small")
  })
})
