import { afterEach, beforeEach, describe, expect, jest, spyOn, test } from "bun:test"
import type { DeviceReply, Status } from "../src/messages"
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
