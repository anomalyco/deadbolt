import { describe, expect, test } from "bun:test"
import { confirmPick, CONFIRM_AFTER_MS, Dwell, Entry } from "../src/ui/dom"

// A page can keep the menu see-through over a decoy and show it the moment a
// press lands, so the menu must have been visible and still for a while
// before the press, not just at it.
describe("Dwell", () => {
  test("a press counts once the menu has been visible for the whole wait", () => {
    const d = new Dwell(500)
    expect(d.settled(1000)).toBe(false)
    d.seen(true, 1000)
    expect(d.settled(1499)).toBe(false)
    expect(d.settled(1500)).toBe(true)
  })

  test("shown at the press doesn't count", () => {
    const d = new Dwell(500)
    d.seen(false, 0)
    d.seen(true, 2000)
    expect(d.settled(2000)).toBe(false)
    expect(d.visible).toBe(true)
  })

  test("any hidden reading starts the wait again", () => {
    const d = new Dwell(500)
    d.seen(true, 0)
    d.seen(false, 900)
    expect(d.settled(1000)).toBe(false)
    d.seen(true, 1000)
    expect(d.settled(1400)).toBe(false)
    expect(d.settled(1500)).toBe(true)
  })

  test("so does any move, visible or not", () => {
    const d = new Dwell(500)
    d.seen(true, 0)
    d.moved(800)
    expect(d.settled(1000)).toBe(false)
    expect(d.settled(1300)).toBe(true)
    // A move while hidden still counts once the menu shows again.
    d.seen(false, 1400)
    d.moved(1600)
    d.seen(true, 1500)
    expect(d.settled(2000)).toBe(false)
    expect(d.settled(2100)).toBe(true)
  })

  test("every reading and move changes the version", () => {
    const d = new Dwell(500)
    const v = d.version
    d.seen(true, 0)
    d.moved(1)
    expect(d.version).toBe(v + 2)
  })
})

describe("confirmPick", () => {
  // A fake clock; `during` runs while the pick waits, as readings would arrive.
  function clock(start: number, during: (d: Dwell) => void = () => {}) {
    let t = start
    const d = new Dwell(500)
    const opts = {
      now: () => t,
      sleep: async (ms: number) => {
        t += ms
        during(d)
      },
      fresh: async () => true,
    }
    return { d, opts, now: () => t }
  }

  test("waits until well after the press, then takes a fresh reading", async () => {
    const { d, opts, now } = clock(1100)
    d.seen(true, 0)
    let freshAt = 0
    expect(await confirmPick(d, 1000, { ...opts, fresh: async () => ((freshAt = now()), true) })).toBe(true)
    expect(freshAt).toBe(1000 + CONFIRM_AFTER_MS)
    expect(await confirmPick(d, 2000, { ...opts, fresh: async () => false })).toBe(false)
  })

  test("a hidden reading that arrives after the press refuses it, even one taken before", async () => {
    const { d, opts } = clock(1050, (d) => d.seen(false, 990))
    d.seen(true, 0)
    expect(await confirmPick(d, 1000, opts)).toBe(false)
  })

  test("so does a move, or any reading, while it waits", async () => {
    let c = clock(1050, (d) => d.moved(1200))
    c.d.seen(true, 0)
    expect(await confirmPick(c.d, 1000, c.opts)).toBe(false)
    c = clock(1050, (d) => d.seen(true, 100))
    c.d.seen(true, 0)
    expect(await confirmPick(c.d, 1000, c.opts)).toBe(false)
  })

  test("never without the dwell before the press", async () => {
    const { d, opts } = clock(1050)
    d.seen(true, 700)
    expect(await confirmPick(d, 1000, opts)).toBe(false)
  })
})

// A page can focus the menu's frame from script and catch the user's next
// Enter. Only focus Deadbolt moved in for the user's own ↓ (or a real press in
// the menu) lets the keyboard pick.
describe("Entry", () => {
  test("focus from anywhere else doesn't count", () => {
    const e = new Entry()
    e.focused(100)
    expect(e.entered).toBe(false)
  })

  test("↓ in the field, then the focus it moved in, counts, in either order", () => {
    const a = new Entry()
    a.offered(100, false)
    a.focused(110)
    expect(a.entered).toBe(true)
    const b = new Entry()
    b.offered(100, true)
    expect(b.entered).toBe(true)
  })

  test("an old ↓ doesn't let a later focus count", () => {
    const e = new Entry(1000)
    e.offered(100, false)
    e.focused(1200)
    expect(e.entered).toBe(false)
  })

  test("one ↓ lets in one focus", () => {
    const e = new Entry()
    e.offered(100, false)
    e.focused(110)
    e.blurred()
    e.focused(120)
    expect(e.entered).toBe(false)
  })

  test("losing focus ends it, and getting it back doesn't restore it", () => {
    const e = new Entry()
    e.offered(100, true)
    e.blurred()
    expect(e.entered).toBe(false)
    e.focused(200)
    expect(e.entered).toBe(false)
  })

  test("a real press in the menu counts once it passes the checks, until focus goes", () => {
    const e = new Entry()
    const press = e.pressed()
    expect(e.entered).toBe(false)
    e.confirmed(press)
    expect(e.entered).toBe(true)
    e.blurred()
    expect(e.entered).toBe(false)
  })

  // A page can show the menu only as the press lands: the menu refuses that
  // press, and it mustn't let a later Enter through either.
  test("a press the menu refused counts for nothing", () => {
    const e = new Entry()
    e.pressed()
    expect(e.entered).toBe(false)
  })

  test("a press still being checked when focus goes counts for nothing", () => {
    const e = new Entry()
    const press = e.pressed()
    e.blurred()
    e.confirmed(press)
    expect(e.entered).toBe(false)
  })

  test("a newer press takes over, and takes back what came before", () => {
    const e = new Entry()
    e.offered(0, true)
    const first = e.pressed()
    expect(e.entered).toBe(false)
    e.pressed()
    e.confirmed(first)
    expect(e.entered).toBe(false)
  })
})
