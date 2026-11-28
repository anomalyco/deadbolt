import { describe, expect, test } from "bun:test"
import { MENU_GAP, MENU_MARGIN, menuPlace } from "../src/content/inline/dom"

// A 900 px tall viewport and a 150 px list (three rows).
const VIEW = 900
const HEIGHT = 150
const field = (top: number, height = 40) => ({ top, bottom: top + height })

describe("the account list's place by its login field", () => {
  test("a mid-viewport login field gets it above, its bottom 6 px over the field, clear of the browser's own list below", () => {
    const r = field(400)
    const placed = menuPlace(r, HEIGHT, VIEW, true)
    expect(placed).toEqual({ side: "above", top: r.top - HEIGHT - MENU_GAP })
    expect(placed.top + HEIGHT).toBe(r.top - 6)
    // Nothing of it in the band below the field, where Chrome's autofill list opens.
    expect(placed.top + HEIGHT).toBeLessThan(r.bottom)
  })

  test("a field near the top of the viewport gets it below, 6 px under the field", () => {
    for (const top of [0, 20, HEIGHT + MENU_MARGIN + MENU_GAP - 1]) {
      const r = field(top)
      expect(menuPlace(r, HEIGHT, VIEW, true)).toEqual({ side: "below", top: r.bottom + 6 })
    }
    // Just enough room above.
    const r = field(HEIGHT + MENU_MARGIN + MENU_GAP)
    expect(menuPlace(r, HEIGHT, VIEW, true).side).toBe("above")
  })

  test("a password box's list doesn't sit on the username box over it: it goes below", () => {
    const username = field(330)
    const password = field(400)
    expect(menuPlace(password, HEIGHT, VIEW, true, null, [username])).toEqual({ side: "below", top: password.bottom + 6 })
    // A field far enough above is clear of it.
    expect(menuPlace(password, HEIGHT, VIEW, true, null, [field(100)]).side).toBe("above")
    // Already above when the username box shows over it (a step that adds it): it moves below.
    expect(menuPlace(password, HEIGHT, VIEW, true, "above", [username]).side).toBe("below")
  })

  test("an identity or card list stays below, and goes above only when it can't fit there", () => {
    expect(menuPlace(field(400), HEIGHT, VIEW, false)).toEqual({ side: "below", top: 446 })
    expect(menuPlace(field(800), HEIGHT, VIEW, false)).toEqual({ side: "above", top: 800 - HEIGHT - 6 })
  })

  test("with no room either side it goes above, kept inside the viewport", () => {
    expect(menuPlace(field(60), 880, VIEW, true)).toEqual({ side: "above", top: MENU_MARGIN })
  })

  test("a list that grows above its field keeps its bottom pinned over it, and stays on its side while it fits", () => {
    const r = field(400)
    let side = menuPlace(r, 58, VIEW, true).side
    for (const height of [58, 104, 150, 242]) {
      const placed = menuPlace(r, height, VIEW, true, side)
      side = placed.side
      expect(side).toBe("above")
      expect(placed.top + height).toBe(r.top - MENU_GAP)
    }
    // Opened below (near the top), it stays below as it grows, rather than jumping over the field.
    const low = field(100)
    expect(menuPlace(low, 58, VIEW, true).side).toBe("above")
    expect(menuPlace(low, 104, VIEW, true, "below")).toEqual({ side: "below", top: low.bottom + 6 })
    // Grown past the room above, it goes below.
    expect(menuPlace(low, 104, VIEW, true, "above")).toEqual({ side: "below", top: low.bottom + 6 })
  })
})
