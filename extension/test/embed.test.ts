import { describe, expect, test } from "bun:test"
import { Announcements } from "../src/content/embed"
import { placeBoxes, throughFrame } from "../src/content/fill"

describe("Announcements", () => {
  test("names the window that announced the nonce, once", async () => {
    const a = new Announcements()
    const child = {}
    a.hear("n1", child, 0)
    expect(await a.from("n1", 10)).toBe(child)
    expect(await a.from("n1", 10)).toBeNull()
  })

  test("waits for an announcement still on its way", async () => {
    const a = new Announcements()
    const child = {}
    const answer = a.from("n1", 1000)
    setTimeout(() => a.hear("n1", child, 0), 5)
    expect(await answer).toBe(child)
  })

  test("none when nobody announces it", async () => {
    expect(await new Announcements().from("n1", 5)).toBeNull()
  })

  test("none when two windows announce the same nonce", async () => {
    const a = new Announcements()
    a.hear("n1", {}, 0)
    a.hear("n1", {}, 1)
    expect(await a.from("n1", 10)).toBeNull()
  })
})

describe("placeBoxes", () => {
  const clip = { left: 0, top: 0, right: 400, bottom: 300 }
  const field = { left: 10, top: 20, right: 210, bottom: 50 }
  const always = () => true

  test("moves boxes into this page's coordinates and hit-tests their middles", () => {
    const hits: number[][] = []
    expect(placeBoxes([field], { x: 100, y: 50 }, clip, (x, y) => (hits.push([x, y]), true))).toEqual([{ left: 110, top: 70, right: 310, bottom: 100 }])
    expect(hits).toEqual([[210, 85]])
  })

  test("a field whose middle is something else's isn't shown", () => {
    expect(placeBoxes([field], { x: 0, y: 0 }, clip, () => false)).toBeNull()
  })

  test("a field mostly cut off by the frame's clip isn't shown", () => {
    expect(placeBoxes([field], { x: 300, y: 0 }, clip, always)).toBeNull()
    expect(placeBoxes([field], { x: 0, y: 290 }, clip, always)).toBeNull()
    // A little cut off is fine; what's left is what goes up.
    expect(placeBoxes([field], { x: 250, y: 0 }, clip, always)).toEqual([{ left: 260, top: 20, right: 400, bottom: 50 }])
  })

  test("every field has to show, and there has to be one", () => {
    expect(placeBoxes([field, { left: 10, top: 500, right: 210, bottom: 530 }], { x: 0, y: 0 }, clip, always)).toBeNull()
    expect(placeBoxes([], { x: 0, y: 0 }, clip, always)).toBeNull()
  })
})

describe("throughFrame", () => {
  function frame(style = "") {
    // A div stands in for the iframe: happy-dom won't load frames, and only the box matters.
    document.body.innerHTML = `<div style="${style}"></div>`
    const el = document.querySelector("div")!
    el.getBoundingClientRect = () => ({ left: 100, top: 50, width: 300, height: 200, right: 400, bottom: 250, x: 100, y: 50, toJSON() {} }) as DOMRect
    Object.defineProperty(el, "offsetWidth", { value: 300, configurable: true })
    Object.defineProperty(el, "offsetHeight", { value: 200, configurable: true })
    document.elementFromPoint = () => el
    return el
  }
  const field = { left: 10, top: 20, right: 210, bottom: 50 }

  test("a plain frame shows its fields where they are on the page", () => {
    expect(throughFrame(frame(), [field])).toEqual([{ left: 110, top: 70, right: 310, bottom: 100 }])
  })

  test("not a faded, clipped or hidden one", () => {
    expect(throughFrame(frame("opacity: 0.02"), [field])).toBeNull()
    expect(throughFrame(frame("clip-path: inset(50%)"), [field])).toBeNull()
    expect(throughFrame(frame("visibility: hidden"), [field])).toBeNull()
  })

  test("not a scaled one", () => {
    const el = frame()
    Object.defineProperty(el, "offsetWidth", { value: 600, configurable: true })
    expect(throughFrame(el, [field])).toBeNull()
  })

  test("not one with something else over the field", () => {
    const el = frame()
    document.elementFromPoint = () => document.body
    expect(throughFrame(el, [field])).toBeNull()
  })
})
