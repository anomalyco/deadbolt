import { afterEach, describe, expect, test } from "bun:test"
import { fieldRect } from "../src/content/field-box"

function box(el: Element, left: number, top: number, width: number, height: number) {
  el.getBoundingClientRect = () => ({ x: left, y: top, left, top, width, height, right: left + width, bottom: top + height, toJSON() {} }) as DOMRect
}

/** Ramp's email field: a bordered box over a floating label and the bare input in its lower half. */
function floating(frame = "border:1px solid rgb(110, 106, 104);background:#fff", extra = "") {
  document.body.innerHTML = `<form><div id="frame" style="${frame}"><div id="content"><label>Email address *</label><input id="email" type="email" style="border:0;background:transparent">${extra}</div></div><button type="submit">Continue</button></form>`
  const input = document.querySelector<HTMLInputElement>("#email")!
  box(input, 365, 434, 562, 24)
  box(document.querySelector("#content")!, 365, 418, 562, 40)
  box(document.querySelector("#frame")!, 352, 410, 576, 56)
  box(document.querySelector("form")!, 352, 410, 576, 164)
  return input
}

afterEach(() => {
  document.body.innerHTML = ""
})

describe("fieldRect", () => {
  test("a floating-label field: the box that draws its frame", () => {
    const r = fieldRect(floating())
    expect([r.left, r.top, r.width, r.height]).toEqual([352, 410, 576, 56])
  })

  test("a box drawn by its background or shadow alone counts too", () => {
    expect(fieldRect(floating("background:rgb(240, 240, 240)")).height).toBe(56)
    expect(fieldRect(floating("box-shadow:0 0 0 1px rgb(0, 0, 0)")).height).toBe(56)
  })

  test("a field that draws its own border is its own box", () => {
    const input = floating()
    input.style.border = "1px solid rgb(0, 0, 0)"
    expect(fieldRect(input).height).toBe(24)
  })

  test("a wrapper that draws nothing, or only a transparent border, isn't a frame", () => {
    expect(fieldRect(floating("")).height).toBe(24)
    expect(fieldRect(floating("border:1px solid transparent")).height).toBe(24)
    expect(fieldRect(floating("border:1px solid rgba(0, 0, 0, 0)")).height).toBe(24)
    // Black is painted: its last channel isn't an alpha.
    expect(fieldRect(floating("border:1px solid rgb(0, 0, 0)")).height).toBe(56)
  })

  test("not a box with another control in it", () => {
    expect(fieldRect(floating(undefined, `<input type="password">`)).height).toBe(24)
    // A show-password or clear button is part of the field.
    expect(fieldRect(floating(undefined, `<button type="button">Show</button>`)).height).toBe(56)
  })

  test("not a box much bigger than the field", () => {
    const input = floating()
    box(document.querySelector("#frame")!, 352, 410, 576, 140)
    expect(fieldRect(input).height).toBe(24)
  })

  test("found once, and dropped when the page grows it past a field's frame", () => {
    const input = floating()
    expect(fieldRect(input).height).toBe(56)
    box(document.querySelector("#frame")!, 352, 410, 900, 56)
    expect(fieldRect(input).width).toBe(562)
  })

  test("a field with no size yet is measured again once it has one", () => {
    const input = floating()
    box(input, 0, 0, 0, 0)
    expect(fieldRect(input).height).toBe(0)
    box(input, 365, 434, 562, 24)
    expect(fieldRect(input).height).toBe(56)
  })
})
