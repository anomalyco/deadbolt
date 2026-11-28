import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { FILL_MENU, fillCommand, fillMenuClicked, listenFillDoors } from "../src/bg/doors"
import { scanPage, type Field } from "../src/content/detect"
import { closeMenu, initMenu, menuHost, type PageState } from "../src/content/inline"
import { manualFields, withManual } from "../src/content/manual"
import type { ToContent } from "../src/messages"
import { installChrome, settle, type FakeChrome } from "./chrome"

// A laid-out page: elements with data-box="left top width height" sit there,
// anything else fills the viewport; a point hits the deepest boxed element.
// The menu's host sits where its inline style puts it, on top of everything.
const rect = Element.prototype.getBoundingClientRect
const hit = { one: document.elementFromPoint, all: document.elementsFromPoint, focus: document.hasFocus, matches: Element.prototype.matches }
const px = (v: string) => Number.parseFloat(v) || 0
function boxOf(el: Element) {
  const s = el === menuHost() ? (el as HTMLElement).style : null
  const b = s ? [px(s.left), px(s.top), px(s.width), px(s.height)] : el.getAttribute("data-box")?.split(" ").map(Number)
  const [left, top, width, height] = b ?? [0, 0, innerWidth, innerHeight]
  return { x: left, y: top, left, top, width, height, right: left + width, bottom: top + height, toJSON() {} } as DOMRect
}
const inside = (el: Element, x: number, y: number) => {
  const r = boxOf(el)
  return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
}
function at(x: number, y: number): Element | null {
  const host = menuHost()
  if (host && inside(host, x, y)) return host
  return Array.from(document.querySelectorAll("[data-box]")).filter((el) => inside(el, x, y)).at(-1) ?? document.body
}
// happy-dom has no popovers: a host shown is open until hidden.
const open = new WeakSet<Element>()

// The content script's page state, as content.ts keeps it: what the scan
// finds, or the fields the user asked to fill where it found none.
let fields: Field[] = []
let manual: Field[] = []
let formId = 0
const state: PageState = {
  targets: () => fields,
  form: () => formId,
  kind: () => null,
  rescan() {
    const r = scanPage()
    const next = withManual(r.kind && r.kind !== "reset" ? r.fields : [], manual)
    if (next.length !== fields.length || next.some((f, i) => f.el !== fields[i].el)) formId++
    fields = next
  },
  formFields: () => [],
  formsForm: () => 0,
  manual(el) {
    state.rescan()
    if (fields.some((f) => f.el === el)) return true
    manual = manualFields(el)
    state.rescan()
    return fields.some((f) => f.el === el)
  },
}

let fake: FakeChrome
const commands: Array<(command: string, tab?: chrome.tabs.Tab) => void> = []
const clicks: Array<(info: chrome.contextMenus.OnClickData, tab?: chrome.tabs.Tab) => void> = []
const created: unknown[] = []

/** What the content script's listeners answer, as Chrome hands a tab's message to them. */
function toContent(message: ToContent): Promise<unknown> {
  return new Promise((resolve) => {
    let waiting = false
    for (const l of fake.listeners) if (l(message, { id: chrome.runtime.id } as chrome.runtime.MessageSender, resolve) === true) waiting = true
    if (!waiting) setTimeout(() => resolve(undefined), 0)
  })
}

beforeAll(() => {
  Element.prototype.getBoundingClientRect = function (this: Element) {
    return boxOf(this)
  }
  document.elementFromPoint = at
  document.elementsFromPoint = (x, y) => [at(x, y)].filter((e): e is Element => !!e)
  document.hasFocus = () => true
  HTMLElement.prototype.showPopover = function (this: HTMLElement) {
    open.add(this)
  }
  HTMLElement.prototype.hidePopover = function (this: HTMLElement) {
    open.delete(this)
  }
  Element.prototype.matches = function (this: Element, selector: string) {
    if (selector === ":popover-open") return open.has(this)
    if (selector === ":modal, :fullscreen") return false
    return hit.matches.call(this, selector)
  } as typeof Element.prototype.matches
  fake = installChrome()
  const c = globalThis.chrome as unknown as Record<string, unknown> & { tabs: Record<string, unknown> }
  c.commands = { onCommand: { addListener: (f: (typeof commands)[number]) => commands.push(f) } }
  c.contextMenus = {
    removeAll: (done: () => void) => done(),
    create: (item: unknown, done?: () => void) => (created.push(item), done?.()),
    onClicked: { addListener: (f: (typeof clicks)[number]) => clicks.push(f) },
  }
  c.tabs.sendMessage = async (tabId: number, message: ToContent, options?: unknown) => {
    fake.delivered.push({ tabId, message, options })
    return toContent(message)
  }
  // The background answers the menu's query with a token for two logins.
  fake.runtimeAnswer = (m) => ((m as { type?: string }).type === "db:query" ? { token: "tok-1", rows: 2 } : null)
  initMenu(state)
  listenFillDoors()
})

afterAll(() => {
  Element.prototype.getBoundingClientRect = rect
  document.elementFromPoint = hit.one
  document.elementsFromPoint = hit.all
  document.hasFocus = hit.focus
  Element.prototype.matches = hit.matches
})

beforeEach(() => {
  closeMenu()
  fake.sent.length = 0
  fake.delivered.length = 0
  fields = []
  manual = []
  // A plain text box with no label, name or form the scan can read anything from: it abstains.
  document.body.innerHTML = `<div><input type="text" name="txt1" data-box="20 400 240 32"><input type="checkbox" data-box="20 440 16 16"></div>`
})

const box = () => document.querySelector<HTMLInputElement>('input[name="txt1"]')!
const queries = () => fake.sent.filter((m) => (m as { type?: string }).type === "db:query") as Array<Record<string, unknown>>

describe("the fill shortcut and \"Fill with Deadbolt\"", () => {
  test("register a context menu item for editable fields on install", () => {
    for (const l of fake.installedListeners) l({ reason: "install" })
    expect(created).toContainEqual({ id: FILL_MENU, title: "Fill with Deadbolt", contexts: ["editable"] })
  })

  test("the scan abstains on the plain text box: no menu on its own", () => {
    expect(scanPage().fields).toEqual([])
  })

  test("⌘⇧L opens the account menu on the focused, abstained text box", async () => {
    box().focus()
    expect(commands.length).toBe(1)
    commands[0]("fill", { id: 1 } as chrome.tabs.Tab)
    await settle()
    // To every frame of the tab; the one whose field has focus took it.
    expect(fake.delivered).toEqual([{ tabId: 1, message: { type: "db:manual-open" }, options: undefined }])
    expect(queries()).toEqual([expect.objectContaining({ type: "db:query", roles: ["username"], focused: "username", explicit: true, again: true })])
    // Open, and above the field (two rows and the list's padding, 6 px over its top at 400).
    const host = menuHost()
    expect(host).not.toBeNull()
    expect(px(host!.style.top) + px(host!.style.height)).toBe(400 - 6)
  })

  test("\"Fill with Deadbolt\" opens it on the field its context menu was for", async () => {
    const event = new MouseEvent("contextmenu", { bubbles: true, composed: true })
    Object.defineProperty(event, "isTrusted", { value: true })
    box().dispatchEvent(event)
    expect(clicks.length).toBe(1)
    clicks[0]({ menuItemId: FILL_MENU, frameId: 0, editable: true } as chrome.contextMenus.OnClickData, { id: 1 } as chrome.tabs.Tab)
    await settle()
    expect(fake.delivered).toEqual([{ tabId: 1, message: { type: "db:manual-open", context: true }, options: { frameId: 0 } }])
    expect(document.activeElement).toBe(box())
    expect(queries()).toEqual([expect.objectContaining({ roles: ["username"], focused: "username", explicit: true })])
    expect(menuHost()).not.toBeNull()
  })

  test("other commands and menu items do nothing", async () => {
    box().focus()
    await fillCommand("record", { id: 1 } as chrome.tabs.Tab)
    await fillMenuClicked({ menuItemId: "other", frameId: 0 }, { id: 1 } as chrome.tabs.Tab)
    await fillCommand("fill", undefined)
    expect(fake.delivered).toEqual([])
  })

  test("never on a box that's hidden, covered or not a login box", async () => {
    document.body.innerHTML = `<input type="text" name="hidden" style="display:none" data-box="20 400 240 32"><input type="text" name="covered" data-box="20 500 240 32"><div data-box="0 480 400 80"></div><input type="number" name="qty" data-box="20 600 240 32">`
    for (const name of ["hidden", "covered", "qty"]) {
      const el = document.querySelector<HTMLInputElement>(`input[name="${name}"]`)!
      el.focus()
      expect(await toContent({ type: "db:manual-open" })).toBe(false)
    }
    expect(queries()).toEqual([])
    expect(menuHost()).toBeNull()
  })

  test("a username box takes the password box after it, and a masked box the username before it", () => {
    document.body.innerHTML = `<form><input type="text" name="user" data-box="20 400 240 32"><input type="password" name="trap" style="display:none" data-box="20 420 240 32"><input type="password" name="pass" data-box="20 440 240 32"></form>`
    const [user, pass] = ["user", "pass"].map((n) => document.querySelector<HTMLInputElement>(`input[name="${n}"]`)!)
    expect(manualFields(user).map((f) => [f.el, f.role])).toEqual([[user, "username"], [pass, "password"]])
    expect(manualFields(pass).map((f) => [f.el, f.role])).toEqual([[user, "username"], [pass, "password"]])
  })
})
