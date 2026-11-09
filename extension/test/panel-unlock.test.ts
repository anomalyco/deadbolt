import { beforeEach, describe, expect, test } from "bun:test"
import { PANEL_PORT, PanelUnlock, type PanelAnswer } from "../src/bg/panel-unlock"
import { ID, installChrome, POPUP_URL, settle, type FakeChrome } from "./chrome"

let fake: FakeChrome
/** How often this test's PanelUnlock said its panel went: one tally each, so an earlier test's timer can't count here. */
let tally: { closed: number }
let panel: PanelUnlock

/** A port as popup.html (or `url`) opens it: what it's told, and a way to close it. */
function port(url = POPUP_URL, name = PANEL_PORT) {
  const heard: PanelAnswer[] = []
  const onMessage: Array<(m: unknown) => void> = []
  const onDisconnect: Array<() => void> = []
  const p = {
    name,
    sender: { id: ID, url },
    postMessage: (m: PanelAnswer) => void heard.push(m),
    onMessage: { addListener: (f: (m: unknown) => void) => void onMessage.push(f) },
    onDisconnect: { addListener: (f: () => void) => void onDisconnect.push(f) },
  } as unknown as chrome.runtime.Port
  panel.connected(p)
  return { heard, hello: (windowId?: number) => onMessage.forEach((f) => f({ windowId })), close: () => onDisconnect.forEach((f) => f()) }
}

beforeEach(() => {
  fake = installChrome()
  const mine = (tally = { closed: 0 })
  panel = new PanelUnlock(() => mine.closed++, 30)
})

describe("the toolbar panel the locked row opens", () => {
  test("opens over the sender's window, and the panel that comes up there learns the row opened it, once", async () => {
    // The panel's address says the row asked while it opens, and only then (the panel reads it for its first frame).
    const named: string[] = []
    ;(chrome.action as unknown as { setPopup: (d: { popup: string }) => Promise<void> }).setPopup = async ({ popup }) => void named.push(popup)
    expect(await panel.open(1)).toBe(true)
    expect(fake.popups).toEqual([7])
    expect(named).toEqual(["popup.html#locked,menu", "popup.html#locked"])
    const first = port()
    first.hello(7)
    expect(first.heard).toEqual([{ fromMenu: true }])
    // The user opening it again from the toolbar is their own.
    const again = port()
    again.hello(7)
    expect(again.heard).toEqual([{ fromMenu: false }])
  })

  test("opened once the panel says it's up, though the browser holds openPopup's answer until the panel goes", async () => {
    let shut = () => {}
    ;(chrome.action as unknown as { openPopup: () => Promise<void> }).openPopup = () => new Promise<void>((resolve) => (shut = resolve))
    const opening = panel.open(1)
    await settle()
    const up = port()
    up.hello(7)
    expect(await opening).toBe(true)
    expect(up.heard).toEqual([{ fromMenu: true }])
    shut()
  })

  test("a panel in another window isn't the row's", async () => {
    await panel.open(1)
    const other = port()
    other.hello(3)
    expect(other.heard).toEqual([{ fromMenu: false }])
  })

  test("won't open over a tab in the background, without openPopup, or when the browser refuses: the row falls back to a tab", async () => {
    fake.tabs[1] = { active: false, windowId: 7 }
    expect(await panel.open(1)).toBe(false)
    fake.tabs[1] = { active: true, windowId: 7 }
    const action = chrome.action as unknown as { openPopup?: unknown }
    const openPopup = action.openPopup
    action.openPopup = undefined
    expect(await panel.open(1)).toBe(false)
    action.openPopup = async () => {
      throw new Error("no focused window")
    }
    expect(await panel.open(1)).toBe(false)
    action.openPopup = openPopup
    expect(fake.popups).toEqual([])
    // Nothing waits on a panel that never opened.
    const later = port()
    later.hello(7)
    expect(later.heard).toEqual([{ fromMenu: false }])
    await Bun.sleep(60)
    expect(tally.closed).toBe(0)
  })

  test("the row's panel closing, before or after unlocking, stops the row waiting; the user's own doesn't", async () => {
    await panel.open(1)
    const row = port()
    row.hello(7)
    const own = port()
    own.hello(7)
    own.close()
    expect(tally.closed).toBe(0)
    row.close()
    expect(tally.closed).toBe(1)
  })

  test("a panel that never comes up stops the row waiting once it would have", async () => {
    await panel.open(1)
    await Bun.sleep(60)
    expect(tally.closed).toBe(1)
    const late = port()
    late.hello(7)
    expect(late.heard).toEqual([{ fromMenu: false }])
  })

  test("only popup.html's own port counts", async () => {
    await panel.open(1)
    for (const p of [port(`chrome-extension://${ID}/device.html`), port("https://example.com/"), port(POPUP_URL, "other")]) {
      p.hello(7)
      expect(p.heard).toEqual([])
    }
    const real = port()
    real.hello(7)
    expect(real.heard).toEqual([{ fromMenu: true }])
    await settle()
  })
})
