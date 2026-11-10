// The inline menu's locked row unlocks in the toolbar panel (popup.html), as
// 1Password's does: the browser draws that panel, so no page can draw a copy
// of it, and the passphrase is never typed into anything placed over a page.
// The panel learns over its port whether the row opened it (it then asks for
// Touch ID at once and closes once unlocked), and the port closing tells the
// waiting menu the panel went.

import { fromExtensionPage } from "./frames"

/**
 * The toolbar panel's address while Deadbolt is locked, and when the locked
 * row opens it. The panel reads it as it starts (vault/app.ts), before any
 * answer can reach it: the browser shows the panel after its first frame, so
 * that frame is already the locked panel at its own size, and says it's
 * waiting on Touch ID when the row asked. Only a hint: the status and the
 * port's answer still decide.
 */
export const LOCKED_PANEL = "popup.html#locked"
export const ASKED_PANEL = "popup.html#locked,menu"
/** Sets the toolbar panel's address; nothing where the browser has no such call. */
export const namePanel = (popup: string) => void Promise.resolve((chrome.action as { setPopup?: (d: { popup: string }) => Promise<void> }).setPopup?.({ popup })).catch(() => {})

/** The port popup.html opens to the background as it starts. */
export const PANEL_PORT = "db:panel"
/** How long a panel the row opened has to say it's up before the row stops waiting for it. */
export const PANEL_ASK_MS = 10_000
/** How long the menu has to say whether the press counted (menu.ts unlock: its check takes at most about 1.4 s). */
export const PRESS_MS = 2500

/** The panel's first message on its port: the window it's in. */
export interface PanelHello {
  windowId?: number
}

/** The answer: whether the locked row opened it, or (`close`) opened it with a press that didn't count. */
export interface PanelAnswer {
  fromMenu: boolean
  close?: boolean
}

export class PanelUnlock {
  /** The window whose panel the row opened, until that panel says it's up. */
  private asked: { windowId: number; at: number; up: () => void; pressed: Promise<boolean>; timer: ReturnType<typeof setTimeout> } | null = null
  /** Presses on a menu's row, by token, waiting on the menu's word on them. */
  private presses = new Map<string, { documentId?: string; settle: (ok: boolean) => void }>()

  /** `closed`: the panel the row opened went (or never came up), so the menu stops waiting. */
  constructor(
    private closed: () => void,
    private askMs = PANEL_ASK_MS,
  ) {}

  /**
   * A press on the row of menu `token` (in document `documentId`). The panel
   * opens at once, and the menu says after whether the press counted: the
   * menu visible and still through it, as a pick's must be (menu.ts unlock).
   * Answers that word, or false if none comes.
   */
  pressed(token: string, documentId?: string): Promise<boolean> {
    this.presses.get(token)?.settle(false)
    return new Promise<boolean>((resolve) => {
      const press = { documentId, settle: (ok: boolean) => {
        clearTimeout(timer)
        if (this.presses.get(token) === press) this.presses.delete(token)
        resolve(ok)
      } }
      const timer = setTimeout(() => press.settle(false), PRESS_MS)
      this.presses.set(token, press)
    })
  }

  /** The menu's word on its press, from the document that pressed. */
  confirm(token: string, ok: boolean, documentId?: string) {
    const press = this.presses.get(token)
    if (press && press.documentId === documentId) press.settle(ok)
  }

  /**
   * Opens the toolbar panel over `tabId`'s window. False when the browser
   * won't: no openPopup, a tab in the background, or a refusal. True as soon
   * as either the browser says it opened or the panel says it's up, whichever
   * comes first: a browser can hold openPopup's answer until the panel goes.
   * The panel learns it was the row's only once `pressed` says the press
   * counted, and closes if it didn't.
   */
  async open(tabId: number, pressed: Promise<boolean> = Promise.resolve(true)): Promise<boolean> {
    const action = chrome.action as typeof chrome.action & { openPopup?: (options?: { windowId?: number }) => Promise<void> }
    if (typeof action.openPopup !== "function") return false
    const tab = await Promise.resolve(chrome.tabs.get(tabId)).catch(() => null)
    if (!tab?.active || tab.windowId === undefined) return false
    this.forget()
    const windowId = tab.windowId
    let up = () => {}
    const hello = new Promise<boolean>((resolve) => (up = () => resolve(true)))
    this.asked = { windowId, at: Date.now(), up, pressed, timer: setTimeout(() => this.asked?.windowId === windowId && (this.forget(), this.closed()), this.askMs) }
    // The browser takes calls in order: the address is set before the panel opens, without waiting on its answer.
    namePanel(ASKED_PANEL)
    const browser = action.openPopup({ windowId }).then(() => true, () => false)
    const opened = await Promise.race([browser, hello])
    // The next one the user opens wasn't asked for by the row.
    namePanel(LOCKED_PANEL)
    if (!opened && this.asked?.windowId === windowId) this.forget()
    return opened
  }

  /** A port opened: popup.html's tells it whether the row opened it, and while it's open, the row waits on it. */
  connected(port: chrome.runtime.Port) {
    if (port.name !== PANEL_PORT || !port.sender || !fromExtensionPage(port.sender, "popup.html")) return
    let fromMenu = false
    const answer = (a: PanelAnswer) => {
      try {
        port.postMessage(a)
      } catch {}
    }
    port.onMessage.addListener((hello: PanelHello) => {
      const asked = this.asked
      fromMenu = !!asked && hello?.windowId === asked.windowId && Date.now() - asked.at < this.askMs
      if (!fromMenu) return answer({ fromMenu })
      asked!.up()
      this.forget()
      void asked!.pressed.then((ok) => answer(ok ? { fromMenu } : { fromMenu: (fromMenu = false), close: true }))
    })
    port.onDisconnect.addListener(() => fromMenu && this.closed())
  }

  private forget() {
    if (this.asked) clearTimeout(this.asked.timer)
    this.asked = null
  }
}
