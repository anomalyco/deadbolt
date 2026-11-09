// The inline menu's locked row unlocks in the toolbar panel (popup.html), as
// 1Password's does: the browser draws that panel, so no page can draw a copy
// of it, and the passphrase is never typed into anything placed over a page.
// The panel learns over its port whether the row opened it (it then asks for
// Touch ID at once and closes once unlocked), and the port closing tells the
// waiting menu the panel went.

import { fromExtensionPage } from "./frames"

/** The port popup.html opens to the background as it starts. */
export const PANEL_PORT = "db:panel"
/** How long a panel the row opened has to say it's up before the row stops waiting for it. */
export const PANEL_ASK_MS = 10_000

/** The panel's first message on its port: the window it's in. */
export interface PanelHello {
  windowId?: number
}

/** The answer: whether the locked row opened it. */
export interface PanelAnswer {
  fromMenu: boolean
}

export class PanelUnlock {
  /** The window whose panel the row opened, until that panel says it's up. */
  private asked: { windowId: number; at: number; timer: ReturnType<typeof setTimeout> } | null = null

  /** `closed`: the panel the row opened went (or never came up), so the menu stops waiting. */
  constructor(
    private closed: () => void,
    private askMs = PANEL_ASK_MS,
  ) {}

  /** Opens the toolbar panel over `tabId`'s window. False when the browser won't: no openPopup, a tab in the background, or a refusal. */
  async open(tabId: number): Promise<boolean> {
    const action = chrome.action as typeof chrome.action & { openPopup?: (options?: { windowId?: number }) => Promise<void> }
    if (typeof action.openPopup !== "function") return false
    const tab = await Promise.resolve(chrome.tabs.get(tabId)).catch(() => null)
    if (!tab?.active || tab.windowId === undefined) return false
    this.forget()
    const windowId = tab.windowId
    this.asked = { windowId, at: Date.now(), timer: setTimeout(() => this.asked?.windowId === windowId && (this.forget(), this.closed()), this.askMs) }
    const opened = await Promise.resolve()
      .then(() => action.openPopup!({ windowId }))
      .then(() => true, () => false)
    if (!opened && this.asked?.windowId === windowId) this.forget()
    return opened
  }

  /** A port opened: popup.html's tells it whether the row opened it, and while it's open, the row waits on it. */
  connected(port: chrome.runtime.Port) {
    if (port.name !== PANEL_PORT || !port.sender || !fromExtensionPage(port.sender, "popup.html")) return
    let fromMenu = false
    port.onMessage.addListener((hello: PanelHello) => {
      const asked = this.asked
      fromMenu = !!asked && hello?.windowId === asked.windowId && Date.now() - asked.at < this.askMs
      if (fromMenu) this.forget()
      port.postMessage({ fromMenu } satisfies PanelAnswer)
    })
    port.onDisconnect.addListener(() => fromMenu && this.closed())
  }

  private forget() {
    if (this.asked) clearTimeout(this.asked.timer)
    this.asked = null
  }
}
