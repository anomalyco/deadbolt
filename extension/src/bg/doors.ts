// The user's own ways to ask for the account menu on a field: the "fill"
// shortcut (⌘⇧L, Ctrl+Shift+L elsewhere; manifest `commands`) and "Fill with
// Deadbolt" in an editable field's context menu. Each tells the content
// script, which opens the menu on that field even where its scan passed over
// it, with a click's checks (see content/inline.ts manualOpen). Only the
// browser raises these, from the user's own key or click: no page can.

import type { ToContent } from "../messages"

declare const DEADBOLT_E2E: boolean | undefined

/** Told each time the browser raises a door, before the content script hears it (bg/recipes.ts allow). */
let opened: ((tabId: number, frameId?: number) => void) | undefined

export const FILL_COMMAND = "fill"
export const FILL_MENU = "deadbolt-fill"

/** The context menu item, made again on install and update (Chrome keeps it while the extension is installed). */
export function registerFillMenu(): void {
  const menus = chrome.contextMenus
  if (!menus) return
  menus.removeAll(() => {
    void chrome.runtime.lastError
    menus.create({ id: FILL_MENU, title: "Fill with Deadbolt", contexts: ["editable"] }, () => void chrome.runtime.lastError)
  })
}

/** The shortcut: to every frame of the tab, of which only the one whose field has focus takes it. */
export async function fillCommand(command: string, tab?: chrome.tabs.Tab): Promise<void> {
  if (command !== FILL_COMMAND || tab?.id === undefined || tab.id < 0) return
  opened?.(tab.id)
  await chrome.tabs.sendMessage(tab.id, { type: "db:manual-open" } satisfies ToContent).catch(() => {})
}

/** "Fill with Deadbolt": to the frame the context menu opened in, about the field it opened on. */
export async function fillMenuClicked(info: Pick<chrome.contextMenus.OnClickData, "menuItemId" | "frameId">, tab?: chrome.tabs.Tab): Promise<void> {
  if (info.menuItemId !== FILL_MENU || tab?.id === undefined || tab.id < 0) return
  opened?.(tab.id, info.frameId ?? 0)
  await chrome.tabs.sendMessage(tab.id, { type: "db:manual-open", context: true } satisfies ToContent, { frameId: info.frameId ?? 0 }).catch(() => {})
}

/** Listens for both; a test's chrome without them gets neither. `onOpen` hears each door the browser raises. */
export function listenFillDoors(onOpen?: (tabId: number, frameId?: number) => void): void {
  opened = onOpen
  chrome.runtime.onInstalled?.addListener(() => registerFillMenu())
  chrome.contextMenus?.onClicked.addListener((info, tab) => void fillMenuClicked(info, tab))
  chrome.commands?.onCommand.addListener((command, tab) => void fillCommand(command, tab))
  // e2e builds only: CDP's key events never reach extension commands, nor its clicks the context menu.
  if (typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true) (globalThis as unknown as { __fill: unknown }).__fill = { command: fillCommand, menu: fillMenuClicked }
}
