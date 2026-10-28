// Service worker: the extension's only link to Deadbolt. It keeps one native
// messaging port to `deadbolt browser-host` and answers the content scripts,
// the inline menu and the popup.

import { Autofill } from "./bg/autofill"
import { fromExtensionPage } from "./bg/frames"
import { Host } from "./bg/host"
import { Passkeys } from "./bg/passkeys"
import { Saver } from "./bg/save"
import type { PopupReply, Status, StatusChanged, ToBackground } from "./messages"

const host = new Host()
const saver = new Saver(host)
const passkeys = new Passkeys(host, { keepBadge: (tabId) => saver.pending(tabId) !== undefined })
const autofill = new Autofill(host, passkeys, (tabId, site) => saver.username(tabId, site))
saver.signedIn = (tabId, site) => void autofill.learnFlow(tabId, site)
passkeys.listen()

function title(status: Status): string {
  switch (status.state) {
    case "ready":
      return "Deadbolt"
    case "locked":
      return "Deadbolt is locked"
    case "not-set-up":
      return "Deadbolt isn't set up yet"
    case "not-installed":
      return "Deadbolt: run `deadbolt browser install`"
    default:
      return "Deadbolt isn't connected"
  }
}

host.onChange((status) => {
  void chrome.runtime.sendMessage({ type: "db:status", status } satisfies StatusChanged).catch(() => {})
  void chrome.action.setTitle({ title: title(status) }).catch(() => {})
})

async function handle(message: ToBackground, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (message.type) {
    case "db:query":
      return autofill.query(sender, message.roles, message.focused, message.form, message.explicit === true, message.identifier, message.again === true)
    case "db:page":
      return autofill.page(sender, message.kind, message.roles, message.form, message.stepped === true, message.idEmpty === true)
    case "db:settled":
      return saver.settled(sender)
    case "db:capture":
      return saver.capture(sender, message)
    case "db:submitted":
      return autofill.submitted(sender)
    // The save offer's surface uses the menu's messages with a token of its own (see bg/save.ts).
    case "db:menu-close":
      if (saver.ownsSurface(message.token)) return saver.surfaceClosed(String(message.token), sender)
      return autofill.menuClose(String(message.token), message.dismissed === true, sender)
    case "db:menu-load":
      if (saver.ownsSurface(message.token)) return saver.surfaceLoad(message.token, sender, String(message.parent))
      return autofill.menuLoad(message.token, sender, String(message.parent))
    case "db:menu-pick":
      return autofill.menuPick(message.token, String(message.ref), sender)
    case "db:menu-dismiss":
      if (saver.ownsSurface(message.token)) return saver.surfaceDismiss(message.token, sender)
      return autofill.menuDismiss(message.token, sender)
    case "db:menu-resize":
      if (saver.ownsSurface(message.token)) return saver.surfaceResize(message.token, sender, Number(message.height), message.width, message.mode)
      return autofill.menuResize(message.token, Number(message.height), sender, message.width, message.mode)
    case "db:surface-choose":
      return ["save", "later", "never"].includes(message.choice) && saver.ownsSurface(message.token)
        ? saver.surfaceChoose(message.token, sender, message.choice)
        : { ok: false, message: "This offer has expired.", gone: true }
    case "db:popup-load": {
      if (!fromExtensionPage(sender, "popup.html")) return null
      const reply: PopupReply = await autofill.popupLoad(message.tabId)
      const offer = reply.status.state === "ready" ? saver.pending(message.tabId) : undefined
      const passkey = reply.status.state === "ready" ? passkeys.prompt(message.tabId) : undefined
      const savingOff = reply.status.state === "ready" ? await saver.savingOff(message.tabId) : undefined
      return { ...reply, ...(offer ? { offer } : {}), ...(passkey ? { passkey } : {}), ...(savingOff ? { savingOff } : {}) }
    }
    case "db:popup-fill":
      return fromExtensionPage(sender, "popup.html") ? autofill.popupFill(message.tabId, String(message.ref)) : { ok: false, message: "" }
    case "db:popup-offer":
      return fromExtensionPage(sender, "popup.html") && ["save", "later", "never"].includes(message.choice)
        ? saver.choose(message.tabId, String(message.id), message.choice)
        : { ok: false, message: "" }
    case "db:popup-saving-on":
      return fromExtensionPage(sender, "popup.html") ? saver.savingOn(message.tabId) : false
  }
}

chrome.runtime.onMessage.addListener((message: ToBackground, sender, respond) => {
  if (typeof message?.type !== "string" || !message.type.startsWith("db:") || message.type === ("db:status" as string)) return
  handle(message, sender).then(
    (reply) => respond(reply ?? null),
    () => respond(null),
  )
  return true
})

chrome.tabs.onRemoved.addListener((tabId) => {
  autofill.forgetTab(tabId)
  saver.forgetTab(tabId)
})
chrome.webNavigation.onCommitted.addListener((d) => {
  void autofill.navigated(d)
  if (d.frameId === 0) saver.navigated(d.tabId, d.url)
})

void host.connect()
