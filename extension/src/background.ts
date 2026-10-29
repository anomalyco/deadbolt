// Service worker: the extension's only link to Deadbolt. The default native
// build keeps one messaging port to `deadbolt browser-host` (bg/host.ts).
// `--standalone` makes the extension its own device, with the Rust vault in
// an offscreen worker (bg/standalone.ts). It answers the content
// scripts, the inline menu, the popup and device.html.

import { Autofill } from "./bg/autofill"
import type { VaultBackend } from "./bg/backend"
import { Forms } from "./bg/forms"
import { fromExtensionPage } from "./bg/frames"
import { Host } from "./bg/host"
import { Learner } from "./bg/learn"
import { Passkeys } from "./bg/passkeys"
import { Saver } from "./bg/save"
import { SignInWith } from "./bg/signinwith"
import { DEVICE_PAGE, deviceCommand, fromVaultPage, StandaloneBackend } from "./bg/standalone"
import type { DeviceReply, PopupReply, Status, StatusChanged, ToBackground } from "./messages"

declare const DEADBOLT_NATIVE: boolean
const standalone = DEADBOLT_NATIVE ? null : new StandaloneBackend()
const host: VaultBackend = DEADBOLT_NATIVE ? new Host() : standalone!
const saver = new Saver(host)
const passkeys = new Passkeys(host, { keepBadge: (tabId) => saver.pending(tabId) !== undefined })
const signInWith = new SignInWith(host)
const autofill = new Autofill(host, passkeys, (tabId, site) => saver.username(tabId, site), signInWith)
const learner = new Learner(host)
const forms = new Forms(host)
saver.signedIn = (tabId, site) => {
  void autofill.learnFlow(tabId, site)
  void learner.signedIn(tabId, site)
}
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
    case "unavailable":
      return "Deadbolt couldn't start"
    default:
      return "Deadbolt isn't connected"
  }
}

host.onChange((status, change) => {
  void chrome.runtime.sendMessage({ type: "db:status", status, ...(change ? { change } : {}) } satisfies StatusChanged).catch(() => {})
  void chrome.action.setTitle({ title: title(status) }).catch(() => {})
})

async function handle(message: ToBackground, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (message.type) {
    case "db:query":
      return autofill.query(sender, message.roles, message.focused, message.form, message.explicit === true, message.identifier, message.again === true, message.kind, message.rules, message.pageAccount)
    case "db:page":
      if (Array.isArray(message.roles)) saver.page(sender, message.kind, message.roles)
      return autofill.page(sender, message.kind, message.roles, message.form, message.stepped === true, message.idEmpty === true)
    case "db:forms-query":
      return forms.query(sender, message.kind, message.form, message.section, message.explicit === true, message.box, message.roles)
    case "db:forms-page":
      return forms.page(sender, message.kinds, message.form)
    case "db:settled":
      return saver.settled(sender)
    case "db:capture":
      return saver.capture(sender, message)
    case "db:failed":
      return saver.failed(sender, message.submission)
    case "db:submitted":
      return autofill.submitted(sender)
    case "db:learn-ask":
      return learner.ask(sender)
    case "db:learn-step":
      return learner.step(sender, String(message.session), message.step)
    // The save offer's surface uses the menu's messages with a token of its own (see bg/save.ts).
    case "db:menu-close":
      if (saver.ownsSurface(message.token)) return saver.surfaceClosed(String(message.token), sender)
      if (forms.owns(message.token)) return forms.menuClose(String(message.token), sender)
      return autofill.menuClose(String(message.token), message.dismissed === true, sender)
    case "db:menu-load":
      if (saver.ownsSurface(message.token)) return saver.surfaceLoad(message.token, sender, String(message.parent))
      if (forms.owns(message.token)) return forms.menuLoad(message.token, sender, String(message.parent))
      return autofill.menuLoad(message.token, sender, String(message.parent))
    case "db:menu-pick":
      if (forms.owns(message.token)) return forms.menuPick(message.token, String(message.ref), sender)
      return autofill.menuPick(message.token, String(message.ref), sender)
    case "db:menu-generate":
      return autofill.menuGenerate(message.token, sender)
    case "db:menu-signin":
      return autofill.menuSignIn(message.token, String(message.ref), sender)
    case "db:menu-dismiss":
      if (saver.ownsSurface(message.token)) return saver.surfaceDismiss(message.token, sender)
      if (forms.owns(message.token)) return forms.menuDismiss(message.token, sender)
      return autofill.menuDismiss(message.token, sender)
    case "db:menu-unlock":
      return menuUnlock(String(message.token), sender)
    case "db:menu-resize":
      if (saver.ownsSurface(message.token)) return saver.surfaceResize(message.token, sender, Number(message.height), message.width, message.mode)
      if (forms.owns(message.token)) return forms.menuResize(message.token, Number(message.height), sender, message.width, message.mode)
      return autofill.menuResize(message.token, Number(message.height), sender, message.width, message.mode)
    case "db:surface-choose":
      return ["save", "later", "never"].includes(message.choice) && saver.ownsSurface(message.token)
        ? saver.surfaceChoose(message.token, sender, message.choice)
        : { ok: false, message: "This offer has expired.", gone: true }
    case "db:popup-load": {
      if (!fromExtensionPage(sender, "popup.html")) return null
      host.used?.()
      const reply: PopupReply = await autofill.popupLoad(message.tabId)
      const offer = reply.status.state === "ready" ? saver.pending(message.tabId) : undefined
      const passkey = reply.status.state === "ready" ? passkeys.prompt(message.tabId) : undefined
      const savingOff = reply.status.state === "ready" ? await saver.savingOff(message.tabId) : undefined
      const learning = await learner.status(message.tabId)
      return { ...reply, ...(offer ? { offer } : {}), ...(passkey ? { passkey } : {}), ...(savingOff ? { savingOff } : {}), ...(learning ? { learning } : {}) }
    }
    case "db:popup-learn":
      if (!fromExtensionPage(sender, "popup.html")) return { ok: false, message: "" }
      return message.on ? learner.start(message.tabId) : learner.stop(message.tabId, "stopped")
    case "db:popup-fill":
      return fromExtensionPage(sender, "popup.html") ? autofill.popupFill(message.tabId, String(message.ref)) : { ok: false, message: "" }
    case "db:popup-offer":
      return fromExtensionPage(sender, "popup.html") && ["save", "later", "never"].includes(message.choice)
        ? saver.choose(message.tabId, String(message.id), message.choice)
        : { ok: false, message: "" }
    case "db:popup-saving-on":
      return fromExtensionPage(sender, "popup.html") ? saver.savingOn(message.tabId) : false
    case "db:popup-lock":
      if (!fromExtensionPage(sender, "popup.html") || !standalone) return host.status
      await standalone.lock()
      return standalone.status
    case "db:device":
      return device(message.command, sender)
  }
}

/** The vault's own commands: only from device.html or the popup of this extension, never a content script or another page. */
async function device(raw: unknown, sender: chrome.runtime.MessageSender): Promise<DeviceReply> {
  if (!fromVaultPage(sender)) return { ok: false, message: "", status: host.status }
  if (!standalone) return { ok: false, message: "This build talks to the Deadbolt app; set it up there.", status: host.status }
  const command = deviceCommand(raw)
  if (!command) return { ok: false, message: "Malformed request.", status: host.status }
  return standalone.device(command)
}

/** The inline menu's locked row, from the menu frame its token was made for: device.html, where the user unlocks. Nothing else is asked of the vault. */
async function menuUnlock(token: string, sender: chrome.runtime.MessageSender): Promise<boolean> {
  if (!standalone || !(await autofill.menuUnlock(token, sender))) return false
  await chrome.tabs.create({ url: chrome.runtime.getURL(DEVICE_PAGE) })
  return true
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
  forms.forgetTab(tabId)
  saver.forgetTab(tabId)
  signInWith.forgetTab(tabId)
  learner.forgetTab(tabId)
})
chrome.webNavigation.onCommitted.addListener((d) => {
  void autofill.navigated(d)
  forms.navigated(d)
  if (d.frameId === 0) {
    saver.navigated(d.tabId, d.url, d.transitionType)
    signInWith.navigated(d.tabId, d.url)
  }
})
// A sign-in with a provider: its popup follows it, and its pages get told the account to point at.
chrome.webNavigation.onCreatedNavigationTarget.addListener((d) => signInWith.opened(d.sourceTabId, d.tabId))
chrome.webNavigation.onDOMContentLoaded.addListener((d) => void signInWith.loaded(d))
chrome.webNavigation.onHistoryStateUpdated.addListener((d) => void signInWith.loaded(d))

void host.connect()
