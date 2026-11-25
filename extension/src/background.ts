// Service worker: the extension's only link to Deadbolt. It keeps one
// messaging port to `deadbolt browser-host` (bg/host.ts), and answers the
// content scripts, the inline menu and the popup.

import { Autofill } from "./bg/autofill"
import { Forms } from "./bg/forms"
import { fromExtensionPage } from "./bg/frames"
import { Host } from "./bg/host"
import { Learner } from "./bg/learn"
import { Passkeys } from "./bg/passkeys"
import { Saver } from "./bg/save"
import { SignInWith } from "./bg/signinwith"
import { ProviderChain } from "./bg/provider-chain"
import { SiteIcons } from "./bg/site-icons"
import { UniversalSignIn } from "./bg/universal"
import type { PopupReply, Status, StatusChanged, ToBackground } from "./messages"

const host = new Host()
const saver = new Saver(host)
// A recording's REC stays on the toolbar button over an offer's or a prompt's "1".
const passkeys = new Passkeys(host, { keepBadge: (tabId) => saver.pending(tabId) !== undefined, badge: (tabId, text) => learner.badge(tabId, text) })
const signInWith = new SignInWith(host)
const providers = new ProviderChain(host, passkeys, signInWith)
const autofill = new Autofill(host, passkeys, (tabId, site) => saver.username(tabId, site), signInWith, providers)
const learner = new Learner(host, { badgeUnder: (tabId) => (saver.pending(tabId) || passkeys.prompt(tabId) ? "1" : "") })
saver.badge = (tabId, text) => learner.badge(tabId, text)
learner.listen()
const forms = new Forms(host)
const siteIcons = new SiteIcons(host)
const universal = new UniversalSignIn(host, autofill, (tabId) => saver.pending(tabId) !== undefined, providers)
autofill.signedOut = (target) => universal.signedOutNow(target)
providers.submitIdentifier = (target, username, form) => autofill.submitIdentifier(target, username, form)
saver.formFrames = (tabId) => forms.reported(tabId)
saver.formFilledFrom = (tabId) => forms.filledFrom(tabId)
saver.signedIn = (tabId, site) => {
  void providers.signedIn(tabId)
  void autofill.signedIn(tabId)
  void universal.signedIn(tabId)
  void autofill.learnFlow(tabId, site)
  void learner.signedIn(tabId, site)
  void siteIcons.used(tabId, site)
}
// After a fill (or a sign-in, above), the site's own icon, kept for the rows (bg/site-icons.ts).
autofill.filled = (tabId, site) => void siteIcons.used(tabId, site)
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
    case "db:provider-check":
      return providers.check(sender)
    case "db:signin-check":
      return universal.check(sender, message.signal, message.provider === true)
    case "db:signin-signout":
      return universal.signedOut(sender)
    case "db:signin-stop":
      if (sender.tab?.id !== undefined) providers.stop(sender.tab.id)
      if (sender.tab?.id !== undefined) return autofill.stopAutomatic(sender.tab.id)
      return
    case "db:query":
      if (sender.tab?.id !== undefined && providers.active(sender.tab.id)) return { rows: 0 }
      return autofill.query(sender, message.roles, message.focused, message.form, message.explicit === true, message.identifier, message.again === true, message.kind, message.rules, message.pageAccount, message.box, message.asksNew)
    case "db:page":
      if (Array.isArray(message.roles)) saver.page(sender, message.kind, message.roles)
      return autofill.page(sender, message.kind, message.roles, message.form, message.stepped === true, message.idEmpty === true, message.asksNew === true)
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
    case "db:form-capture":
      return saver.formCapture(sender, message)
    case "db:form-outcome":
      return saver.formOutcome(sender, message.submission, message.ok === true)
    case "db:submitted":
      return autofill.submitted(sender)
    case "db:menu-away":
      return autofill.menuAway(sender, message.dismissed === true)
    case "db:menu-move":
      return autofill.menuMove(sender, message.box)
    case "db:learn-step":
      return learner.step(sender, String(message.session), message.step)
    case "db:learn-events":
      return learner.events(sender, String(message.session), message.events, message.words)
    // The save offer's surface uses the menu's messages with a token of its own (see bg/save.ts).
    case "db:menu-close":
      if (universal.owns(message.token)) return universal.closed(message.token, sender, message.dismissed === true)
      if (saver.ownsSurface(message.token)) return saver.surfaceClosed(String(message.token), sender)
      if (forms.owns(message.token)) return forms.menuClose(String(message.token), sender)
      return autofill.menuClose(String(message.token), message.dismissed === true, sender)
    case "db:menu-load":
      if (universal.owns(message.token)) return universal.load(message.token, sender, String(message.parent))
      if (saver.ownsSurface(message.token)) return saver.surfaceLoad(message.token, sender, String(message.parent))
      if (forms.owns(message.token)) return forms.menuLoad(message.token, sender, String(message.parent))
      return autofill.menuLoad(message.token, sender, String(message.parent))
    case "db:menu-pick":
      if (universal.owns(message.token)) return universal.pick(message.token, String(message.ref), sender)
      if (forms.owns(message.token)) return forms.menuPick(message.token, String(message.ref), sender)
      return autofill.menuPick(message.token, String(message.ref), sender)
    case "db:menu-generate":
      return autofill.menuGenerate(message.token, sender)
    case "db:menu-signin":
      if (universal.owns(message.token)) return universal.provider(message.token, String(message.ref), sender)
      return autofill.menuSignIn(message.token, String(message.ref), sender)
    case "db:menu-dismiss":
      if (universal.owns(message.token)) return universal.dismiss(message.token, sender)
      if (saver.ownsSurface(message.token)) return saver.surfaceDismiss(message.token, sender)
      if (forms.owns(message.token)) return forms.menuDismiss(message.token, sender)
      return autofill.menuDismiss(message.token, sender)
    case "db:menu-resize":
      if (universal.owns(message.token)) return universal.resize(message.token, sender, Number(message.height), message.width, message.mode)
      if (saver.ownsSurface(message.token)) return saver.surfaceResize(message.token, sender, Number(message.height), message.width, message.mode)
      if (forms.owns(message.token)) return forms.menuResize(message.token, Number(message.height), sender, message.width, message.mode)
      return autofill.menuResize(message.token, Number(message.height), sender, message.width, message.mode)
    case "db:surface-choose":
      return ["save", "later", "never", "new"].includes(message.choice) && saver.ownsSurface(message.token)
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
    case "db:popup-record":
      return fromExtensionPage(sender, "popup.html") ? learner.status(message.tabId) : null
    case "db:popup-learn":
      if (!fromExtensionPage(sender, "popup.html")) return { ok: false, message: "" }
      return message.on ? learner.start(message.tabId) : learner.stop(message.tabId, "stopped")
    case "db:popup-recorded":
      if (!fromExtensionPage(sender, "popup.html") || !["download", "delete", "dismiss"].includes(message.action)) return { ok: false, message: "" }
      return learner.recorded(message.tabId, message.action)
    case "db:popup-fill":
      return fromExtensionPage(sender, "popup.html") ? autofill.popupFill(message.tabId, String(message.ref)) : { ok: false, message: "" }
    case "db:popup-offer":
      return fromExtensionPage(sender, "popup.html") && ["save", "later", "never", "new"].includes(message.choice)
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
  void providers.closed(tabId)
  void universal.closeTab(tabId)
  autofill.forgetTab(tabId)
  forms.forgetTab(tabId)
  saver.forgetTab(tabId)
  signInWith.forgetTab(tabId)
  learner.forgetTab(tabId)
})
chrome.webNavigation.onCommitted.addListener((d) => {
  providers.navigated(d)
  void autofill.navigated(d)
  forms.navigated(d)
  learner.navigated(d)
  // A page back from the back/forward cache has no DOMContentLoaded: it's told here.
  void learner.loaded(d)
  if (d.frameId === 0) {
    void universal.closeTab(d.tabId)
    saver.navigated(d.tabId, d.url, d.transitionType)
    signInWith.navigated(d.tabId, d.url)
  }
})
// A sign-in with a provider: its popup follows it, and its pages get told the account to point at.
chrome.webNavigation.onCreatedNavigationTarget.addListener((d) => {
  learner.opened(d)
  if (providers.active(d.sourceTabId)) void providers.opened(d)
  else signInWith.opened(d.sourceTabId, d.tabId)
})
chrome.webNavigation.onDOMContentLoaded.addListener((d) => {
  void learner.loaded(d)
  if (providers.active(d.tabId)) void providers.loaded(d)
  else void signInWith.loaded(d)
})
chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  learner.navigated(d)
  if (providers.active(d.tabId)) { providers.navigated(d); void providers.loaded(d) }
  else void signInWith.loaded(d)
})

void host.connect()
