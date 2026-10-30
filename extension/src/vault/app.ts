// The browser-only Deadbolt's own UI, in the toolbar popup and in device.html
// (the same views in a wider frame). It sets the vault up (pairing with a
// device that has it, or a new one), unlocks it, and shows it: search across
// every login with this site's first, a login's details with its current
// one-time code, adding and editing logins, the settings (devices, passkeys,
// the lock preset, the vault's name), and a page's passkey call in the popup,
// as the native popup asks it. Passphrases and passwords go to the
// background in one message and are never kept here or in storage.

import type { DeviceCommand, DevicePasskey, DeviceReply, ItemKind, ItemSummary, LockPreset, PasskeyChoice, PasskeyPrompt, PopupReply, Reauth, ReauthChanged, Status, StatusChanged, VaultDevice } from "../messages"
import { CLIPBOARD_PERMISSIONS, record } from "../bg/clipboard"
import { account, type Account } from "../protocol"
import { h, icon, ICONS, svg } from "../ui/dom"
import { ROLL_CSS } from "../ui/motion"
import { passkeyCard } from "../ui/passkey"
import { ago, button, enter, glyph, iconButton, ONLINE_SECS, run as send } from "./kit"
import { itemDetailView, itemEditView, kindsView } from "./items"
import { detailView, editView, listView } from "./logins"
import { settingsView } from "./settings"
import { reauthView, Setup, unlockView } from "./setup"

export type Surface = "popup" | "page"

/** Set once Strict's first copy asked for the clipboard permissions, so it asks once. */
const ASKED_KEY = "deadbolt.clipboardAsked"

/** `kind`: the item's type, where the view knows it; else it's looked up, a login if it isn't listed yet. */
export type Route = { name: "list" } | { name: "item"; ref: string; kind?: string; then?: "reveal" | "copy" } | { name: "edit"; ref?: string; kind?: string } | { name: "new" } | { name: "settings" }

/** What a view shows and how it follows the vault: `update` when the data changed under it, `leave` when it goes. */
export interface View {
  el: HTMLElement
  update?: () => void
  focus?: () => void
  leave?: () => void
}

/** This tab's site in the popup: logins, offers, passkeys, saving and learning state. */
export interface Site {
  tabId: number
  host: string
  accounts: Account[]
  offer?: PopupReply["offer"]
  passkey?: PasskeyPrompt
  savingOff?: string
  learning?: PopupReply["learning"]
}

/** How long the popup stays open after a passkey choice for the passphrase prompt it leads to. */
const PASSKEY_REAUTH_MS = 10_000

export interface Sync {
  /** Unix seconds of the latest sync with any other device. */
  last: number | null
  others: number
  online: number
  busy: boolean
}

/** Everything a view needs: the vault's data, a way to ask it things, and to move between views. */
export class App {
  status: Status = { state: "connecting" }
  /** Every item, sorted by title. */
  items: ItemSummary[] | null = null
  /** The types New can add, from the core's schemas. */
  kinds: ItemKind[] | null = null
  devices: VaultDevice[] | null = null
  /** The vault's passkeys (never their keys), for settings. */
  passkeys: DevicePasskey[] | null = null
  vaultName = ""
  preset: LockPreset = "comfortable"
  site: Site | null = null
  syncing = false
  /** A page's fill waiting on the passphrase, shown before anything else. */
  reauth: Reauth | null = null
  /** The search, kept across views. */
  query = ""
  private route: Route = { name: "list" }
  private view: View | null = null
  private shell = ""
  private stage = h("div", { class: "stage" })
  private live = h("div", { class: "sr-only", role: "status", "aria-live": "polite" })
  private footer = h("footer", { class: "bottom sync" })
  private header = h("header", { class: "top" })
  private setup: Setup

  constructor(
    readonly root: HTMLElement,
    readonly surface: Surface,
  ) {
    root.classList.add("vault", surface)
    this.setup = new Setup(this)
  }

  run(command: DeviceCommand): Promise<DeviceReply> {
    return this.ask(command).then((r) => {
      this.status = r.status
      return r
    })
  }

  /** A command whose answer may be stale by the time it comes: the caller decides whether its status counts. */
  ask(command: DeviceCommand): Promise<DeviceReply> {
    return send(command, () => this.status)
  }

  announce(message: string) {
    this.live.textContent = ""
    requestAnimationFrame(() => (this.live.textContent = message))
  }

  /** Shows `route`, coming in from the side it's going: 1 deeper, -1 back. */
  go(route: Route, dir: -1 | 0 | 1 = 1) {
    this.route = route
    this.show(dir)
  }

  /** The current state's view, again: what the status says, else the route. */
  show(dir: -1 | 0 | 1 = 0, animate = true) {
    this.view?.leave?.()
    const view = this.build()
    this.view = view
    this.stage.replaceChildren(view.el)
    if (animate) enter(view.el, dir)
    view.focus?.()
    this.paintChrome()
  }

  private build(): View {
    switch (this.status.state) {
      case "ready":
        break
      case "not-set-up":
        return this.setup.view()
      case "locked":
        return unlockView(this)
      case "connecting":
        return message(icon("keyhole"), "Starting Deadbolt…", null, true)
      case "unavailable":
        return message(glyph("warning"), "Deadbolt couldn't start", this.status.detail || "The vault didn't answer.")
      default:
        return message(icon("plug"), "Deadbolt isn't running", "Reload the extension and try again.")
    }
    if (this.reauth) return reauthView(this, this.reauth)
    // A page's passkey call: when one is waiting, the popup shows only this, as the native one does.
    if (this.surface === "popup" && this.site?.passkey) return this.passkeyView(this.site.tabId, this.site.passkey)
    switch (this.route.name) {
      case "list":
        return listView(this)
      case "item": {
        const kind = this.kindOf(this.route.ref, this.route.kind)
        return kind === "login" ? detailView(this, this.route.ref, this.route.then) : itemDetailView(this, this.route.ref)
      }
      case "edit": {
        const kind = this.route.ref ? this.kindOf(this.route.ref, this.route.kind) : (this.route.kind ?? "login")
        return kind === "login" ? editView(this, this.route.ref) : itemEditView(this, kind, this.route.ref)
      }
      case "new":
        return kindsView(this)
      case "settings":
        return settingsView(this)
    }
  }

  /** The header and the sync footer, which belong to the state, not the view. */
  paintChrome() {
    const ready = this.status.state === "ready"
    const right: Node[] = []
    if (ready) {
      const settings = iconButton(glyph("gear"), "Settings", () => this.go(this.route.name === "settings" ? { name: "list" } : { name: "settings" }, this.route.name === "settings" ? -1 : 1))
      if (this.route.name === "settings") settings.classList.add("on")
      settings.setAttribute("aria-pressed", String(this.route.name === "settings"))
      right.push(settings, iconButton(icon("lock"), "Lock", (b) => void this.lock(b)))
    } else right.push(pill(this.status))
    this.header.replaceChildren(
      h("span", { class: "logo" }, svg(ICONS.deadbolt)),
      h("span", { class: "brand" }, "Deadbolt", ready && this.vaultName ? h("span", { class: "vault-name" }, this.vaultName) : null),
      ...right,
    )
    this.footer.hidden = !ready
    if (ready) this.paintSync()
  }

  sync(): Sync {
    const now = Date.now() / 1000
    const others = (this.devices ?? []).filter((d) => !d.current)
    const seen = others.map((d) => d.lastSeen ?? 0).filter((t) => t > 0)
    return { last: seen.length ? Math.max(...seen) : null, others: others.length, online: seen.filter((t) => now - t <= ONLINE_SECS).length, busy: this.syncing }
  }

  private paintSync() {
    const s = this.sync()
    const text =
      this.devices === null
        ? ""
        : s.busy
          ? "Syncing…"
          : s.others === 0
            ? "Only on this browser"
            : `${s.last ? `Synced ${ago(s.last)}` : "Not synced yet"} · ${s.online} of ${s.others} online`
    const dot = h("span", { class: `sync-dot${s.online ? " on" : ""}${s.busy ? " busy" : ""}`, "aria-hidden": "true" })
    const now = iconButton(glyph("sync"), "Sync now", () => void this.syncNow(), s.busy ? "spinning" : "")
    if (s.busy) now.setAttribute("disabled", "")
    const pair = s.others === 0 && !s.busy && this.devices !== null ? button("link", "Pair a device", () => this.go({ name: "settings" })) : null
    this.footer.replaceChildren(h("span", { class: "sync-text" }, dot, h("span", {}, text)), pair ?? (s.others ? now : h("span")))
  }

  async syncNow() {
    if (this.syncing) return
    this.syncing = true
    this.paintSync()
    // The sync pushes "items" when it's done, which refreshes the lists.
    const r = await this.run({ type: "device-sync", wait: true })
    this.syncing = false
    this.paintSync()
    this.announce(r.ok ? "Synced." : r.message)
  }

  /** Whether a copied password gets cleared off the clipboard (the optional clipboard permissions). */
  clears(): Promise<boolean> {
    return chrome.permissions.contains({ permissions: CLIPBOARD_PERMISSIONS }).catch(() => false)
  }

  /** Asks for the clipboard permissions, from the user's click. Answers whether they were granted. */
  askClearing(): Promise<boolean> {
    return chrome.permissions.request({ permissions: CLIPBOARD_PERMISSIONS }).catch(() => false)
  }

  /** Under Strict, the first copy asks once for the clipboard permissions, so copied passwords get cleared. */
  async offerClearing() {
    if (this.preset !== "strict" || (await this.clears())) return
    const got = await chrome.storage.local.get(ASKED_KEY).catch(() => ({}) as Record<string, unknown>)
    if (got[ASKED_KEY]) return
    await chrome.storage.local.set({ [ASKED_KEY]: true }).catch(() => {})
    await this.askClearing()
  }

  /** The page copied a password or code: the background clears it in 30 s if it may. It gets only a salted hash of it. */
  async copiedSecret(value: string): Promise<string> {
    const r = await this.run({ type: "device-copied", ...(await record(value)) })
    return r.ok && r.reply.clears === true ? "Copied. It clears in 30 seconds." : "Copied."
  }

  /** Asks whether a page's fill waits on the passphrase, and shows its prompt (or stops showing it). */
  async loadReauth() {
    if (this.status.state !== "ready") return
    const r = await this.run({ type: "device-reauth" })
    const next = r.ok ? reauthOf(r.reply.reauth) : null
    if (next?.id === this.reauth?.id) return
    this.reauth = next
    if (this.shell === "ready") this.show(0)
  }

  /** The fill was answered (or ended with `message`): the popup closes; device.html goes back to the vault. */
  reauthDone(message?: string) {
    this.reauth = null
    if (this.surface === "popup" && !message) return window.close()
    this.show(-1)
    if (message) this.announce(message)
  }

  async reauthCancel(reauth: Reauth) {
    await this.run({ type: "device-reauth-cancel", id: reauth.id })
    if (this.reauth?.id !== reauth.id) return
    this.reauth = null
    if (this.surface === "popup") return window.close()
    this.show(-1)
  }

  private passkeyView(tabId: number, prompt: PasskeyPrompt): View {
    const card = passkeyCard(prompt, tabId, { chosen: (choice) => void this.passkeyChosen(prompt, choice), ended: () => void this.refresh() })
    return { el: h("section", { class: "view" }, card), focus: () => card.querySelector<HTMLElement>(".btn.primary")?.focus() }
  }

  /**
   * The background took a passkey choice. Under Strict a sign-in or save asks
   * for the passphrase next (`prompt.passphrase`): the popup stays open until
   * that prompt comes, and shows it. Otherwise the page takes it from here.
   */
  private async passkeyChosen(prompt: PasskeyPrompt, choice: PasskeyChoice) {
    if (this.site?.passkey?.id === prompt.id) this.site.passkey = undefined
    if (!prompt.passphrase || (choice.action !== "use" && choice.action !== "save")) return window.close()
    const until = Date.now() + PASSKEY_REAUTH_MS
    await this.loadReauth()
    while (!this.reauth && this.status.state === "ready" && Date.now() < until) {
      await new Promise((done) => setTimeout(done, 250))
      await this.loadReauth()
    }
    if (!this.reauth) window.close()
  }

  /** The vault just opened (unlock, create, join): show it, unless a status push already did. */
  opened() {
    if (this.shell === this.status.state) return
    this.render()
    void this.refresh()
  }

  private async lock(b: HTMLButtonElement) {
    b.disabled = true
    await this.run({ type: "device-lock" })
    this.route = { name: "list" }
    this.query = ""
    this.render()
  }

  /** Builds the whole page for the current status (only when the status changes). */
  render() {
    if (this.status.state !== "not-set-up") this.setup.reset()
    if (this.status.state !== "ready") {
      this.items = null
      this.devices = null
      this.passkeys = null
      this.site = null
      this.reauth = null
    }
    if (!this.root.contains(this.stage)) this.root.replaceChildren(this.header, this.stage, this.footer, this.live)
    const first = this.shell === ""
    this.shell = this.status.state
    this.show(0, !first)
  }

  /** The type of item `ref`: as the route says, else as the list has it. */
  kindOf(ref: string, kind?: string): string {
    return kind ?? this.items?.find((i) => i.ref === ref)?.kind ?? "login"
  }

  /** The vault's logins, for the views that only show those. */
  get logins(): Account[] | null {
    return this.items ? (this.items.filter((i) => i.kind === "login") as Account[]) : null
  }

  /** Reads the vault's logins, devices and settings again, and this tab's site, then lets the view follow. */
  async refresh() {
    if (this.status.state !== "ready") return
    const [items, d, s, site, kinds, passkeys] = await Promise.all([
      this.run({ type: "device-items" }),
      this.run({ type: "device-devices" }),
      this.run({ type: "device-settings" }),
      this.loadSite(),
      this.kinds ? null : this.run({ type: "device-kinds" }),
      this.run({ type: "device-passkeys" }),
    ])
    if (this.status.state !== "ready") return this.render()
    if (items.ok && Array.isArray(items.reply.items)) this.items = (items.reply.items as unknown[]).map(itemSummary).filter((a): a is ItemSummary => a !== null).sort((a, b) => a.title.localeCompare(b.title))
    if (kinds?.ok && Array.isArray(kinds.reply.kinds)) this.kinds = kinds.reply.kinds as ItemKind[]
    if (d.ok && Array.isArray(d.reply.devices)) {
      this.devices = d.reply.devices.map(vaultDevice).filter((x): x is VaultDevice => x !== null)
      if (typeof d.reply.vault === "string") this.vaultName = d.reply.vault
    }
    if (s.ok && typeof s.reply.preset === "string") this.preset = s.reply.preset as LockPreset
    if (passkeys.ok && Array.isArray(passkeys.reply.passkeys))
      this.passkeys = passkeys.reply.passkeys.map(devicePasskey).filter((x): x is DevicePasskey => x !== null).sort((a, b) => a.rpId.localeCompare(b.rpId) || (a.username ?? "").localeCompare(b.username ?? ""))
    const prompt = this.site?.passkey?.id
    this.site = site
    // A passkey call came or went: it replaces the whole view.
    if (site?.passkey?.id !== prompt && !this.reauth) return this.show(0)
    this.view?.update?.()
    this.paintChrome()
  }

  /** This tab's site again (a learning session's steps), and the view follows. */
  async refreshSite() {
    if (this.status.state !== "ready" || this.surface !== "popup") return
    const prompt = this.site?.passkey?.id
    this.site = await this.loadSite()
    if (this.site?.passkey?.id !== prompt && !this.reauth) return this.show(0)
    this.view?.update?.()
  }

  async loadPreset() {
    const s = await this.run({ type: "device-settings" })
    if (s.ok && typeof s.reply.preset === "string") this.preset = s.reply.preset as LockPreset
  }

  /** The popup's tab: its site's logins and any offer to save, as the native popup has them. */
  private async loadSite(): Promise<Site | null> {
    if (this.surface !== "popup") return null
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }).catch(() => [])
    if (tab?.id === undefined) return null
    const reply = (await chrome.runtime.sendMessage({ type: "db:popup-load", tabId: tab.id }).catch(() => null)) as PopupReply | null
    if (!reply || reply.unfillable || !(reply.site || reply.host)) return null
    return { tabId: tab.id, host: reply.site || reply.host || "", accounts: reply.accounts, offer: reply.offer, passkey: reply.passkey, savingOff: reply.savingOff, learning: reply.learning }
  }

  /** Follows the background's status pushes, and starts. */
  start() {
    document.head.append(h("style", {}, ROLL_CSS))
    chrome.runtime.onMessage.addListener((message: StatusChanged | ReauthChanged) => {
      if (message?.type === "db:reauth") return void this.loadReauth()
      if (message?.type !== "db:status") return
      const was = this.status.state
      this.status = message.status
      if (this.status.state !== was) {
        if (this.status.state !== "ready") this.route = { name: "list" }
        this.render()
        if (this.status.state === "not-set-up") void this.setup.check()
      } else if (this.status.state === "not-set-up") this.setup.pushed()
      // Every answer from the vault pushes its status (loading this tab's site
      // asks for it too): only a change of state or of the logins is news.
      else if (this.status.state === "ready" && message.change === "items") void this.refresh()
      if (this.status.state === "ready" && this.status.state !== was) void this.refresh()
    })
    addEventListener("pagehide", () => {
      this.setup.stop()
      // Closed without an answer: the fill it asked for doesn't wait on it. A
      // device.html closed in a background tab never showed the prompt (the
      // popup or another tab did), so it leaves the fill waiting.
      if (this.reauth && document.visibilityState === "visible") void this.ask({ type: "device-reauth-cancel", id: this.reauth.id })
    })
    // While the tab is learning, its step count follows along, as in the native popup.
    if (this.surface === "popup") setInterval(() => this.site?.learning && void this.refreshSite(), 1000)
    // A vault slow to answer shows that it's starting, never an empty frame.
    const slow = setTimeout(() => this.shell === "" && this.render(), 250)
    void this.run({ type: "device-status" }).then(async () => {
      clearTimeout(slow)
      if (this.status.state === "not-set-up") await this.setup.check()
      if (this.status.state === "locked") await this.loadPreset()
      if (this.status.state === "ready") await this.loadReauth()
      this.render()
      if (this.status.state === "ready") void this.refresh()
    })
  }
}

const REAUTH_KINDS: ReadonlyArray<Reauth["kind"]> = ["card", "passkey-get", "passkey-create"]

/** An item of the list, checked: a login's account fields as protocol.ts checks them, and the rest. */
function itemSummary(v: unknown): ItemSummary | null {
  const i = v as Record<string, unknown> | null
  if (!i || typeof i.kind !== "string" || typeof i.title !== "string" || typeof i.ref !== "string") return null
  const words = Array.isArray(i.search) ? i.search.filter((w): w is string => typeof w === "string") : []
  const base = i.kind === "login" ? account(i) : { ref: i.ref, title: i.title, urls: Array.isArray(i.urls) ? i.urls.filter((u): u is string => typeof u === "string") : [] }
  if (!base) return null
  return { ...base, kind: i.kind, title: i.title, search: words, ...(typeof i.detail === "string" ? { detail: i.detail } : {}), ...(typeof i.primary === "string" ? { primary: i.primary } : {}) }
}

function reauthOf(v: unknown): Reauth | null {
  const r = v as Partial<Reauth> | null
  if (!r || typeof r.id !== "string" || typeof r.title !== "string" || typeof r.site !== "string") return null
  return { id: r.id, title: r.title, site: r.site, ...(REAUTH_KINDS.includes(r.kind) ? { kind: r.kind } : {}) }
}

function devicePasskey(v: unknown): DevicePasskey | null {
  const k = v as Partial<DevicePasskey> | null
  if (!k || typeof k.ref !== "string" || typeof k.vault !== "string" || typeof k.rpId !== "string" || typeof k.credentialId !== "string") return null
  return {
    ref: k.ref,
    vault: k.vault,
    rpId: k.rpId,
    credentialId: k.credentialId,
    ...(typeof k.username === "string" && k.username ? { username: k.username } : {}),
    ...(typeof k.created === "string" && k.created ? { created: k.created } : {}),
  }
}

function vaultDevice(v: unknown): VaultDevice | null {
  const d = v as Partial<VaultDevice> | null
  if (!d || typeof d.id !== "string" || typeof d.name !== "string") return null
  return { id: d.id, name: d.name, current: d.current === true, lastSeen: typeof d.lastSeen === "number" ? d.lastSeen : null }
}

function pill(status: Status): HTMLElement {
  const [label, tone] = status.state === "locked" ? ["Locked", "warn"] : status.state === "not-set-up" ? ["Not set up", ""] : status.state === "connecting" ? ["Starting", ""] : ["Not running", "bad"]
  return h("span", { class: `pill ${tone}` }, label)
}

/** A whole-view message: starting, or something went wrong. */
export function message(glyphEl: Element, title: string, detail: string | null, busy = false): View {
  return {
    el: h(
      "section",
      { class: "view center" },
      h("div", { class: "state" }, h("span", { class: `state-icon${busy ? " pulse" : ""}` }, glyphEl), h("h2", {}, title), detail ? h("p", { class: "muted" }, detail) : null),
    ),
  }
}

export function mountVault(root: HTMLElement, surface: Surface) {
  new App(root, surface).start()
}
