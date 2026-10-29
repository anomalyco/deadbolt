// The browser-only Deadbolt's own UI, in the toolbar popup and in device.html
// (the same views in a wider frame). It sets the vault up (pairing with a
// device that has it, or a new one), unlocks it, and shows it: search across
// every login with this site's first, a login's details with its current
// one-time code, adding and editing logins, and the settings (devices, the
// lock preset, the vault's name). Passphrases and passwords go to the
// background in one message and are never kept here or in storage.

import type { DeviceCommand, DeviceReply, LockPreset, PopupReply, Status, StatusChanged, VaultDevice } from "../messages"
import { account, type Account } from "../protocol"
import { h, icon, ICONS, svg } from "../ui/dom"
import { ROLL_CSS } from "../ui/motion"
import { ago, button, enter, glyph, iconButton, ONLINE_SECS, run as send } from "./kit"
import { detailView, editView, listView } from "./logins"
import { settingsView } from "./settings"
import { Setup, unlockView } from "./setup"

export type Surface = "popup" | "page"

export type Route = { name: "list" } | { name: "item"; ref: string; then?: "reveal" | "copy" } | { name: "edit"; ref?: string } | { name: "settings" }

/** What a view shows and how it follows the vault: `update` when the data changed under it, `leave` when it goes. */
export interface View {
  el: HTMLElement
  update?: () => void
  focus?: () => void
  leave?: () => void
}

/** This tab's site in the popup: its logins, an offer to save, and the tab to fill. */
export interface Site {
  tabId: number
  host: string
  accounts: Account[]
  offer?: PopupReply["offer"]
}

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
  logins: Account[] | null = null
  devices: VaultDevice[] | null = null
  vaultName = ""
  preset: LockPreset = "comfortable"
  site: Site | null = null
  syncing = false
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
    switch (this.route.name) {
      case "list":
        return listView(this)
      case "item":
        return detailView(this, this.route.ref, this.route.then)
      case "edit":
        return editView(this, this.route.ref)
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
    const r = await this.run({ type: "device-sync", wait: true })
    this.syncing = false
    if (!r.ok) this.announce(r.message)
    await this.refresh()
    this.paintSync()
    this.announce("Synced.")
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
      this.logins = null
      this.devices = null
      this.site = null
    }
    if (!this.root.contains(this.stage)) this.root.replaceChildren(this.header, this.stage, this.footer, this.live)
    const first = this.shell === ""
    this.shell = this.status.state
    this.show(0, !first)
  }

  /** Reads the vault's logins, devices and settings again, and this tab's site, then lets the view follow. */
  async refresh() {
    if (this.status.state !== "ready") return
    const [l, d, s, site] = await Promise.all([this.run({ type: "device-logins" }), this.run({ type: "device-devices" }), this.run({ type: "device-settings" }), this.loadSite()])
    if (this.status.state !== "ready") return this.render()
    if (l.ok && Array.isArray(l.reply.accounts)) this.logins = l.reply.accounts.map(account).filter((a): a is Account => a !== null).sort((a, b) => a.title.localeCompare(b.title))
    if (d.ok && Array.isArray(d.reply.devices)) {
      this.devices = d.reply.devices.map(vaultDevice).filter((x): x is VaultDevice => x !== null)
      if (typeof d.reply.vault === "string") this.vaultName = d.reply.vault
    }
    if (s.ok && typeof s.reply.preset === "string") this.preset = s.reply.preset as LockPreset
    this.site = site
    this.view?.update?.()
    this.paintChrome()
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
    return { tabId: tab.id, host: reply.site || reply.host || "", accounts: reply.accounts, offer: reply.offer }
  }

  /** Follows the background's status pushes, and starts. */
  start() {
    document.head.append(h("style", {}, ROLL_CSS))
    chrome.runtime.onMessage.addListener((message: StatusChanged) => {
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
    addEventListener("pagehide", () => this.setup.stop())
    // A vault slow to answer shows that it's starting, never an empty frame.
    const slow = setTimeout(() => this.shell === "" && this.render(), 250)
    void this.run({ type: "device-status" }).then(async () => {
      clearTimeout(slow)
      if (this.status.state === "not-set-up") await this.setup.check()
      if (this.status.state === "locked") await this.loadPreset()
      this.render()
      if (this.status.state === "ready") void this.refresh()
    })
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
