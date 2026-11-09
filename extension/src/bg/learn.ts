// Background side of Record (see src/learn.ts): one recording per tab,
// started and stopped from the popup or the `record` shortcut. It hands every
// frame of the tab the recording's id and salt, turns each frame's steps into
// log lines (deciding from the salted digest whether a typed value was a
// saved username, then dropping the digest), adds what Chrome sees of the tab
// (navigations, popups) to the frames' timelines, and has the native host
// append it all, in order, to the recording's log. A recording ends when the
// user stops it, takes the tab to another site themselves, gives it no input
// for IDLE_MS, after LEARN_TTL_MS, or with its tab; it badges the toolbar
// button "REC" while it runs. Then the popup offers its log for Download or
// Delete. Frames on another site than the page share small caps of their
// own, so an ad can't use up a recording. Frames join when the background
// tells them (on each frame's DOMContentLoaded): they never ask. Words typed
// in the recording come as salted digests, which scrub addresses and titles
// and never reach the log. Recordings are kept in chrome.storage.session too,
// so a service worker that restarts picks them up where they were.

import { frameOf, IDLE_MS, keyName, LEARN_TTL_MS, MAX_CROSS_EVENTS, MAX_CROSS_STEPS, MAX_EVENTS, MAX_ORIGIN_EVENTS, MAX_INPUTS, MAX_STEPS, MAX_WORDS, keypadText, noDigits, tagsOnly, truthOf, usernameDigest, type LearnEnd, type LearnSession, type LearnStep, type LearnTaken, type Target, type TimelineEvent, type TimelineType } from "../learn"
import type { LearnReply, RecordedReply, Recording } from "../messages"
import type { VaultBackend } from "./backend"
import { learnExport } from "./learn-log"
import { siteOf } from "./site"

/** A line the host takes, well under its 64 KiB request limit. */
const MAX_LINE = 56 * 1024
/** The timeline goes to the log in batches: at most this often, or once this many wait. */
const FLUSH_MS = 1000
const FLUSH_EVENTS = 100
/** chrome.storage.session: `learn:<tab id>` → the tab's Stored recording; `learned:<tab id>` → its Done one. */
const PREFIX = "learn:"
const DONE = "learned:"
const BADGE = "#f02e29"
/** Navigations the user started: the address bar, a bookmark, a start page. Links and redirects (a provider's sign-in) aren't. */
const BY_HAND = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated", "start_page"])

declare const DEADBOLT_E2E: boolean | undefined

/** What outlives a service worker restart. */
interface Stored {
  id: string
  site: string
  host: string
  salt: string
  startedAt: number
  until: number
  steps: number
  events: number
  /** What frames on other sites than the page have used of their own caps. */
  crossSteps: number
  crossEvents: number
  /** Each cross-site origin's share of crossEvents. */
  byOrigin: Record<string, number>
  /** The site the tab's top page is on now: where a navigation by hand leaves from. */
  top: string
  /** When the user last did anything in a frame of the tab: a pointer, a key, typing. A page's own focus() or scrollTo() isn't. */
  lastInput: number
  /** Salted digests of the saved usernames for the site. */
  usernames: string[]
  /** Salted digests of the words typed in the recording (see Words). */
  words: string[]
}

interface Active extends Omit<Stored, "usernames" | "words"> {
  usernames: Set<string>
  words: Set<string>
  timer: ReturnType<typeof setTimeout>
  idle: ReturnType<typeof setTimeout>
  /** Lines are written one after another, in order. */
  writes: Promise<void>
  /** Timeline events waiting for their line; Chrome's navigations with their address, scrubbed when the line is written. */
  pending: Array<TimelineEvent & { url?: URL }>
  dropped: number
  flushing?: ReturnType<typeof setTimeout>
}

/** A finished recording, until the popup downloads, deletes or puts it away. */
interface Done {
  session: string
  host: string
  steps: number
}

/** What the user did, not the page: these keep a recording from going idle. */
const INPUT = new Set<TimelineType>(["pointerdown", "pointerup", "click", "dblclick", "key", "input"])
const TYPES = new Set<TimelineType>(["pointerdown", "pointerup", "click", "dblclick", "key", "focus", "blur", "input", "change", "submit", "scroll", "unload"])
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")

/** Strings clipped and arrays capped, however the step was put together. */
function bounded(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return value.slice(0, 200)
  if (typeof value === "number") return Number.isFinite(value) ? Math.round(value) : 0
  if (typeof value === "boolean" || value === null) return value
  if (depth > 5) return null
  if (Array.isArray(value)) return value.slice(0, MAX_INPUTS).map((v) => bounded(v, depth + 1))
  if (typeof value === "object") {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, 40)) if (v !== undefined) out[k.slice(0, 40)] = bounded(v, depth + 1)
    return out
  }
  return null
}

const str = (v: unknown, n = 80) => (typeof v === "string" && v ? v.slice(0, n) : undefined)
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? Math.round(v) : undefined)
const SHAPES = new Set(["secret", "email", "phone", "digits", "text"])
const BANDS = new Set(["1-3", "4-8", "9-16", "17-32", "33+"])

/** Only the fields a target has, each bounded: whatever a frame sends, nothing else gets in. */
function target(v: unknown): Target | undefined {
  const t = v as Record<string, unknown> | null
  if (!t || typeof t !== "object" || typeof t.tag !== "string") return undefined
  // A keypad's key, as the frame says or as its text shows (keypadText): no text, label, id or name, a path of tags.
  const keypad = t.keypad === true || [t.text, t.label].some((v) => typeof v === "string" && keypadText(v))
  const path = str(t.path, 200) ?? ""
  const out: Target = { tag: t.tag.slice(0, 20), path: keypad ? tagsOnly(path) : noDigits(path) }
  for (const k of ["type", "name", "id", "role", "label", "autocomplete", "text", "detected"] as const) {
    const s = str(t[k], k === "text" ? 40 : 80)
    if (s && !(keypad && (k === "text" || k === "label" || k === "id" || k === "name"))) out[k] = k === "role" || k === "autocomplete" || k === "type" || k === "detected" ? s : noDigits(s)
  }
  if (keypad) out.keypad = true
  if (t.inShadow === true) out.inShadow = true
  return out
}

/** A frame's timeline event, rebuilt from the fields it may have. */
function timelineEvent(v: unknown): TimelineEvent | null {
  const e = v as Record<string, unknown> | null
  if (!e || typeof e !== "object" || !TYPES.has(e.type as TimelineType)) return null
  const out: TimelineEvent = { t: Math.max(0, num(e.t) ?? 0), type: e.type as TimelineType }
  const t = target(e.target)
  if (t) out.target = t
  const submitter = target(e.submitter)
  if (submitter) out.submitter = submitter
  // Where a keypad's key was pressed would tell which.
  if (!t?.keypad)
    for (const k of ["x", "y"] as const) {
      const n = num(e[k])
      if (n !== undefined) out[k] = n
    }
  // Only a key's name, or `char`: never which character.
  const key = str(e.key, 20)
  if (key && (key === "char" || keyName(key) === key)) out.key = key
  const mods = str(e.mods, 30)
  if (mods) out.mods = mods
  const inputType = str(e.inputType, 40)
  if (inputType) out.inputType = inputType
  if (SHAPES.has(e.shape as string)) out.shape = e.shape as TimelineEvent["shape"]
  if (BANDS.has(e.length as string) && out.shape !== "secret") out.length = e.length as TimelineEvent["length"]
  return out
}

/** Pages no extension may script: Chrome's own, the Web Store. */
function blocked(url: URL | null): string | null {
  if (!url || !/^https?:$/.test(url.protocol)) return "Deadbolt can't record the browser's own pages."
  if (url.hostname === "chromewebstore.google.com" || (url.hostname === "chrome.google.com" && url.pathname.startsWith("/webstore"))) return "Chrome doesn't let extensions record the Web Store."
  return null
}

async function topUrl(tabId: number): Promise<URL | null> {
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
  try {
    return frame?.url ? new URL(frame.url) : null
  } catch {
    return null
  }
}

export interface LearnerOptions {
  /** Another badge the tab has under REC ("1": an offer or a passkey prompt waiting). */
  badgeUnder?: (tabId: number) => string
}

export class Learner {
  private tabs = new Map<number, Active>()
  private done = new Map<number, Done>()
  /** The recordings a previous service worker left, back in `tabs` and `done`. */
  private ready: Promise<void>
  private badgeUnder: NonNullable<LearnerOptions["badgeUnder"]>

  constructor(
    private host: VaultBackend,
    options: LearnerOptions = {},
  ) {
    this.badgeUnder = options.badgeUnder ?? (() => "")
    this.ready = this.restore()
  }

  /**
   * The `record` shortcut (manifest `commands`) starts and stops recording
   * the tab it's pressed in. Started so, the popup opens: a cue that it
   * records even when Deadbolt's button isn't pinned to the toolbar.
   */
  listen() {
    const command = (name: string, tab?: chrome.tabs.Tab) => {
      if (name !== "record" || tab?.id === undefined) return
      const tabId = tab.id
      void this.toggle(tabId).then((r) => {
        if (r.ok && this.tabs.has(tabId)) void chrome.action.openPopup?.(tab.windowId === undefined ? {} : { windowId: tab.windowId }).catch(() => {})
      })
    }
    chrome.commands?.onCommand.addListener(command)
    // e2e builds only: CDP's key events never reach extension commands, so the scenario fires it here.
    if (typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true) (globalThis as unknown as { __command: typeof command }).__command = command
  }

  async toggle(tabId: number): Promise<LearnReply> {
    await this.ready
    return this.tabs.has(tabId) ? this.stop(tabId, "stopped") : this.start(tabId)
  }

  /** What the popup shows for the tab. */
  async status(tabId: number): Promise<Recording> {
    await this.ready
    const a = this.tabs.get(tabId)
    if (a) return { state: "on", host: a.host, startedAt: a.startedAt, until: a.until, steps: a.events }
    const d = this.done.get(tabId)
    if (d) return { state: "done", ...d }
    const why = blocked(await topUrl(tabId))
    return why ? { state: "blocked", message: why } : { state: "off" }
  }

  async start(tabId: number): Promise<LearnReply> {
    await this.ready
    const url = await topUrl(tabId)
    const why = blocked(url)
    if (why || !url) return { ok: false, message: why ?? "" }
    await this.host.reconnectNow()
    if (!this.host.capabilities.includes("learn"))
      return { ok: false, message: this.host.status.state === "ready" || this.host.status.state === "locked" ? "This Deadbolt can't keep a recording. Update Deadbolt, then try again." : "Deadbolt isn't connected, so there's nowhere to keep a recording." }
    if (this.tabs.has(tabId)) await this.stop(tabId, "replaced")
    await this.dismiss(tabId)

    const site = siteOf(url.hostname) ?? url.hostname
    const salt = hex(crypto.getRandomValues(new Uint8Array(16)))
    // The saved usernames for the site, only as digests, to tell a typed username.
    const usernames = new Set<string>()
    let saved = 0
    if (this.host.status.state === "ready") {
      const list = await this.host.send({ type: "list", origin: url.origin }).catch(() => null)
      saved = list?.accounts.length ?? 0
      for (const a of list?.accounts ?? []) if (a.username) usernames.add(await usernameDigest(salt, a.username))
    }
    const now = Date.now()
    const a: Active = {
      id: crypto.randomUUID(),
      site,
      host: url.hostname,
      salt,
      startedAt: now,
      until: now + LEARN_TTL_MS,
      steps: 0,
      events: 0,
      crossSteps: 0,
      crossEvents: 0,
      byOrigin: {},
      top: site,
      lastInput: now,
      usernames,
      words: new Set(),
      timer: setTimeout(() => void this.stop(tabId, "timeout"), LEARN_TTL_MS),
      idle: setTimeout(() => this.idle(tabId), IDLE_MS),
      writes: Promise.resolve(),
      pending: [],
      dropped: 0,
    }
    this.tabs.set(tabId, a)
    void this.save(tabId, a)
    const started = await this.write(a, {
      event: "start",
      site,
      origin: url.origin,
      path: (await frameOf(url, true, 0)).path,
      at: new Date(now).toISOString(),
      extension: chrome.runtime.getManifest?.().version ?? "",
      savedLogins: saved,
    })
    if (!started) {
      clearTimeout(a.timer)
      clearTimeout(a.idle)
      this.tabs.delete(tabId)
      void this.forget(tabId)
      return { ok: false, message: "Deadbolt couldn't start the recording." }
    }
    this.badge(tabId)
    void this.broadcast(tabId, this.session(a))
    return { ok: true }
  }

  /**
   * A frame of a recording tab loaded its document: it joins (frames never
   * ask, so a page nobody records costs no message). A new top page also
   * gets REC back: Chrome cleared the tab's badge with the old one.
   */
  async loaded(d: { tabId: number; frameId: number; documentId?: string }) {
    await this.ready
    const a = this.tabs.get(d.tabId)
    if (!a || Date.now() >= a.until) return
    if (d.frameId === 0) this.badge(d.tabId)
    const target = d.documentId ? { documentId: d.documentId } : { frameId: d.frameId }
    await chrome.tabs.sendMessage(d.tabId, { type: "db:learn", session: this.session(a) }, target).catch(() => {})
  }

  async step(sender: chrome.runtime.MessageSender, session: string, step: LearnStep): Promise<LearnTaken> {
    await this.ready
    const tabId = sender.tab?.id
    const a = tabId === undefined ? undefined : this.tabs.get(tabId)
    if (!a || a.id !== session || Date.now() >= a.until || typeof step !== "object" || step === null) return false
    const sameSite = this.sameSite(sender, a)
    // Full: the recording goes on; this frame's steps aren't kept.
    if (a.steps >= MAX_STEPS || (!sameSite && a.crossSteps >= MAX_CROSS_STEPS)) return "full"
    const inputs = Array.isArray(step.inputs) ? step.inputs : []
    for (const input of inputs) {
      const typed = input?.typed
      if (!typed || typeof typed !== "object") continue
      typed.savedUsername = typeof typed.digest === "string" && a.usernames.has(typed.digest)
      delete typed.digest
      typed.truth = truthOf(typed)
    }
    a.steps++
    if (!sameSite) a.crossSteps++
    void this.save(tabId!, a)
    // The background's own fields last: a frame doesn't get to say them.
    const line = bounded({ ...step, event: "step", seq: a.steps, frameId: sender.frameId ?? 0, sameSite }) as Record<string, unknown>
    // Too big: the inputs go first, the rest of the step stays.
    if (JSON.stringify(line).length > MAX_LINE) line.inputs = (line.inputs as unknown[]).filter((i) => (i as { typed?: unknown }).typed)
    return (await this.write(a, line)) ? true : false
  }

  /**
   * A frame's batch of its timeline and the digests of words typed since:
   * each event checked and bounded, then logged in batches. Answers "full"
   * when this frame's share is used up; the recording goes on.
   */
  async events(sender: chrome.runtime.MessageSender, session: string, events: unknown, words?: unknown): Promise<LearnTaken> {
    await this.ready
    const tabId = sender.tab?.id
    const a = tabId === undefined ? undefined : this.tabs.get(tabId)
    if (!a || a.id !== session || Date.now() >= a.until || !Array.isArray(events)) return false
    if (Array.isArray(words)) for (const w of words.slice(0, 50)) if (typeof w === "string" && /^[0-9a-f]{64}$/.test(w) && a.words.size < MAX_WORDS) a.words.add(w)
    const frameId = sender.frameId ?? 0
    const sameSite = this.sameSite(sender, a)
    // Each cross-site origin's share; past 50 origins, the rest share one.
    const origin = String(sender.origin ?? "")
    const share = Object.hasOwn(a.byOrigin, origin) || Object.keys(a.byOrigin).length < 50 ? origin : "*"
    let full = false
    for (const raw of events.slice(0, 200)) {
      const dropped = num((raw as { dropped?: unknown } | null)?.dropped)
      if (dropped) a.dropped += Math.max(0, Math.min(10_000, dropped))
      const e = timelineEvent(raw)
      if (!e) continue
      if (a.events >= MAX_EVENTS || (!sameSite && (a.crossEvents >= MAX_CROSS_EVENTS || (a.byOrigin[share] ?? 0) >= MAX_ORIGIN_EVENTS))) {
        a.dropped++
        full = true
        continue
      }
      if (!sameSite) {
        a.crossEvents++
        a.byOrigin[share] = (a.byOrigin[share] ?? 0) + 1
      }
      // The user did something: the recording isn't idle. A page can focus and scroll on its own.
      if (INPUT.has(e.type)) a.lastInput = Date.now()
      this.add(tabId!, a, { ...e, frameId, sameSite })
    }
    return full ? "full" : true
  }

  /**
   * A page or frame of a recording tab committed, or its address changed in
   * place. A top page the user took to another site themselves (the address
   * bar, a bookmark) ends the recording; links and redirects, a provider's
   * sign-in among them, don't.
   */
  navigated(d: { tabId: number; frameId: number; url: string; transitionType?: string; transitionQualifiers?: string[] }) {
    const a = this.tabs.get(d.tabId)
    if (!a) return
    let url: URL
    try {
      url = new URL(d.url)
    } catch {
      return
    }
    if (d.frameId === 0) {
      const site = siteOf(url.hostname) ?? url.hostname
      // Back or forward is by hand too, whatever took the entry there first.
      const byHand = BY_HAND.has(d.transitionType ?? "") || !!d.transitionQualifiers?.some((q) => q === "from_address_bar" || q === "forward_back")
      if (site !== a.top && byHand) return void this.stop(d.tabId, "left")
      a.top = site
      this.badge(d.tabId)
    }
    this.add(d.tabId, a, { t: Date.now() - a.startedAt, type: "navigate", frameId: d.frameId, url, ...(d.transitionType ? { transition: d.transitionType } : {}) })
  }

  /** A recording tab opened a window or tab (a provider's sign-in, usually). */
  opened(d: { sourceTabId: number; sourceFrameId: number; url: string }) {
    const a = this.tabs.get(d.sourceTabId)
    if (!a) return
    let url: URL
    try {
      url = new URL(d.url)
    } catch {
      return
    }
    this.add(d.sourceTabId, a, { t: Date.now() - a.startedAt, type: "popup", frameId: d.sourceFrameId, url })
  }

  /** The save judge saw a sign-in work in the tab: a mark on the timeline. */
  async signedIn(tabId: number, site: string) {
    await this.ready
    const a = this.tabs.get(tabId)
    if (a && a.site === site) this.add(tabId, a, { t: Date.now() - a.startedAt, type: "signed-in" })
  }

  async stop(tabId: number, reason: LearnEnd): Promise<LearnReply> {
    await this.ready
    const a = this.tabs.get(tabId)
    if (!a) return { ok: true }
    this.tabs.delete(tabId)
    void this.forget(tabId)
    clearTimeout(a.timer)
    clearTimeout(a.idle)
    clearTimeout(a.flushing)
    this.flush(a)
    await this.write(a, { event: "end", reason, steps: a.steps, events: a.events, ...(a.dropped ? { dropped: a.dropped } : {}), durationMs: Date.now() - a.startedAt })
    if (reason !== "closed") {
      void this.broadcast(tabId, null)
      this.badge(tabId)
      const d: Done = { session: a.id, host: a.host, steps: a.events }
      this.done.set(tabId, d)
      void chrome.storage.session.set({ [DONE + tabId]: d }).catch(() => {})
    }
    return { ok: true }
  }

  /** The tab's finished recording: its log, as Settings downloads one; deleted; or put away. Download keeps it, and the note, for Delete after. */
  async recorded(tabId: number, action: "download" | "delete" | "dismiss"): Promise<RecordedReply> {
    await this.ready
    const d = this.done.get(tabId)
    if (!d) return { ok: false, message: "That recording is gone." }
    if (action === "dismiss") return this.dismiss(tabId).then(() => ({ ok: true }))
    await this.host.reconnectNow()
    if (!this.host.capabilities.includes("learn-files"))
      return { ok: false, message: "This Deadbolt can't hand recordings back. Update Deadbolt; meanwhile it's in ~/.local/state/deadbolt/learn." }
    try {
      if (action === "delete") {
        await this.host.send({ type: "learn-delete", session: d.session })
        await this.dismiss(tabId)
        return { ok: true }
      }
      let text = ""
      let offset: number | null = 0
      while (offset !== null && text.length < 8 * 1024 * 1024) {
        const part: { text: string; next: number | null } = await this.host.send({ type: "learn-read", session: d.session, offset })
        text += part.text
        offset = part.next
      }
      const lines = text.split("\n").filter(Boolean)
      return { ok: true, text: learnExport([{ session: d.session, updated: 0, bytes: text.length, lines }]) }
    } catch (err) {
      return { ok: false, message: (err as Error).message || "Deadbolt couldn't read the recording." }
    }
  }

  forgetTab(tabId: number) {
    void this.stop(tabId, "closed")
    this.done.delete(tabId)
    void chrome.storage.session.remove(DONE + tabId).catch(() => {})
  }

  /** The tab's toolbar badge: REC while it records, else `under` (what an offer or prompt wants), or whatever was under it. */
  badge(tabId: number, under?: string) {
    const text = this.tabs.has(tabId) ? "REC" : (under ?? this.badgeUnder(tabId))
    void Promise.all([chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE }), chrome.action.setBadgeText({ tabId, text })]).catch(() => {})
  }

  /** Whether the tab is recording, for the other badges to leave REC alone. */
  recording(tabId: number) {
    return this.tabs.has(tabId)
  }

  private session(a: Active): LearnSession {
    return { id: a.id, salt: a.salt, startedAt: a.startedAt, until: a.until, words: [...a.words] }
  }

  /** No input for IDLE_MS ends the recording; input since puts it off. */
  private idle(tabId: number) {
    const a = this.tabs.get(tabId)
    if (!a) return
    const left = a.lastInput + IDLE_MS - Date.now()
    if (left <= 0) return void this.stop(tabId, "idle")
    a.idle = setTimeout(() => this.idle(tabId), left)
    void this.save(tabId, a)
  }

  /** From where Chrome says the frame is, not where the frame says it is. */
  private sameSite(sender: chrome.runtime.MessageSender, a: Active): boolean {
    try {
      return siteOf(new URL(String(sender.origin ?? sender.url)).hostname) === a.site
    } catch {
      return false
    }
  }

  private add(tabId: number, a: Active, e: TimelineEvent & { url?: URL }) {
    if (a.events >= MAX_EVENTS) {
      a.dropped++
      return
    }
    a.events++
    a.pending.push(e)
    if (a.pending.length >= FLUSH_EVENTS) this.flush(a)
    else a.flushing ??= setTimeout(() => this.flush(a), FLUSH_MS)
    if (a.events % 25 === 0) void this.save(tabId, a)
  }

  /**
   * The waiting timeline events as lines, each under the host's limit. A
   * navigation's address is scrubbed as the line is written, of the words
   * typed by then (a search's digests come with the Enter that sends it).
   */
  private flush(a: Active) {
    clearTimeout(a.flushing)
    a.flushing = undefined
    const waiting = a.pending.splice(0)
    if (!waiting.length) return
    const words = { salt: a.salt, digests: a.words }
    const lines = (async () => {
      const events: TimelineEvent[] = []
      for (const { url, ...e } of waiting) events.push(url ? { ...e, frame: await frameOf(url, e.type === "popup" || e.frameId === 0, 0, [], words) } : e)
      const out: Array<Record<string, unknown>> = []
      let batch: TimelineEvent[] = []
      let size = 0
      for (const e of events) {
        const n = JSON.stringify(e).length + 1
        if (size + n > MAX_LINE - 100 && batch.length) {
          out.push({ event: "timeline", events: batch })
          batch = []
          size = 0
        }
        batch.push(e)
        size += n
      }
      if (batch.length) out.push({ event: "timeline", events: batch })
      return out
    })()
    void this.write(a, lines)
  }

  /** Takes back the recordings a previous service worker kept; one past its time, or idle, ends now. */
  private async restore() {
    const all = (await chrome.storage.session.get(null).catch(() => ({}))) as Record<string, unknown>
    const now = Date.now()
    for (const [key, value] of Object.entries(all)) {
      if (key.startsWith(DONE)) {
        const tabId = Number(key.slice(DONE.length))
        const d = value as Done | undefined
        if (Number.isInteger(tabId) && d && typeof d.session === "string" && typeof d.host === "string") this.done.set(tabId, { session: d.session, host: d.host, steps: Number(d.steps) || 0 })
        continue
      }
      const tabId = Number(key.slice(PREFIX.length))
      const s = value as Stored | undefined
      if (!key.startsWith(PREFIX) || !Number.isInteger(tabId) || this.tabs.has(tabId)) continue
      if (!s || typeof s.id !== "string" || typeof s.salt !== "string" || typeof s.until !== "number" || !Array.isArray(s.usernames)) {
        void this.forget(tabId)
        continue
      }
      const lastInput = typeof s.lastInput === "number" ? s.lastInput : now
      const a: Active = {
        ...s,
        host: typeof s.host === "string" ? s.host : s.site,
        events: Number(s.events) || 0,
        crossSteps: Number(s.crossSteps) || 0,
        crossEvents: Number(s.crossEvents) || 0,
        byOrigin: s.byOrigin && typeof s.byOrigin === "object" ? { ...s.byOrigin } : {},
        top: typeof s.top === "string" ? s.top : s.site,
        lastInput,
        usernames: new Set(s.usernames),
        words: new Set(Array.isArray(s.words) ? s.words.filter((w) => typeof w === "string").slice(0, MAX_WORDS) : []),
        timer: setTimeout(() => void this.stop(tabId, "timeout"), Math.max(0, s.until - now)),
        idle: setTimeout(() => this.idle(tabId), Math.max(0, lastInput + IDLE_MS - now)),
        writes: Promise.resolve(),
        pending: [],
        dropped: 0,
      }
      this.tabs.set(tabId, a)
    }
  }

  private async dismiss(tabId: number) {
    this.done.delete(tabId)
    await chrome.storage.session.remove(DONE + tabId).catch(() => {})
  }

  private save(tabId: number, a: Active): Promise<void> {
    const stored: Stored = {
      id: a.id,
      site: a.site,
      host: a.host,
      salt: a.salt,
      startedAt: a.startedAt,
      until: a.until,
      steps: a.steps,
      events: a.events,
      crossSteps: a.crossSteps,
      crossEvents: a.crossEvents,
      byOrigin: a.byOrigin,
      top: a.top,
      lastInput: a.lastInput,
      usernames: [...a.usernames],
      words: [...a.words],
    }
    return chrome.storage.session.set({ [PREFIX + tabId]: stored }).catch(() => {})
  }

  private forget(tabId: number): Promise<void> {
    return chrome.storage.session.remove(PREFIX + tabId).catch(() => {})
  }

  /** Every frame of the tab. */
  private async broadcast(tabId: number, session: LearnSession | null) {
    await chrome.tabs.sendMessage(tabId, { type: "db:learn", session }).catch(() => {})
  }

  /** Writes `line`, or the lines it comes to, after every line before it. */
  private write(a: Active, line: Record<string, unknown> | Promise<Array<Record<string, unknown>>>): Promise<boolean> {
    const done = a.writes.then(async () => {
      let ok = true
      for (const l of line instanceof Promise ? await line : [line]) ok = (await this.host.send({ type: "learn", session: a.id, line: l }).then(() => true, () => false)) && ok
      return ok
    })
    a.writes = done.then(() => {})
    return done
  }
}
