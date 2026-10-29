// Background side of "Learn this site" (see src/learn.ts): one session per
// tab, started and stopped from the popup. It hands every frame of the tab the
// session's id and salt, turns each frame's steps into log lines (deciding
// from the salted digest whether a typed value was a saved username, then
// dropping the digest), and has the native host append them, in order, to the
// session's log. A session ends when the user stops it, a few seconds after a
// sign-in the save judge saw work, after LEARN_TTL_MS, or with its tab.

import { LEARN_TTL_MS, MAX_INPUTS, MAX_STEPS, truthOf, usernameDigest, type LearnEnd, type LearnSession, type LearnStep } from "../learn"
import type { LearnReply, Learning } from "../messages"
import { topTarget } from "./frames"
import type { Host } from "./host"
import { siteOf } from "./site"

/** After a sign-in works, the page it lands on is recorded too, then the session ends. */
const AFTER_SIGN_IN_MS = 2500
/** A line the host takes, well under its 64 KiB request limit. */
const MAX_LINE = 56 * 1024

interface Active {
  id: string
  site: string
  salt: string
  startedAt: number
  until: number
  steps: number
  /** Salted digests of the saved usernames for the site. */
  usernames: Set<string>
  timer: ReturnType<typeof setTimeout>
  /** Lines are written one after another, in order. */
  writes: Promise<void>
  ending?: ReturnType<typeof setTimeout>
}

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

export class Learner {
  private tabs = new Map<number, Active>()

  constructor(private host: Host) {}

  /** What the popup shows for the tab. */
  status(tabId: number): Learning | undefined {
    const a = this.tabs.get(tabId)
    return a ? { site: a.site, steps: a.steps, until: a.until } : undefined
  }

  async start(tabId: number): Promise<LearnReply> {
    const { target, url } = await topTarget(tabId)
    const site = url && siteOf(url.hostname)
    if (!target || !url || !site) return { ok: false, message: "Deadbolt learns sites only on https pages and local dev hosts." }
    await this.host.reconnectNow()
    if (!this.host.capabilities.includes("learn")) return { ok: false, message: "This Deadbolt can't keep a learning log. Update Deadbolt, then try again." }
    if (this.tabs.has(tabId)) await this.stop(tabId, "replaced")

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
      salt,
      startedAt: now,
      until: now + LEARN_TTL_MS,
      steps: 0,
      usernames,
      timer: setTimeout(() => void this.stop(tabId, "timeout"), LEARN_TTL_MS),
      writes: Promise.resolve(),
    }
    this.tabs.set(tabId, a)
    const started = await this.write(a, {
      event: "start",
      site,
      origin: url.origin,
      path: url.pathname.slice(0, 200),
      at: new Date(now).toISOString(),
      extension: chrome.runtime.getManifest?.().version ?? "",
      savedLogins: saved,
    })
    if (!started) {
      clearTimeout(a.timer)
      this.tabs.delete(tabId)
      return { ok: false, message: "Deadbolt couldn't start the learning log." }
    }
    void this.broadcast(tabId, { id: a.id, salt, until: a.until })
    return { ok: true, learning: this.status(tabId) }
  }

  /** For a frame that just loaded: the session it joins, if its tab is learning. */
  ask(sender: chrome.runtime.MessageSender): LearnSession | null {
    const a = sender.tab?.id === undefined ? undefined : this.tabs.get(sender.tab.id)
    return a && Date.now() < a.until ? { id: a.id, salt: a.salt, until: a.until } : null
  }

  async step(sender: chrome.runtime.MessageSender, session: string, step: LearnStep): Promise<boolean> {
    const tabId = sender.tab?.id
    const a = tabId === undefined ? undefined : this.tabs.get(tabId)
    if (!a || a.id !== session || Date.now() >= a.until || a.steps >= MAX_STEPS || typeof step !== "object" || step === null) return false
    const inputs = Array.isArray(step.inputs) ? step.inputs : []
    for (const input of inputs) {
      const typed = input?.typed
      if (!typed || typeof typed !== "object") continue
      typed.savedUsername = typeof typed.digest === "string" && a.usernames.has(typed.digest)
      delete typed.digest
      typed.truth = truthOf(typed)
    }
    let frameSite: string | null = null
    try {
      frameSite = siteOf(new URL(String(step.frame?.origin)).hostname)
    } catch {
      frameSite = null
    }
    a.steps++
    const line = bounded({ event: "step", seq: a.steps, frameId: sender.frameId ?? 0, sameSite: frameSite === a.site, ...step }) as Record<string, unknown>
    // Too big: the inputs go first, the rest of the step stays.
    if (JSON.stringify(line).length > MAX_LINE) line.inputs = (line.inputs as unknown[]).filter((i) => (i as { typed?: unknown }).typed)
    return this.write(a, line)
  }

  /** The save judge saw a sign-in work in the tab: record where it lands, then end. */
  signedIn(tabId: number, site: string) {
    const a = this.tabs.get(tabId)
    if (!a || a.site !== site || a.ending) return
    a.ending = setTimeout(() => void this.stop(tabId, "signed-in"), AFTER_SIGN_IN_MS)
  }

  async stop(tabId: number, reason: LearnEnd): Promise<LearnReply> {
    const a = this.tabs.get(tabId)
    if (!a) return { ok: true }
    this.tabs.delete(tabId)
    clearTimeout(a.timer)
    clearTimeout(a.ending)
    await this.write(a, { event: "end", reason, steps: a.steps, durationMs: Date.now() - a.startedAt })
    if (reason !== "closed") void this.broadcast(tabId, null)
    return { ok: true }
  }

  forgetTab(tabId: number) {
    void this.stop(tabId, "closed")
  }

  /** Every frame of the tab. */
  private async broadcast(tabId: number, session: LearnSession | null) {
    await chrome.tabs.sendMessage(tabId, { type: "db:learn", session }).catch(() => {})
  }

  private write(a: Active, line: Record<string, unknown>): Promise<boolean> {
    const done = a.writes.then(() =>
      this.host.send({ type: "learn", session: a.id, line }).then(
        () => true,
        () => false,
      ),
    )
    a.writes = done.then(() => {})
    return done
  }
}
