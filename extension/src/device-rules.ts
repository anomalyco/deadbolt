// Rules the browser-only Deadbolt's background and its pages share: the lock
// presets (docs/extension-device.md) and what a vault's name may be.

import type { LockedBy, LockPreset } from "./messages"

/**
 * How long without use before the vault locks (never, for "until-quit"),
 * whether the screen locking locks it, and whether showing or copying a
 * password asks for the passphrase or platform verification again. Every
 * preset locks when the browser quits. Every preset keeps keys only in worker
 * memory, and locks if the worker or its offscreen owner is lost. No key goes
 * in storage.session. Changing to "until-quit" takes the passphrase or Touch ID.
 */
export const PRESETS: Record<LockPreset, { name: string; idleMs: number; screenLock: boolean; reauth: boolean }> = {
  strict: { name: "Strict", idleMs: 5 * 60_000, screenLock: true, reauth: true },
  comfortable: { name: "Comfortable", idleMs: 60 * 60_000, screenLock: true, reauth: false },
  relaxed: { name: "Relaxed", idleMs: 12 * 60 * 60_000, screenLock: false, reauth: false },
  "until-quit": { name: "Until you quit the browser", idleMs: Infinity, screenLock: false, reauth: false },
}
/** The stricter of two presets: the one listed first in PRESETS. */
export function stricter(a: LockPreset, b: LockPreset): LockPreset {
  const order = Object.keys(PRESETS)
  return order.indexOf(a) <= order.indexOf(b) ? a : b
}
/** Whether changing from `from` to `to` takes the passphrase or Touch ID first, as the vault's worker checks (crates/ext-core/src/policy.rs). */
export const changeNeedsProof = (from: LockPreset, to: LockPreset) => to === "until-quit" && from !== "until-quit"
export const DEFAULT_PRESET: LockPreset = "comfortable"
export const isPreset = (v: unknown): v is LockPreset => typeof v === "string" && Object.hasOwn(PRESETS, v)

/** "5 minutes", "1 hour", "12 hours". */
export function duration(ms: number): string {
  const minutes = Math.round(ms / 60_000)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`
  const hours = Math.round(minutes / 60)
  return `${hours} hour${hours === 1 ? "" : "s"}`
}

/** How to quit the browser here: ⌘Q on a Mac. Elsewhere Ctrl+Q doesn't quit Chrome. */
export function quitKeys(nav: { platform?: string; userAgentData?: { platform?: string } } = globalThis.navigator ?? {}): string {
  const platform = nav.userAgentData?.platform || nav.platform || ""
  return /mac/i.test(platform) ? "⌘Q" : "close every window, or Ctrl+Shift+Q on Linux"
}

/** A preset in one line, from what it does: "Locks after 5 minutes idle and when the screen locks. …" */
export function describePreset(preset: LockPreset, quit = quitKeys()): string {
  const p = PRESETS[preset]
  if (!Number.isFinite(p.idleMs)) return `Stays unlocked, even through sleep and screen lock, until you quit the browser (${quit}). Anyone using this computer can see and fill your passwords, cards and codes meanwhile.`
  const idle = `Locks after ${duration(p.idleMs)} idle`
  const screen = p.screenLock ? `${idle} and when the screen locks.` : `${idle}. Stays unlocked when the screen locks.`
  return p.reauth ? `${screen} Asks for your passphrase to show or copy a password.` : screen
}

/** "Locked · 12 h idle": why the vault last locked, in a few words, for the locked popup. */
export function lockedLine(by: LockedBy): string {
  const why = {
    idle: by.idleMs && Number.isFinite(by.idleMs) ? `${short(by.idleMs)} idle` : "idle",
    screen: "screen locked",
    quit: "browser restarted",
    worker: "vault worker stopped",
    offscreen: "browser closed the vault's page",
    manual: "you locked it",
    update: "extension updated",
    changed: "lock setting changed",
    removed: "removed from vault",
  }[by.reason]
  return `Locked · ${why}`
}

/** "5 min", "1 h", "12 h". */
function short(ms: number): string {
  const minutes = Math.round(ms / 60_000)
  return minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} h`
}

const REASONS = new Set<string>(["idle", "screen", "quit", "worker", "offscreen", "manual", "update", "changed", "removed"])
/** A LockedBy read back from storage or a reply, or null. */
export function isLockedBy(v: unknown): v is LockedBy {
  const by = v as LockedBy | null
  return typeof by === "object" && by !== null && REASONS.has(by.reason) && (by.idleMs === undefined || typeof by.idleMs === "number")
}

/** A vault's name: as the core's valid_name has it. */
export const VAULT_NAME = /^[a-z][a-z0-9_-]{0,63}$/
