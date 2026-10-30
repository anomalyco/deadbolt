// Rules the browser-only Deadbolt's background and its pages share: the lock
// presets (docs/extension-device.md) and what a vault's name may be.

import type { LockPreset } from "./messages"

/**
 * How long without use before the vault locks, whether the screen locking
 * locks it, and whether showing or copying a password asks for the
 * passphrase or platform verification again. Every preset locks when the
 * browser quits. Every preset keeps keys only in worker memory, and locks
 * if the worker or its offscreen owner is lost. No key goes in storage.session.
 */
export const PRESETS: Record<LockPreset, { name: string; idleMs: number; screenLock: boolean; reauth: boolean }> = {
  strict: { name: "Strict", idleMs: 5 * 60_000, screenLock: true, reauth: true },
  comfortable: { name: "Comfortable", idleMs: 60 * 60_000, screenLock: true, reauth: false },
  relaxed: { name: "Relaxed", idleMs: 12 * 60 * 60_000, screenLock: false, reauth: false },
}
export const DEFAULT_PRESET: LockPreset = "comfortable"
export const isPreset = (v: unknown): v is LockPreset => typeof v === "string" && Object.hasOwn(PRESETS, v)

/** "5 minutes", "1 hour", "12 hours". */
export function duration(ms: number): string {
  const minutes = Math.round(ms / 60_000)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`
  const hours = Math.round(minutes / 60)
  return `${hours} hour${hours === 1 ? "" : "s"}`
}

/** A preset in one line, from what it does: "Locks after 5 minutes idle and when the screen locks. …" */
export function describePreset(preset: LockPreset): string {
  const p = PRESETS[preset]
  const idle = `Locks after ${duration(p.idleMs)} idle`
  const screen = p.screenLock ? `${idle} and when the screen locks.` : `${idle}. Stays unlocked when the screen locks.`
  return p.reauth ? `${screen} Asks for your passphrase to show or copy a password.` : screen
}

/** A vault's name: as the core's valid_name has it. */
export const VAULT_NAME = /^[a-z][a-z0-9_-]{0,63}$/
