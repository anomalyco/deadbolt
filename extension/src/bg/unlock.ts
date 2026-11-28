// Unlocking from the locked menu in one click. "Unlock Deadbolt" asks
// `deadbolt browser-host` for Touch ID, or, when that can't unlock it, to
// bring Deadbolt's own window forward for the passphrase. The passphrase is
// never typed in the browser: a passphrase box beside a page's own fields is
// what a phishing page copies. The menu stays open meanwhile, and once the
// vault is ready it lists the site's logins in place (Autofill.resumeUnlock).

import type { UnlockReply } from "../messages"
import { HostError, type VaultBackend } from "./backend"

/** How long the menu waits for the vault to unlock (the passphrase, typed in Deadbolt's window) before it stops waiting. */
export const UNLOCK_WAIT_MS = 2 * 60_000
/** Touch ID's prompt waits on the user; the host answers once it's done. */
const PROMPT_TIMEOUT_MS = 90_000

/** The open menu that asked to unlock: the tab and frame it's in, and its token. */
export interface PendingUnlock {
  tabId: number
  frameId: number
  token: string
  at: number
}

export class Unlocker {
  /** The menu waiting on the unlock it asked for; the latest ask wins. */
  pending: PendingUnlock | null = null

  constructor(
    private host: VaultBackend,
    /** The vault is ready for the menu that asked: it lists the site's logins. */
    private resume: (pending: PendingUnlock) => Promise<void>,
  ) {
    host.onChange((status) => {
      const p = this.pending
      // Still locked: the user is at Touch ID or in Deadbolt's window.
      if (!p || status.state === "locked" || status.state === "connecting") return
      this.pending = null
      if (status.state === "ready" && Date.now() - p.at <= UNLOCK_WAIT_MS) void this.resume(p)
    })
  }

  /** Asks the host to unlock for the menu `target`, which then waits for the vault (see the constructor). */
  async prompt(target: Omit<PendingUnlock, "at">): Promise<UnlockReply> {
    if (!this.host.capabilities.includes("unlock-prompt")) return { ok: false, message: "Unlock Deadbolt in its app, then come back." }
    this.pending = { ...target, at: Date.now() }
    try {
      const reply = await this.host.send({ type: "unlock-prompt" }, { timeout: PROMPT_TIMEOUT_MS })
      return { ok: true, app: reply.app }
    } catch (err) {
      if (this.pending?.token === target.token) this.pending = null
      if (err instanceof HostError && err.code === "cancelled") return { ok: false, message: "Touch ID was cancelled." }
      return { ok: false, message: "Couldn't unlock here. Open Deadbolt to unlock it." }
    }
  }
}
