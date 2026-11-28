// Background side of learned forms (content/recipe.ts): the recipes a
// frame's page has, a recipe the user teaches by filling a form by hand, and
// "Reset learned form" in the popup. The daemon keeps each recipe on its
// login and checks it there (crates/core/src/site_recipe.rs): only a login
// of the page's own site, only a recipe for the page's exact origin.

import type { ListReply } from "../protocol"
import type { VaultBackend } from "./backend"
import { sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"

/** How long a taught recipe waits for its fill, and a fill for its recipe. */
const PAIR_MS = 2 * 60_000
const MAX_RECIPE = 512

const keyOf = (t: FrameTarget) => `${t.tabId}:${t.frameId}:${t.documentId}`

/** The origin a recipe says it's for, if it reads as one at all (the daemon checks the rest). */
function recipeOrigin(recipe: unknown): string | null {
  if (typeof recipe !== "string" || !recipe || recipe.length > MAX_RECIPE) return null
  try {
    const v = JSON.parse(recipe) as { origin?: unknown }
    return typeof v?.origin === "string" ? v.origin : null
  } catch {
    return null
  }
}

interface Pending {
  target: FrameTarget
  recipe?: { json: string; form: number; at: number }
  fill?: { ref: string; form: number; at: number }
}

export class Recipes {
  /** Per document: the recipe its manual fields made and the login a pick filled them with, until both are in. */
  private pending = new Map<string, Pending>()

  constructor(
    private host: VaultBackend,
    /** The logins of an origin (Autofill.list): each carries its recipe for that exact origin. */
    private list: (origin: string, fresh?: boolean) => Promise<ListReply>,
  ) {}

  /** Whether the host keeps recipes: an older one never lists or saves them. */
  private get on() {
    return this.host.capabilities.includes("site-recipe")
  }

  /**
   * The recipes for the asking frame's exact origin, from its logins; null
   * when they can't be read now (locked, not connected), so it asks later.
   */
  async forFrame(sender: chrome.runtime.MessageSender): Promise<string[] | null> {
    const target = await targetFor(sender)
    if (!target) return []
    if (this.host.status.state !== "ready") return null
    if (!this.on) return []
    const reply = await this.list(target.origin).catch(() => null)
    if (!reply) return null
    return [...new Set(reply.accounts.flatMap((a) => (a.recipe ? [a.recipe] : [])))]
  }

  /**
   * A frame's content script made `recipe` from the fields the user just
   * asked Deadbolt to fill by hand (form snapshot `form`). It's saved once a
   * pick fills that form with a login (see filled), on that login.
   */
  async learned(sender: chrome.runtime.MessageSender, recipe: unknown, form: unknown) {
    const target = await targetFor(sender)
    if (!target || !this.on || recipeOrigin(recipe) !== target.origin || !Number.isSafeInteger(form)) return
    const p = this.entry(target)
    p.recipe = { json: recipe as string, form: form as number, at: Date.now() }
    await this.commit(p)
  }

  /** A pick filled form `form` in `target` with login `ref` (Autofill.fillAndArm). */
  async filled(target: FrameTarget, ref: string, form: number) {
    const p = this.pending.get(keyOf(target))
    if (!p?.recipe) return
    p.fill = { ref, form, at: Date.now() }
    await this.commit(p)
  }

  private entry(target: FrameTarget): Pending {
    const now = Date.now()
    for (const [k, p] of this.pending) if (Math.max(p.recipe?.at ?? 0, p.fill?.at ?? 0) < now - PAIR_MS) this.pending.delete(k)
    const key = keyOf(target)
    let p = this.pending.get(key)
    if (!p) this.pending.set(key, (p = { target }))
    return p
  }

  /** Saves the recipe on the login, once both are in, for the same form and lately. */
  private async commit(p: Pending) {
    const { recipe, fill, target } = p
    if (!recipe || !fill || recipe.form !== fill.form || Math.abs(recipe.at - fill.at) > PAIR_MS) return
    this.pending.delete(keyOf(target))
    await this.host.send({ type: "save-recipe", origin: target.origin, ref: fill.ref, recipe: recipe.json }).catch(() => {})
  }

  /**
   * "Reset learned form" in the popup: every login of the tab's top page
   * forgets the form it was taught there, and the page stops using it.
   * Whether any did.
   */
  async reset(tabId: number): Promise<boolean> {
    const { target } = await topTarget(tabId)
    if (!target || !this.on || this.host.status.state !== "ready") return false
    const reply = await this.list(target.origin, true).catch(() => null)
    const taught = reply?.accounts.filter((a) => a.recipe) ?? []
    for (const a of taught) await this.host.send({ type: "save-recipe", origin: target.origin, ref: a.ref }).catch(() => {})
    this.pending.delete(keyOf(target))
    await sendToFrame(target, { type: "db:recipes-set", recipes: [] })
    return taught.length > 0
  }

  forgetTab(tabId: number) {
    for (const [k, p] of this.pending) if (p.target.tabId === tabId) this.pending.delete(k)
  }
}
