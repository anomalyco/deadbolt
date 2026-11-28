// Background side of learned forms (content/recipe.ts): the recipes a
// page has, a recipe the user teaches by filling a form by hand, and "Reset
// learned form" in the popup. The daemon keeps each recipe on its login and
// checks it there (crates/core/src/site/recipe.rs): only a login of the
// page's own site, only a recipe for the page's exact origin.
//
// Only a top page is taught, and only right after the browser itself raised
// one of the fill doors in that tab (bg/doors.ts: the shortcut or "Fill with
// Deadbolt", which no page can raise): a content script's word alone never
// saves a recipe.

import type { ListReply } from "../protocol"
import type { VaultBackend } from "./backend"
import { sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"

/** How long a fill door the browser raised lets its tab teach a form. */
export const DOOR_MS = 10_000
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
  /** When the browser last raised a fill door in each tab's top page. */
  private doors = new Map<number, number>()

  constructor(
    private host: VaultBackend,
    /** The logins of an origin (Autofill.list): each carries its recipe for that exact origin. */
    private list: (origin: string, fresh?: boolean) => Promise<ListReply>,
    /** Drops the cached logins of an origin (Autofill.forgetList), once one of them changed. */
    private forgetList: (origin: string) => void = () => {},
  ) {}

  /** Whether the host keeps recipes: an older one never lists or saves them. */
  private get on() {
    return this.host.capabilities.includes("site-recipe")
  }

  /**
   * The browser raised a fill door in `tabId` (bg/doors.ts), for frame
   * `frameId` (the context menu's) or whichever has focus (the shortcut's,
   * undefined). Only the top page is taught.
   */
  allow(tabId: number, frameId?: number) {
    if (frameId === undefined || frameId === 0) this.doors.set(tabId, Date.now())
  }

  /** Whether `target` may be taught a form now: a top page whose tab the browser just raised a fill door in. */
  allowed(target: FrameTarget): boolean {
    const at = this.doors.get(target.tabId)
    return this.on && target.frameId === 0 && at !== undefined && Date.now() - at <= DOOR_MS
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
    return this.recipesOf(target.origin)
  }

  private async recipesOf(origin: string, fresh = false): Promise<string[] | null> {
    const reply = await this.list(origin, fresh).catch(() => null)
    if (!reply) return null
    return [...new Set(reply.accounts.flatMap((a) => (a.recipe ? [a.recipe] : [])))]
  }

  /**
   * A top page's content script made `recipe` from the fields the user just
   * asked Deadbolt to fill by hand (form snapshot `form`). Kept only right
   * after the browser raised a fill door there (see allow), and saved once a
   * pick on that menu fills that form with a login (see filled), on that login.
   */
  async learned(sender: chrome.runtime.MessageSender, recipe: unknown, form: unknown) {
    const target = await targetFor(sender)
    if (!target || !this.allowed(target) || recipeOrigin(recipe) !== target.origin || !Number.isSafeInteger(form)) return
    const p = this.entry(target)
    p.recipe = { json: recipe as string, form: form as number, at: Date.now() }
    await this.commit(p)
  }

  /** A pick in a teaching menu (Autofill.menuPick) filled form `form` in `target` with login `ref`. */
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

  /**
   * Saves the recipe on the login, once both are in, for the same form and
   * lately; then the page hears its recipes, so a single-page app that comes
   * back to this form finds it without a reload.
   */
  private async commit(p: Pending) {
    const { recipe, fill, target } = p
    if (!recipe || !fill || recipe.form !== fill.form || Math.abs(recipe.at - fill.at) > PAIR_MS) return
    this.pending.delete(keyOf(target))
    const saved = await this.host.send({ type: "save-recipe", origin: target.origin, ref: fill.ref, recipe: recipe.json }).then(() => true, () => false)
    if (!saved) return
    this.forgetList(target.origin)
    const recipes = await this.recipesOf(target.origin, true)
    if (recipes) await sendToFrame(target, { type: "db:recipes-set", recipes })
  }

  /**
   * "Reset learned form" in the popup: every login of the tab's top page
   * forgets the form it was taught there, and the page stops using it.
   * Whether any did.
   */
  async reset(tabId: number): Promise<boolean> {
    const { target } = await topTarget(tabId)
    if (!target || !this.on || this.host.status.state !== "ready") return false
    this.forgetTab(tabId)
    const reply = await this.list(target.origin, true).catch(() => null)
    const taught = reply?.accounts.filter((a) => a.recipe) ?? []
    let cleared = 0
    for (const a of taught) if (await this.host.send({ type: "save-recipe", origin: target.origin, ref: a.ref }).then(() => true, () => false)) cleared++
    this.forgetList(target.origin)
    const recipes = await this.recipesOf(target.origin, true)
    await sendToFrame(target, { type: "db:recipes-set", recipes: recipes ?? [] })
    return cleared > 0
  }

  forgetTab(tabId: number) {
    this.doors.delete(tabId)
    for (const [k, p] of this.pending) if (p.target.tabId === tabId) this.pending.delete(k)
  }
}
