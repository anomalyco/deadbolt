// A learned form (a SiteRecipe, see crates/core/src/site_recipe.rs): where a
// login's fields are on one page, for a form the scan passed over. The user
// teaches one by asking Deadbolt to fill a field the scan didn't take (the
// fill shortcut or "Fill with Deadbolt", see content/manual.ts) and picking a
// login; it's kept on that login in the vault and syncs with it.
//
// A recipe is the form's shape only: never a value. It locates each field by
// its place among its cluster's controls (see content/graph.ts) and the
// cluster by its fingerprint, so a page whose form changed shape gets
// nothing from it (stale): the scan decides there as it would anyway, and no
// field is filled by a stale guess.

import type { FormCluster, FormGraph } from "./graph"
import { concealed, ignored } from "./graph"
import { masked } from "./detect"
import type { FieldRole } from "../messages"

/** The most a recipe's JSON may be, as the daemon checks it. */
export const MAX_RECIPE_BYTES = 512
const MAX_SLOTS = 4
const MAX_PATH = 128
const MAX_TOKEN = 64
const MAX_NTH = 300

export type RecipeRole = "username" | "email" | "phone" | "password" | "new-password" | "otp"
const ROLES: RecipeRole[] = ["username", "email", "phone", "password", "new-password", "otp"]
const SECRET_ROLES: RecipeRole[] = ["password", "new-password"]

export interface RecipeSlot {
  role: RecipeRole
  id?: string
  name?: string
  autocomplete?: string
  nthInput: number
}

export interface SiteRecipe {
  v: 1
  origin: string
  pathPattern: string
  clusterFingerprint: string
  slots: RecipeSlot[]
}

/** A field a recipe locates, or a recipe is built from. */
export interface RecipeField {
  el: HTMLInputElement
  role: FieldRole
}

const encoder = new TextEncoder()
const bytes = (text: string) => encoder.encode(text).length
const token = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TOKEN && !/[\s\p{Cc}]/u.test(v)

/** A path segment that names one record (a number, a long id): any other matches it too. */
const ID_SEGMENT = /^\d+$|^(?=[^/]*\d)[0-9a-z_-]{8,}$/i

/** The page's path as a recipe keeps it: id-like segments as `*`. Null when it's too long to keep. */
export function pathPattern(pathname: string): string | null {
  const path = (pathname || "/").split("/").map((s) => (ID_SEGMENT.test(s) ? "*" : s)).join("/")
  return path.startsWith("/") && path.length <= MAX_PATH && !/[\s?#\p{Cc}]/u.test(path) ? path : null
}

/** Whether `pathname` is a page `pattern` was learned on. */
export function pathMatches(pattern: string, pathname: string): boolean {
  const want = pattern.split("/")
  const have = (pathname || "/").split("/")
  return want.length === have.length && want.every((s, i) => s === have[i] || (s === "*" && have[i] !== ""))
}

const pick = (s: Record<string, unknown>) => ({
  ...(token(s.id) ? { id: s.id } : {}),
  ...(token(s.name) ? { name: s.name } : {}),
  ...(token(s.autocomplete) ? { autocomplete: s.autocomplete } : {}),
})

/**
 * A recipe the host sent, if it's well formed: the daemon checked it when it
 * was saved, but one from another device's newer version may not read.
 */
export function parseRecipe(raw: unknown): SiteRecipe | null {
  if (typeof raw !== "string" || bytes(raw) > MAX_RECIPE_BYTES) return null
  let v: unknown
  try {
    v = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof v !== "object" || v === null) return null
  const r = v as Record<string, unknown>
  if (r.v !== 1 || typeof r.origin !== "string" || typeof r.pathPattern !== "string" || !token(r.clusterFingerprint)) return null
  if (!Array.isArray(r.slots) || !r.slots.length || r.slots.length > MAX_SLOTS) return null
  const slots: RecipeSlot[] = []
  for (const s of r.slots as unknown[]) {
    if (typeof s !== "object" || s === null) return null
    const slot = s as Record<string, unknown>
    const nth = slot.nthInput
    if (!ROLES.includes(slot.role as RecipeRole) || !Number.isInteger(nth) || (nth as number) < 0 || (nth as number) >= MAX_NTH) return null
    if ([slot.id, slot.name, slot.autocomplete].some((t) => t !== undefined && !token(t))) return null
    slots.push({ role: slot.role as RecipeRole, nthInput: nth as number, ...pick(slot) })
  }
  return { v: 1, origin: r.origin, pathPattern: r.pathPattern, clusterFingerprint: r.clusterFingerprint, slots }
}

const autocompleteOf = (el: HTMLInputElement) => (el.getAttribute("autocomplete") || "").trim().toLowerCase()

/**
 * The recipe for the fields the user just had filled by hand (`fields`, in
 * `cluster`, on the page at `origin` and `pathname`), as JSON of at most
 * MAX_RECIPE_BYTES: each field's role, its place among the cluster's
 * controls and the attributes that name it. Never a value. Null when the
 * fields aren't all in the cluster, aren't 1 to 4 roles a recipe takes, or
 * the page's path is too long to keep.
 */
export function buildSiteRecipe(origin: string, pathname: string, cluster: FormCluster, fields: RecipeField[]): string | null {
  const path = pathPattern(pathname)
  if (!path || !fields.length || fields.length > MAX_SLOTS || !token(cluster.fingerprint)) return null
  const slots: RecipeSlot[] = []
  for (const f of fields) {
    const nth = cluster.controls.indexOf(f.el)
    if (nth < 0 || nth >= MAX_NTH || !ROLES.includes(f.role as RecipeRole) || slots.some((s) => s.nthInput === nth)) return null
    slots.push({ role: f.role as RecipeRole, nthInput: nth, ...pick({ id: f.el.id, name: f.el.getAttribute("name"), autocomplete: autocompleteOf(f.el) }) })
  }
  const recipe: SiteRecipe = { v: 1, origin, pathPattern: path, clusterFingerprint: cluster.fingerprint, slots }
  // Too big: the attributes go, the least telling first; the places stay.
  for (const drop of [null, "autocomplete", "id", "name"] as const) {
    if (drop) for (const s of slots) delete s[drop]
    const json = JSON.stringify(recipe)
    if (bytes(json) <= MAX_RECIPE_BYTES) return json
  }
  return null
}

/** The cluster's control a slot names, if it's still that field and may be filled. */
function slotField(cluster: FormCluster, slot: RecipeSlot): RecipeField | null {
  const el = cluster.controls[slot.nthInput]
  if (!(el instanceof HTMLInputElement)) return null
  if (slot.id !== undefined && el.id !== slot.id) return null
  if (slot.name !== undefined && el.getAttribute("name") !== slot.name) return null
  if (slot.autocomplete !== undefined && autocompleteOf(el) !== slot.autocomplete) return null
  // Never a box no one can reach or type into, nor one the site keeps password managers from.
  if (el.disabled || el.readOnly || concealed(el) || ignored(el)) return null
  // A password only ever goes into a box that masks it, and nothing else does.
  if (SECRET_ROLES.includes(slot.role) !== masked(el)) return null
  return { el, role: slot.role }
}

/**
 * The fields `recipes` (JSON, as the host lists them) locate on the page at
 * `origin` and `pathname` in `graph`: those of the first recipe for this
 * exact origin and path whose cluster is on the page with the same
 * fingerprint, and whose every slot is still its field (see slotField).
 * `stale`: a recipe was for this page but its form changed shape, and
 * nothing of it is used.
 */
export function applySiteRecipes(graph: Pick<FormGraph, "clusters">, origin: string, pathname: string, recipes: readonly unknown[]): { fields: RecipeField[]; stale: boolean } {
  let stale = false
  for (const raw of recipes) {
    const recipe = parseRecipe(raw)
    if (!recipe || recipe.origin !== origin || !pathMatches(recipe.pathPattern, pathname)) continue
    const cluster = graph.clusters.find((c) => c.fingerprint === recipe.clusterFingerprint)
    const fields = cluster ? recipe.slots.map((s) => slotField(cluster, s)) : []
    if (cluster && fields.every((f) => f !== null)) return { fields: fields as RecipeField[], stale: false }
    stale = true
  }
  return { fields: [], stale }
}
