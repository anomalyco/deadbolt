// Writes an identity or a card into the fields of one section, and answers
// the background's checks before it (which fields may be filled; for a
// frame, where they show). The rules are the logins' (fill.ts, embed.ts):
// only fields fixed when the fill was approved, still where they were
// scanned, each one checked right before it's written.

import type { FormRole, FormsAck, FormsApproved, FormValues } from "../messages"
import type { CardField, FormKind, IdentityField } from "../protocol"
import { Approvals } from "./approvals"
import type { FormControl } from "./detect"
import { ownBoxes } from "./embed"
import { clippedBox, fillable, filledByDeadbolt, hiddenByStyle, noteFilled, onTop, ownValue, typedByUser } from "./fill"
import { formFieldInPlace, sectionFields, type FormField } from "./forms"
import { withAddressParts } from "./address"
import { cardBrand } from "../payments"
import { chooseOption, isCombobox } from "./combobox"
import { CHOICE_ROLES, choiceFor, countryOf, monthOf, readBirthday, readBirthdayParts, readCardNumber, readExpiry, readExpiryParts, readPhone, shownText, shows, splitName, splitNumber, valueFor } from "./transform"

export interface FormsState {
  fields(): FormField[]
  /** Which snapshot `fields` is; it changes whenever they do. */
  form(): number
  rescan(): void
}

export const formApprovals = new Approvals<FormField>()

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/**
 * Sets a field's value through its own native setter, as fill.ts does for
 * inputs, so frameworks see the change. A select takes an option's value.
 * Checks the field once more right after focusing it.
 */
export function setFormValue(el: FormControl, value: string, guard: (el: FormControl) => boolean = () => true): boolean {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
  const setter = Object.getOwnPropertyDescriptor(proto, "value")!.set!
  el.focus({ preventScroll: true })
  if (!guard(el)) return false
  noteFilled(el, value)
  setter.call(el, value)
  if (el instanceof HTMLSelectElement && el.value !== value) return false
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: el instanceof HTMLSelectElement ? null : value }))
  el.dispatchEvent(new Event("change", { bubbles: true }))
  return true
}

/** The smallest an identity field may be, in CSS pixels: anything smaller is there to be missed. */
const MIN_IDENTITY = { width: 40, height: 16 }

/**
 * Whether an identity field may be filled as it stands, without scrolling
 * to it: enabled, at least 40×16, not hidden by style, all of it on screen,
 * and what's under its middle is the field (`ours`, Deadbolt's own surface,
 * doesn't count). An address goes only into fields the user can see now;
 * a page that tucks a field away gets nothing in it.
 */
export function onScreen(el: FormControl, ours?: Element | null, disabledSelect = false): boolean {
  if (!el.isConnected || (el.disabled && !(disabledSelect && el instanceof HTMLSelectElement)) || ("readOnly" in el && el.readOnly)) return false
  const r = el.getBoundingClientRect()
  if (r.width < MIN_IDENTITY.width || r.height < MIN_IDENTITY.height || hiddenByStyle(el)) return false
  const box = clippedBox(el)
  if (!box || (box.right - box.left) * (box.bottom - box.top) < 0.95 * r.width * r.height) return false
  return onTop(el, box, ours)
}

/** The check a field of `kind` gets before it's approved and again before it's written. */
export const fillCheck = (kind: FormKind, ours?: Element | null) => (el: FormControl) => (kind === "identity" ? onScreen(el, ours) : fillable(el, ours))

/**
 * The check at approval: as fillCheck, except that an address select the
 * page has disabled until an earlier field is chosen (a state list waiting
 * for its country) is approved to wait for it. It's written only once the
 * page enables it, after the full check again (see fillForm).
 */
const approveCheck = (kind: FormKind, ours?: Element | null) => (el: FormControl) => (kind === "identity" ? onScreen(el, ours, true) : fillable(el, ours))

/** A select with nothing to choose yet: disabled, or only placeholder options (no value). */
const unloaded = (el: FormControl) => el instanceof HTMLSelectElement && (el.disabled || !Array.from(el.options).some((o) => o.value))

/** How long a select waits for its options after the rest of the fill (a country's states loading). */
const DEPENDENT_WAIT_MS = 2500

/**
 * Fills one section's fields from `values`: each field gets what its role
 * and its element want (see transform.ts); a card number split over boxes
 * goes in only as a whole, one slice per box; a whole address in the first
 * line is split for a form that asks for its parts (see address.ts); a
 * country or state combobox gets its option chosen (see combobox.ts), the
 * country first. Fields with nothing to write are left alone, and so are
 * fields holding what the user typed themselves (a value Deadbolt filled
 * before may be replaced). Returns the roles written.
 */
export async function fillForm(fields: FormField[], given: FormValues, check: (el: FormControl) => boolean = fillable): Promise<{ filled: FormRole[]; last?: FormControl }> {
  const filled: FormRole[] = []
  let last: FormControl | undefined
  const roles = fields.map((f) => f.role)
  const values = withAddressParts(given, roles)
  let ordered = [...fields].sort((a, b) => (a.el.compareDocumentPosition(b.el) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1))
  // The country before the region, wherever it is: a state list can depend on it.
  const region = ordered.findIndex((f) => f.role === "address-level1")
  const late = ordered.filter((f, i) => region >= 0 && i > region && f.role === "country")
  if (late.length) {
    ordered = ordered.filter((f) => !late.includes(f))
    ordered.splice(region, 0, ...late)
  }
  // With a calling code box of its own, the number box takes the national number.
  const national = roles.includes("tel-country-code")
  const ok = (group: FormField[]) => (el: FormControl) => group.every(formFieldInPlace) && check(el)
  const done = new Set<FormField>()
  const later: FormField[] = []
  for (const f of ordered) {
    if (done.has(f)) continue
    if (f.role === "cc-number" && f.split) {
      const boxes = ordered.filter((b) => b.role === "cc-number" && b.split && b.form === f.form)
      boxes.forEach((b) => done.add(b))
      if (!values.number || !boxes.every((b) => ok(boxes)(b.el))) continue
      if ((await Promise.all(boxes.map((b) => typedByUser(b.el, b.el.value)))).some(Boolean)) continue
      const parts = splitNumber(values.number, boxes.map((b) => b.el))
      let i = 0
      if (filled.length) await sleep(30)
      while (i < boxes.length && setFormValue(boxes[i].el, parts[i], ok(boxes))) i++
      if (i === boxes.length) {
        filled.push("cc-number")
        last = boxes[i - 1].el
      }
      continue
    }
    done.add(f)
    // A select that has nothing to choose yet waits for the fields before it (its country) to load it.
    if (unloaded(f.el)) {
      later.push(f)
      continue
    }
    // A combobox for a country or state is chosen in, not typed in (see combobox.ts).
    if (isCombobox(f.el) && CHOICE_ROLES.has(f.role)) {
      const choice = choiceFor(f.role, values)
      if (!choice || shows(f.el.value, choice) || !ok([f])(f.el) || (await typedByUser(f.el, f.el.value))) continue
      if (filled.length) await sleep(30)
      if (await chooseOption(f.el, choice, ok([f]), () => formFieldInPlace(f))) {
        filled.push(f.role)
        last = f.el
      }
      continue
    }
    const value = valueFor(f.role === "tel" && national ? "tel-national" : f.role, f.el, values)
    if (value === undefined || value === "" || !ok([f])(f.el)) continue
    if (!(f.el instanceof HTMLSelectElement) && (await typedByUser(f.el, f.el.value))) continue
    // A beat between fields for pages that react to each one (a country that redraws the region list).
    if (filled.length) await sleep(30)
    if (setFormValue(f.el, value, ok([f]))) {
      filled.push(f.role)
      last = f.el
    }
  }
  // Selects the page fills in once an earlier choice is made: only after
  // this fill wrote something, for a moment, each one once it has its
  // option, through the full check.
  const until = Date.now() + DEPENDENT_WAIT_MS
  for (const f of filled.length ? later : []) {
    let value: string | undefined
    while (Date.now() < until && (unloaded(f.el) || (value = valueFor(f.role, f.el, values)) === undefined)) await sleep(100)
    if (!value || !ok([f])(f.el)) continue
    if (setFormValue(f.el, value, ok([f]))) {
      filled.push(f.role)
      last = f.el
    }
  }
  return { filled: [...new Set(filled)], last }
}

/** The section's fields that may be filled now; with `measure`, only if they all show (for a frame). */
export async function approveForms(state: FormsState, form: number, kind: FormKind, section: string | undefined, measure: boolean, ours?: Element | null): Promise<FormsApproved | null> {
  state.rescan()
  if (state.form() !== form) return null
  const fields = sectionFields(state.fields(), section, kind).filter((f) => approveCheck(kind, ours)(f.el))
  if (!fields.length) return null
  const boxes = measure ? await ownBoxes(fields) : undefined
  if (boxes === null || state.form() !== form) return null
  return { approval: formApprovals.grant(form, fields), roles: [...new Set(fields.map((f) => f.role))], ...(boxes ? { boxes } : {}) }
}

/** Where a forms approval's fields show now: all of them, still found. */
export function approvedForms(state: FormsState, id: string) {
  state.rescan()
  const fields = formApprovals.get(id, state.form())
  const current = state.fields()
  if (!fields || !fields.every((f) => current.some((c) => c.el === f.el && c.role === f.role))) return Promise.resolve(null)
  return ownBoxes(fields)
}

/** A fill's fields: only those approved, still among the current ones. */
export function takeApproved(state: FormsState, id: string, form: number): FormField[] | null {
  state.rescan()
  return formApprovals.take(id, form, state.fields())
}

// ---- Reading what was submitted, for a save ------------------------------------

/**
 * What a submitted form held in identity and card fields, by the host's
 * field names. Never a security code. `typed`: the fields the user typed
 * into or chose in themselves; `filled`: those still holding what Deadbolt
 * filled. Only those may change a saved item (bg/save.ts); any other value
 * is the page's, kept only for a new item, and only if it showed.
 */
export interface Submitted {
  card?: Partial<Record<CardField, string>>
  identity?: Partial<Record<IdentityField, string>>
  typed?: string[]
  filled?: string[]
}

const inOrder = (a: FormField, b: FormField) => (a.el.compareDocumentPosition(b.el) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1)

/** How many of `fields` hold what the user typed or chose themselves. */
async function typedIn(fields: FormField[]): Promise<number> {
  return (await Promise.all(fields.map((f) => typedByUser(f.el, f.el.value)))).filter(Boolean).length
}

/** Each value read, with the fields it came from (a full name gives a given and a family name). */
type Read<K extends string> = { values: Partial<Record<K, string>>; from: Map<K, FormControl[]> }

/**
 * What the user submitted in `fields`, for an offer to save it once the
 * submit has gone through (bg/save.ts). A kind counts only when the user
 * typed into (or chose in) at least one of its fields themselves: a form
 * Deadbolt filled and nobody changed offers nothing. Each value says
 * whether the user typed it or Deadbolt filled it; one that's neither (the
 * page's own) is kept only if its field showed as a fill needs it to
 * (fillCheck: on screen, its size, on top), checked as the submit came in,
 * before the page could react to it. A card number counts only as typed or
 * filled, and a security code is never read. Of several identity sections
 * (shipping and billing), the one most typed into. `ours`: Deadbolt's own
 * surface, which covers nothing. Read in memory, for the background only.
 */
export async function readSubmitted(fields: FormField[], ours?: Element | null): Promise<Submitted> {
  // As the page stands now, before any await lets it change.
  const shown = new Set(fields.filter((f) => fillCheck(f.kind, ours)(f.el)).map((f) => f.el))
  const out: Submitted = {}
  const typed: string[] = []
  const filled: string[] = []
  const keep = async <K extends string>(read: Read<K>) => {
    for (const [key, els] of read.from) {
      if (read.values[key] === undefined) continue
      if ((await Promise.all(els.map((el) => typedByUser(el, el.value)))).some(Boolean)) typed.push(key)
      else if ((await Promise.all(els.map((el) => filledByDeadbolt(el, el.value)))).every(Boolean)) filled.push(key)
      else if (!els.every((el) => shown.has(el))) delete read.values[key]
    }
    return Object.keys(read.values).length ? read.values : undefined
  }
  const cards = fields.filter((f) => f.kind === "card" && f.role !== "cc-csc")
  if (cards.length && (await typedIn(cards))) out.card = await keep(await readCard(cards))
  const sections = new Map<string, FormField[]>()
  for (const f of fields) if (f.kind === "identity") sections.set(f.section, [...(sections.get(f.section) ?? []), f])
  let best: FormField[] | undefined
  let most = 0
  for (const list of sections.values()) {
    const n = await typedIn(list)
    if (n > most) [best, most] = [list, n]
  }
  if (best) out.identity = await keep(readIdentity(best))
  if (!out.card) delete out.card
  if (!out.identity) delete out.identity
  if (out.card || out.identity) Object.assign(out, { typed, filled })
  return out
}

/**
 * A card's values. The number: every box of one split over several, else
 * the first box with one, only as typed or filled by Deadbolt. Its brand
 * only from the number's digits, never from the page's own card type select.
 */
async function readCard(cards: FormField[]): Promise<Read<Exclude<CardField, "cvv">>> {
  const read: Read<Exclude<CardField, "cvv">> = { values: {}, from: new Map() }
  const set = (key: Exclude<CardField, "cvv">, value: string | undefined, from: Array<FormControl | undefined>) => {
    const els = from.filter((el): el is FormControl => !!el)
    if (!value || !els.length) return
    read.values[key] = value
    read.from.set(key, els)
  }
  const numbers = cards.filter((f) => f.role === "cc-number").sort(inOrder)
  const split = numbers.filter((f) => f.split)
  const boxes = (split.length ? split : numbers.filter((f) => f.el.value).slice(0, 1)).map((f) => f.el)
  const own = await Promise.all(boxes.map((b) => ownValue(b, b.value)))
  const number = boxes.length && own.every((v) => v !== undefined) ? readCardNumber(own.join("")) : undefined
  set("number", number, boxes)
  set("brand", number && cardBrand(number), boxes)
  const first = (role: FormRole) => cards.find((f) => f.role === role && f.el.value.trim())?.el
  const exp = first("cc-exp")
  const month = first("cc-exp-month")
  const year = first("cc-exp-year")
  if (exp) set("expiry", readExpiry(exp.value), [exp])
  else if (month && year) set("expiry", readExpiryParts(monthOf(month), year instanceof HTMLSelectElement ? year.value || shownText(year) : year.value), [month, year])
  const name = first("cc-name")
  if (name) set("cardholder", name.value.trim(), [name])
  else {
    const parts = [first("cc-given-name"), first("cc-family-name")]
    set("cardholder", parts.map((el) => el?.value.trim()).filter(Boolean).join(" "), parts)
  }
  return read
}

function readIdentity(list: FormField[]): Read<IdentityField> {
  const read: Read<IdentityField> = { values: {}, from: new Map() }
  const el = (role: FormRole) => list.find((f) => f.role === role && f.el.value.trim())?.el
  const text = (role: FormRole) => el(role)?.value.trim() || undefined
  const set = (key: IdentityField, value: string | undefined, from: Array<FormControl | undefined>) => {
    const els = from.filter((e): e is FormControl => !!e)
    if (!value || !els.length) return
    read.values[key] = value
    read.from.set(key, els)
  }
  const full = el("name")
  if (full) {
    const [given, family] = splitName(full.value)
    set("given-name", given, [full])
    set("family-name", family, [full])
  }
  for (const [key, role] of [["given-name", "given-name"], ["additional-name", "additional-name"], ["family-name", "family-name"], ["email", "email"], ["organization", "organization"], ["job-title", "organization-title"]] as const) set(key, text(role), [el(role)])
  const honorific = el("honorific-prefix")
  set("honorific", honorific && shownText(honorific), [honorific])
  const street = el("street-address")
  if (street) {
    const lines = street.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    set("address-line1", lines[0], [street])
    set("address-line2", lines[1], [street])
    set("address-line3", lines.slice(2).join(", "), [street])
  }
  for (const [key, role] of [["address-line1", "address-line1"], ["address-line2", "address-line2"], ["address-line3", "address-line3"], ["city", "address-level2"], ["postal-code", "postal-code"]] as const) set(key, text(role), [el(role)])
  const region = el("address-level1")
  if (region instanceof HTMLSelectElement) set("region", /^[a-z]{2,3}$/i.test(region.value.trim()) ? region.value.trim().toUpperCase() : shownText(region), [region])
  else set("region", region?.value.trim(), [region])
  const country = el("country")
  set("country", country && countryOf(country), [country])
  const phone = el("tel") ?? el("tel-national")
  if (phone) {
    const code = el("tel-country-code")
    const calling = code ? /\+\s?(\d{1,4})/.exec(`${shownText(code)} ${code.value}`)?.[1] : undefined
    set("phone", readPhone(phone.value.trim(), calling), [phone, ...(calling ? [code] : [])])
  }
  const bday = el("bday")
  const day = el("bday-day")
  const month = el("bday-month")
  const year = el("bday-year")
  if (bday) set("birthday", readBirthday(bday), [bday])
  else if (day && month && year) set("birthday", readBirthdayParts(day.value, monthOf(month), year.value), [day, month, year])
  return read
}

export type { FormsAck }
