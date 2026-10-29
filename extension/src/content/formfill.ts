// Writes an identity or a card into the fields of one section, and answers
// the background's checks before it (which fields may be filled; for a
// frame, where they show). The rules are the logins' (fill.ts, embed.ts):
// only fields fixed when the fill was approved, still where they were
// scanned, each one checked right before it's written.

import type { FormRole, FormsAck, FormsApproved, FormValues } from "../messages"
import type { FormKind } from "../protocol"
import { Approvals } from "./approvals"
import type { FormControl } from "./detect"
import { ownBoxes } from "./embed"
import { fillable } from "./fill"
import { formFieldInPlace, sectionFields, type FormField } from "./forms"
import { splitNumber, valueFor } from "./transform"

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
  setter.call(el, value)
  if (el instanceof HTMLSelectElement && el.value !== value) return false
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: el instanceof HTMLSelectElement ? null : value }))
  el.dispatchEvent(new Event("change", { bubbles: true }))
  return true
}

/**
 * Fills one section's fields from `values`: each field gets what its role
 * and its element want (see transform.ts); a card number split over boxes
 * goes in only as a whole, one slice per box. Fields with nothing to write
 * are left alone. Returns the roles written.
 */
export async function fillForm(fields: FormField[], values: FormValues, check: (el: FormControl) => boolean = fillable): Promise<{ filled: FormRole[]; last?: FormControl }> {
  const filled: FormRole[] = []
  let last: FormControl | undefined
  const ordered = [...fields].sort((a, b) => (a.el.compareDocumentPosition(b.el) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1))
  const ok = (group: FormField[]) => (el: FormControl) => group.every(formFieldInPlace) && check(el)
  const done = new Set<FormField>()
  for (const f of ordered) {
    if (done.has(f)) continue
    if (f.role === "cc-number" && f.split) {
      const boxes = ordered.filter((b) => b.role === "cc-number" && b.split && b.form === f.form)
      boxes.forEach((b) => done.add(b))
      if (!values.number || !boxes.every((b) => ok(boxes)(b.el))) continue
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
    const value = valueFor(f.role, f.el, values)
    if (value === undefined || value === "" || !ok([f])(f.el)) continue
    // A beat between fields for pages that react to each one (a country that redraws the region list).
    if (filled.length) await sleep(30)
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
  const fields = sectionFields(state.fields(), section, kind).filter((f) => fillable(f.el, ours))
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

export type { FormsAck }
