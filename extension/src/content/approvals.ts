// The fields a fill may write, fixed when the background asked which may be
// filled (db:approve). A field that turns fillable later, such as a disabled
// password the page enables once the username is focused, isn't among them.

import type { Field } from "./detect"

const KEEP = 4

export class Approvals<F extends { el: Element; role: string } = Field> {
  private granted = new Map<string, { form: number; fields: F[] }>()

  /** Approves `fields` of form snapshot `form`; returns the id a fill names. */
  grant(form: number, fields: F[]): string {
    const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("")
    this.granted.set(id, { form, fields: [...fields] })
    for (const old of this.granted.keys()) if (this.granted.size > KEEP) this.granted.delete(old)
    return id
  }

  /** The approved fields, if `id` is for form snapshot `form`. */
  get(id: string, form: number): F[] | null {
    const a = this.granted.get(id)
    return a && a.form === form ? a.fields : null
  }

  /**
   * What a fill may write: the fields `id` approved that are still among the
   * form's `current` fields, never more. Each approval fills once.
   */
  take(id: string, form: number, current: F[]): F[] | null {
    const fields = this.get(id, form)
    this.granted.delete(id)
    if (!fields) return null
    return current.filter((c) => fields.some((f) => f.el === c.el && f.role === c.role))
  }
}

export const approvals = new Approvals()
