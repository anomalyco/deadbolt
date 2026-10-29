// Weak labels for crawled fields, from what the site itself declares
// (autocomplete tokens, input type) and, failing that, name/id hints. They
// are not ground truth: they're what a page's own markup says, so they
// disagree with the detector both when it's wrong and when the markup is.

import type { FrameProbe, InputFact } from "./probe"

export type Coarse = "identifier" | "password" | "otp" | "other"
export type LabelSource = "autocomplete" | "type" | "hint"

export interface WeakLabel {
  role: string
  source: LabelSource
}

export function coarse(role: string | null | undefined): Coarse | null {
  if (!role) return null
  if (role === "username" || role === "email" || role === "phone") return "identifier"
  if (role === "password" || role === "new-password") return "password"
  if (role === "otp") return "otp"
  return "other"
}

const HINT: Array<[RegExp, string]> = [
  [/pass(word|wd)?|pwd|kennwort|contrase|mot.?de.?passe|senha|parol/i, "password"],
  [/one.?time|otp|totp|mfa|2fa|verif\w*.?code|auth\w*.?code|security.?code|sms.?code/i, "otp"],
  [/e.?mail|correo|courriel/i, "email"],
  [/user|login|logon|account|identifier|signin|member|benutzer|usuario|utilisateur/i, "username"],
]

export function weakLabel(f: InputFact): WeakLabel | null {
  const ac = f.autocomplete.split(/\s+/)
  if (ac.includes("current-password")) return { role: "password", source: "autocomplete" }
  if (ac.includes("new-password")) return { role: "new-password", source: "autocomplete" }
  if (ac.includes("one-time-code")) return { role: "otp", source: "autocomplete" }
  if (ac.includes("username")) return { role: "username", source: "autocomplete" }
  if (ac.includes("email")) return { role: "email", source: "autocomplete" }
  if (f.type === "password") return { role: "password", source: "type" }
  if (f.type === "email") return { role: "email", source: "type" }
  const code = `${f.name} ${f.id}`
  for (const [re, role] of HINT) if (re.test(code)) return { role, source: "hint" }
  if (ac.includes("tel") || ac.includes("tel-national")) return { role: "phone", source: "autocomplete" }
  return null
}

export type Agreement = "match" | "coarse" | "miss" | "wrong" | "extra" | "none" | "out-of-scope"

/** How the detector's role compares with the weak label. */
export function agreement(label: WeakLabel | null, role: string | null): Agreement {
  if (!label && !role) return "none"
  if (!label) return "extra"
  if (!role) return "miss"
  if (label.role === role) return "match"
  // A password box the site only marks as type=password can be either kind.
  if (label.source === "type" && coarse(label.role) === "password" && coarse(role) === "password") return "match"
  return coarse(label.role) === coarse(role) ? "coarse" : "wrong"
}

export interface FieldRow {
  frame: number
  i: number
  label: WeakLabel | null
  role: string | null
  agreement: Agreement
  inShadow: boolean
}

export const visibleRows = (frames: FrameProbe[]): FieldRow[] =>
  frames.flatMap((fr, frame) =>
    fr.inputs
      .filter((f) => f.visible)
      .map((f) => {
        const label = weakLabel(f)
        const agree = f.outOfScope && !f.role && label ? "out-of-scope" : agreement(label, f.role)
        return { frame, i: f.i, label, role: f.role, agreement: agree, inShadow: f.inShadow }
      }),
  )
