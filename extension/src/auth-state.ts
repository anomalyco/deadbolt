// Conservative, value-free auth-state judgement shared by the background and
// tests. A page can only supply hints, never proof of an authenticated session.
export const SIGNIN_SETTING = "offerToSignIn"
export const SIGNED_IN_MS = 5 * 60_000
export const SIGNIN_QUIET_MS = 30 * 60_000

export interface AuthSignals {
  loginForm: boolean
  loginRoute: boolean
  entry: boolean
  signOut: boolean
  account: boolean
  accountMenu: boolean
  appShell: boolean
  challenge: boolean
  uncertain: boolean
}

export interface AuthReport extends AuthSignals {
  /** Opaque content-script handle, not a selector the page can redirect. */
  action?: string
}

export function authState(s: AuthSignals, remembered = false): "signed-in" | "signed-out" | "unknown" {
  // Signed-in evidence wins even against a login form or a provider button.
  if (s.signOut || s.account || remembered) return "signed-in"
  if (s.uncertain || s.challenge || s.accountMenu || s.appShell) return "unknown"
  const score = (s.loginForm ? 6 : 0) + (s.entry ? 6 : 0) + (s.loginRoute ? 2 : 0)
  return score >= 6 ? "signed-out" : "unknown"
}

/** Full username/email, at token boundaries; never an email's local part. */
export function matchesAccount(text: string, usernames: string[]): boolean {
  const hay = text.toLocaleLowerCase()
  const word = /[\p{L}\p{N}_.+@-]/u
  return usernames.some((raw) => {
    const name = raw.trim().toLocaleLowerCase()
    if (name.length < 4 || name.length > 500) return false
    for (let i = hay.indexOf(name); i >= 0; i = hay.indexOf(name, i + 1))
      if (!word.test(hay[i - 1] ?? "") && !word.test(hay[i + name.length] ?? "")) return true
    return false
  })
}

/** Deliberately stricter than ordinary autofill: no sibling hosts or ports. */
export function exactSignInOrigin(saved: string, origin: string): boolean {
  try {
    return new URL(saved.includes("://") ? saved : `https://${saved}`).origin === origin
  } catch {
    return false
  }
}
