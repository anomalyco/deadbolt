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
  if (s.signOut || remembered) return "signed-in"
  if (s.uncertain || s.challenge || s.accountMenu || s.appShell) return "unknown"
  const score = (s.loginForm ? 6 : 0) + (s.entry ? 6 : 0) + (s.loginRoute ? 2 : 0)
  return score >= 6 ? "signed-out" : "unknown"
}

/** Deliberately stricter than ordinary autofill: no sibling hosts or ports. */
export function exactSignInOrigin(saved: string, origin: string): boolean {
  try {
    return new URL(saved.includes("://") ? saved : `https://${saved}`).origin === origin
  } catch {
    return false
  }
}
