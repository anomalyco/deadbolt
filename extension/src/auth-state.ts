// Conservative, value-free auth-state judgement shared by the background and
// tests. A page can only supply hints, never proof of an authenticated session.
export const SIGNIN_SETTING = "offerToSignIn"
/**
 * The setting's stored value: on unless the person turned it off. The
 * toggle writes only on a change, so a missing key (a new install, or one
 * that never touched it) is the default, on; an explicit `false` stays off.
 */
export const signInOn = (stored: unknown) => stored !== false
/** Reads the setting (see signInOn). */
export async function signInEnabled(): Promise<boolean> {
  return signInOn((await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING])
}
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
  /** Known providers (ids) whose "Sign in with …" button shows in the page: no account, no text. */
  providers?: string[]
}

export function authState(s: AuthSignals, remembered = false): "signed-in" | "signed-out" | "unknown" {
  // Signed-in evidence wins even against a login form or a provider button.
  if (s.signOut || remembered) return "signed-in"
  if (s.uncertain || s.challenge || s.accountMenu || s.appShell) return "unknown"
  const score = (s.loginForm ? 6 : 0) + (s.entry ? 6 : 0) + (s.loginRoute ? 2 : 0)
  return score >= 6 ? "signed-out" : "unknown"
}

/**
 * A saved URL naming exactly this origin: scheme, host and port. The corner
 * offer and a provider's button need it; a pick's own sign-in takes the same
 * host on any path, its `www.` twin or a provider's sign-in host (see
 * bg/autofill.ts signInHost). Ordinary autofill takes any host of the site.
 */
export function exactSignInOrigin(saved: string, origin: string): boolean {
  try {
    return new URL(saved.includes("://") ? saved : `https://${saved}`).origin === origin
  } catch {
    return false
  }
}
