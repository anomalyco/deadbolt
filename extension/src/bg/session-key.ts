// Browser-session restoration, NOT an extra encryption boundary: the random
// wrapping key and its envelope share storage.session. A key held only by the
// worker/offscreen document cannot survive both being discarded. See the
// security review in docs/extension-device.md before changing this lifetime.
export const SESSION_KEY = "deadbolt.sessionKey"

export interface SessionKey {
  key: string
  wrapped: string
}

export function isSessionKey(value: unknown): value is SessionKey {
  const v = value as Partial<SessionKey> | null
  return !!v && typeof v.key === "string" && /^[0-9a-f]{64}$/.test(v.key) && typeof v.wrapped === "string" && /^[0-9a-f]{208}$/.test(v.wrapped)
}

export const randomKey = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (v) => v.toString(16).padStart(2, "0")).join("")
