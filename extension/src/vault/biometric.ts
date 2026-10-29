// Only imported by trusted vault pages. The RP is this extension's own origin,
// never a website, and the browser owns the authenticator UI and UV check.
import type { App } from "./app"

interface Token { id: string; salt: string }
interface PrfResult { prf?: { enabled?: boolean; results?: { first: ArrayBuffer } } }
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
const bytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16))
const random = () => crypto.getRandomValues(new Uint8Array(32))

function token(value: unknown): Token | null {
  if (typeof value !== "string") return null
  try {
    const t = JSON.parse(value) as Token
    return typeof t.id === "string" && /^(?:[0-9a-f]{2}){1,1023}$/.test(t.id) && typeof t.salt === "string" && /^[0-9a-f]{64}$/.test(t.salt) ? t : null
  } catch { return null }
}

export async function enrollment(app: App): Promise<Token | null> {
  const r = await app.ask({ type: "device-biometric-info" })
  return r.ok ? token(r.reply.token) : null
}

function output(credential: PublicKeyCredential): string {
  const value = (credential.getClientExtensionResults() as PrfResult).prf?.results?.first
  if (!value || value.byteLength !== 32) throw new Error("This authenticator doesn't support PRF unlock. Use your passphrase instead.")
  const data = new Uint8Array(value)
  const result = hex(data)
  data.fill(0)
  return result
}

async function get(t: Token): Promise<string> {
  const credential = await navigator.credentials.get({ publicKey: {
    challenge: random(), userVerification: "required", timeout: 60_000,
    allowCredentials: [{ type: "public-key", id: bytes(t.id), transports: ["internal"] }],
    extensions: { prf: { eval: { first: bytes(t.salt) } } } as AuthenticationExtensionsClientInputs,
  } }) as PublicKeyCredential | null
  if (!credential || hex(new Uint8Array(credential.rawId)) !== t.id) throw new Error("The unlock passkey wasn't found. Use your passphrase and Reset Touch ID in Settings.")
  return output(credential)
}

export async function verify(app: App): Promise<string> {
  try {
    const t = await enrollment(app)
    if (!t) throw new Error("Touch ID isn't set up. Use your passphrase instead.")
    return await get(t)
  } catch (e) { throw new Error(explain(e)) }
}

export async function enroll(app: App, passphrase: string): Promise<void> {
  if (!globalThis.PublicKeyCredential || !(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) throw new Error("No platform authenticator is available. Keep using your passphrase.")
  const salt = random()
  try {
    const credential = await navigator.credentials.create({ publicKey: {
      challenge: random(), rp: { name: "Deadbolt unlock" },
      user: { id: random(), name: "Deadbolt", displayName: "Deadbolt on this browser" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
      attestation: "none", timeout: 60_000,
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    } }) as PublicKeyCredential | null
    if (!credential || !(credential.getClientExtensionResults() as PrfResult).prf?.enabled) throw new Error("This authenticator doesn't support PRF unlock. No unlock key was saved. Keep using your passphrase.")
    const t = { id: hex(new Uint8Array(credential.rawId)), salt: hex(salt) }
    // Prove a subsequent assertion works before enrolling, including authenticators
    // that report enabled but don't evaluate PRF during creation.
    const prf = await get(t)
    const r = await app.run({ type: "device-biometric-set", token: JSON.stringify(t), prf, passphrase })
    if (!r.ok) throw new Error(r.message)
    await chrome.storage.local.set({ "deadbolt.unlockMethod": "touch-id" })
  } catch (e) { throw new Error(explain(e)) }
}

function explain(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") return "Touch ID was cancelled, unavailable, or its passkey was removed. Use your passphrase; Settings → Reset Touch ID lets you enroll again."
  if (error instanceof DOMException && error.name === "SecurityError") return "This browser doesn't allow passkey unlock on the extension's origin. Use your passphrase instead."
  return error instanceof Error ? error.message : "Touch ID couldn't unlock. Use your passphrase instead."
}
