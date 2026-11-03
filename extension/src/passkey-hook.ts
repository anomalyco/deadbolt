// Runs in the page's own JS world (content_scripts world: MAIN), before any
// page script, and answers navigator.credentials.create/get for passkeys from
// Deadbolt. Ported from Foyer (github.com/R44VC0RP/foyer,
// src/passkey-hook.ts, by Ryan Vogel), without its call reporting and FedCM.
//
// The request goes to the extension, which checks the frame by the origin the
// browser reports, asks the user in the toolbar popup or the inline menu, and
// has the daemon sign. Private keys never enter the browser. When Deadbolt has
// no passkey for the site, can't make one the site accepts, or the user
// prefers, the browser's own WebAuthn runs instead.
//
// The isolated content script offers this script one MessagePort at
// document_start (see content/passkeys.ts). This script is listed first in
// the manifest, so its capturing listener sees that offer before any page
// listener can, and keeps the first port only. Nothing secret crosses the
// port: requests are the page's own options, answers the credential the page
// asked for.

import { serializeCreate, serializeGet, snapshot } from "./passkey-options"

type Reply = { id: number; ok: boolean; result?: any; error?: { name?: string; message?: string } }

const marker = Symbol.for("deadbolt.passkeys")
const proto = (globalThis as any).CredentialsContainer?.prototype
const ERRORS = new Set(["NotAllowedError", "SecurityError", "InvalidStateError", "AbortError", "NotSupportedError"])

let port: MessagePort | null = null
let seq = 0
const waiting = new Map<number, { resolve: (v: any) => void; reject: (e: unknown) => void }>()

window.addEventListener(
  "message",
  function accept(event) {
    if (port || event.source !== window || event.data?.deadbolt !== "passkey-port" || !event.ports?.[0]) return
    event.stopImmediatePropagation()
    window.removeEventListener("message", accept, true)
    port = event.ports[0]
    port.onmessage = (m: MessageEvent<Reply>) => {
      const w = waiting.get(m.data?.id)
      if (!w) return
      waiting.delete(m.data.id)
      if (m.data.ok) return w.resolve(m.data.result)
      const name = m.data.error?.name && ERRORS.has(m.data.error.name) ? m.data.error.name : "NotAllowedError"
      w.reject(new DOMException(m.data.error?.message || "The operation either timed out or was not allowed.", name))
    }
    port.postMessage({ op: "ack" })
  },
  true,
)

function ask(op: "get" | "create", payload: unknown, signal?: AbortSignal): Promise<any> {
  const id = ++seq
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject })
    port!.postMessage({ id, op, payload })
    signal?.addEventListener("abort", () => {
      if (!waiting.delete(id)) return
      port?.postMessage({ id, op: "cancel" })
      reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"))
    })
  })
}

// ---- Encoding -----------------------------------------------------------------

function fromB64url(s: string): ArrayBuffer {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

// ---- Credential objects ---------------------------------------------------------

const define = (target: object, props: Record<string, unknown>) => {
  for (const [key, value] of Object.entries(props)) Object.defineProperty(target, key, { value, enumerable: true, configurable: true })
  return target
}

const TRANSPORTS = ["internal"]

function credential(kind: "create" | "get", r: any, credProps: boolean): PublicKeyCredential {
  const PKC = (globalThis as any).PublicKeyCredential
  const rawId = fromB64url(r.credentialId)
  const clientDataJSON = fromB64url(r.clientDataJSON)
  let response: object
  let json: Record<string, unknown>
  if (kind === "create") {
    const authenticatorData = fromB64url(r.authenticatorData)
    const publicKey = fromB64url(r.publicKey)
    response = Object.create((globalThis as any).AuthenticatorAttestationResponse?.prototype ?? Object.prototype)
    define(response, {
      clientDataJSON,
      attestationObject: fromB64url(r.attestationObject),
      getTransports: () => TRANSPORTS.slice(),
      getAuthenticatorData: () => authenticatorData.slice(0),
      getPublicKey: () => publicKey.slice(0),
      getPublicKeyAlgorithm: () => -7,
    })
    json = {
      clientDataJSON: r.clientDataJSON,
      attestationObject: r.attestationObject,
      authenticatorData: r.authenticatorData,
      publicKey: r.publicKey,
      publicKeyAlgorithm: -7,
      transports: TRANSPORTS.slice(),
    }
  } else {
    response = Object.create((globalThis as any).AuthenticatorAssertionResponse?.prototype ?? Object.prototype)
    define(response, {
      clientDataJSON,
      authenticatorData: fromB64url(r.authenticatorData),
      signature: fromB64url(r.signature),
      userHandle: r.userHandle ? fromB64url(r.userHandle) : null,
    })
    json = { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, signature: r.signature, userHandle: r.userHandle ?? null }
  }
  // Every Deadbolt passkey is discoverable.
  const extensions = kind === "create" && credProps ? { credProps: { rk: true } } : {}
  const cred = Object.create(PKC?.prototype ?? Object.prototype)
  define(cred, {
    id: r.credentialId,
    rawId,
    type: "public-key",
    response,
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({ ...extensions }),
    toJSON: () => ({
      id: r.credentialId,
      rawId: r.credentialId,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: { ...extensions },
      response: json,
    }),
  })
  return cred
}

// ---- Hooks -------------------------------------------------------------------------

if (proto && !proto[marker]) {
  proto[marker] = true
  const originalGet = proto.get
  const originalCreate = proto.create

  // The page's options are read first, lists into arrays (`snapshot`), and
  // the browser's own flow gets that copy, whichever way the call goes.
  const hook = (kind: "get" | "create", original: (options?: any) => Promise<unknown>, self: CredentialsContainer, given: any) => {
    const publicKey = given?.publicKey
    if (!publicKey || (typeof publicKey !== "object" && typeof publicKey !== "function")) return original.call(self, given)
    let options: any
    try {
      options = snapshot(kind, given, publicKey)
    } catch (err) {
      // An iterator that throws: the browser's own reading would too.
      return Promise.reject(err)
    }
    const native = () => original.call(self, options)
    if (!port || !window.isSecureContext) return native()
    let payload: unknown
    try {
      payload = kind === "get" ? serializeGet(options) : serializeCreate(options)
    } catch {
      return native()
    }
    if (options.signal?.aborted) return Promise.reject(options.signal.reason ?? new DOMException("The operation was aborted.", "AbortError"))
    return (async () => {
      const r = await ask(kind, payload, options.signal)
      if (r?.fallback) return native()
      return credential(kind, r, kind === "create" && !!options.publicKey.extensions?.credProps)
    })()
  }

  proto.get = function (this: CredentialsContainer, options?: any) {
    return hook("get", originalGet, this, options)
  }

  proto.create = function (this: CredentialsContainer, options?: any) {
    return hook("create", originalCreate, this, options)
  }
}
