// The page's navigator.credentials options, serialized for the extension in
// the page's own world by passkey-hook.ts. Ported from Foyer
// (github.com/R44VC0RP/foyer, src/passkey-hook.ts, by Ryan Vogel).
//
// Options go whole: the extension, not this side, decides what it can
// answer, and anything it can't goes to the browser.

function bytes(source: unknown): Uint8Array | undefined {
  if (source instanceof ArrayBuffer) return new Uint8Array(source)
  if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
  return undefined
}

function b64url(source: unknown): string | undefined {
  const b = bytes(source)
  if (!b) return undefined
  let s = ""
  for (const x of b) s += String.fromCharCode(x)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// A list the page passes may be any iterable, a generator say, that reads
// only once. So the hook reads each list the extension looks at into an
// array, once, before anything else, and both the extension and the
// browser's own flow get that array; the browser never sees a spent iterator.
// Anything not iterable stays as it is, for the browser to refuse.
function materialize(list: unknown): unknown {
  if ((typeof list !== "object" && typeof list !== "function") || list === null) return list
  const iterator = (list as any)[Symbol.iterator]
  if (typeof iterator !== "function") return list
  return Array.from({ [Symbol.iterator]: () => iterator.call(list) })
}

const LISTS = { get: ["allowCredentials"], create: ["excludeCredentials", "pubKeyCredParams"] } as const

const own = (target: object, key: string, value: unknown) => Object.defineProperty(target, key, { value, enumerable: true, configurable: true, writable: true })

/**
 * The page's options with its lists read once into arrays. Everything else
 * is the page's own, inherited, so the browser reads every member it knows,
 * as from the page's object.
 */
export function snapshot(kind: "get" | "create", options: object, publicKey: object): object {
  const pk = Object.create(publicKey)
  for (const key of LISTS[kind]) own(pk, key, materialize((publicKey as any)[key]))
  return own(Object.create(options), "publicKey", pk)
}

// Every entry, so the extension sees the whole list: one that isn't a
// public-key credential id goes as null, and the call to the browser.
const ids = (list: unknown) => {
  if (list === undefined) return undefined
  if (typeof list !== "object" || list === null || typeof (list as any)[Symbol.iterator] !== "function") return null
  return Array.from(list as Iterable<any>, (c) => (c?.type === "public-key" && b64url(c.id)) || null)
}
// Likewise each algorithm, null where the entry isn't a public-key one with
// a numeric alg.
const algorithms = (list: unknown) => {
  if (list === undefined) return undefined
  if (!Array.isArray(list)) return null
  return list.map((p) => (p?.type === "public-key" && typeof p.alg === "number" ? p.alg : null))
}
const text = (v: unknown) => (typeof v === "string" ? v : undefined)
const num = (v: unknown) => (typeof v === "number" ? v : undefined)

export function serializeGet(options: any) {
  const pk = options.publicKey
  return {
    challenge: b64url(pk.challenge),
    rpId: text(pk.rpId),
    allow: ids(pk.allowCredentials),
    userVerification: text(pk.userVerification),
    mediation: text(options.mediation),
    timeout: num(pk.timeout),
  }
}

export function serializeCreate(options: any) {
  const pk = options.publicKey
  const select = pk.authenticatorSelection ?? {}
  return {
    challenge: b64url(pk.challenge),
    rpId: text(pk.rp?.id),
    user: { id: b64url(pk.user?.id), name: String(pk.user?.name ?? ""), displayName: String(pk.user?.displayName ?? "") },
    algorithms: algorithms(pk.pubKeyCredParams),
    exclude: ids(pk.excludeCredentials),
    userVerification: text(select.userVerification),
    attachment: text(select.authenticatorAttachment),
    timeout: num(pk.timeout),
  }
}
