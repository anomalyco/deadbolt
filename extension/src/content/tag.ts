// The keyed tag fill.ts keeps of what each field last held: taken on every
// keystroke, so synchronous and cheap. Two 32-bit lanes of a multiply-xor
// hash over the value's UTF-16 units, 64 bits in all, each seeded from a
// random key made once per document (crypto.getRandomValues) that never
// leaves the content script. The page never sees a tag, so it can't search
// for a value that collides with the one typed; and a tag says nothing of
// the value without the key.

/** A fresh random key, or null where the page's context has no crypto.getRandomValues. */
export const tagKey = (): Uint32Array | null =>
  typeof globalThis.crypto?.getRandomValues === "function" ? crypto.getRandomValues(new Uint32Array(4)) : null

/** murmur3's finalizer: every input bit reaches every output bit. */
function mix(h: number): number {
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b)
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35)
  return (h ^ (h >>> 16)) >>> 0
}

/** The value's 64-bit tag under `key` (four 32-bit words), as 16 hex digits. */
export function tag(value: string, key: Uint32Array): string {
  let a = key[0] ^ value.length
  let b = key[1] ^ Math.imul(value.length, 0x9e3779b1)
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    a = Math.imul(a ^ c ^ key[2], 0xcc9e2d51)
    a = (a << 15) | (a >>> 17)
    b = Math.imul(b ^ c ^ key[3], 0x1b873593)
    b = (b << 13) | (b >>> 19)
    b = (b + a) | 0
  }
  return mix(a ^ key[3]).toString(16).padStart(8, "0") + mix(b ^ key[2] ^ a).toString(16).padStart(8, "0")
}
