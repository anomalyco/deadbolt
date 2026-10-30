// Hosts the Gauntlet (site.ts) on its own, for trying Deadbolt in a real
// browser. The demo login lives in seed.json (mode 0600) beside this file,
// made on first start with a random password and TOTP secret; delete it for
// new ones.
//
//   PORT=47830 bun server.ts
//
// GAUNTLET_URL is the public origin written into seed.json.
// GAUNTLET_SAME_SITE and GAUNTLET_CROSS_SITE are origins that serve this same
// server, for the frame pages: another origin of the same site, and another
// site. Without them those pages say they aren't available.

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs"
import { randomBytes, randomInt } from "node:crypto"
import { join } from "node:path"
import { gauntlet, KEYPAD_PIN, type Account } from "./site"

const PORT = Number(process.env.PORT ?? 47830)
const HOST = process.env.HOST ?? "127.0.0.1"
const PUBLIC = process.env.GAUNTLET_URL ?? `http://${HOST}:${PORT}`
const SEED = process.env.GAUNTLET_SEED ?? join(import.meta.dir, "seed.json")

interface Seed {
  url: string
  title: string
  username: string
  password: string
  otpauth: string
  /** Other identifiers the same account signs in with on some pages. */
  aliases: { phone: string; customerNumber: string; username: string }
  pin: string
  keypadPin: string
  birthday: string
}

function b32(bytes: Uint8Array) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const b of bytes) bits += b.toString(2).padStart(8, "0")
  return (bits.match(/.{1,5}/g) ?? []).map((c) => A[parseInt(c.padEnd(5, "0"), 2)]).join("")
}

function seed(): Seed {
  if (existsSync(SEED)) return JSON.parse(readFileSync(SEED, "utf8"))
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!"
  const password = Array.from({ length: 18 }, () => alphabet[randomInt(alphabet.length)]).join("")
  const username = "kit@gauntlet.demo"
  const s: Seed = {
    url: PUBLIC,
    title: "Gauntlet",
    username,
    password,
    otpauth: `otpauth://totp/Gauntlet:${username}?secret=${b32(randomBytes(20))}&issuer=Gauntlet`,
    aliases: { phone: "+1 415 555 0123", customerNumber: "40021987", username: "kit" },
    pin: String(randomInt(100000, 1000000)),
    keypadPin: KEYPAD_PIN,
    birthday: "1990-07-04",
  }
  writeFileSync(SEED, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 })
  chmodSync(SEED, 0o600)
  return s
}

const s = seed()
const account: Account = {
  username: s.username,
  password: s.password,
  totp: new URL(s.otpauth).searchParams.get("secret") ?? undefined,
  aliases: [s.aliases.phone, s.aliases.customerNumber, s.aliases.username],
  pin: s.pin,
  birthday: s.birthday,
}

const handle = gauntlet({
  base: "",
  accounts: [account],
  sameSiteOrigin: () => process.env.GAUNTLET_SAME_SITE ?? null,
  crossSiteOrigin: () => process.env.GAUNTLET_CROSS_SITE ?? null,
  hint: `Sign in as <strong>${s.username}</strong> (save it to Deadbolt from seed.json, with its TOTP). The same account answers to ${s.aliases.phone}, customer number ${s.aliases.customerNumber} and username “${s.aliases.username}”; birth date ${s.birthday}.`,
})

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  async fetch(req) {
    return (await handle(req)) ?? new Response("not found", { status: 404 })
  },
})
console.log(`The Gauntlet: http://${server.hostname}:${server.port} (public ${PUBLIC})`)
