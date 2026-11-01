// A whole postal address written on one line ("1112 Cole St, San Francisco,
// CA, 94117, United States"), split into street, city, region, postal code
// and country, for identities that keep all of it in their first address
// line. Reads from the end: a country, then a postal code and region in the
// shapes the US, Canada, Australia, the UK and "PLZ City" countries write
// them, then the city; what's left is the street. Anything it isn't sure of
// gives null, and the line is filled whole as before. Pure: nothing here
// reads or writes the page.

import type { FormRole, FormValues } from "../messages"
import { plain } from "./forms"
import { COUNTRY_ALIASES, REGIONS } from "./transform"

export interface AddressParts {
  line1: string
  /** A second street part: a unit, or the street after a flat number. */
  line2?: string
  city: string
  /** The region's code where it's in REGIONS ("CA"), else as written. */
  region?: string
  postal?: string
  /** ISO 3166-1 alpha-2. */
  country?: string
}

/** Postal codes by country, for the countries whose regions REGIONS knows, and the UK. */
const POSTAL: Record<string, RegExp> = {
  US: /^\d{5}(?:-\d{4})?$/,
  CA: /^[A-Z]\d[A-Z] ?\d[A-Z]\d$/i,
  AU: /^\d{4}$/,
  GB: /^[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}$/i,
}
/** Any postal code read on its own: the above, four or five digits, or the Dutch "1234 AB". */
const ANY_POSTAL = /^(?:\d{5}(?:-\d{4})?|\d{4}(?: ?[A-Z]{2})?|[A-Z]\d[A-Z] ?\d[A-Z]\d|[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2})$/i
/** "CA 94117", "ON M5V 2T6", "London SW1A 1AA": something, then a postal code. */
const BEFORE_POSTAL = /^(.*\S)\s+(\d{5}(?:-\d{4})?|\d{4}|[A-Z]\d[A-Z] ?\d[A-Z]\d|[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2})$/i
/** "10115 Berlin", "1012 AB Amsterdam": a postal code, then the city. */
const POSTAL_FIRST = /^(\d{4,5}|\d{4} ?[A-Z]{2})\s+(\p{L}.*)$/u
const UNIT = /^(?:(?:apt|apartment|suite|ste|unit|flat|floor|fl|room|rm|bldg|building)\.?\s|#\s?\d)/i
const letters = (s: string) => /\p{L}/u.test(s)

let countries: Map<string, string> | null = null
/** Codes Intl names that aren't countries now: old ones ("DD", East Germany) and groupings. */
const NOT_COUNTRIES = new Set(["AN", "BU", "CS", "DD", "EU", "EZ", "FX", "NT", "QO", "QU", "SU", "TP", "UN", "XA", "XB", "YU", "ZR", "ZZ"])

/** The country a name stands for: its name in English or a few other languages, or a common alias ("USA", "UK"). */
export function countryCode(text: string): string | undefined {
  const t = plain(text).trim()
  if (!t) return undefined
  if (!countries) {
    countries = new Map()
    for (const [code, aliases] of Object.entries(COUNTRY_ALIASES)) for (const a of aliases) countries.set(a, code)
    const langs = [...new Set(["en", "de", "fr", "es", "it", "nl", "pt", globalThis.document?.documentElement.lang || globalThis.navigator?.language || "en"])]
    for (const lang of langs) {
      let names: Intl.DisplayNames
      try {
        names = new Intl.DisplayNames([lang], { type: "region" })
      } catch {
        continue
      }
      for (let a = 65; a <= 90; a++)
        for (let b = 65; b <= 90; b++) {
          const code = String.fromCharCode(a, b)
          if (NOT_COUNTRIES.has(code)) continue
          const name = names.of(code)
          if (name && name !== code && !countries.has(plain(name).trim())) countries.set(plain(name).trim(), code)
        }
    }
  }
  return countries.get(t)
}

/** The region `text` names (its code or its name), in `country` if known, else in any table. */
function findRegion(text: string, country?: string, postal?: string): { code: string; country: string } | undefined {
  const t = plain(text).trim()
  if (!t) return undefined
  const tables = country ? [country] : Object.keys(REGIONS)
  const found = tables.flatMap((c) =>
    Object.entries(REGIONS[c] ?? {})
      .filter(([code, name]) => code.toLowerCase() === t || plain(name).trim() === t)
      .map(([code]) => ({ code, country: c })),
  )
  // "WA" is in two tables: the postal code says which.
  return found.find((r) => !postal || !POSTAL[r.country] || POSTAL[r.country].test(postal)) ?? (postal ? undefined : found[0])
}

/** The parts of a one-line address, or null when they can't be told apart with confidence. */
export function parseAddress(line: string): AddressParts | null {
  const parts = line.split(/\s*[,\n]\s*/).map((p) => p.trim()).filter(Boolean)
  if (parts.length < 2) return null
  let country = countryCode(parts[parts.length - 1])
  if (country) parts.pop()
  let postal: string | undefined
  let region: { code: string; country: string } | undefined
  let city: string | undefined
  const last = () => parts[parts.length - 1] ?? ""

  if (ANY_POSTAL.test(last())) {
    // "…, CA, 94117" or "…, London, SW1A 1AA"
    postal = parts.pop()
    region = parts.length > 2 ? findRegion(last(), country, postal) : undefined
    if (region) parts.pop()
  } else {
    let m = BEFORE_POSTAL.exec(last())
    if (m) {
      // "…, CA 94117", "…, London SW1A 1AA", "…, San Francisco CA 94117"
      parts.pop()
      postal = m[2]
      region = findRegion(m[1], country, postal)
      if (!region) {
        // "ZZ 94117": a code for a region this doesn't know.
        if (/^[A-Z]{2,3}$/.test(m[1])) return null
        const words = /^(.*\S)\s+([A-Z]{2,3})$/.exec(m[1])
        region = words ? findRegion(words[2], country, postal) : undefined
        city = region ? words![1] : m[1]
      }
    } else if ((m = POSTAL_FIRST.exec(last()))) {
      // "…, 10115 Berlin"
      parts.pop()
      postal = m[1]
      city = m[2]
    } else {
      // "…, San Francisco, CA" with no postal code
      region = parts.length > 2 ? findRegion(last(), country) : undefined
      if (region) parts.pop()
    }
  }
  if (!postal && !region) return null
  if (region) country ??= region.country
  // Five digits alone could be anywhere; Canada's and the UK's codes say where they are.
  if (postal && !country) country = POSTAL.CA.test(postal) ? "CA" : POSTAL.GB.test(postal) ? "GB" : undefined
  if (postal && country && POSTAL[country] && !POSTAL[country].test(postal)) return null
  if (region && region.country !== country) return null
  city ??= parts.pop()
  if (!city || !letters(city) || /\d/.test(city)) return null
  if (parts.length < 1 || parts.length > 3 || !parts.every(letters)) return null
  // A unit ("Apt 4", "Flat 2") goes second, whichever way round it was written.
  const unit = parts.length === 2 ? parts.findIndex((p) => UNIT.test(p)) : -1
  const street = unit === 0 ? [parts[1], parts[0]] : parts
  return {
    line1: street[0],
    ...(street.length > 1 ? { line2: street.slice(1).join(", ") } : {}),
    city,
    ...(region ? { region: region.code } : {}),
    ...(postal ? { postal: postal.toUpperCase() } : {}),
    ...(country ? { country } : {}),
  }
}

const SEPARATE: FormRole[] = ["address-level2", "postal-code", "address-level1"]

/**
 * The identity's values with a whole address in its first line split into
 * the parts a form asks for separately (a city box, a postal code box, a
 * state): the street goes into the first line, a unit into the second if
 * the form has one, and the rest into their own fields. The identity's own
 * fields always win. A form with one address box, or an address that can't
 * be split with confidence, keeps the line whole.
 */
export function withAddressParts(v: FormValues, roles: FormRole[]): FormValues {
  const line = v["address-line1"]
  if (!line || v.city || v["postal-code"] || !roles.includes("address-line1") || !roles.some((r) => SEPARATE.includes(r))) return v
  const p = parseAddress(line)
  if (!p) return v
  const second = roles.includes("address-line2") && !v["address-line2"]
  return {
    ...v,
    "address-line1": p.line2 && !second ? `${p.line1}, ${p.line2}` : p.line1,
    ...(p.line2 && second ? { "address-line2": p.line2 } : {}),
    city: p.city,
    ...(p.postal ? { "postal-code": p.postal } : {}),
    ...(p.region && !v.region ? { region: p.region } : {}),
    ...(p.country && !v.country ? { country: p.country } : {}),
  }
}
