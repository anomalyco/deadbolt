// Turns an identity's or card's values (by the host's field names) into what
// each detected field wants: a full or split name, a street address joined
// or in lines, a phone number national or international, a country or region
// as a code, a name or the matching <select> option, birthday parts, an
// expiry as MM/YY, MM/YYYY or separate month and year, and a card number
// with or without spaces, or split across boxes. Pure functions: the element
// is read (its options, maxlength, placeholder, type), never written.

import type { FormRole, FormValues } from "../messages"
import type { FormControl } from "./detect"
import { plain } from "./forms"

const digits = (s: string) => s.replace(/\D/g, "")
const pad = (n: number | string) => String(n).padStart(2, "0")
const attr = (el: FormControl, name: string) => (el.getAttribute(name) ?? "").toLowerCase()
const maxLen = (el: FormControl) => (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && el.maxLength > 0 ? el.maxLength : 0

// ---- Places ------------------------------------------------------------------------

/** Calling codes for the countries whose national numbers the transforms know how to read. */
const CALLING: Record<string, string> = {
  US: "1", CA: "1", GB: "44", IE: "353", DE: "49", FR: "33", ES: "34", IT: "39", NL: "31", BE: "32", CH: "41", AT: "43",
  SE: "46", NO: "47", DK: "45", FI: "358", PT: "351", PL: "48", AU: "61", NZ: "64", JP: "81", CN: "86", IN: "91", BR: "55", MX: "52",
}
/** Countries that write a trunk 0 before national numbers. */
const TRUNK_ZERO = new Set(["GB", "IE", "DE", "FR", "IT", "NL", "BE", "CH", "AT", "SE", "NO", "FI", "PL", "AU", "NZ", "JP", "CN", "IN"])

const REGIONS: Record<string, Record<string, string>> = {
  US: {
    AL: "Alabama", AK: "Alaska", AZ: "Arizona", AR: "Arkansas", CA: "California", CO: "Colorado", CT: "Connecticut", DE: "Delaware",
    DC: "District of Columbia", FL: "Florida", GA: "Georgia", HI: "Hawaii", ID: "Idaho", IL: "Illinois", IN: "Indiana", IA: "Iowa",
    KS: "Kansas", KY: "Kentucky", LA: "Louisiana", ME: "Maine", MD: "Maryland", MA: "Massachusetts", MI: "Michigan", MN: "Minnesota",
    MS: "Mississippi", MO: "Missouri", MT: "Montana", NE: "Nebraska", NV: "Nevada", NH: "New Hampshire", NJ: "New Jersey",
    NM: "New Mexico", NY: "New York", NC: "North Carolina", ND: "North Dakota", OH: "Ohio", OK: "Oklahoma", OR: "Oregon",
    PA: "Pennsylvania", RI: "Rhode Island", SC: "South Carolina", SD: "South Dakota", TN: "Tennessee", TX: "Texas", UT: "Utah",
    VT: "Vermont", VA: "Virginia", WA: "Washington", WV: "West Virginia", WI: "Wisconsin", WY: "Wyoming", PR: "Puerto Rico",
  },
  CA: {
    AB: "Alberta", BC: "British Columbia", MB: "Manitoba", NB: "New Brunswick", NL: "Newfoundland and Labrador", NS: "Nova Scotia",
    NT: "Northwest Territories", NU: "Nunavut", ON: "Ontario", PE: "Prince Edward Island", QC: "Quebec", SK: "Saskatchewan", YT: "Yukon",
  },
  AU: { ACT: "Australian Capital Territory", NSW: "New South Wales", NT: "Northern Territory", QLD: "Queensland", SA: "South Australia", TAS: "Tasmania", VIC: "Victoria", WA: "Western Australia" },
}

/** Other names a country goes by in option lists. */
const COUNTRY_ALIASES: Record<string, string[]> = {
  US: ["usa", "us", "united states of america", "america"],
  GB: ["uk", "great britain", "britain", "england"],
  NL: ["holland"],
  KR: ["korea", "south korea"],
  RU: ["russia"],
}
/** ISO 3166-1 alpha-3 for the commonest countries, which some selects use as values. */
const ALPHA3: Record<string, string> = {
  US: "usa", CA: "can", GB: "gbr", DE: "deu", FR: "fra", ES: "esp", IT: "ita", NL: "nld", AU: "aus", JP: "jpn", MX: "mex", BR: "bra", IN: "ind", CN: "chn", IE: "irl", CH: "che", SE: "swe",
}

function regionName(code: string, lang: string): string | undefined {
  try {
    return new Intl.DisplayNames([lang], { type: "region" }).of(code)
  } catch {
    return undefined
  }
}

const pageLang = () => document.documentElement.lang || navigator.language || "en"

/** Every way the country is written: its code, alpha-3, its name in English and in the page's language, aliases. */
export function countryNames(code: string): string[] {
  const c = code.toUpperCase()
  const names = [c.toLowerCase(), ALPHA3[c], regionName(c, "en"), regionName(c, pageLang()), ...(COUNTRY_ALIASES[c] ?? [])]
  return [...new Set(names.filter((n): n is string => !!n).map((n) => plain(n).trim()))]
}

/** The region's code and name, whichever of the two the identity has. */
function regionForms(region: string, country: string): string[] {
  const table = REGIONS[country.toUpperCase()] ?? {}
  const r = plain(region).trim()
  for (const [code, name] of Object.entries(table)) if (code.toLowerCase() === r || plain(name).trim() === r) return [code.toLowerCase(), plain(name).trim()]
  return [r]
}

/**
 * The option whose value or text is one of `wanted` (already plain), exactly,
 * else one whose text starts with one ("Germany (+49)").
 */
export function matchOption(el: HTMLSelectElement, wanted: string[]): string | undefined {
  const opts = Array.from(el.options).filter((o) => !o.disabled)
  const exact = opts.find((o) => wanted.includes(plain(o.value).trim()) || wanted.includes(plain(o.text).trim()))
  if (exact) return exact.value
  return opts.find((o) => wanted.some((w) => w.length > 2 && plain(o.text).trim().startsWith(w)))?.value
}

// ---- Values per role -------------------------------------------------------------

/** The cardholder's given and family names: all but the last word, and the last. */
function splitName(full: string): [string, string] {
  const parts = full.trim().split(/\s+/)
  return parts.length < 2 ? [full.trim(), ""] : [parts.slice(0, -1).join(" "), parts[parts.length - 1]]
}

/** A phone number's parts: calling code and national digits, if the country is known. */
function phoneParts(phone: string, country: string): { code?: string; national: string; international: string } {
  const c = country.toUpperCase()
  const cc = CALLING[c]
  const d = digits(phone)
  if (phone.trim().startsWith("+") && cc && d.startsWith(cc)) {
    const rest = d.slice(cc.length)
    return { code: cc, national: TRUNK_ZERO.has(c) ? `0${rest}` : rest, international: `+${d}` }
  }
  if (phone.trim().startsWith("+")) return { national: d, international: `+${d}` }
  return { code: cc, national: d, international: cc ? `+${cc}${d.replace(/^0/, "")}` : phone }
}

/** YYYY-MM-DD as numbers, if that's what it is. */
function dateParts(iso: string): { y: number; m: number; d: number } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso)
  return m ? { y: +m[1], m: +m[2], d: +m[3] } : null
}

/** An expiry (YYYY-MM, or MM/YY as typed) as numbers. */
export function expiryParts(expiry: string): { y: number; m: number } | null {
  let m = /^(\d{4})-(\d{1,2})$/.exec(expiry.trim())
  if (m) return { y: +m[1], m: +m[2] }
  m = /^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/.exec(expiry.trim())
  if (m) return { y: m[2].length === 2 ? 2000 + +m[2] : +m[2], m: +m[1] }
  return null
}

const MONTH_WORDS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]

/** A month in a select: by number (with or without a leading zero) or by its English or local name. */
function monthOption(el: HTMLSelectElement, month: number): string | undefined {
  const local = (() => {
    try {
      return plain(new Intl.DateTimeFormat(pageLang(), { month: "long" }).format(new Date(2000, month - 1, 15))).trim()
    } catch {
      return ""
    }
  })()
  const byNumber = matchOption(el, [String(month), pad(month)])
  if (byNumber) return byNumber
  return Array.from(el.options).find((o) => {
    const t = plain(o.text).trim()
    return t.startsWith(MONTH_WORDS[month - 1]) || (!!local && t.startsWith(local.slice(0, 3))) || t.startsWith(`${pad(month)} `) || t.startsWith(`${month} `)
  })?.value
}

/** A year in a select, written in four digits or two. */
const yearOption = (el: HTMLSelectElement, year: number) => matchOption(el, [String(year), pad(year % 100)])

/**
 * How a single expiry box wants it, from its placeholder or label, then its
 * maxlength: MM/YY by default, MM/YYYY, MMYY or MM / YY.
 */
export function expiryText(el: FormControl, y: number, m: number): string {
  if (el instanceof HTMLInputElement && el.type === "month") return `${y}-${pad(m)}`
  const hint = `${attr(el, "placeholder")} ${attr(el, "aria-label")} ${attr(el, "title")}`
  const shape = /(mm|\d\d)(\s*)([/\-.]?)(\s*)(yyyy|aaaa|jjjj|yy|aa|jj)/.exec(hint)
  const len = maxLen(el)
  const long = shape ? shape[5].length === 4 : len >= 7 && len <= 9
  const year = long ? String(y) : pad(y % 100)
  if (shape) return `${pad(m)}${shape[2]}${shape[3]}${shape[4]}${year}`
  if (len === 4) return `${pad(m)}${year}`
  return `${pad(m)}/${year}`
}

/**
 * A card number for one box: spaced in fours when its placeholder shows
 * groups ("1234 1234 1234 1234"), else digits only. Masks that space it
 * themselves take digits.
 */
export function cardNumberText(el: FormControl, number: string): string {
  const d = digits(number)
  const placeholder = attr(el, "placeholder")
  const spaced = /\d{4} \d{4}/.test(placeholder) || /(•|x|\*){4} (•|x|\*){4}/i.test(placeholder)
  const len = maxLen(el)
  if (spaced && (!len || len >= d.length + Math.ceil(d.length / 4) - 1)) return d.replace(/(\d{4})(?=\d)/g, "$1 ")
  return d
}

/**
 * What each role writes, given the values and the element. Undefined: the
 * values don't have it, or (for a select) no option matches.
 */
export function valueFor(role: FormRole, el: FormControl, v: FormValues): string | undefined {
  const select = el instanceof HTMLSelectElement ? el : null
  const text = (s: string | undefined) => {
    if (!s) return undefined
    return select ? matchOption(select, [plain(s).trim()]) : s
  }
  switch (role) {
    case "name":
      return text([v["given-name"], v["additional-name"], v["family-name"]].filter(Boolean).join(" ") || undefined)
    case "honorific-prefix":
      return text(v.honorific)
    case "given-name":
    case "additional-name":
    case "family-name":
    case "email":
    case "address-line1":
    case "address-line2":
    case "address-line3":
    case "postal-code":
      return text(v[role])
    case "organization":
      return text(v.organization)
    case "organization-title":
      return text(v["job-title"])
    case "address-level2":
      return text(v.city)
    case "street-address": {
      const lines = [v["address-line1"], v["address-line2"], v["address-line3"]].filter(Boolean)
      if (!lines.length) return undefined
      return el instanceof HTMLTextAreaElement ? lines.join("\n") : lines.join(", ")
    }
    case "address-level1": {
      if (!v.region) return undefined
      const forms = regionForms(v.region, v.country ?? "")
      if (select) return matchOption(select, forms)
      // A two- or three-letter box takes the code.
      const len = maxLen(el)
      return len > 0 && len <= 3 && forms[0].length <= len ? forms[0].toUpperCase() : v.region
    }
    case "country": {
      if (!v.country) return undefined
      const names = countryNames(v.country)
      if (select) return matchOption(select, names)
      const len = maxLen(el)
      if (len === 2) return v.country.toUpperCase()
      if (len === 3) return (ALPHA3[v.country.toUpperCase()] ?? v.country).toUpperCase()
      return regionName(v.country.toUpperCase(), pageLang()) ?? v.country
    }
    case "tel":
    case "tel-national":
    case "tel-country-code": {
      if (!v.phone) return undefined
      const p = phoneParts(v.phone, v.country ?? "")
      if (role === "tel-country-code") {
        if (!p.code) return undefined
        return select ? matchOption(select, [`+${p.code}`, p.code, plain(v.country ?? "").trim(), ...countryNames(v.country ?? "").map((n) => `${n} ${p.code}`)]) : `+${p.code}`
      }
      // A box too short for the number with its country code, or a form with
      // a country code box of its own, takes the national number.
      const len = maxLen(el)
      const national = role === "tel-national" || (len > 0 && len < p.international.length) || hasCountryCodeBox(el)
      return national ? p.national : p.international
    }
    case "bday":
    case "bday-day":
    case "bday-month":
    case "bday-year": {
      const d = v.birthday ? dateParts(v.birthday) : null
      if (!d) return undefined
      if (role === "bday-day") return select ? matchOption(select, [String(d.d), pad(d.d)]) : maxLen(el) === 1 ? String(d.d) : pad(d.d)
      if (role === "bday-month") return select ? monthOption(select, d.m) : pad(d.m)
      if (role === "bday-year") return select ? yearOption(select, d.y) : maxLen(el) === 2 ? pad(d.y % 100) : String(d.y)
      if (el instanceof HTMLInputElement && el.type === "date") return `${d.y}-${pad(d.m)}-${pad(d.d)}`
      // A text box: the order its placeholder shows, else the page's locale's.
      const hint = attr(el, "placeholder")
      const dayFirst = /^d/.test(hint) || (!/^m/.test(hint) && !/^y/.test(hint) && !/^en-us/i.test(pageLang()) && !/^en$/i.test(pageLang()))
      if (/^y/.test(hint)) return `${d.y}-${pad(d.m)}-${pad(d.d)}`
      const sep = /[./-]/.exec(hint)?.[0] ?? "/"
      return dayFirst ? [pad(d.d), pad(d.m), d.y].join(sep) : [pad(d.m), pad(d.d), d.y].join(sep)
    }
    case "cc-name":
      return text(v.cardholder)
    case "cc-given-name":
      return v.cardholder ? text(splitName(v.cardholder)[0]) : undefined
    case "cc-family-name":
      return v.cardholder ? text(splitName(v.cardholder)[1] || undefined) : undefined
    case "cc-number":
      return v.number ? cardNumberText(el, v.number) : undefined
    case "cc-csc":
      return v.cvv ? digits(v.cvv) : undefined
    case "cc-type": {
      if (!v.brand) return undefined
      const b = plain(v.brand).trim()
      const aliases = b === "american express" ? [b, "amex"] : b === "mastercard" ? [b, "master card", "mc"] : [b]
      return select ? matchOption(select, aliases) ?? Array.from(select.options).find((o) => plain(o.text).includes(` ${aliases[0].split(" ")[0]}`))?.value : v.brand
    }
    case "cc-exp":
    case "cc-exp-month":
    case "cc-exp-year": {
      const e = v.expiry ? expiryParts(v.expiry) : null
      if (!e) return undefined
      if (role === "cc-exp") return select ? undefined : expiryText(el, e.y, e.m)
      if (role === "cc-exp-month") return select ? monthOption(select, e.m) : maxLen(el) === 1 ? String(e.m) : pad(e.m)
      if (select) return yearOption(select, e.y)
      return maxLen(el) === 2 || /yy(?!yy)/.test(attr(el, "placeholder")) ? pad(e.y % 100) : String(e.y)
    }
  }
}

/** The field's form also has a box (or select) for the calling code. */
function hasCountryCodeBox(el: FormControl): boolean {
  const scope = el.form ?? el.closest("form") ?? el.ownerDocument
  return Array.from(scope.querySelectorAll("input, select")).some((o) => o !== el && /tel-country-code/.test(o.getAttribute("autocomplete") ?? ""))
}

/** A card number's slice for box `i` of `boxes`: as many digits as each box takes, four by default. */
export function splitNumber(number: string, boxes: FormControl[]): string[] {
  const d = digits(number)
  const out: string[] = []
  let at = 0
  boxes.forEach((b, i) => {
    const len = i === boxes.length - 1 ? d.length - at : maxLen(b) || 4
    out.push(d.slice(at, at + len))
    at += len
  })
  return out
}
