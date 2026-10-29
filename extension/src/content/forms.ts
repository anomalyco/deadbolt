// Identity and payment field detection: names, email, phone, postal
// addresses, birthdays and cards, grouped into sections (a shipping address,
// a billing address, a card). Login detection (detect.ts) is separate and
// unchanged; on a field both could claim (an email box), a login form wins.
//
// A field's role comes from its autocomplete token first (the HTML spec's
// names, which are the roles' names here), then from its labels and
// placeholder, then from its id and name, in a few languages, then from its
// shape: inputmode, maxlength, and a <select>'s options (countries, regions,
// months, years). Text is matched in memory only; nothing here leaves the page.

import { CARD_ROLES, FORM_ROLES, formKindOf, type FormRole } from "../messages"
import type { FormKind } from "../protocol"
import { ignored, isVisible, labelText, type FormControl } from "./detect"
import { deepQueryAll, openRoots } from "./shadow"

export interface FormField {
  el: FormControl
  role: FormRole
  kind: FormKind
  /** The section the field belongs to (see sectionsOf): a pick fills every field of its section. */
  section: string
  /** On each box of a card number split into several boxes: how many boxes. */
  split?: number
  /** Where the field was when the page was scanned: its form, and the node it's a child of. */
  form: HTMLFormElement | null
  parent: Node | null
}

/** The field is still where it was scanned. */
export const formFieldInPlace = (f: FormField) =>
  f.el.isConnected && (f.el.form ?? f.el.closest("form")) === f.form && f.el.parentNode === f.parent

const SKIP_TYPES = new Set(["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range", "color", "password", "search", "time", "week", "datetime-local"])
/** Section modifiers that can come before the field name in an autocomplete attribute. */
const MODIFIER = /^(section-.+|shipping|billing|home|work|mobile|fax|pager)$/
const LOGIN_TOKENS = new Set(["username", "current-password", "new-password", "one-time-code", "webauthn"])
/** Tokens that name a role here, beyond the roles' own names. */
const TOKEN_ALIAS: Record<string, FormRole> = {
  "country-name": "country",
  "tel-local": "tel-national",
  "honorific-suffix": "honorific-prefix",
  "cc-additional-name": "cc-name",
  "cc-exp-year": "cc-exp-year",
}
const KNOWN = new Set<string>(FORM_ROLES)

/** Lowercase, accent-free text with only letters, digits and slashes, single spaced. */
export function plain(text: string): string {
  return ` ${text
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .replace(/[^\p{L}\p{N}/]+/gu, " ")
    .trim()} `
}

// ---- Text clues --------------------------------------------------------------

/**
 * Whole words for Latin and Cyrillic text; CJK, which runs words together,
 * matches anywhere. The patterns below are written `\b(…)\b` for reading.
 */
const w = (r: RegExp) =>
  new RegExp(r.source.replace(/^\\b\(/, "(?<![\\p{Script=Latin}\\p{Script=Cyrillic}\\p{N}])(?:").replace(/\)\\b$/, ")(?![\\p{Script=Latin}\\p{Script=Cyrillic}\\p{N}])"), "u")

/** Never a card or an address: coupons, gift cards, searches and the like. */
const NOT_A_FORM_FIELD = w(/\b(gift ?card|coupon|promo|voucher|discount|search|captcha|loyalty|referral|quantity|qty|comment|message|subject|newsletter|subscribe)\b/)
const CARD_CONTEXT = w(/\b(card|credit|debit|cc|kreditkarte|tarjeta|carte|carta|cartao|kaart|カード|卡)\b/)

/** In order: the first that matches wins, so narrower roles come before the ones they'd be mistaken for. */
const CLUES: Array<[FormRole, RegExp]> = ([
  ["cc-csc", /\b(cvc2?|cvv2?|cvn|csc|cid|security code|card verification|verification (code|number|value)|codigo de seguridad|code de securite|cryptogramme|prufnummer|kartenprufnummer|sicherheitscode|codice di sicurezza|beveiligingscode|セキュリティコード|安全码)\b/],
  ["cc-number", /\b(card ?(number|no|num|nr)|cc ?(num|number|no)|ccnumber|cardnumber|credit card|debit card|numero de (la )?tarjeta|numero de carte|kartennummer|numero (della )?carta|kaartnummer|numero do cartao|カード番号|卡号|номер карты)\b/],
  ["cc-exp", /\b(mm ?\/? ?(yyyy|yy|aaaa|aa|jjjj|jj))\b/],
  ["cc-exp-month", /\b((exp|expiry|expiration|expires|valid|ablauf|venc\w*|caduc\w*|scad\w*)\s*(\w+\s+)?(month|mm|mois|monat|mes|mese)|(month|mm|mois|monat|mes)\s*(of\s+)?(exp\w*)|cc ?exp ?month|cc ?month|exp ?mm)\b/],
  ["cc-exp-year", /\b((exp|expiry|expiration|expires|valid|ablauf|venc\w*|caduc\w*|scad\w*)\s*(\w+\s+)?(year|yy|yyyy|annee|jahr|ano|anno)|(year|yy|yyyy)\s*(of\s+)?(exp\w*)|cc ?exp ?year|cc ?year|exp ?yy(yy)?)\b/],
  ["cc-exp", /\b(exp(iry|iration|ires)?( date)?|valid (thru|through|until)|mm ?\/? ?(yy|yyyy|aa|jj)|ablaufdatum|gultig bis|fecha de (vencimiento|caducidad)|date d expiration|scadenza|vervaldatum|有効期限|有效期)\b/],
  ["cc-name", /\b(name on (the )?card|card ?holder|cardholder|holder name|(card|cc) ?name|nom (du|sur la) (titulaire|carte)|titulaire|karteninhaber|titular( de la tarjeta)?|intestatario|kaarthouder|カード名義)\b/],
  ["cc-type", /\b(card ?type|card ?brand|cc ?type|kartentyp|tipo de tarjeta)\b/],
  ["email", /\b(e ?mail|courriel|correo|メール|邮箱|почта)\b/],
  ["tel-country-code", /\b(country code|calling code|dial(ing)? code|phone code|indicatif|landesvorwahl|prefijo)\b/],
  ["tel", /\b(phone|mobile|tel|telephone|telefon|telefono|telefone|telefoon|handy|cell|portable|携帯|電話|电话|手机|телефон)\b/],
  ["organization-title", /\b(job ?title|position|organization title|berufsbezeichnung|cargo|poste|funzione)\b/],
  ["organization", /\b(company|organi[sz]ation|business name|firma|unternehmen|empresa|societe|entreprise|azienda|bedrijf|会社|公司)\b/],
  ["additional-name", /\b(middle ?name|middle initial|middle|second name|zweiter vorname)\b/],
  ["given-name", /\b(first ?name|given ?name|forename|fname|first|vorname|prenom|nombre(?! (de usuario|completo))|nome(?! (completo|utente))|voornaam|primeiro nome|имя)\b/],
  ["family-name", /\b(last ?name|surname|family ?name|lname|last|nachname|familienname|nom de famille|nom(?! complet)|apellidos?|cognome|achternaam|sobrenome|фамилия)\b/],
  ["honorific-prefix", /\b(salutation|honorific|anrede|civilite|tratamiento|prefix)\b/],
  ["address-line3", /\b(address ?(line)? ?3|address3|addr3|street3)\b/],
  ["address-line2", /\b(address ?(line)? ?2|address2|addr2|street2|apt|apartment|suite|unit|flat|floor|building|adresszusatz|complemento|complement( d adresse)?|piso)\b/],
  ["address-line1", /\b(address ?(line)? ?1|address1|addr1|street1|street( address)?|address|strasse|stra[sß]e und hausnummer|calle|rue|straat|direccion|adresse|indirizzo|endereco|住所|地址|адрес)\b/],
  ["postal-code", /\b(zip( ?code)?|postal( ?code)?|post ?code|postcode|plz|postleitzahl|codigo postal|code postal|cep|cap|郵便番号|邮编|индекс)\b/],
  ["address-level2", /\b(city|town|suburb|locality|ort|stadt|ciudad|ville|citta|localidad|cidade|plaats|市区町村|城市|город)\b/],
  ["address-level1", /\b(state|province|region|county|prov|bundesland|estado|provincia|departement|都道府県|省|область)\b/],
  ["country", /\b(country|nation|land|pais|pays|paese|国|страна)\b/],
  // After every role whose label ends in "name" (street, city, state, country, company…), and never for those.
  ["name", /\b(full ?name|your name|(?<!(street|city|town|country|state|province|region|company|business|user|account|card|display|screen|nick|middle|first|last|family|given) )name|nombre completo|nom complet|vollstandiger name|nome completo|お名前|氏名|姓名)\b/],
  ["bday", /\b(birth|birthday|birthdate|dob|date of birth|geburts\w*|nacimiento|naissance|nascita|geboortedatum|生年月日|出生)\b/],
] as Array<[FormRole, RegExp]>).map(([role, re]) => [role, w(re)])

const DAY = w(/\b(day|dd|tag|dia|jour|giorno)\b/)
const MONTH = w(/\b(month|mm|monat|mes|mois|mese)\b/)
const YEAR = w(/\b(year|yyyy|yy|jahr|ano|annee|anno)\b/)
/** Logins' own words: a field that says these isn't a name or address. */
const LOGIN_WORDS = w(/\b(user ?name|login|password|passwort|account|benutzername)\b/)

/** The role text names, if any: a label first, then the id and name. */
function fromText(display: string, code: string): FormRole | null {
  for (const text of [display, code]) {
    if (!text.trim() || NOT_A_FORM_FIELD.test(text) || LOGIN_WORDS.test(text)) continue
    for (const [role, re] of CLUES) {
      if (!re.test(text)) continue
      // "Name" next to "card" is the cardholder; plain "card" words never make an address.
      if (role === "name" && CARD_CONTEXT.test(text)) return "cc-name"
      if (role === "bday") return DAY.test(text) ? "bday-day" : MONTH.test(text) ? "bday-month" : YEAR.test(text) ? "bday-year" : "bday"
      return role
    }
  }
  return null
}

function autocompleteRole(el: FormControl): FormRole | "login" | null {
  const tokens = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).filter(Boolean)
  const name = tokens.filter((t) => !MODIFIER.test(t)).pop()
  if (!name) return null
  if (LOGIN_TOKENS.has(name)) return "login"
  const role = TOKEN_ALIAS[name] ?? name
  return KNOWN.has(role) ? (role as FormRole) : null
}

/** "shipping" or "billing" from the autocomplete attribute's own section words. */
function tokenSection(el: FormControl): string {
  const tokens = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/)
  return tokens.find((t) => t === "shipping" || t === "billing") ?? tokens.find((t) => t.startsWith("section-")) ?? ""
}

// ---- Shape clues ---------------------------------------------------------------

const MONTH_NAMES = /^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|janv|fevr|mars|avr|mai|juin|juil|aout|sept|okt|dez|ene|abr|ago|dic|gen|mag|giu|lug|set|ott)/
const COUNTRY_WORDS = /^(united states|canada|united kingdom|germany|deutschland|france|spain|espana|italy|italia|japan|australia|mexico|netherlands|brazil|brasil|india|china|sweden|switzerland|ireland)$/
const US_STATE_WORDS = /^(alabama|alaska|arizona|california|colorado|florida|georgia|new york|texas|washington|ohio|oregon|ontario|quebec|british columbia|new south wales|victoria|queensland)$/

/** What a select's options are, if they say: months, days, years (past or future), countries or regions. */
export function optionsKind(el: HTMLSelectElement): "month" | "day" | "past-year" | "future-year" | "country" | "region" | null {
  const opts = Array.from(el.options)
    .map((o) => ({ value: o.value.trim().toLowerCase(), text: plain(o.text).trim() }))
    .filter((o) => o.value || o.text)
  const numbers = opts.map((o) => Number(o.value || o.text)).filter((n) => Number.isInteger(n))
  const year = new Date().getFullYear()
  if (opts.length >= 12 && opts.length <= 14 && opts.filter((o) => MONTH_NAMES.test(o.text)).length >= 10) return "month"
  if (numbers.length >= 12 && numbers.length <= 13 && numbers.every((n) => n >= 0 && n <= 12)) return "month"
  if (numbers.length >= 28 && numbers.length <= 32 && numbers.every((n) => n >= 0 && n <= 31)) return "day"
  const years = numbers.filter((n) => n >= 1900 && n <= year + 30)
  if (years.length >= 5 && years.length >= numbers.length - 1) return years.filter((y) => y >= year).length > years.length / 2 ? "future-year" : "past-year"
  const twoDigit = numbers.filter((n) => n >= year % 100 && n <= (year % 100) + 25)
  if (twoDigit.length >= 5 && twoDigit.length === numbers.length && opts.every((o) => /^\d{2}$/.test(o.value || o.text))) return "future-year"
  if (opts.length >= 20 && opts.filter((o) => COUNTRY_WORDS.test(o.text)).length >= 3) return "country"
  if (opts.length >= 10 && opts.filter((o) => US_STATE_WORDS.test(o.text)).length >= 3) return "region"
  return null
}

/** The role a select's options give it, in a card section or not. */
function roleFromOptions(el: HTMLSelectElement, card: boolean): FormRole | null {
  switch (optionsKind(el)) {
    case "month":
      return card ? "cc-exp-month" : "bday-month"
    case "future-year":
      return card ? "cc-exp-year" : null
    case "past-year":
      return "bday-year"
    case "day":
      return "bday-day"
    case "country":
      return "country"
    case "region":
      return "address-level1"
  }
  return null
}

/** A select labelled only "month" or "year": what kind follows from its section. */
function roleForDatePart(role: FormRole | null, el: FormControl, display: string, card: boolean): FormRole | null {
  if (role) return role
  if (!MONTH.test(display) && !YEAR.test(display)) return null
  const month = MONTH.test(display)
  if (card) return month ? "cc-exp-month" : "cc-exp-year"
  return el instanceof HTMLSelectElement ? roleFromOptions(el, false) : null
}

// ---- The page ------------------------------------------------------------------

const eligible = (el: Element): el is FormControl =>
  (el instanceof HTMLInputElement && !SKIP_TYPES.has((el.getAttribute("type") || "text").toLowerCase())) || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement

interface Candidate {
  el: FormControl
  role: FormRole | null
  display: string
  code: string
  maxLength: number
}

function codeOf(el: Element): string {
  return plain([el.id, el.getAttribute("name"), el.getAttribute("data-testid")].filter(Boolean).join(" ").replace(/[_\-[\].]+/g, " "))
}

/** Every visible identity or payment field in the page, by role and section. */
export function scanForms(roots = openRoots()): FormField[] {
  const found: Candidate[] = []
  for (const el of deepQueryAll("input, select, textarea", roots).slice(0, 300)) {
    if (!eligible(el) || !isVisible(el) || ignored(el)) continue
    const ac = autocompleteRole(el)
    if (ac === "login") continue
    const display = plain(labelText(el))
    const code = codeOf(el)
    let role = ac ?? fromText(display, code)
    // A street address in one box is a textarea.
    if (role === "address-line1" && el instanceof HTMLTextAreaElement) role = "street-address"
    if (el instanceof HTMLTextAreaElement && role && role !== "street-address") role = null
    // A box for a full date wants the birthday whole.
    if (el instanceof HTMLInputElement && el.type === "date" && role?.startsWith("bday")) role = "bday"
    if (el instanceof HTMLInputElement && el.type === "month" && role?.startsWith("cc-exp")) role = "cc-exp"
    if (el instanceof HTMLInputElement && el.type === "email" && !role) role = "email"
    if (el instanceof HTMLInputElement && el.type === "tel" && !role) role = "tel"
    found.push({ el, role, display, code, maxLength: el instanceof HTMLInputElement && el.maxLength > 0 ? el.maxLength : 0 })
  }
  splitCardBoxes(found)
  // Selects and date parts with no role of their own: their options, or their section, say.
  const cardForms = new Set(found.filter((c) => c.role && formKindOf(c.role) === "card").map((c) => formOf(c.el)))
  for (const c of found) {
    if (c.role) continue
    const card = cardForms.has(formOf(c.el))
    c.role = roleForDatePart(null, c.el, c.display + c.code, card) ?? (c.el instanceof HTMLSelectElement ? roleFromOptions(c.el, card) : null)
  }
  const fields = sectionsOf(found.filter((c): c is Candidate & { role: FormRole } => c.role !== null))
  // One lone box guessed from its text (a newsletter's email, a phone
  // number on its own) isn't an address form; one the site marked is.
  const tokened = new Set(found.filter((c) => autocompleteRole(c.el) !== null).map((c) => c.el))
  const size = new Map<string, number>()
  for (const f of fields) size.set(f.section, (size.get(f.section) ?? 0) + 1)
  return fields.filter((f) => f.kind === "card" || size.get(f.section)! > 1 || tokened.has(f.el))
}

const formOf = (el: Element): HTMLFormElement | null => (el as FormControl).form ?? el.closest("form")

/**
 * A card number in several short boxes: the first says so (its label, name
 * or token), and the next few short boxes in the same form, with nothing of
 * their own to say, are the rest of it. Each box gets the number's role.
 */
function splitCardBoxes(found: Candidate[]) {
  for (let i = 0; i < found.length; i++) {
    const first = found[i]
    if (first.role !== "cc-number" || !first.maxLength || first.maxLength > 6) continue
    const group = [first]
    for (let j = i + 1; j < found.length && group.length < 5; j++) {
      const next = found[j]
      const short = next.el instanceof HTMLInputElement && next.maxLength > 0 && next.maxLength <= 6
      if (!short || formOf(next.el) !== formOf(first.el) || (next.role && next.role !== "cc-number")) break
      group.push(next)
    }
    if (group.length < 2) continue
    for (const c of group) c.role = "cc-number"
    ;(first as Candidate & { split?: number }).split = group.length
    for (const c of group) (c as Candidate & { split?: number }).split = group.length
    i += group.length - 1
  }
}

const SECTION_WORDS: Array<[string, RegExp]> = ([
  ["billing", /\b(billing|bill to|invoice|payment address|rechnung\w*|facturation|facturacion|fatturazione|factuur\w*)\b/],
  ["shipping", /\b(shipping|ship to|delivery|deliver to|liefer\w*|versand\w*|livraison|envio|entrega|spedizione|bezorg\w*)\b/],
] as Array<[string, RegExp]>).map(([name, re]) => [name, w(re)])

/** "billing" or "shipping" from the field's surroundings: its ancestors' names, a legend or heading in them. */
function contextSection(el: Element): string {
  let node = el.parentElement
  const form = formOf(el)
  for (let depth = 0; node && depth < 8; depth++, node = node.parentElement) {
    const own = plain([node.id, node.getAttribute("class"), node.getAttribute("aria-label"), node.getAttribute("data-section")].filter(Boolean).join(" ").replace(/[_\-]+/g, " "))
    const heading = node.querySelector(":scope > legend, :scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > [role=heading]")
    const text = own + plain(heading?.textContent?.slice(0, 120) ?? "")
    for (const [name, re] of SECTION_WORDS) if (re.test(text)) return name
    if (node === form) break
  }
  return ""
}

/**
 * Groups fields into sections: per form (or the page, for fields outside
 * one), then by the autocomplete section words, then by their
 * surroundings (a "Billing address" fieldset), and a role seen twice
 * without either starts a new section (two address blocks one after the
 * other). Card fields are a section of their own in each form.
 */
function sectionsOf(found: Array<Candidate & { role: FormRole; split?: number }>): FormField[] {
  const forms: Array<HTMLFormElement | null> = []
  const out: FormField[] = []
  const counters = new Map<string, { n: number; seen: Set<FormRole> }>()
  for (const c of found) {
    const form = formOf(c.el)
    if (!forms.includes(form)) forms.push(form)
    const kind = formKindOf(c.role)
    const tag = tokenSection(c.el) || contextSection(c.el)
    const base = `${forms.indexOf(form)}:${kind}:${tag}`
    let counter = counters.get(base)
    if (!counter) counters.set(base, (counter = { n: 0, seen: new Set() }))
    const repeats = counter.seen.has(c.role) && !c.split && kind === "identity"
    if (repeats) counter = { n: counter.n + 1, seen: new Set() }
    counters.set(base, counter)
    counter.seen.add(c.role)
    out.push({ el: c.el, role: c.role, kind, section: `${base}:${counter.n}`, split: c.split, form, parent: c.el.parentNode })
  }
  return out
}

/** The fields of one section; for a card, every card field of the scan (a card is one per page in practice). */
export function sectionFields(fields: FormField[], section: string | undefined, kind: FormKind): FormField[] {
  return fields.filter((f) => f.kind === kind && (kind === "card" || section === undefined || f.section === section))
}

export const isCardRole = (role: FormRole) => (CARD_ROLES as readonly string[]).includes(role)
