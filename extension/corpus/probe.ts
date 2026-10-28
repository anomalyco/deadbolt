// Runs inside each frame of a crawled page (bundled to an IIFE by crawl.ts).
// It records facts about every input and runs Deadbolt's real detector
// (src/content/detect.ts) on the live DOM. Read-only: it never types, focuses
// or submits anything. `clickEntry` is the only thing that touches the page,
// and only when the crawler follows a sign-in button that has no link.

import { isVisible, scanPage } from "../src/content/detect"
import { openRoots, deepQueryAll } from "../src/content/shadow"

export interface Rect {
  x: number
  y: number
  w: number
  h: number
}

export interface InputFact {
  i: number
  type: string
  name: string
  id: string
  autocomplete: string
  placeholder: string
  ariaLabel: string
  label: string
  maxLength: number
  inputMode: string
  visible: boolean
  inShadow: boolean
  formActionHost: string
  rect: Rect
  /** Detector's role for this field, null when it skipped or didn't classify it. */
  role: string | null
  split?: number
  /** Outside the form the detector judged (it reports that form's fields only). */
  outOfScope?: boolean
}

export interface FrameProbe {
  url: string
  origin: string
  title: string
  kind: string | null
  submit: { text: string; rect: Rect } | null
  inputs: InputFact[]
  shadowRoots: number
  /** Iframes from other hosts, by src host. */
  iframes: Array<{ host: string; src: string; visible: boolean; rect: Rect }>
  ssoButtons: string[]
  challenge: boolean
  error?: string
  scanMs: number
}

export interface EntryCandidate {
  i: number
  text: string
  href: string
  tag: string
  score: number
}

const clip = (s: string | null | undefined, n = 80) => (s ?? "").replace(/\s+/g, " ").trim().slice(0, n)

function rectOf(el: Element): Rect {
  const r = el.getBoundingClientRect()
  return { x: Math.round(r.left + scrollX), y: Math.round(r.top + scrollY), w: Math.round(r.width), h: Math.round(r.height) }
}

function labelOf(el: HTMLInputElement): string {
  const parts: string[] = []
  for (const l of Array.from(el.labels ?? [])) parts.push((l as HTMLElement).innerText ?? l.textContent ?? "")
  const by = el.getAttribute("aria-labelledby")
  const root = el.getRootNode() as Document | ShadowRoot
  if (by) for (const id of by.split(/\s+/)) parts.push(root.getElementById?.(id)?.textContent ?? "")
  return clip(parts.filter(Boolean).join(" "))
}

function hostOf(url: string): string {
  try {
    return new URL(url, location.href).hostname
  } catch {
    return ""
  }
}

const SSO = /\b(continue|sign ?in|log ?in|sign ?up)\s+(with|using|via)\s+(google|apple|microsoft|facebook|github|twitter|x|linkedin|amazon|yahoo|sso|passkey)\b/i
const CHALLENGE_TITLE = /just a moment|attention required|verify you are human|are you a robot|access denied|request blocked|pardon our interruption|security check/i
const CHALLENGE_BOX = "#challenge-form, #challenge-running, #challenge-stage, #cf-challenge-running, .cf-turnstile, #px-captcha, #sec-if-cpt-container"

function run(): FrameProbe {
  const roots = openRoots()
  const all = deepQueryAll<HTMLInputElement>("input", roots).slice(0, 300)
  const index = new Map<Element, number>()
  const inputs: InputFact[] = []
  for (const el of all) {
    const type = (el.getAttribute("type") || "text").toLowerCase()
    if (["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range", "color"].includes(type)) continue
    index.set(el, inputs.length)
    const form = el.form ?? el.closest("form")
    inputs.push({
      i: inputs.length,
      type,
      name: clip(el.getAttribute("name")),
      id: clip(el.id),
      autocomplete: clip(el.getAttribute("autocomplete")).toLowerCase(),
      placeholder: clip(el.placeholder),
      ariaLabel: clip(el.getAttribute("aria-label")),
      label: labelOf(el),
      maxLength: el.maxLength > 0 ? el.maxLength : 0,
      inputMode: clip(el.getAttribute("inputmode")),
      visible: isVisible(el),
      inShadow: el.getRootNode() instanceof ShadowRoot,
      formActionHost: form ? hostOf(form.getAttribute("action") || location.href) : "",
      rect: rectOf(el),
      role: null,
    })
  }

  let kind: string | null = null
  let submit: FrameProbe["submit"] = null
  let error: string | undefined
  const s0 = performance.now()
  try {
    const result = scanPage()
    kind = result.kind
    for (const f of result.fields) {
      const i = index.get(f.el)
      if (i !== undefined) {
        inputs[i].role = f.role
        if (f.split) inputs[i].split = f.split
      }
    }
    const form = result.fields.find((f) => f.owner.form)?.owner.form
    if (form) for (const [el, i] of index) if (!form.contains(el)) inputs[i].outOfScope = true
    if (result.submit) {
      const t = (result.submit as HTMLElement).innerText || (result.submit as HTMLInputElement).value || result.submit.getAttribute("aria-label") || ""
      submit = { text: clip(t, 40), rect: rectOf(result.submit) }
    }
  } catch (e) {
    error = String(e)
  }
  const scanMs = performance.now() - s0

  const iframes: FrameProbe["iframes"] = []
  for (const f of deepQueryAll<HTMLIFrameElement>("iframe", roots).slice(0, 50)) {
    const src = f.getAttribute("src") || ""
    const host = hostOf(src)
    if (!host || host === location.hostname || !/^https?:/.test(new URL(src, location.href).protocol)) continue
    iframes.push({ host, src: clip(src, 200), visible: isVisible(f), rect: rectOf(f) })
  }

  const ssoButtons = new Set<string>()
  for (const el of deepQueryAll("a, button, [role=button]", roots).slice(0, 800)) {
    const text = clip((el as HTMLElement).innerText || el.getAttribute("aria-label") || "", 60)
    if (text && SSO.test(text) && isVisible(el)) ssoButtons.add(text)
    if (ssoButtons.size >= 8) break
  }

  return {
    url: location.href,
    origin: location.origin,
    title: clip(document.title, 120),
    kind,
    submit,
    inputs,
    shadowRoots: roots.length - 1,
    iframes,
    ssoButtons: [...ssoButtons],
    challenge: CHALLENGE_TITLE.test(document.title) || !!document.querySelector(CHALLENGE_BOX),
    error,
    scanMs: Math.round(scanMs * 10) / 10,
  }
}

// ---- Sign-in entry points ---------------------------------------------------

const ENTRY_TEXT =
  /^(sign ?in|log ?in|login|log on|sign on|my account|account|anmelden|einloggen|connexion|se connecter|iniciar sesi[oó]n|entrar|acceder|accedi|inloggen|aanmelden|zaloguj|войти|вход|ログイン|登录|登入|로그인|giriş yap|đăng nhập|masuk|logga in|kirjaudu|přihlásit)/i
const ENTRY_HREF = /log-?in|sign-?in|signin|logon|auth|sso|account|anmelden|connexion|entrar|my-?account/i
const NOT_ENTRY = /sign ?up|register|create|join|logout|log out|sign out|help|forgot|business|partner|seller|developer|advertis/i

let entryEls: Element[] = []

function entries(): EntryCandidate[] {
  const out: EntryCandidate[] = []
  entryEls = []
  const els = deepQueryAll("a[href], button, [role=button], [role=link]").slice(0, 3000)
  for (const el of els) {
    if (!isVisible(el) && !(el instanceof HTMLAnchorElement)) continue
    const text = clip((el as HTMLElement).innerText || el.getAttribute("aria-label") || el.getAttribute("title") || "", 60)
    let href = el instanceof HTMLAnchorElement ? el.href : ""
    if (href.startsWith("mailto:") || href.startsWith("tel:")) continue
    // A link that goes nowhere is a button: it's clicked, not visited.
    if (href.startsWith("javascript:") || (el.getAttribute("href") ?? "").startsWith("#")) href = ""
    let score = 0
    if (ENTRY_TEXT.test(text)) score += /^(my )?account/i.test(text) ? 7 : 12
    else if (/\b(sign ?in|log ?in|login)\b/i.test(text)) score += 6
    if (href && ENTRY_HREF.test(new URL(href).pathname + new URL(href).hostname)) score += /log-?in|sign-?in|signin/i.test(href) ? 5 : 2
    if (NOT_ENTRY.test(text)) score -= 8
    if (score < 5) continue
    if (isVisible(el)) score += 2
    entryEls.push(el)
    out.push({ i: entryEls.length - 1, text, href, tag: el.tagName.toLowerCase(), score })
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 10)
}

function clickEntry(i: number): boolean {
  const el = entryEls[i] as HTMLElement | undefined
  if (!el) return false
  el.click()
  return true
}

;(globalThis as unknown as { __deadboltCorpus: unknown }).__deadboltCorpus = { run, entries, clickEntry }
