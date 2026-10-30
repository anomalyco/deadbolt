// Weighted clues for classifying login fields and forms, and for telling
// sign-in-provider buttons apart. Ported from Foyer
// (github.com/R44VC0RP/foyer, src/clues.ts, by Ryan Vogel).
//
// Every signal adds or subtracts a small score instead of deciding on its own:
// labels and placeholders (display text), id/name/class (code text), the
// autocomplete attribute, the input type, neighbouring fields and the kind of
// form around them. The highest score above a threshold wins.
//
// All text here is matched in memory and thrown away. Nothing in this file is
// ever stored or sent anywhere.

import type { FieldRole } from "../messages"

export type Provider =
  | "google" | "apple" | "microsoft" | "github" | "facebook" | "x" | "linkedin" | "gitlab" | "slack" | "discord"
  | "amazon" | "okta" | "sso"

export type Clue = readonly [phrase: string, score: number]
export type FormKind = "login" | "signup" | "change-password" | "reset" | "mfa" | "newsletter"

// ---- Text normalisation ------------------------------------------------------

const NON_SPACED = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u

/** Lowercase, accent-free words separated by single spaces, padded: " sign in ". */
export function words(text: string): string {
  const out = text
    // "Googleでログイン" -> "Google でログイン": split Latin from CJK so names match.
    .replace(/([\p{Script=Latin}\p{N}])(?=[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}])/gu, "$1 ")
    .replace(/([\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}])(?=[\p{Script=Latin}\p{N}])/gu, "$1 ")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
  return out ? ` ${out} ` : " "
}

export const squash = (text: string) => text.replace(/ /g, "")

/** Whole-phrase match on word boundaries; CJK phrases match anywhere. */
export function hasPhrase(normalized: string, phrase: string): boolean {
  return NON_SPACED.test(phrase) ? normalized.includes(phrase) : normalized.includes(` ${phrase} `)
}

/** Phrases are written readably below and normalised once at load. */
function prepare(clues: Clue[]): Clue[] {
  return clues.map(([p, s]) => [words(p).trim(), s] as const)
}

// ---- Field clues -------------------------------------------------------------

const NOT_A_LOGIN_FIELD: Clue[] = [
  ["search", -8], ["coupon", -6], ["promo", -6], ["voucher", -6], ["gift card", -6], ["discount", -6],
  ["first name", -4], ["last name", -4], ["full name", -3], ["company", -3], ["street", -4], ["city", -4],
  ["zip", -5], ["zipcode", -6], ["zip code", -6], ["postal", -5], ["post code", -5], ["postcode", -6],
  ["card number", -6], ["card", -4], ["cvc", -6], ["cvv", -6], ["sort code", -6], ["iban", -6],
  ["message", -4], ["comment", -4], ["subject", -3], ["referral", -4], ["quantity", -5], ["amount", -5],
  ["price", -5], ["birth", -5], ["year", -4], ["age", -3],
  // Security questions: answers the user knows, never a login field.
  ["security question", -8], ["secret question", -8], ["security answer", -8], ["your answer", -6], ["answer", -5],
  ["memorable", -5],
]

/** A security question's answer, often in a masked box: never a password. */
const SECRET_ANSWER: Clue[] = [["security question", -8], ["secret question", -8], ["answer", -6], ["question", -6], ["memorable", -5]]

export const FIELD_CLUES: Record<FieldRole, Clue[]> = {
  username: prepare([
    ["username", 5], ["user name", 5], ["user id", 4], ["userid", 4], ["login id", 4], ["login", 2], ["log in", 1],
    ["sign in", 1], ["account name", 3], ["account", 1], ["identifier", 3], ["member id", 3], ["member number", 3],
    ["customer number", 2], ["handle", 1], ["email or username", 3], ["username or email", 3], ["email or phone", 2],
    ["benutzername", 5], ["benutzer", 3], ["nombre de usuario", 5], ["usuario", 3], ["nom d utilisateur", 5],
    ["identifiant", 4], ["nome utente", 5], ["utente", 3], ["gebruikersnaam", 5], ["nome de usuario", 5],
    ["ユーザー名", 5], ["ユーザーid", 4], ["用户名", 5], ["账号", 4], ["帳號", 4], ["логин", 4],
    ["имя пользователя", 5], ["아이디", 4], ["사용자 이름", 5],
    ["captcha", -6], ["address", -2], ["your name", -2], ["title", -2],
    ...NOT_A_LOGIN_FIELD,
  ]),
  email: prepare([
    ["email", 5], ["e mail", 5], ["email address", 5], ["mail", 2], ["correo", 4], ["correo electronico", 5],
    ["courriel", 5], ["adresse e mail", 5], ["e mail adresse", 5], ["indirizzo email", 5], ["e mailadres", 5],
    ["メール", 4], ["メールアドレス", 5], ["邮箱", 5], ["电子邮件", 5], ["電子郵件", 5], ["почта", 4],
    ["электронная почта", 5], ["이메일", 5],
    ["confirm", -2], ["repeat", -2], ["again", -2], ["retype", -2], ["re enter", -2],
    ["newsletter", -2], ["subscribe", -2], ["friend", -3], ["recipient", -3],
    ...NOT_A_LOGIN_FIELD,
  ]),
  phone: prepare([
    ["phone", 5], ["phone number", 5], ["mobile", 4], ["mobile number", 5], ["cell", 2], ["telephone", 5],
    ["tel", 2], ["telefono", 5], ["numero de telephone", 5], ["handynummer", 5], ["telefonnummer", 5],
    ["携帯", 4], ["电话", 5], ["手机", 5], ["電話", 5], ["телефон", 5], ["휴대폰", 5], ["전화", 4],
    ["country code", -4], ["extension", -4], ["fax", -5], ["area code", -3],
    ...NOT_A_LOGIN_FIELD,
  ]),
  password: prepare([
    ["password", 5], ["passwd", 5], ["pwd", 4], ["pass", 1], ["contrasena", 5], ["mot de passe", 5],
    ["passwort", 5], ["kennwort", 5], ["wachtwoord", 5], ["senha", 5], ["パスワード", 5], ["密码", 5], ["密碼", 5],
    ["пароль", 5], ["비밀번호", 5], ["pin", -2],
    ["new", -3], ["confirm", -4], ["repeat", -4], ["retype", -4], ["re enter", -4], ["again", -3], ["create", -3],
    ["choose", -3], ["nouveau", -3], ["neues", -3], ["nueva", -3], ["wiederholen", -4], ["confirmer", -4],
    ["confirmar", -4], ["otp", -3], ["one time", -3],
    ...SECRET_ANSWER,
  ]),
  "new-password": prepare([
    ["new password", 5], ["create password", 5], ["create a password", 5], ["choose password", 5],
    ["choose a password", 5], ["confirm password", 5], ["confirm your password", 5], ["repeat password", 5],
    ["retype password", 5], ["re enter password", 5], ["password again", 5], ["new", 2], ["confirm", 2],
    ["nouveau mot de passe", 5], ["confirmer le mot de passe", 5], ["neues passwort", 5],
    ["passwort wiederholen", 5], ["nueva contrasena", 5], ["confirmar contrasena", 5], ["新しいパスワード", 5],
    ["新密码", 5], ["确认密码", 5], ["новый пароль", 5], ["새 비밀번호", 5],
    ...SECRET_ANSWER,
  ]),
  otp: prepare([
    ["one time code", 6], ["one time password", 6], ["otp", 5], ["totp", 5], ["verification code", 6],
    ["verify code", 5], ["security code", 5], ["authentication code", 6], ["auth code", 4], ["authenticator", 4],
    ["2fa", 5], ["two factor", 5], ["mfa", 5], ["sms code", 5], ["login code", 5], ["code", 2], ["passcode", 3],
    ["6 digit", 4], ["enter code", 4], ["pin", 3], ["token", 2], ["token code", 4],
    ["codigo de verificacion", 6], ["code de verification", 6],
    ["bestatigungscode", 6], ["verifizierungscode", 6], ["確認コード", 6], ["認証コード", 6],
    ["код подтверждения", 6], ["인증번호", 6],
    ["captcha", -6], ["country", -4], ["area code", -6], ["invite", -5], ["tracking", -6],
    ...NOT_A_LOGIN_FIELD,
  ]),
  captcha: prepare([["captcha", 8], ["recaptcha", 8], ["are you human", 5], ["characters shown", 4]]),
}

/** Short tokens allowed to match inside ids/names (everything else needs 4+ letters). */
const SHORT_CODE_TOKENS = new Set(["pwd", "otp", "2fa", "mfa", "usr", "sms", "tel", "pin"])

// Autocomplete tokens that settle a field almost by themselves.
const AUTOCOMPLETE: Record<string, Partial<Record<FieldRole, number>>> = {
  username: { username: 9 },
  email: { email: 8, username: 2 },
  "current-password": { password: 10 },
  "new-password": { "new-password": 10, password: -4 },
  "one-time-code": { otp: 12 },
  tel: { phone: 8 },
  "tel-national": { phone: 8 },
  "tel-local": { phone: 8 },
  webauthn: { username: 2 },
}
/** Autocomplete tokens that say "this is not a login field". */
const NON_LOGIN_AUTOCOMPLETE = /^(name|given-name|family-name|additional-name|nickname|honorific-.*|organization.*|street-address|address-.*|postal-code|country.*|cc-.*|bday.*|sex|url|photo|language|transaction-.*)$/

export interface FieldFacts {
  type: string
  autocomplete: string[]
  /** words() of labels, aria-label, placeholder, title and nearby text. */
  display: string
  /** squash(words()) of id, name, class and test ids. */
  code: string
  maxLength: number
  inputMode: string
  /** The field's label asks a question ("What was your first pet's name?"). */
  question?: boolean
}

export const ROLES = Object.keys(FIELD_CLUES) as FieldRole[]

export function scoreField(f: FieldFacts): Record<FieldRole, number> {
  const score = Object.fromEntries(ROLES.map((r) => [r, 0])) as Record<FieldRole, number>
  // Whether the label itself names a login field: a question that doesn't is a security question.
  let named = false
  for (const role of ROLES) {
    for (const [phrase, value] of FIELD_CLUES[role]) {
      if (hasPhrase(f.display, phrase)) {
        score[role] += value
        if (value > 0 && role !== "captcha") named = true
      }
      const compact = squash(phrase)
      if ((compact.length >= 4 || SHORT_CODE_TOKENS.has(compact)) && f.code.includes(compact)) score[role] += value * 0.8
    }
  }

  for (const token of f.autocomplete) {
    const boost = AUTOCOMPLETE[token]
    if (boost) for (const [role, value] of Object.entries(boost)) score[role as FieldRole] += value
    else if (NON_LOGIN_AUTOCOMPLETE.test(token)) for (const role of ROLES) score[role] -= 6
  }

  const isPassword = f.type === "password"
  if (isPassword) {
    // A bare password box is most often a sign-in; form context can flip it.
    score.password += 4
    score["new-password"] += 3
    score.otp += 1
    score.username -= 10
    score.email -= 10
    score.phone -= 10
  } else {
    score.password -= 10
    score["new-password"] -= 10
  }
  if (f.type === "email") {
    score.email += 5
    score.username += 1
    score.otp -= 3
  }
  if (f.type === "tel") {
    score.phone += 5
    score.otp += 1
  }
  if (f.inputMode === "email") score.email += 3
  if (f.inputMode === "tel") score.phone += 3
  if (f.inputMode === "numeric") score.username -= 1
  // Shape alone (a short numeric box) is also a birth year, zip or amount, so it
  // only strengthens a code field that text or autocomplete already pointed at.
  if (score.otp > 0) {
    if (f.type === "number") score.otp += 2
    if (f.inputMode === "numeric") score.otp += 1
    if (f.maxLength >= 4 && f.maxLength <= 8 && !isPassword) score.otp += 2
  }
  if (f.type === "number") score.phone += 1
  // "What was the name of your first pet?": an answer the user knows, whatever its type or autocomplete.
  if (f.question && !named) for (const role of ROLES) score[role] -= 20
  return score
}

export const FIELD_THRESHOLD = 3

export function bestRole(score: Record<FieldRole, number>): FieldRole | null {
  let best: FieldRole | null = null
  for (const role of ROLES) if (score[role] >= FIELD_THRESHOLD && (!best || score[role] > score[best])) best = role
  return best
}

// ---- Form clues --------------------------------------------------------------

export const FORM_CLUES: Record<FormKind, Clue[]> = {
  login: prepare([
    ["sign in", 3], ["signin", 3], ["log in", 3], ["login", 3], ["log on", 2], ["sign on", 2], ["welcome back", 2],
    ["forgot password", 2], ["forgot your password", 2], ["remember me", 2], ["keep me signed in", 2],
    ["stay signed in", 2], ["don t have an account", 2], ["se connecter", 3], ["connexion", 3], ["anmelden", 3],
    ["einloggen", 3], ["iniciar sesion", 3], ["entrar", 2], ["accedi", 3], ["inloggen", 3], ["ログイン", 3],
    ["サインイン", 3], ["登录", 3], ["登入", 3], ["войти", 3], ["вход", 3], ["로그인", 3],
    ["already have an account", -2],
    ["confirm password", -4], ["repeat password", -4], ["i agree", -2], ["subscribe", -3], ["newsletter", -3],
    ["checkout", -3], ["shipping", -3], ["billing", -2], ["change password", -4], ["current password", -2],
    ["reset password", -2],
  ]),
  signup: prepare([
    ["sign up", 3], ["signup", 3], ["create account", 4], ["create an account", 4], ["create your account", 4],
    ["register", 3], ["registration", 3], ["join now", 2], ["get started", 1], ["confirm password", 3],
    ["i agree", 2], ["terms of service", 1], ["already have an account", 3], ["s inscrire", 3], ["inscription", 3],
    ["creer un compte", 4], ["registrieren", 3], ["konto erstellen", 4], ["crear cuenta", 4], ["registrarse", 3],
    ["registrati", 3], ["crea account", 4], ["新規登録", 4], ["アカウント作成", 4], ["注册", 4], ["регистрация", 4],
    ["회원가입", 4],
    ["forgot password", -2], ["remember me", -2], ["welcome back", -2], ["don t have an account", -3],
  ]),
  "change-password": prepare([
    ["change password", 5], ["change your password", 5], ["update password", 4], ["current password", 3],
    ["old password", 4], ["passwort andern", 5], ["changer le mot de passe", 5], ["cambiar contrasena", 5],
    ["パスワード変更", 5], ["修改密码", 5], ["сменить пароль", 5],
    ["forgot password", -2], ["sign in", -1],
  ]),
  reset: prepare([
    ["reset password", 4], ["reset your password", 4], ["forgot password", 2], ["forgot your password", 3],
    ["recover", 2], ["recovery", 2], ["send reset link", 4], ["trouble signing in", 2], ["mot de passe oublie", 3],
    ["passwort vergessen", 3], ["olvidaste tu contrasena", 3],
  ]),
  mfa: prepare([
    ["two factor", 3], ["2 step", 3], ["two step", 3], ["verification code", 3], ["enter the code", 3],
    ["enter code", 2], ["sent a code", 3], ["we sent", 2], ["authenticator app", 3], ["verify it s you", 3],
    ["check your phone", 2], ["code de verification", 3], ["bestatigungscode", 3], ["確認コード", 3],
    ["card number", -4], ["checkout", -4], ["pay", -3], ["shipping", -3],
  ]),
  newsletter: prepare([
    ["subscribe", 4], ["newsletter", 4], ["mailing list", 4], ["stay in touch", 2], ["stay updated", 2],
    ["get updates", 2], ["sign up for", 2], ["join our", 1],
    ["password", -3], ["sign in", -2], ["log in", -2],
  ]),
}

export const FORM_KINDS = Object.keys(FORM_CLUES) as FormKind[]

export function scoreFormText(text: string): Record<FormKind, number> {
  const score = Object.fromEntries(FORM_KINDS.map((k) => [k, 0])) as Record<FormKind, number>
  for (const kind of FORM_KINDS) for (const [phrase, value] of FORM_CLUES[kind]) if (hasPhrase(text, phrase)) score[kind] += value
  return score
}

// ---- Sign-in provider buttons ------------------------------------------------

const PROVIDER_NAMES: Array<[Provider, string[]]> = [
  ["google", ["google"]],
  ["apple", ["apple", "apple id"]],
  ["microsoft", ["microsoft", "microsoft account", "outlook", "office 365", "azure ad", "entra id"]],
  ["github", ["github"]],
  ["facebook", ["facebook"]],
  ["x", ["twitter", "x"]],
  ["linkedin", ["linkedin"]],
  ["gitlab", ["gitlab"]],
  ["slack", ["slack"]],
  ["discord", ["discord"]],
  ["amazon", ["amazon"]],
  ["okta", ["okta"]],
  ["sso", ["sso", "single sign on", "saml", "enterprise sso", "your company", "work account", "company account", "organization account"]],
].map(([p, names]) => [p as Provider, (names as string[]).map((n) => words(n).trim()).sort((a, b) => b.length - a.length)])

const CONNECTORS = [
  "sign in with", "sign in using", "sign in via", "signin with", "log in with", "log in using", "log in via",
  "login with", "login via", "continue with",
  "connect with", "sign up with", "signup with", "register with", "sign on with", "authenticate with", "use", "with",
  "via", "using", "se connecter avec", "connexion avec", "continuer avec", "s inscrire avec", "anmelden mit",
  "weiter mit", "fortfahren mit", "mit", "iniciar sesion con", "continuar con", "con", "accedi con",
  "continua con", "entrar com", "continuar com", "com", "inloggen met", "doorgaan met", "met", "でログイン",
  "でサインイン", "で続ける", "で続行", "войти через", "продолжить с", "через", "로 로그인", "으로 로그인",
  "로 계속하기",
]
  .map((c) => words(c).trim())
  .sort((a, b) => b.length - a.length)

const FILLER = ["your", "my", "an", "a", "the", "account", "id", "workspace", "entra", "anmelden", "einloggen"]
const DENY = [
  "share", "follow", "tweet", "like us", "post", "download", "app store", "play", "get it on", "watch",
  "pay", "checkout", "buy",
]

function removeOnce(text: string, phrase: string): string {
  if (NON_SPACED.test(phrase)) return text.replace(phrase, " ")
  return text.replace(` ${phrase} `, " ")
}

/**
 * A control is a provider button when its label is essentially just the
 * provider name plus a connector ("Continue with Google", "Google",
 * "Se connecter avec Apple"). Sentences that merely mention a provider
 * ("Sign in with Google to sync your calendar") leave too much text behind.
 */
export function providerFromLabel(label: string): { provider: Provider; connector: boolean } | null {
  const text = words(label)
  if (squash(text).length > 48 || DENY.some((d) => hasPhrase(text, words(d).trim()))) return null
  for (const [provider, names] of PROVIDER_NAMES) {
    const name = names.find((n) => hasPhrase(text, n))
    if (!name) continue
    let rest = removeOnce(text, name)
    const connector = CONNECTORS.find((c) => hasPhrase(rest, c))
    if (connector) rest = removeOnce(rest, connector)
    for (const filler of FILLER) while (hasPhrase(rest, filler)) rest = removeOnce(rest, filler)
    // A bare "X" is a close button far more often than a Twitter button.
    if (provider === "x" && name === "x" && !connector) continue
    if (squash(rest).length <= 3) return { provider, connector: !!connector }
  }
  return null
}
