// Messages inside the extension: content scripts, the inline menu and the
// popup all talk to the background worker, which alone talks to the native
// host. Secrets appear only in FillValues, sent by the background to the one
// document and form the user chose to fill, and in a capture, sent by a
// content script after the user submitted a login form.

import type { LearnSession, LearnStep } from "./learn"
import type { Account, Change, FieldRules, FormCard, FormField as HostField, FormIdentity, FormKind, HostStatus } from "./protocol"

export type FieldRole = "username" | "email" | "phone" | "password" | "new-password" | "otp" | "captcha"
export type SurfaceKind = "login" | "signup" | "change-password" | "reset" | "mfa"
/** What Deadbolt's in-page surface shows: the account list, a pill on a field or at the top right, or the save offer. */
export type SurfaceMode = "accounts" | "pill" | "save"
export const SURFACE_MODES: SurfaceMode[] = ["accounts", "pill", "save"]

/** Roles the inline menu opens on; on a new-password box, only in sign-up and change-password forms. */
export const MENU_ROLES: FieldRole[] = ["username", "email", "phone", "password", "otp", "new-password"]
/** Forms whose new-password boxes get a generated password. */
export const GENERATE_KINDS: SurfaceKind[] = ["signup", "change-password"]
export const IDENTIFIER_ROLES: FieldRole[] = ["username", "email", "phone"]
/** Roles a fill can write. */
export const FIELD_ROLES: FieldRole[] = ["username", "email", "phone", "password", "new-password", "otp"]

/**
 * What an identity or payment field takes, named by its HTML autocomplete
 * token (see content/forms.ts). `country` covers country and country-name.
 */
export const IDENTITY_ROLES = [
  "name", "honorific-prefix", "given-name", "additional-name", "family-name", "email", "tel", "tel-national", "tel-country-code",
  "organization", "organization-title", "street-address", "address-line1", "address-line2", "address-line3", "address-level1",
  "address-level2", "postal-code", "country", "bday", "bday-day", "bday-month", "bday-year",
] as const
export const CARD_ROLES = ["cc-name", "cc-given-name", "cc-family-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type"] as const
export type IdentityRole = (typeof IDENTITY_ROLES)[number]
export type CardRole = (typeof CARD_ROLES)[number]
export type FormRole = IdentityRole | CardRole
export const FORM_ROLES: FormRole[] = [...IDENTITY_ROLES, ...CARD_ROLES]
export const formKindOf = (role: FormRole): FormKind => ((CARD_ROLES as readonly string[]).includes(role) ? "card" : "identity")

/** The host fields each role needs. */
export const FIELDS_FOR: Record<FormRole, HostField[]> = {
  name: ["given-name", "additional-name", "family-name"],
  "honorific-prefix": ["honorific"],
  "given-name": ["given-name"],
  "additional-name": ["additional-name"],
  "family-name": ["family-name"],
  email: ["email"],
  tel: ["phone", "country"],
  "tel-national": ["phone", "country"],
  "tel-country-code": ["phone", "country"],
  organization: ["organization"],
  "organization-title": ["job-title"],
  "street-address": ["address-line1", "address-line2", "address-line3"],
  "address-line1": ["address-line1"],
  "address-line2": ["address-line2"],
  "address-line3": ["address-line3"],
  "address-level1": ["region", "country"],
  "address-level2": ["city"],
  "postal-code": ["postal-code"],
  country: ["country"],
  bday: ["birthday"],
  "bday-day": ["birthday"],
  "bday-month": ["birthday"],
  "bday-year": ["birthday"],
  "cc-name": ["cardholder"],
  "cc-given-name": ["cardholder"],
  "cc-family-name": ["cardholder"],
  "cc-number": ["number"],
  "cc-exp": ["expiry"],
  "cc-exp-month": ["expiry"],
  "cc-exp-year": ["expiry"],
  "cc-csc": ["cvv"],
  "cc-type": ["brand"],
}

/** Every host field the roles need, once each. */
export const fieldsFor = (roles: FormRole[]) => [...new Set(roles.flatMap((r) => FIELDS_FOR[r]))]

/** Host fields that make the agent ask for Touch ID. */
export const VERIFIED_FIELDS: HostField[] = ["number", "cvv"]

/** How the menu names what an identity fills, by role, in the order it lists them. */
export const FILLS_WORD: Partial<Record<FormRole, string>> = {
  name: "name", "honorific-prefix": "name", "given-name": "name", "additional-name": "name", "family-name": "name",
  email: "email", tel: "phone", "tel-national": "phone", "tel-country-code": "phone", organization: "company", "organization-title": "company",
  "street-address": "address", "address-line1": "address", "address-line2": "address", "address-line3": "address", "address-level1": "address",
  "address-level2": "address", "postal-code": "address", country: "address", bday: "birthday", "bday-day": "birthday", "bday-month": "birthday", "bday-year": "birthday",
}
const FILLS_ORDER = ["name", "email", "phone", "company", "address", "birthday"]

/**
 * What an identity with values for `has` (host field names) fills of a
 * section with these roles, in words. A role counts when the identity has
 * its own field (a phone box needs the phone, not just the country).
 */
export function fillsWords(roles: FormRole[], has: string[]): string[] {
  const words = new Set<string>()
  for (const r of roles) {
    const own = FIELDS_FOR[r].filter((f) => f !== "country" || r === "country")
    const word = FILLS_WORD[r]
    if (word && own.some((f) => has.includes(f))) words.add(word)
  }
  return FILLS_ORDER.filter((w) => words.has(w))
}

/** An identity's or card's values, by the host's field names (see FIELDS_FOR). */
export type FormValues = Record<string, string>

export interface FillValues {
  username?: string
  password?: string
  totp?: string
  /** A generated password, for every new-password box. */
  newPassword?: string
}

/** Where the extension stands with Deadbolt, as the popup and menus show it. */
export type Status =
  | { state: "connecting" }
  | { state: "not-installed" }
  | { state: "disconnected"; message: string }
  | { state: Exclude<HostStatus, "ready">; detail?: string }
  | { state: "ready"; version: string }

export type ToBackground =
  // content script
  /**
   * `explicit`: the user clicked into the field or pressed ↓ in it, rather
   * than just focusing it. `identifier`: on a password or code field, what
   * the form's username or email box holds, so the menu can narrow to the
   * login it names (see Autofill.query). It stays in the extension. Only a
   * username the user typed (or Deadbolt filled) is sent as it.
   * `pageAccount`: on a password or code field with no `identifier`, the
   * account a provider's own sign-in page shows (accounts.google.com's chip
   * or hidden username, see isAccountPage). The background takes it only
   * from such a page's exact https origin, and it only narrows the menu,
   * never hides it. `again`: the user pressed ↓ or clicked the field a
   * second time, asking for the whole list. `rules`: on a new-password box,
   * what the page asks of the password. From a frame, `box` is where the
   * field shows in the frame's viewport, so the menu can open in the top
   * page under it (see Autofill.query).
   */
  | { type: "db:query"; roles: FieldRole[]; focused: FieldRole; form: number; kind: SurfaceKind | null; rules?: FieldRules; explicit?: boolean; again?: boolean; identifier?: string; pageAccount?: string; box?: Box }
  /** `stepped`: since the last fill in this document, the user submitted or the filled fields went. */
  /** `idEmpty`: the form has a username or email box and it's empty (a "Use a different account" step). */
  | { type: "db:page"; kind: SurfaceKind | null; roles: FieldRole[]; form: number; stepped: boolean; idEmpty?: boolean }
  /** The top page may have finished a sign-in step: it showed no login form for a moment, or moved on to a code step. */
  | { type: "db:settled" }
  /** `kind` and `roles`: the submitted form's, to tell it if it shows again. */
  /** `generated`: the new password is the one generated under that id, so it isn't sent. `submission`: this document's count of submits. */
  | { type: "db:capture"; username?: string; password?: string; newPassword?: string; generated?: string; title: string; kind: SurfaceKind | null; roles: FieldRole[]; submission: number }
  /** The form submitted as `submission` still shows, five seconds on: the sign-in failed. */
  | { type: "db:failed"; submission: number }
  /** The user themselves submitted a login form here: a trusted click on its submit control, or Enter in one of its fields. */
  | { type: "db:submitted" }
  | { type: "db:menu-close"; token: string; dismissed?: boolean }
  /**
   * From a frame whose login field's menu the background opened in the top
   * page: the user typed in the field, clicked elsewhere in the frame, or
   * (`dismissed`) pressed esc. The menu goes.
   */
  | { type: "db:menu-away"; dismissed?: boolean }
  /**
   * The user clicked into an identity or card field (see content/forms.ts):
   * the menu for it. `section` names the field's section in form snapshot
   * `form`. From a frame, `box` is where the field shows in the frame's
   * viewport, so the menu can open in the top page under it.
   */
  | { type: "db:forms-query"; kind: FormKind; form: number; section: string; roles: FormRole[]; explicit?: boolean; box?: Box }
  /** The identity and card sections this frame's forms have now, for card fills that span frames. */
  | { type: "db:forms-page"; kinds: FormKind[]; form: number }
  /** A frame that just loaded asks whether its tab is learning (see src/learn.ts): a LearnSession or null. */
  | { type: "db:learn-ask" }
  /** A step of the learning session `session`, from this frame. */
  | { type: "db:learn-step"; session: string; step: LearnStep }
  // inline menu
  /** `parent`: the origin of the parent window that handed the menu its token. */
  | { type: "db:menu-load"; token: string; parent: string }
  | { type: "db:menu-pick"; token: string; ref: string }
  | { type: "db:menu-generate"; token: string }
  /** The user picked a "Sign in with …" row: point at the site's button for it (see SignInReply). */
  | { type: "db:menu-signin"; token: string; ref: string }
  | { type: "db:menu-dismiss"; token: string }
  /** The locked row of a browser-only Deadbolt was clicked: open device.html to unlock it. Answers true if it opened. */
  | { type: "db:menu-unlock"; token: string }
  /** The size the surface needs; with `mode`, the mode it's folding into (only ever "pill"). */
  | { type: "db:menu-resize"; token: string; height: number; width?: number; mode?: SurfaceMode }
  /** The save offer in the page was answered. "later" only puts the surface away: the toolbar keeps the offer. */
  | { type: "db:surface-choose"; token: string; choice: OfferChoice }
  // popup
  | { type: "db:popup-load"; tabId: number }
  | { type: "db:popup-fill"; tabId: number; ref: string }
  /** `id`: the offer the popup showed; any other gets nothing. */
  | { type: "db:popup-offer"; tabId: number; id: string; choice: OfferChoice }
  /** Turn saving back on for the tab's site after "Never for this site". */
  | { type: "db:popup-saving-on"; tabId: number }
  /** Start or stop learning the tab's site. Answers with a LearnReply. */
  | { type: "db:popup-learn"; tabId: number; on: boolean }
  /** Lock the browser-only Deadbolt now (bg/standalone.ts). Answers with the Status after. */
  | { type: "db:popup-lock" }
  // device.html, the standalone device's own page (bg/standalone.ts): answers with a DeviceReply
  | { type: "db:device"; command: DeviceCommand }
  // passkeys (bg/passkeys.ts): the content script relays the page's hook
  /** `request`: the hook's id for the call; `options`: the page's options, checked in the background. */
  | { type: "pk:get" | "pk:create"; request: number; options: unknown; allowed: boolean }
  | { type: "pk:cancel"; request: number }
  /** The popup's answer to the passkey prompt `id`. */
  | { type: "pk:popup-choose"; tabId: number; id: string; choice: PasskeyChoice }

export type ToContent =
  /**
   * `form` is the form snapshot the fill was chosen for; a changed form gets
   * nothing. `approval` names the fields db:approve said may be filled: only
   * those are written.
   */
  /**
   * `generated`: the id of the generated password in `values`, kept by the
   * agent once the page has it. `notice`: a sign-in session's step filled
   * without a pick shows a pill on the field, with this token for its frame.
   */
  | { type: "db:fill"; values: FillValues; form: number; approval: string; generated?: string; notice?: string }
  /** The agent kept the generated password filled under this id: a submit names it by id from now on. */
  | { type: "db:generated"; generated: string }
  /**
   * Which of the form's fields may be filled now (see Approved). With
   * `measure`, for a frame: where they show, and only if they all do. With
   * `sameSite`, a frame whose every frame up to the top page is its site
   * (see sameSiteTop): its fields get a top page's field checks, without the
   * visibility reading, which the frames above take of the frame instead.
   */
  | { type: "db:approve"; form: number; measure: boolean; sameSite?: boolean }
  /** Where the fields of `approval` show now, if every one of them still does (`sameSite`: as for db:approve). */
  | { type: "db:approved"; approval: string; sameSite?: boolean }
  /**
   * What the top page shows now, to tell whether a sign-in worked (see
   * PageFacts). `username`: the one just submitted, to look for on the page.
   */
  | { type: "db:probe"; username?: string }
  /**
   * Point at the site's own "Sign in with <provider>" button, if one shows;
   * answers whether it found one. The user clicks it, never Deadbolt.
   */
  | { type: "db:point"; provider: string }
  /** On the provider's account chooser: point at the tile for this account. Only the provider's own top page gets it. */
  | { type: "db:chooser"; account: string }
  /** Report the login form now, or that there's none. Answers once the background has it. */
  | { type: "db:report" }
  | { type: "db:close-menu"; token: string; unlock?: boolean }
  | { type: "db:unlock-return" }
  | { type: "db:unlock-wait" }
  | { type: "db:resize-menu"; token: string; height: number; width?: number; mode?: SurfaceMode }
  /**
   * Open the menu under `box` (in this page's viewport), for a login,
   * identity or card field in a frame below; with `mode` "pill", a sign-in
   * session step's pill on that field instead. Top page only.
   */
  | { type: "db:open-at"; token: string; rows: number; box: Box; mode?: "pill"; captioned?: true }
  /** Which of the form's identity or card fields may be filled now: those of `section`, or every one of `kind` (see Approved). */
  | { type: "db:forms-approve"; form: number; kind: FormKind; section?: string; measure: boolean }
  /** Where the fields of a forms approval show now, if every one of them still does. */
  | { type: "db:forms-approved"; approval: string }
  /** An identity's or card's values for the fields `approval` named, in form snapshot `form`. */
  | { type: "db:forms-fill"; values: FormValues; form: number; approval: string }
  /**
   * Puts the surface `token` (folded into its pill) out of sight while
   * frames below are measured, and back after (`hold` false): Chromium reads
   * nothing as fully visible while anything shows in the top layer. Answers
   * whether nothing of Deadbolt's shows now; asked about another token (or
   * ""), it touches nothing.
   */
  | { type: "db:hold"; token: string; hold: boolean }
  /** To a frame: the menu the top page showed for its field went. */
  | { type: "db:menu-gone" }
  /** Open the save offer in the page, with this token for its frame (see bg/save.ts). */
  | { type: "db:surface"; token: string }
  // Can the user see a frame's form? (see shownInPage)
  /**
   * To the frame above: where those boxes show in it, through the element
   * `nonce` names; with `track`, only if a fresh visibility reading of that
   * element says it's unobscured; with `unsandboxed`, only if that element
   * has no `sandbox` attribute.
   */
  | { type: "db:frame-child"; nonce: string; boxes: Box[]; track?: boolean; unsandboxed?: boolean }
  /** To the frame below: tell the frame above which element you're in. */
  | { type: "db:frame-announce"; nonce: string }
  /** To every frame of a tab: the learning session it joins, or null when it ends. */
  | { type: "db:learn"; session: LearnSession | null }

/**
 * What the top page shows after a sign-in was submitted, as the content
 * script's answer to db:probe. Only booleans: no page text or values.
 */
export interface PageFacts {
  /** A login, sign-up or change-password form still shows. */
  loginForm: boolean
  /** That form's password box is empty. */
  passwordEmpty: boolean
  /** A code step: the password went through, the sign-in isn't finished. */
  mfa: boolean
  /** A visible error, such as "Incorrect password" or "Too many attempts". */
  error: boolean
  /** A captcha or bot challenge. */
  challenge: boolean
  /** The submitted username shows on the page. */
  account: boolean
  /** A visible Sign out or Log out control. */
  signOut: boolean
  /** The URL looks like a sign-in step (see LOGIN_URL). */
  loginish: boolean
}

/** A rectangle in a frame's viewport, in CSS pixels. */
export interface Box {
  left: number
  top: number
  right: number
  bottom: number
}

/** An answer to db:approved or db:frame-child; null when anything doesn't show. */
export interface FrameBoxes {
  boxes: Box[]
}

/**
 * A content script's answer to db:approve: the fields that may be filled,
 * fixed when it answered. A fill asks the host only for their `roles` and
 * writes only into them, never a field that became fillable after.
 */
export interface Approved {
  approval: string
  roles: FieldRole[]
  /** With `measure`: where each field shows in the frame's viewport. */
  boxes?: Box[]
  /** Background only: measured as a same-site frame (see shownInPage). */
  sameSite?: boolean
}

/** A content script's answer to db:forms-approve: which identity or card fields may be filled. */
export interface FormsApproved {
  approval: string
  roles: FormRole[]
  boxes?: Box[]
}

/** A content script's answer to db:forms-fill: the fields it actually wrote. */
export interface FormsAck {
  filled: FormRole[]
}

/** A content script's answer to db:fill: the fields it actually wrote. */
export interface FillAck {
  filled: FieldRole[]
  /** A generated password a new-password box's `pattern` doesn't take: nothing was written. */
  rejected?: boolean
  /** A sign-in session's step in a frame: where the last field written shows in the frame's viewport, for its pill in the top page. */
  box?: Box
}

/** Broadcast to open extension pages (popup, menus) when the host's state changes. */
export interface StatusChanged {
  type: "db:status"
  status: Status
  /** What changed, when the host says (the vault's logins, say), not just that it answered. */
  change?: Change
}

export interface QueryReply {
  token?: string
  /** Rows the menu will show, so the frame can be sized before it loads. */
  rows: number
}

export type MenuLoadReply =
  /** `passkeys`: for a sign-in waiting on a passkey pick (conditional mediation). */
  /** `continueAs`: the site signs in identifier first and has one login: say "Continue as …". */
  | { kind: "accounts"; site: string; accounts: Account[]; focused: FieldRole; passkeys?: MenuPasskey[]; continueAs?: boolean }
  | { kind: "generate"; site: string }
  /**
   * An identity or card field's menu: the identities or cards to pick from.
   * `into`: a card goes into a payment provider's frame too ("Stripe").
   * `verify`: the agent asks for Touch ID before a card's number goes out.
   * `passphrase`: the browser-only vault, under Strict, asks for the passphrase first.
   */
  /** `fills`: for each identity, by ref, what of the section it has values for ("name", "email", "address"). */
  | { kind: "forms"; form: FormKind; site: string; identities: FormIdentity[]; cards: FormCard[]; into?: string; verify: boolean; passphrase?: boolean; fills?: Record<string, string[]> }
  /** A pill on a field a sign-in session's step just filled ("Password filled"). */
  | { kind: "notice"; label: string; title: string }
  | { kind: "status"; status: Status }
  /** The save offer's surface: what it may show. Never the password. */
  | { kind: "offer"; site: string; username: string; update: boolean }

export type PickReply = { ok: true } | { ok: false; message: string }

/** The answer to a "Sign in with …" pick: whether the site's button was found and is being pointed at. */
export type SignInReply = { ok: true; found: boolean; provider: string } | { ok: false; message: string }

export interface PopupReply {
  status: Status
  /** The tab's site, from the host; or why the tab gets no logins. */
  site?: string
  unfillable?: "scheme" | "insecure"
  host?: string
  accounts: Account[]
  error?: string
  /** A save or update waiting for the user's answer, for this tab. */
  offer?: SaveOffer
  /** A passkey sign-in or registration waiting for the user, for this tab. */
  passkey?: PasskeyPrompt
  /** The tab's site, when the user said "Never for this site". */
  savingOff?: string
  /** The tab is learning its site (see src/learn.ts). */
  learning?: Learning
}

export interface Learning {
  site: string
  /** Steps logged so far. */
  steps: number
  until: number
}

export type LearnReply = { ok: true; learning?: Learning } | { ok: false; message: string }

/** "later" (Not now) also holds back the same login on this site for a day; "never" stops offers for the site. */
export type OfferChoice = "save" | "later" | "never"

export interface SaveOffer {
  /** Made for each offer; the popup answers by it. */
  id: string
  site: string
  username: string
  update: boolean
}

/** `gone`: the offer answered isn't the one waiting anymore. */
export type ChooseReply = { ok: true; message: string } | { ok: false; message: string; gone?: boolean }

/** A passkey a waiting autofill sign-in can use, as the inline menu shows it. */
export interface MenuPasskey {
  ref: string
  vault: string
  username?: string
}

/** The background's answer to the page's hook. `credential` holds base64url fields. */
export type HookReply = { credential: Record<string, string> } | { fallback: true } | { error: { name: string; message: string } }

/**
 * What the popup asks about a page's passkey call. `verify`: Deadbolt asks
 * for Touch ID before it signs. `passphrase`: the browser-only Deadbolt asks
 * for the passphrase next (Strict, unless the site discourages verification),
 * as a Reauth the popup shows before it closes.
 */
export type PasskeyPrompt = {
  id: string
  rpId: string
  verify: boolean
  passphrase?: boolean
} & (
  | { kind: "get"; passkeys: Array<{ ref: string; vault: string; username?: string; created?: string }> }
  /** `registered`: the site already has one of its excluded passkeys in Deadbolt. */
  | { kind: "create"; username: string; registered: boolean }
)

/** `fallback`: the browser's own passkey flow, such as a phone or security key. */
export type PasskeyChoice = { action: "use"; ref: string } | { action: "save" } | { action: "fallback" } | { action: "cancel" }

/**
 * What the standalone device's own pages (device.html and the popup) ask of
 * it: set it up, unlock, lock, pair and sync it, manage its devices and
 * settings, and see, add, edit and delete items by hand. The background takes these
 * only from those two pages of this extension.
 */
export type UnlockProof = { passphrase: string; prf?: never } | { prf: string; passphrase?: never }

export type DeviceCommand =
  | { type: "device-status" }
  | { type: "device-create"; passphrase: string; name: string }
  | ({ type: "device-unlock" } & UnlockProof)
  | { type: "device-biometric-info" }
  | { type: "device-biometric-check"; passphrase: string }
  | { type: "device-biometric-set"; passphrase: string; prf: string; token: string }
  | { type: "device-biometric-reset" }
  | { type: "device-lock" }
  /** Admit the device that `deadbolt join` shows this code on. */
  | { type: "device-pair"; code: string }
  /**
   * First run, joining a vault another device has: start waiting to be
   * admitted (`{ type: "device-join-start", code, phase: "waiting" }`; the
   * background names this browser), ask how it's going (JoinStatus), finish
   * with this browser's own passphrase once admitted, or cancel. Cancel never
   * reaches the vault: the background ends its worker, as Lock does.
   */
  | { type: "device-join-start" }
  | { type: "device-join-status" }
  | { type: "device-join-finish"; passphrase: string }
  | { type: "device-join-cancel" }
  /** `wait`: answer once a sync round has finished (at most 30 s), not as soon as it starts. */
  | { type: "device-sync"; wait?: boolean }
  /** Every item in the vault, for the page's list: `{ type: "device-items", items: ItemSummary[] }`. */
  | { type: "device-items" }
  /** The item types the page can add and their fields: `{ type: "device-kinds", kinds: ItemKind[] }`. */
  | { type: "device-kinds" }
  /** The vault's devices: `{ type: "device-devices", devices: VaultDevice[] }`. */
  | { type: "device-devices" }
  /** One item without its secrets (ItemDetail), with a one-time code's current code. */
  | { type: "device-item"; ref: string }
  /**
   * One secret value, to reveal or copy (a login's password unless `field`
   * names another), or a file's whole value (`name`, a line break, base64)
   * to download: `{ type: "device-secret", value }`. Strict asks for the
   * passphrase or platform verification every time.
   */
  | { type: "device-secret"; ref: string; field?: string; passphrase?: string; prf?: string }
  /**
   * Adds a login by hand, or edits `ref`; an edit with an empty password
   * keeps the one it has. `otp` and `notes`, when given, set the one-time
   * password secret and the notes; empty, they remove them.
   */
  | { type: "device-save"; ref?: string; entry: { title: string; url: string; username: string; password: string; otp?: string; notes?: string } }
  /**
   * Adds an item of `kind`, or edits `ref`: `fields` are set, `remove` taken
   * off, and `name` (when given, empty clears it) names it. Fields left out
   * stay as they are. `{ type: "device-item-save", ref, created }`.
   */
  | { type: "device-item-save"; ref?: string; kind?: string; name?: string; fields: ItemInput[]; remove?: string[] }
  /** Deletes an item, on every device once synced. */
  | { type: "device-item-delete"; ref: string; passphrase?: string }
  /** Removes another device from the vault. */
  | { type: "device-remove"; id: string }
  /** Renames the vault. */
  | { type: "device-rename"; name: string }
  /** This browser's settings: `{ type: "device-settings", preset }`. */
  | { type: "device-settings" }
  | { type: "device-preset"; preset: LockPreset }
  /** The user opened something (a login's details): counts as use for the idle lock, once, never on a poll. */
  | { type: "device-used" }
  /** A new password from the core's generator: `{ type: "device-generate", password }`. */
  | { type: "device-generate"; length: number; symbols: boolean }
  /**
   * The page copied a password or code: clear it in 30 s if the clipboard
   * permissions allow (`{ clears }`). Only its salted hash (bg/clipboard.ts),
   * never the value.
   */
  | { type: "device-copied"; salt: string; hash: string }
  /** The fill waiting on the passphrase, if any: `{ type: "device-reauth", reauth: Reauth | null }`. */
  | { type: "device-reauth" }
  /** The passphrase for fill `id`, once: the background runs that fill with it and forgets it. */
  | ({ type: "device-reauth-confirm"; id: string } & UnlockProof)
  /** The user turned fill `id` down: nothing is filled. */
  | { type: "device-reauth-cancel"; id: string }
  /** The vault's passkeys, never their keys: `{ type: "device-passkeys", passkeys: DevicePasskey[] }`. */
  | { type: "device-passkeys" }
  /**
   * Deletes passkey `ref` from the vault (passkeys only for now); the delete
   * syncs to the other devices. Strict asks for the passphrase every time,
   * as device-secret does: without it the vault answers `passphrase_needed`.
   */
  | { type: "device-delete"; ref: string; passphrase?: string }
  | { type: "list"; origin: string }
  | { type: "save"; origin: string; entry: { title: string; url: string; username: string; password: string } }

/**
 * A request waiting on the passphrase under Strict, as Deadbolt's own pages
 * ask for it: a card's number or code to fill (`kind` "card", the default),
 * or a passkey sign-in ("passkey-get") or registration ("passkey-create").
 */
export interface Reauth {
  id: string
  kind?: "card" | "passkey-get" | "passkey-create"
  /** "Visa •••• 4242"; for a passkey, its username (or "Passkey"). */
  title: string
  site: string
}

/** A passkey in the vault, as device-passkeys lists it: never its private key. `created`: ISO date. */
export interface DevicePasskey {
  ref: string
  vault: string
  rpId: string
  credentialId: string
  username?: string
  created?: string
}

/** Broadcast to Deadbolt's own pages when a fill starts or stops waiting on the passphrase: they ask device-reauth. */
export interface ReauthChanged {
  type: "db:reauth"
}

/** device-join-status's reply: `code` while waiting (so a reloaded page shows it again), `vault` once admitted, `message` when it failed. */
export type JoinStatus = { type: "device-join-status"; phase: "waiting" | "admitted" | "failed" | "idle"; code?: string; vault?: string; message?: string }

/** A member of the vault; `current`: this browser. `lastSeen`: when it last synced with this browser (unix seconds). */
export type VaultDevice = { id: string; name: string; current: boolean; lastSeen?: number | null }

/** How soon the browser-only Deadbolt locks by itself (docs/extension-device.md, Lock presets). */
export type LockPreset = "strict" | "comfortable" | "relaxed"

/** A field to set in device-item-save. `type` only for a field the item's type doesn't know. */
export interface ItemInput {
  name: string
  value: string
  type?: string
}

/** An item type the page can add: its noun ("secure note") and its fields, as the core's schema has them. */
export interface ItemKind {
  kind: string
  noun: string
  fields: Array<{ name: string; type: string; required: boolean; multiline: boolean }>
}

/**
 * One item in the page's list (device-items): its type, label and detail
 * as the agent names them, and the words a search finds it by (never a
 * secret). A login also has its Account's fields.
 */
export interface ItemSummary extends Partial<Account> {
  ref: string
  kind: string
  title: string
  detail?: string
  urls: string[]
  search: string[]
  /** The field the item is for, which its row copies: a login's password, a card's number, a note's body. */
  primary?: string
}

/** A field of an item's details. `secret`: its value comes only from device-secret. A file has its name as `value`, and its `size`. */
export interface ItemField {
  name: string
  type: string
  value?: string
  secret?: boolean
  size?: number
}

/** device-item's reply: an item without its secrets. `totp.until`: when the code ends (unix seconds). */
export interface ItemDetail extends ItemSummary {
  name: string | null
  editable: boolean
  /** A login's website. */
  url?: string
  fields: ItemField[]
  totp?: { code: string; period: number; until: number }
}

/** `reply`: the vault's answer as it gave it; `ms`: how long it took. */
export type DeviceReply =
  | { ok: true; reply: Record<string, unknown>; ms: number; status: Status }
  /** `code`: why, for the page to act on ("wrong_passphrase", "passphrase_needed", "backoff", "locked", "expired"). */
  | { ok: false; message: string; status: Status; code?: string; retryAt?: number }
