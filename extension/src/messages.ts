// Messages inside the extension: content scripts, the inline menu and the
// popup all talk to the background worker, which alone talks to the native
// host. Secrets appear only in FillValues, sent by the background to the one
// document and form the user chose to fill, and in a capture, sent by a
// content script after the user submitted a login form.

import type { Account, HostStatus } from "./protocol"

export type FieldRole = "username" | "email" | "phone" | "password" | "new-password" | "otp" | "captcha"
export type SurfaceKind = "login" | "signup" | "change-password" | "reset" | "mfa"
/** What Deadbolt's in-page surface shows: the account list, a pill on a field or at the top right, or the save offer. */
export type SurfaceMode = "accounts" | "pill" | "save"
export const SURFACE_MODES: SurfaceMode[] = ["accounts", "pill", "save"]

/** Roles the inline menu opens on. */
export const MENU_ROLES: FieldRole[] = ["username", "email", "phone", "password", "otp"]
export const IDENTIFIER_ROLES: FieldRole[] = ["username", "email", "phone"]
/** Roles a fill can write. */
export const FIELD_ROLES: FieldRole[] = ["username", "email", "phone", "password", "new-password", "otp"]

export interface FillValues {
  username?: string
  password?: string
  totp?: string
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
  /** `explicit`: the user clicked into the field or pressed ↓ in it, rather than just focusing it. */
  /**
   * `identifier`: on a password or code field, what the form's username or
   * email box holds, so the menu can narrow to the login it names (see
   * Autofill.query). It stays in the extension. `again`: the user pressed ↓
   * or clicked the field a second time, asking for the whole list.
   */
  | { type: "db:query"; roles: FieldRole[]; focused: FieldRole; form: number; explicit?: boolean; again?: boolean; identifier?: string }
  /** `stepped`: since the last fill in this document, the user submitted or the filled fields went. */
  /** `idEmpty`: the form has a username or email box and it's empty (a "Use a different account" step). */
  | { type: "db:page"; kind: SurfaceKind | null; roles: FieldRole[]; form: number; stepped: boolean; idEmpty?: boolean }
  /** The top page may have finished a sign-in step: it showed no login form for a moment, or moved on to a code step. */
  | { type: "db:settled" }
  | { type: "db:capture"; username?: string; password?: string; newPassword?: string; title: string }
  /** The user themselves submitted a login form here: a trusted click on its submit control, or Enter in one of its fields. */
  | { type: "db:submitted" }
  | { type: "db:menu-close"; token: string; dismissed?: boolean }
  // inline menu
  /** `parent`: the origin of the parent window that handed the menu its token. */
  | { type: "db:menu-load"; token: string; parent: string }
  | { type: "db:menu-pick"; token: string; ref: string }
  /** The user picked a "Sign in with …" row: point at the site's button for it (see SignInReply). */
  | { type: "db:menu-signin"; token: string; ref: string }
  | { type: "db:menu-dismiss"; token: string }
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
  /** `notice`: a sign-in session's step filled without a pick shows a pill on the field, with this token for its frame. */
  | { type: "db:fill"; values: FillValues; form: number; approval: string; notice?: string }
  /**
   * Which of the form's fields may be filled now (see Approved). With
   * `measure`, for a frame: where they show, and only if they all do.
   */
  | { type: "db:approve"; form: number; measure: boolean }
  /** Where the fields of `approval` show now, if every one of them still does. */
  | { type: "db:approved"; approval: string }
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
  | { type: "db:close-menu"; token: string }
  | { type: "db:resize-menu"; token: string; height: number; width?: number; mode?: SurfaceMode }
  /** Open the save offer in the page, with this token for its frame (see bg/save.ts). */
  | { type: "db:surface"; token: string }
  // Can the user see a frame's form? (see shownInPage)
  /** To the frame above: where those boxes show in it, through the element `nonce` names. */
  | { type: "db:frame-child"; nonce: string; boxes: Box[] }
  /** To the frame below: tell the frame above which element you're in. */
  | { type: "db:frame-announce"; nonce: string }

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
}

/** A content script's answer to db:fill: the fields it actually wrote. */
export interface FillAck {
  filled: FieldRole[]
}

/** Broadcast to open extension pages (popup, menus) when the host's state changes. */
export interface StatusChanged {
  type: "db:status"
  status: Status
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
}

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
 * for Touch ID before it signs.
 */
export type PasskeyPrompt = {
  id: string
  rpId: string
  verify: boolean
} & (
  | { kind: "get"; passkeys: Array<{ ref: string; vault: string; username?: string; created?: string }> }
  /** `registered`: the site already has one of its excluded passkeys in Deadbolt. */
  | { kind: "create"; username: string; registered: boolean }
)

/** `fallback`: the browser's own passkey flow, such as a phone or security key. */
export type PasskeyChoice = { action: "use"; ref: string } | { action: "save" } | { action: "fallback" } | { action: "cancel" }
