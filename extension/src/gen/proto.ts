// Generated from crates/proto (deadbolt-proto) by `bun run gen:proto`. Do not
// edit: change the Rust types and regenerate. CI fails when this file is stale.
//
// The messages between the extension and `deadbolt browser-host`, as
// specified in docs/autofill.md. The browser does the framing (a native-endian
// u32 length, then UTF-8 JSON); this file is the JSON. extension/src/protocol.ts
// adds the TypeScript-only helpers and the checks on what the host sends.

export const NATIVE_HOST = "anomaly.deadbolt.browser"
export const PROTOCOL = 3

/** An identity's fields a form may ask for, named after the HTML autocomplete tokens (`city` is `address-level2`, `region` `address-level1`). */
export const IDENTITY_FIELDS = ["honorific", "given-name", "additional-name", "family-name", "nickname", "organization", "job-title", "email", "phone", "address-line1", "address-line2", "address-line3", "city", "region", "postal-code", "country", "birthday"] as const
/** A card's fields a form may ask for. `number` and `cvv` raise Touch ID in the daemon when it's on; `expiry` is `YYYY-MM`. */
export const CARD_FIELDS = ["cardholder", "number", "expiry", "cvv", "brand"] as const
export type IdentityField = (typeof IDENTITY_FIELDS)[number]
export type CardField = (typeof CARD_FIELDS)[number]
export type FormField = IdentityField | CardField

/**
 * A secret on the wire: wiped on drop; Debug leaves it out. A newtype, so
 * its JSON is the string itself.
 */
export type Secret = string

/** A value autofill can ask for. */
export type Want = "username" | "password" | "totp"

/** How a login typed into a page compares with the saved ones. */
export type CheckStatus = "new" | "update" | "same"

/** What a site asks of user verification in a passkey ceremony. */
export type UserVerification = "required" | "preferred" | "discouraged"

/** The kinds of item forms fill from. */
export type FormKind = "identity" | "card"

/** Whether the host can serve requests now, in `hello`. */
export type HostStatus = "ready" | "locked" | "not-set-up" | "unavailable"

/** What the host pushes about the daemon, in `changed`. */
export type Change = "locked" | "unlocked" | "items" | "stopped" | "started"

/** Why a request was refused, in `error`. */
export type ErrorCode =
  | "forbidden"
  | "locked"
  | "not_found"
  | "domain_mismatch"
  | "bad_request"
  | "rate_limited"
  | "exists"
  | "cancelled"
  | "weak"
  | "failed"

/**
 * A "Sign in with Google" login: the provider and, if the login it signs
 * in with is in one of the user's vaults, that login's username, else its
 * title. Never any other value of that login.
 */
export type SignIn = {
  /**
   * The provider's id (`google`, see
   * `SIGN_IN_PROVIDERS`) or, for one
   * this version doesn't know, its name as given.
   */
  provider: string
  account?: string
}

/**
 * What a page says about a new-password field: its `passwordrules`, length
 * limits and the characters its `pattern` takes.
 */
export type FieldRules = {
  rules?: string
  minLength?: number
  maxLength?: number
  allowed?: string
}

/**
 * A save's provider link: the provider's id and the login (a ref) it signs
 * in with.
 */
export type EntrySignIn = {
  provider: string
  account: string
}

/**
 * A login to save: a password, typed or `generated`, or a provider link
 * (`signIn`) in its place.
 */
export type Entry = {
  title: string
  url: string
  username?: string
  password?: Secret
  generated?: string
  /** In place of a password: a login that signs in with a provider login. */
  signIn?: EntrySignIn
}

/** The passkeys saved for the page's relying party. */
export type PasskeyList = {
  origin: string
  rpId?: string
}

/** The account a registration is for, as the page names it. */
export type PasskeyUser = {
  id: string
  name: string
  displayName?: string
}

export type PasskeyCreate = {
  origin: string
  rpId?: string
  challenge: string
  user: PasskeyUser
  /** Credential ids already registered, which must not be registered again. */
  exclude: string[]
  userVerification: UserVerification
}

export type PasskeyGet = {
  origin: string
  rpId?: string
  ref: string
  challenge: string
  userVerification: UserVerification
}

export type PasskeyCancel = {
  /** The id of the `passkey-create` or `passkey-get` to stop. */
  request: number
}

/** A message from the extension, after its `id`. */
export type RequestBody =
  | { type: "hello" }
  | {
      type: "list"
      origin: string
    }
  | {
      type: "fill"
      origin: string
      ref: string
      want: Want[]
    }
  | {
      type: "generate"
      origin: string
      rules?: string
      minLength?: number
      maxLength?: number
      allowed?: string
    }
  | {
      type: "generate-check"
      origin: string
      rules?: string
      minLength?: number
      maxLength?: number
      allowed?: string
    }
  | {
      type: "generate-keep"
      origin: string
      generated: string
    }
  | {
      type: "generate-drop"
      origin: string
      generated: string
    }
  | {
      type: "check"
      origin: string
      username?: string
      password?: Secret
      generated?: string
    }
  | {
      type: "save"
      origin: string
      entry: Entry
      ref?: string
    }
  | {
      type: "forms"
      origin: string
      kinds: FormKind[]
    }
  | {
      type: "fill-form"
      origin: string
      ref: string
      fields: FormField[]
    }
  | {
      type: "save-form"
      origin: string
      kind: FormKind
      ref?: string
      fields: Partial<Record<FormField, string>>
    }
  | { type: "passkey-list" } & PasskeyList
  | { type: "passkey-create" } & PasskeyCreate
  | { type: "passkey-get" } & PasskeyGet
  | { type: "passkey-cancel" } & PasskeyCancel
  | {
      type: "learn"
      session: string
      line: Record<string, unknown>
    }
  | {
      type: "learn-read"
      session: string
      offset?: number
    }
  | {
      type: "learn-delete"
      session: string
    }
  | { type: "unlock-prompt" }

/** A login saved for the site, without values. */
export type Account = {
  ref: string
  vault: string
  title: string
  username?: string
  hasPassword: boolean
  hasTotp: boolean
  urls: string[]
  /**
   * A "Sign in with Google" login: the provider (a known id such as
   * `google`, or a name), and the linked account's username or title.
   */
  signIn?: SignIn
}

/** What a fill asked for and the login has. */
export type SiteValues = {
  username?: string
  password?: Secret
  totp?: Secret
}

/** An identity a form can be filled from: no values, only which fields it has. */
export type FormIdentity = {
  ref: string
  vault: string
  title: string
  /** "Alex Mercer · 123 Main St, Brooklyn"; may be empty. */
  summary: string
  fields: IdentityField[]
}

/** A card a form can be filled from: never its number or code. */
export type FormCard = {
  ref: string
  vault: string
  title: string
  brand?: string
  last4: string
  /** `YYYY-MM`. */
  expiry?: string
  cardholder?: string
  /** The ref of the identity whose address is its billing address. */
  billing?: string
  fields: CardField[]
}

/** A passkey saved for the relying party; never its private key. */
export type Passkey = {
  ref: string
  vault: string
  credentialId: string
  username?: string
  /** `YYYY-MM-DD`. */
  created?: string
}

/** The `passkeys` reply. */
export type Passkeys = {
  rpId: string
  canVerify: boolean
  passkeys: Passkey[]
}

/** The `passkey-created` reply. */
export type PasskeyCreated = {
  ref: string
  credentialId: string
  clientDataJSON: string
  attestationObject: string
  authenticatorData: string
  publicKey: string
  verified: boolean
}

/** The `passkey-assertion` reply. */
export type PasskeyAssertion = {
  credentialId: string
  clientDataJSON: string
  authenticatorData: string
  signature: string
  userHandle: string
  verified: boolean
}

/**
 * What the host sends: the answer to a request, or (`changed`) a change
 * it pushes on its own.
 */
export type Body =
  | {
      type: "hello"
      protocol: number
      version: string
      status: HostStatus
      detail?: string
      /** What this host does (`CAPABILITIES`). */
      capabilities: string[]
      /** Locked, and Touch ID can unlock it now (`unlock-prompt` asks for it). */
      touchIdReady?: boolean
    }
  | {
      type: "list"
      /** The site the origin belongs to, as the logins are saved for. */
      site: string
      accounts: Account[]
    }
  | {
      type: "fill"
      username?: string
      password?: Secret
      totp?: Secret
    }
  | {
      type: "generate"
      password: Secret
      /** Names it in `check` and `save`. */
      generated: string
    }
  | { type: "generate-check" }
  | { type: "generate-keep" }
  | { type: "generate-drop" }
  | {
      type: "check"
      status: CheckStatus
      /** The refs of the saved logins with that username. */
      matches: string[]
    }
  | {
      type: "save"
      ref: string
      created: boolean
    }
  | {
      type: "error"
      code: ErrorCode
      message: string
    }
  | {
      type: "changed"
      change: Change
      /** On `locked`: Touch ID can unlock it now, as hello's says. */
      touchIdReady?: boolean
    }
  | {
      type: "forms"
      identities: FormIdentity[]
      cards: FormCard[]
      /** Whether filling a card's number or code now raises Touch ID. */
      canVerify: boolean
    }
  | {
      type: "fill-form"
      /** Only the fields asked for that the item has. */
      values: Partial<Record<FormField, string>>
      /** Whether Touch ID verified the user for this fill. */
      verified: boolean
    }
  | {
      type: "save-form"
      ref: string
      created: boolean
    }
  | { type: "passkeys" } & Passkeys
  | { type: "passkey-created" } & PasskeyCreated
  | { type: "passkey-assertion" } & PasskeyAssertion
  | {
      type: "passkey-cancelled"
      found: boolean
    }
  | { type: "learned" }
  | {
      type: "learn-text"
      text: string
      /** Where the rest of the log starts, or null at its end. */
      next: number | null
    }
  | {
      type: "learn-deleted"
      found: boolean
    }
  | {
      type: "unlock-prompt"
      app: boolean
    }
