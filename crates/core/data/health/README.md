# Password health directories

Compiled into `deadbolt-core` (`crates/core/src/health/directory.rs`) so weak,
reused, compromised-site, two-factor, and passkey checks run offline with zero
network requests. Refresh the first three with `bun scripts/sync-health-data.ts`
(snapshot date: 2026-10-30) and Apple's two with `bun scripts/sync-quirks.ts`.

- `2fa.json`: TOTP-supporting domains and setup links from
  [2FA Directory](https://2fa.directory/) (`2factorauth/twofactorauth`, MIT).
- `passkeys.json`: passkey-supporting domains and setup links from
  [Passkeys Directory](https://passkeys.2fa.directory/) (`2factorauth/passkeys`,
  CC BY 4.0).
- `breaches.json`: verified password-exposing domain breaches from
  [Have I Been Pwned](https://haveibeenpwned.com/API/v3) (`/api/v3/breaches`,
  CC BY 4.0).
- `change-urls.json` and `shared.json`: `quirks/change-password-URLs.json` and
  `quirks/shared-credentials.json` from Apple's
  [password-manager-resources](https://github.com/apple/password-manager-resources)
  at commit `6c0cedf7b5664cfc41bcc0a0d9e59325d0468271` (2026-11-19), under the MIT license
  in `LICENSE.md`. `shared.json` is Apple's file with every field kept;
  autofill offers a login saved on one site of a `shared` group on the
  others, and one saved on a `from` site on its `to` sites, never the
  reverse (`crates/core/src/site/shared.rs`).
