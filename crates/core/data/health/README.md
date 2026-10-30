# Password health directories

Compiled into `deadbolt-core` (`crates/core/src/health/directory.rs`) so weak,
reused, compromised-site, two-factor, and passkey checks run offline with zero
network requests. Refresh with `bun scripts/sync-health-data.ts` (snapshot
date: 2026-10-30).

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
  at commit `d158201a3c67899494b1beea0a6c016a44d835d5` (MIT).
