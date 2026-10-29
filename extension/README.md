# Deadbolt for Chromium

Deadbolt's browser extension for Chrome, Brave, Arc and Edge (Manifest V3). It
fills and saves logins, and makes and signs in with passkeys, through
`deadbolt browser-host`, the native messaging host, which passes each request
to the Deadbolt agent. The agent decides which logins a page gets and signs
with passkeys; the extension never holds the vault, a private key, or the
passphrase.

How it works, which pages get logins, and the host's messages are in
[`docs/autofill.md`](../docs/autofill.md).

## Develop

```sh
bun install
bun run build      # dist/, load it unpacked
bun run watch      # rebuild on change
bun run check      # typecheck and unit tests
```

Load `dist/` with **Load unpacked** on `brave://extensions` (or
`chrome://extensions`) with Developer mode on, and run
`deadbolt browser install` once so the browser can start the host. The build
writes `manifest-key.txt` into the manifest's `key`, which fixes the id at
`jhocodkhpifjndffenppfmdkmiolngal`.

## Layout

| Path                     | What                                                                         |
| ------------------------ | ---------------------------------------------------------------------------- |
| `src/background.ts`      | Service worker: routes messages                                              |
| `src/bg/host.ts`         | The one native port: hello, ids, backoff, `changed`                          |
| `src/bg/frames.ts`       | Which frames get logins; delivery to one document                            |
| `src/bg/autofill.ts`     | Menu tokens, fills, generated passwords, multi-step sign-in sessions, popup  |
| `src/bg/save.ts`         | Captured submits, sign-in outcomes, `check`, offers, `save`                  |
| `src/bg/site.ts`         | Fillable origins and same-site frames                                        |
| `src/bg/signinwith.ts`   | "Sign in with" sessions: popup, provider pages, chooser account              |
| `src/bg/passkeys.ts`     | WebAuthn calls: frame and rpId checks, prompts, fallback                     |
| `src/bg/learn.ts`        | "Learn this site" sessions: saved-username check, log lines                  |
| `src/learn.ts`           | Learning log records and value-free helpers (shape, scrub)                   |
| `src/passkey-hook.ts`    | Page-world `navigator.credentials` hook                                      |
| `src/passkey-options.ts` | The hook's options, serialized whole for the extension                       |
| `src/content.ts`         | Content script: scans, submit capture, settled-page signal                   |
| `src/content/outcome.ts` | What a settled page shows, as yes-or-no facts for `bg/save.ts`               |
| `src/content/ring.ts`    | Ring and pill around what the user should click, closed shadow               |
| `src/content/`           | Detection, Shadow DOM, filling, the menu frame, field rules, passkey channel |
| `src/menu.ts`            | The in-page surface: account list, generated password, fill pill, save offer |
| `src/popup.ts`           | Toolbar popup: logins, offers, passkeys, Learn this site                     |
| `src/ui/motion.ts`       | Springs (CSS `linear()` and retargeting), rolled labels                      |
| `src/protocol.ts`        | Host message types and parsing                                               |
| `src/signin.ts`          | "Sign in with" providers: names, hosts, button words                         |
| `src/messages.ts`        | Messages inside the extension                                                |
| `static/`                | Manifest, pages, CSS (OpenCode theme), Geist fonts, icons                    |
| `e2e/`                   | Headless Chromium runs against a fake host                                   |
| `corpus/`                | Real-site crawl, and `learned.ts` for Learn this site logs                   |

Tests in `test/` run under `bun test` with happy-dom: form detection on
fixtures (including Shadow DOM and frames), origin and same-site rules, frame
targeting, menu tokens and fills against a fake `chrome`, offers and their
timers, host message parsing, the host client against a fake port, and
learning sessions (what a step records, and that no typed value leaves it).

`bun run e2e` loads an e2e build of the extension (`scripts/build.ts --e2e`,
which e2e/run.ts makes for itself) in headless Chromium with fresh
profiles and `e2e/fake-host.py` as the host. `--only security` runs the
hidden, covered, swapped and navigated cases that CI runs; `--stills <dir>`
saves screenshots, and `--video <dir>` records the `film` run (menu, fill,
sign-in, save offer in the page). `--only passkeys --deadbolt <path to deadbolt>` runs the
passkey cases against the real `deadbolt browser-host` and a throwaway store,
and checks every registration and assertion with `@simplewebauthn/server`.

## Not here

- **Opening the app.** Deadbolt has no URL scheme and the host no message for
  it, so "Open Deadbolt" in the popup says where to find the app.
- "Sign in with…" memory, Firefox and Safari.

## Credit

Much of this extension is adapted from
[Foyer](https://github.com/R44VC0RP/foyer) by Ryan Vogel, an autofill
extension for pluggable password managers. Each adapted file says so in its
header.

Adapted from Foyer: form and field detection with weighted clues
(`content/clues.ts`, `content/detect.ts`), Shadow DOM traversal
(`content/shadow.ts`), filling that frameworks notice (`content/fill.ts`), the
inline menu as an extension frame in a closed shadow root
(`content/inline.ts`, `menu.ts`; the top-layer popover host is Deadbolt's), the visibility guard (`ui/dom.ts`),
token-bound frame targeting and the email-first continuation, which sign-in sessions grew from (`bg/frames.ts`,
`bg/autofill.ts`), the capture-check-save flow (`bg/save.ts`), sender origin
rules (`bg/site.ts`), the passkey hook (`passkey-hook.ts`,
`passkey-options.ts`), its channel
(`content/passkeys.ts`), the passkey frame and relying party checks and the
autofill sign-in (`bg/passkeys.ts`), and the build script.

Left out: Foyer's provider abstraction and Bun bridge (Deadbolt has one host),
its passkey store and signing in the extension (the agent holds and signs),
its call reporting and FedCM hooks, SSO memory, the external-extension allowlist, sign-in recipe learning
and its dataset, and the dashboard.

New for Deadbolt: the host client and protocol types, the popup and its save
offers, the one in-page surface and its motion, the same-site frame check, the sign-in outcome probe, the
postMessage token handoff, form-bound fills and fill acks, the single acked
passkey port (Foyer accepted whichever port acked first), passkey prompts in
the popup, generated passwords held by the agent until a sign-up goes through
(only strong ones, with page patterns read by a small parser rather than run),
the OpenCode theme and the icons.
