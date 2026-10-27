# Deadbolt for Chromium

Deadbolt's browser extension for Chrome, Brave, Arc and Edge (Manifest V3). It
fills and saves logins through `deadbolt browser-host`, the native messaging
host, which passes each request to the Deadbolt agent. The agent decides which
logins a page gets; the extension never holds the vault or asks for the
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

| Path                    | What                                                            |
| ----------------------- | --------------------------------------------------------------- |
| `src/background.ts`     | Service worker: routes messages                                 |
| `src/bg/host.ts`        | The one native port: hello, ids, backoff, `changed`             |
| `src/bg/frames.ts`      | Which frames get logins; delivery to one document               |
| `src/bg/autofill.ts`    | Menu tokens, fills, email-first continuation, popup             |
| `src/bg/save.ts`        | Captured submits, `check`, offers in the popup, `save`          |
| `src/bg/site.ts`        | Fillable origins and same-site frames                           |
| `src/content.ts`        | Content script: scans, submit capture, quiet-page signal        |
| `src/content/`          | Detection, Shadow DOM, filling, the menu frame                  |
| `src/menu.ts`           | Inline menu page                                                |
| `src/popup.ts`          | Toolbar popup: status, logins, save offers                      |
| `src/protocol.ts`       | Host message types and parsing                                  |
| `src/messages.ts`       | Messages inside the extension                                   |
| `static/`               | Manifest, pages, CSS (OpenCode theme), Geist fonts, icons       |
| `e2e/`                  | Headless Chromium runs against a fake host                      |

Tests in `test/` run under `bun test` with happy-dom: form detection on
fixtures (including Shadow DOM and frames), origin and same-site rules, frame
targeting, menu tokens and fills against a fake `chrome`, offers and their
timers, host message parsing, and the host client against a fake port.

`bun run e2e` loads the built extension in headless Chromium with fresh
profiles and `e2e/fake-host.py` as the host. `--only security` runs the
hidden, covered, swapped and navigated cases that CI runs; `--stills <dir>`
saves screenshots.

## Not here

- **Password generation.** The host offers `list`, `fill`, `check` and `save`
  and no `generate`, so sign-up forms get no suggestion.
- **Opening the app.** Deadbolt has no URL scheme and the host no message for
  it, so "Open Deadbolt" in the popup says where to find the app.
- Passkeys, "Sign in with…" memory, Firefox and Safari.

## Credit

Much of this extension is adapted from
[Foyer](https://github.com/R44VC0RP/foyer) by Ryan Vogel, an autofill
extension for pluggable password managers. Each adapted file says so in its
header.

Adapted from Foyer: form and field detection with weighted clues
(`content/clues.ts`, `content/detect.ts`), Shadow DOM traversal
(`content/shadow.ts`), filling that frameworks notice (`content/fill.ts`), the
inline menu as an extension frame in a closed shadow root
(`content/inline.ts`, `menu.ts`), the visibility guard (`ui/dom.ts`),
token-bound frame targeting and the email-first continuation (`bg/frames.ts`,
`bg/autofill.ts`), the capture-check-save flow (`bg/save.ts`), sender origin
rules (`bg/site.ts`) and the build script.

Left out: Foyer's provider abstraction and Bun bridge (Deadbolt has one host),
passkeys, SSO memory, the external-extension allowlist, sign-in recipe learning
and its dataset, and the dashboard.

New for Deadbolt: the host client and protocol types, the popup and its save
offers, the same-site frame check, the quiet-page sign-in signal, the
postMessage token handoff, form-bound fills and fill acks, the OpenCode theme
and the icons.
