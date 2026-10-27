# Browser autofill

Deadbolt fills and saves passwords, and makes and signs in with passkeys, in
Chromium browsers (Chrome, Brave, Arc, Edge, Chromium) through its own
extension, in `extension/`. This doc covers
the agent's side, the native messaging host, the extension, and the messages
between them.

```text
web page ─ content script ─ extension ══ native messaging ══ deadbolt browser-host ── agent socket ── agent
                                          (stdin/stdout)        (shape checks only)                   (decides)
```

- **The agent decides.** Matching a page to logins, refusing another site's
  login, computing one-time codes and comparing passwords all happen in the
  agent (`crates/cli/src/agent/autofill.rs`, rules in `crates/cli/src/site.rs`).
  Each agent command names the page's origin and the agent works out the site
  itself, so nothing upstream can widen what a page gets.
- **The host is a pipe.** `deadbolt browser-host` checks the shape of each
  message, turns it into one agent command (`site-logins`, `site-fill`,
  `site-check`, `site-save`, `passkey-list`, `passkey-create`,
  `passkey-get`) and passes the agent's watch stream back as `changed`
  messages. It never prompts for a passphrase or Touch ID; the agent asks for
  Touch ID itself before it signs with a passkey (see Passkeys).
- **The extension** finds login forms, asks the host, and fills. Saves need a
  click in the extension's own UI.

## Install

```sh
deadbolt browser install                      # browsers found on this computer
deadbolt browser install --browser brave      # or name them: chrome brave arc edge chromium all
deadbolt browser uninstall                    # every browser, or --browser
```

`install` writes `pw.deadbolt.browser.json` to each browser's
`NativeMessagingHosts` directory:

| Browser  | macOS (`~/Library/Application Support/…`) | Linux (`$XDG_CONFIG_HOME` or `~/.config/…`) |
| -------- | ----------------------------------------- | ------------------------------------------- |
| Chrome   | `Google/Chrome`                           | `google-chrome`                             |
| Brave    | `BraveSoftware/Brave-Browser`             | `BraveSoftware/Brave-Browser`               |
| Arc      | `Arc/User Data`                           | (none)                                      |
| Edge     | `Microsoft Edge`                          | `microsoft-edge`                            |
| Chromium | `Chromium`                                | `chromium`                                  |

```json
{
  "name": "pw.deadbolt.browser",
  "description": "Deadbolt password manager",
  "path": "/absolute/path/to/deadbolt",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://jhocodkhpifjndffenppfmdkmiolngal/"]
}
```

Without `--browser`, a browser counts as installed when its directory exists.
Run `install` again after moving the binary.

**`path` is the `deadbolt` binary itself.** A browser runs a host with one
argument, the caller's origin (`chrome-extension://<id>/`), and a manifest
can't add others. So when `deadbolt` gets exactly one argument starting with
`chrome-extension://`, it runs `deadbolt browser-host <origin>`. A launcher
script would also work, but it's a second file that has to point at the
binary and can drift from it.

**The extension id is fixed by a key.** `extension/manifest-key.txt` holds the
base64 DER SubjectPublicKeyInfo of an RSA-2048 key, which goes in the extension
manifest's `key` field. Chrome derives the id from it: SHA-256 of the DER, the
first 16 bytes in hex, each digit `0`–`f` written as a letter `a`–`p`. That
gives `jhocodkhpifjndffenppfmdkmiolngal`, which a unit test checks against
`EXTENSION_ID`. Only the public key is committed. Loading the extension
unpacked doesn't need the private key, and it was discarded. Packing a `.crx`
ourselves would need a new key, so a new id. The Chrome Web Store signs with
its own key, so a store listing gets another id, and that id would go into
`allowed_origins` too.

The host refuses to start for any origin other than the extension's, and
`allowed_origins` already stops the browser from connecting any other
extension.

## Load the extension unpacked (Brave, Chrome, Arc, Edge)

There's no store listing yet. Build it and load it from disk:

```sh
cd extension
bun install
bun run build                  # writes extension/dist
deadbolt browser install       # lets the browser start deadbolt browser-host
```

1. Open `brave://extensions` (`chrome://extensions` in Chrome and Arc,
   `edge://extensions` in Edge).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose `extension/dist`.

The manifest's `key` gives it the id `jhocodkhpifjndffenppfmdkmiolngal`, the
one `install` allows. After rebuilding, click the reload arrow on its card.
If the toolbar popup says the helper isn't installed, run
`deadbolt browser install` and open the popup again.

## The extension

One service worker owns the extension's only port to the host
(`chrome.runtime.connectNative("pw.deadbolt.browser")`). It sends hello on
connect, reconnects with backoff (1s up to 60s) when the host goes away, and
follows `changed`. It never asks for the passphrase: a locked vault shows
"Unlock Deadbolt" and waits for `unlocked`. A `stopped` push shows Deadbolt as
not running without sending hello, which would start the agent again.

- **Inline menu.** Focusing a username, email, password or code field in the
  top page after a click or keypress opens a menu of that site's logins,
  title and username, under the field. ↓/↑ choose, ⏎ fills, esc closes, and
  ↓ reopens it. While Deadbolt is locked, the menu's "locked" row opens on
  focus once per site until Deadbolt locks or unlocks again; after that it
  takes a click into the field or ↓. Fields in frames get no menu (see Frames). It's an extension
  page in an iframe inside a closed shadow root on a plain element, so the
  page can't read it or click it for you.
- **Menu visibility.** The menu samples its own visibility rather than
  watching it continuously: an `IntersectionObserver` with `trackVisibility`
  gives a reading at most every 100 ms, saying whether the menu is fully on
  screen, unscaled, opaque and uncovered. A pick, by mouse or keyboard,
  counts only if every reading for at least 500 ms before the key or button
  went down said so and the menu hadn't moved or changed size, and nothing
  changes until a fresh reading taken 400 ms after the press confirms it. A
  frame hears about changes the page makes to it only after a short delay,
  so a reading right at the press can predate them. Every change starts the
  500 ms again. If it's covered, faded, clipped, shown only at the press or
  can't be measured, it fills nothing and says so. A page that covers the
  menu briefly between two readings can go unseen (see the threat model).
- **Keyboard picks.** ⏎ picks only after the user's own ↓ in the field
  moved focus into the menu, or a real press inside the menu put it there
  and passed the same visibility checks as a pick. A press the menu refused
  lets no later ⏎ pick either. Focus that got into the menu any other way, such as by Tab from a field
  the page made last in the tab order or by a script, doesn't count, and
  leaving the menu ends it even if focus comes back. Such a menu says "Press
  ↓ in the field to choose."
- **Menu tokens.** The menu page's URL carries nothing. When it loads it asks
  its parent with `postMessage`; the content script answers only that frame's
  window, at the extension's origin, with a token bound to the tab, frame,
  document and origin that opened the menu. The first extension page to
  present the token, with that origin as its parent, owns it; any other page,
  or the same token after the page navigated or the menu closed, gets nothing.
- **Filling.** The service worker fills only a document that just asked: the
  content script must have reported the focused form for this frame, the
  frame's origin (as the browser reports it, never `null`) must be fillable,
  and the reply goes to that exact `documentId`, so a frame that navigated
  away gets nothing. The popup's Fill works the same way, into the top page's
  form, or into a frame's when the top page has none (see Frames). Before it
  chooses, the popup asks the top page for a fresh report, and a page whose
  form went away without a navigation, such as an app that swapped it for a
  frame, reports that it has none. Values go
  only to the form they were asked for: if the form was replaced or its
  fields changed, nothing is filled. When the user picks or clicks Fill, the
  content script fixes which of the form's fields may be filled right then;
  the host is asked only for their values and only those fields are written
  (the open menu itself doesn't count as covering a field then; it closes
  before anything is written).
  A field the page enables or shows later, such as a disabled password it
  turns on when the username is focused for the fill, gets nothing. If the
  sign-in was cancelled (Esc, or a
  navigation the page didn't make) while the host was answering, the values
  are dropped instead of delivered.
  Each field is checked again right before its value is written, and before
  each digit of a split code: it must still be in the form and under the
  parent it was found in, enabled, editable, and visible through every
  ancestor up to the top of the page, across shadow roots (display,
  visibility, opacity, clip, size, on screen, not covered). Split one-time
  code boxes fill only as one whole group within one form.
- **Email-first sign-ins.** When the content script reports that it filled a
  username into the top page, the next step (a password or code field) on
  the same origin fills from the same login once, within two minutes. The
  page has to have moved on first: a new document, or in the same one, the
  user submitting or the filled fields going away. A matching field showing
  up next to the one just filled isn't enough. Frames never continue. Esc,
  closing the menu, another origin, or a navigation the page didn't make (a
  typed address, a bookmark, a reload, back or forward) cancels it, including
  for fills still on their way.
- **Frames.** Every frame runs the content script, but only frames on the same
  site as the top page get logins, and sandboxed frames get none. A frame
  gets no inline menu: where it sits, how big it is and what covers it are
  up to the page around it, and a menu inside can't watch that. A frame's
  form fills only from the popup, and only if the user can see it through
  every frame above it, checked when the user clicks Fill and again once the
  values are in hand. Both checks cover exactly the fields that will be
  written. The frame checks its fields (style up the tree, size,
  clipping, on screen, nothing over them, and a fresh `trackVisibility`
  reading, which also sees covers that let clicks through). Then each frame
  above, up to the top page, checks the element the frame below sits in the
  same way, unscaled, and that the fields' middles land on it. Any frame on
  the way that can't answer, such as one without the content script, means
  no fill. If more than one frame's form shows, nothing is filled.
- **Popup.** Shows whether Deadbolt is ready, locked, not set up, or the host
  isn't installed (with the `deadbolt browser install` command), and the
  current site's logins with Fill and Copy username. Passwords are never
  copied: every app can read the clipboard and clipboard managers keep it.
- **Saving.** When you submit a login, sign-up or change-password form, the
  content script hands the username and password to the service worker,
  which keeps them in memory for up to three minutes from when the password
  was submitted (a username on its own joins it but doesn't extend that), and
  forgets them when Deadbolt locks or disconnects or the tab moves to another
  site.
- **Did the sign-in work?** The top page says when it settles: no login form
  for a couple of seconds, a code step, or a couple of seconds after a
  submit. The service worker then asks that document what it shows (see
  Sign-in outcomes) and judges it. Only a sign-in that worked gets a `check`.
  On `new` or `update` the offer goes to the toolbar popup, never the page:
  the toolbar button gets a badge, and for a confirmed sign-in the popup
  opens by itself where the browser allows it, at most once per site every
  ten minutes (see the threat model). The popup asks "Save login for <site>?"
  or "Update password for <username>?" with Save, Not now and Never for this
  site, and sends `save` only on Save. Not now also holds back the same
  username on the site for a day (the service worker keeps a SHA-256 of the
  site and username, salted once per browser session, in session storage,
  not the username). Never for this
  site keeps the site in the extension's local storage, and from then on
  nothing typed there is kept or checked; the popup says "Saving is off for
  <site>" with Turn on. Each offer has its own id, and Save or Not now answers only
  the offer the popup showed; if another took its place, the popup shows that
  one instead. A check that finishes after the tab left the site, closed, or
  Deadbolt locked offers nothing. Offers expire after five minutes. A new login is named after
  the form's page title and saved with that page's URL, without its query or
  fragment. A `rate_limited` check offers nothing; a `rate_limited` fill says
  to try again in a moment.
- **Sign-in outcomes.** The content script answers with yes-or-no facts
  only, never page text or values (`content/outcome.ts`): a login form still
  shows, and its password box is empty; a code step; an error (a field
  marked `aria-invalid`, or an alert or error box in view whose text says
  incorrect, invalid, too many attempts and the like, in English, French,
  German or Spanish; vaguer words such as expired, locked or try again, and
  polite live regions and `alert` boxes, count only by a login form); a
  captcha or bot check (a "Just a moment" page, a visible reCAPTCHA,
  hCaptcha, Turnstile or Arkose frame or widget, or a captcha box on a login
  form); the submitted username, or an email's part before the @, as a whole
  word of four characters or more; a Sign out control; a sign-in looking
  URL. Each walk is bounded: 400 elements, error boxes with more than 400
  characters or a dozen elements skipped, 200 characters read from each, and
  30 ms in all. The judgment, in order:
  - An error with no account or Sign out showing, or with the form back, or
    the form back with an empty password: failed. No offer, and from then on
    that password is offered only by a confirmed sign-in.
  - A code step or a captcha: pending. No offer yet, and the password is
    kept up to five minutes from the submit, for the page after it.
  - The form still there: not yet.
  - The account or Sign out shows: confirmed. Offered, and the popup may
    open.
  - Nothing either way: looked at again four seconds later. Still nothing is
    likely, and offered with the badge only. On a sign-in looking URL
    (`/login?error=1`, `/session`) nothing is offered, except after a sign-up
    or new password, whose next page is often "verify your email".
  Failed and pending keep what was typed until it expires: a retry with the
  right password replaces it and starts over.
- **Sites that opt out.** A field is left alone, with no menu, fill or save,
  when it, its form or the page's `<body>` has `data-1p-ignore`,
  `data-op-ignore`, `data-lpignore="true"`, `data-bwignore`,
  `data-form-type="other"` or `data-deadbolt-ignore`.
- **Noise filters.** Only a real click, Enter or form submit (a trusted
  event) captures, and only a password typed in the field or filled by
  Deadbolt counts. The extension keeps an HMAC of those values, under a key
  only the content script holds, rather than the values. These keep script
  noise out of the popup; they don't prove where a password came from (see
  the threat model).
- **No password generator.** The host's capabilities are
  `list`, `fill`, `check`, `save` and `passkeys`; there's no `generate`
  message yet, so sign-up forms get no suggested password.
- **Passkeys.** A script in the page's own world answers
  `navigator.credentials.create` and `get` from Deadbolt, through the
  toolbar popup or the inline menu, and hands anything Deadbolt can't do back
  to the browser (see Passkeys).

## Which logins a page gets

These rules follow Foyer's (see Prior art), so the two behave alike:

- **Pages:** https only, or http on `localhost`, `127.0.0.1`, `*.localhost`
  and `*.test` (a trailing dot allowed). Anything else (http sites, `file:`,
  `data:`, extension pages) gets `bad_request`.
- **A page's site** is the registrable domain of its host under the full
  Public Suffix List, private section included (the `psl` crate, compiled in,
  updated by bumping it). `gist.github.com` is on `github.com`, while
  `alice.github.io` and `bob.github.io` are two sites. An IPv4 address,
  `localhost` and a single label are their own sites. A page whose host is a
  public suffix itself (`github.io`, `co.uk`) has no site and gets nothing.
- **A saved URL is on the site** when its host is the site, under it, or has
  it as its registrable domain. A URL without `://` is read as `https://`.
  Hosts are parsed as browsers parse them (WHATWG URL rules via the `url`
  crate): lowercase, IDNs in punycode, port and path ignored. Lookalikes
  don't match: `github.com.evil.com`, `evilgithub.com`, a punycode `gíthub.com`
  or `https://github.com@evil.com` aren't on `github.com`.
- **Labels agree:** a login's title when it has no name, and search, use
  the same host parsing, so `https://evil.com\@github.com` is labelled
  `evil.com`, where it would fill.
- **A login's URLs** are all its fields of type url: `url`, plus `url-2`,
  `url-3`… that imports keep. Any one matching is enough. A list shows only
  the URLs that match.
- **Every vault** is searched. A `ref` is `<vault id>:<item id>` (64 and 32
  lowercase hex digits), so it names one login without ambiguity. New logins
  go to the default vault.

## Passkeys

Deadbolt keeps passkeys in the vault and signs with them in the agent, so a
passkey made on one device signs in on every device the vault syncs to. The
private key never leaves the agent: not to the host, the extension or the
app.

```text
page ── passkey-hook (MAIN world) ══ one acked MessagePort ══ content script ── service worker ── host ── agent
        navigator.credentials        (page options only)                         sender.origin       Touch ID, signs
```

- **In the vault** a passkey is an item of kind `passkey`: `rp-id`,
  `username`, `credential-id`, `user-handle` (both base64url), `private-key`
  (a base64url PKCS#8 P-256 key, a secret field), `created` and `notes`. Its
  own kind, rather than fields on a login, because a passkey belongs to a
  relying party id, not to URLs, and because a login and its passkey change
  and go away independently. An item kind gets core's rules for free:
  required fields, and a secret field that listings, search and the app
  never show. The agent alone reads the private key, to sign. Registering again for
  the same user on the same relying party replaces the item, unless the site
  excluded it: the agent checks `excludeCredentials` again just before it
  saves, so one that appeared while the user was asked is never replaced.
- **Algorithm:** ES256 (COSE -7) only. A registration whose
  `pubKeyCredParams` lacks it goes to the browser.
- **Attestation:** `none`, with a fixed AAGUID
  (`3a31ecda-fefc-f251-1f3e-a11bfdc1de5f`) and canonical CBOR (RFC 8949
  core deterministic encoding). Credential ids are 16 random bytes.
- **Sign counter: always 0.** The vault syncs, so the same passkey signs on
  several devices with no shared counter; any count would go backwards
  sometimes and look like a cloned key. WebAuthn lets an authenticator that
  can't keep a counter send 0, and relying parties then skip the check. The
  flags say so too: BE (backup eligible) and BS (backed up) are set, as for
  any synced passkey.
- **Flags:** UP (the user clicked Sign in or Save in Deadbolt's own UI), BE
  and BS always, AT on registration, and UV only after Touch ID.
- **User verification (UV)** means the agent asked Touch ID and the Secure
  Enclave released this store's biometric key, the same check unlock makes,
  and the key opened the store. It asks once per registration or sign-in,
  one prompt at a time, and closes the prompt if the request is cancelled.
  - `discouraged`: no prompt, UV=0.
  - `preferred` (the default): Touch ID when it's on and set up for this
    store, else UV=0.
  - `required`: Touch ID, or the request fails before anything is stored or
    signed ("this site requires user verification, and Touch ID is off or not
    set up"). The extension, which learns from `passkey-list` whether the
    agent can verify, hands such a request to the browser instead, and the
    popup says when Touch ID will be asked.
  Clicking Deadbolt's prompt is presence, not verification, so it never sets
  UV on its own.
- **Client data** is built by the agent from the origin the browser reported
  for the frame (`sender.origin`): `type`, the challenge, that origin, and
  `crossOrigin: false`. Nothing the page says goes into it except the
  challenge.
- **Relying party id:** the page's host when the page names none, or one it
  names that is the host or a parent of it on the same site, by the Public
  Suffix List with its private section (`site::rp_id`). Never a public
  suffix (`github.io`, `co.uk`), an IP address or another site. The
  extension checks first (`SecurityError`, "This relying party ID isn't this
  site's.") and the agent checks again (`domain_mismatch`).
- **Frames:** a sandboxed or opaque frame (origin `"null"`) gets
  `NotAllowedError`, "Deadbolt offers no passkeys to sandboxed frames."
  Deadbolt takes a call only from a frame whose every ancestor, up to the top
  page, is on its origin, by the browser's own frame records (`frameChain`,
  the walk autofill uses): `crossOrigin` in the client data is then always
  false, as the extension checks before the page gets it. A frame inside
  another origin, even one inside a page of its own origin, or one whose
  chain the browser can't account for, goes to the browser, which knows the
  rules for delegating WebAuthn to cross-origin frames. So does a frame whose
  Permissions Policy doesn't allow `publickey-credentials-get` (or `-create`),
  which the content script reads from `document.permissionsPolicy` in its
  isolated world, and an autofill request in any frame. Incognito tabs go to
  the browser.
- **Credential lists** go whole or not at all. `allowCredentials`,
  `excludeCredentials` and `pubKeyCredParams` reach the extension entry by
  entry; past 64 entries, or with any entry that isn't a `public-key`
  credential id (or algorithm) Deadbolt can read, the whole call goes to the
  browser. Deadbolt never cuts a list short or drops entries, so a nonempty
  allow list never becomes "any passkey" and an unreadable algorithm list
  never becomes "any algorithm". A page may pass any iterable, a generator
  say, which reads only once, so the hook reads each list into an array
  first and hands the browser's own flow that same copy of the options.
- **Registration** (`create`) puts "Save a passkey for <rp id>?" in the
  toolbar popup with Save, Cancel and Use another device. The popup opens by
  itself where the browser allows it, and the toolbar button gets a badge.
  If one of the site's `excludeCredentials` is already in the vault, the
  popup says so and the page gets `InvalidStateError`, as it does when one
  is saved while the user is asked (the agent's `exists`).
- **Sign-in** (`get`) without `mediation` asks "Sign in to <rp id> with a
  passkey?" in the popup, with the site's passkeys (those in
  `allowCredentials`, or all for the relying party), Sign in, Use another
  device and Cancel. With `mediation: "conditional"` they
  join the inline menu's rows on the top page's username and password fields,
  under the menu's visibility and keyboard rules, and wait there until the
  user picks one, the page aborts or the document goes away. One request per
  document waits there; a newer one replaces it.
- **Back to the browser:** Deadbolt hands the call to the browser's own
  WebAuthn, unchanged, when the site wants another algorithm or a
  `cross-platform` authenticator, asks `silent`, has no passkey Deadbolt
  holds, needs `required` verification Deadbolt can't give, Deadbolt isn't
  ready (locked, not running, or a host without `passkeys`), or the user
  chooses Use another device.
- **Ending:** the page's `AbortSignal`, the timeout (clamped to 1 to 10
  minutes, 5 by default), closing the tab, and a navigation of the frame, or
  of the top page for every frame in the tab, end the request: the signal
  with `AbortError`, the rest with `NotAllowedError`. The request counts from
  the moment it arrives, so these end it at any step, even before the prompt.
  Before the prompt, before the agent is asked, and before the page gets a
  credential, the extension checks again that the call is live and its
  frame's document and ancestors are unchanged. A ceremony waiting for the
  host to reconnect is never sent once its request has ended. One already at
  the agent gets `passkey-cancel`, which closes the Touch ID prompt.
- **Limits:** a tab holds 8 requests at once, counted as each arrives; more
  get `NotAllowedError` before anything is asked. A document lists the
  site's passkeys 4 times at once, then once a second, and requests for the
  same relying party id while one lists share it. The host allows 20 lists
  a quarter-second, 10 ceremonies a second and 4 at once, and answers
  `rate_limited` past them, which the page sees as `NotAllowedError`.
- **The page↔extension channel:** the content script offers the hook one
  `MessagePort` at `document_start` and nothing more. The hook is the first
  content script in the manifest and runs in the page's world before any page
  script; its capturing listener takes that one offer and stops it reaching
  the page. The content script accepts requests only after the hook's ack on
  that port. (Foyer, which this ports, offered a port whenever asked and took
  whichever acked first, so a page could take it over.)

## Threat model

- **Same-user processes are trusted, as they are for the CLI.** Any program
  running as you can run `deadbolt get`, talk to the agent socket, or run
  `deadbolt browser-host` with the extension's origin as its argument. The
  origin check only confirms which browser extension connected; it doesn't
  stop local programs. Protection against them would need the OS, such as
  code signing checks on the socket peer.
- **Web pages are not trusted.** A page can't reach the host: only the
  extension can, and the extension passes the frame origin the browser
  reports, never anything the page said. The agent refuses another site's
  login even if the extension asks for it (`domain_mismatch`), so a bug or a
  compromise in the extension's matching can't leak logins across sites.
- **What leaves the agent:** a list carries titles, usernames, vault names
  and matching URLs, never passwords or one-time password secrets. A fill
  carries only what it asked for, and a one-time password only as its current
  code. A check returns new, update or same and which logins matched. It
  compares passwords by BLAKE3 hash, in constant time, and never reveals
  them.
- **Secrets in transit** go only over stdin/stdout and the agent socket, never
  argv. They are held in `Zeroizing` buffers, and Debug output prints
  `<redacted>` in their place. Neither the host nor the agent logs them.
- **Check results stay in the extension.** A check is a password oracle
  for the page's site, so nothing the page can see depends on it: the offer
  is shown only in the toolbar popup, and the page gets no prompt, message or
  element from it. A page can still choose a password and submit it in a way
  that passes the noise filters; the result is an offer the user sees and can
  decline, and no value reaches the page. One bit can: when the extension
  opens the popup by itself, the page's window loses focus, so a page
  watching for `blur` learns that an offer appeared, and so whether the
  password it chose matched. So every check that finishes uses up the site's
  (registrable domain's) ten-minute turn, across tabs, whatever it said:
  `same`, `new`, `update`, or `rate_limited`. The popup opens by itself only
  when that check offered something and took the turn; every other offer only
  badges the toolbar button. A page therefore learns at most one bit per site
  per ten minutes, and each time the user sees a popup they can decline.
  Only a confirmed sign-in (see Sign-in outcomes) can open the popup, so only
  its check takes the turn; a page decides what it shows, so it can choose
  which checks those are, but a check that can't open the popup tells it
  nothing. Not now and Never for this site stop checks, so a page that sees
  no popup where one would have opened may learn the user said one of them.
  The probe itself puts nothing in the page. A fill's values reach only the content script's isolated world
  and the fields it writes. The host rate-limits checks and fills as well, so
  a runaway or compromised caller can't guess quickly.
- **Pages can't steer fills.** A fill needs the user's pick in a menu the
  page can't script or see into, or a click in the popup. It goes only to the
  document and form that asked, only into fields the user can see that were
  fillable when the user chose (a field the page turns on mid-fill gets
  nothing), and is
  refused unless the menu's visibility readings said it was visible and still
  from 500 ms before the press until 400 ms after it. Focus a page puts in the
  menu never lets ⏎ pick. A page that can see the fields it asked to fill can
  still read the values once they're written; that is the point of autofill,
  and why only same-site frames get logins.
- **The menu's visibility is sampled.** Readings come at most every 100 ms,
  so a page that covers or fades the menu for less than that, timed around
  the press, may not show up in any reading, and the press counts. The user
  still has to press on a menu that was shown and still for the half second
  before, and the cover has to land between readings. This is why frames,
  whose placement the page around them controls, get no menu and fill only
  from the popup after an explicit check.
- **Passkeys: a page signs only for itself.** A page can call WebAuthn as
  often as it likes, but every answer is bound to the origin the browser
  reported for its frame, which the agent writes into the client data and
  checks the relying party id against. A page can't name another site's
  relying party, a public suffix, or reach Deadbolt from a sandboxed frame,
  and a frame with any cross-origin ancestor, or a Permissions Policy that
  turns WebAuthn off, never gets Deadbolt's passkeys. Both the
  extension and the agent check, so a bug in either alone doesn't widen it.
- **Passkeys: the user answers outside the page.** A registration or
  sign-in needs a click in the toolbar popup, or a pick in the inline menu
  under its visibility rules, never a page element. What the page learns
  before that is whether Deadbolt took the call: a site with no passkey in
  Deadbolt, or one Deadbolt can't serve, sees the browser's own dialog
  instead. That reveals whether the vault holds a passkey for this site,
  which the site's own `allowCredentials` already narrows to its accounts.
- **Passkeys: what crosses the channel.** The page↔extension port carries
  the page's own options and the credential it asked for, nothing else. The
  hook runs in the page's world, so the page can see or replace it; that only
  changes the page's own calls, which are bound to its origin all the same.
  The port is taken before page scripts run and opened only by the hook's
  ack, so a page can't pose as another frame or inject calls into one.
- **Passkeys: the private key stays in the agent.** Replies carry the public
  key, the credential id, authenticator data, client data and the signature.
  A listing gives the extension the relying party id, credential id, vault,
  username and date. The app shows a passkey's site, username and date and
  never the key.
- **Passkeys: UV means Touch ID.** UV is set only when the Secure Enclave
  released this store's biometric key for the ceremony, so a site that
  requires verification gets a real one or none. An unlocked vault without
  Touch ID still signs with UV=0 where the site allows it: anyone at the
  unlocked Mac, or a same-user process, can sign in with a saved passkey,
  just as they can fill a saved password.
- **The idle lock:** fill, save, and a passkey registration or sign-in count
  as use. Hello, list, check and passkey-list don't, because a browser asks
  for those on every page and would otherwise hold the vault open.
- **Locked means locked.** While the store is locked, every request but hello
  gets `locked`. Hello starts the agent if it isn't running but never unlocks
  it.

## Host messages

Every message is a frame: a 32-bit length in native byte order, then that
many bytes of UTF-8 JSON. The extension connects with
`chrome.runtime.connectNative("pw.deadbolt.browser")` and keeps the port open.
Requests are answered in order, except passkey registrations and sign-ins,
which wait on the user and answer when done, and `passkey-cancel`, which is
answered at once, even while a request ahead of it waits on the agent.
`changed` messages can arrive between replies.
The host exits when the port closes.

- **Limits:** requests are capped at 64 KiB. A bigger one is skipped whole and
  answered with `bad_request` and `"id": null`, and the connection stays open.
  Replies stay under the browser's 1 MB limit. A list too large to fit becomes
  a `failed` error.
- **Rate limits:** per connection, `check` allows a burst of 20 then one a
  second, `fill` a burst of 60 then four a second, and `passkey-create` and
  `passkey-get` together a burst of 10 then one a second, with at most four
  running at once. Past that a request gets `rate_limited`; nothing else is
  limited.
- **Requests** carry an `id`, a string of up to 200 characters or a number. The
  reply echoes it. A message without a usable id, or one that isn't JSON, gets
  `bad_request` with `"id": null`.
- **`origin`** is the origin of the frame the form is in, such as
  `https://gist.github.com` or `http://localhost:3000`.
- **Unknown fields** are ignored. Values are strings unless noted otherwise.

### hello

```json
{ "id": "1", "type": "hello" }
{ "id": "1", "type": "hello", "protocol": 1, "version": "0.1.0+abc123",
  "status": "ready", "capabilities": ["list", "fill", "check", "save", "passkeys"] }
```

`status` is one of:

- `ready`: unlocked.
- `locked`: `detail` says "Unlock Deadbolt to fill passwords".
- `not-set-up`: no device yet.
- `unavailable`: the agent couldn't be reached or started; `detail` says why.

Hello starts the agent if needed. It's the only message that does.

### list: the logins for a page

```json
{ "id": "2", "type": "list", "origin": "https://github.com" }
{ "id": "2", "type": "list", "site": "github.com", "accounts": [
  { "ref": "<64 hex>:<32 hex>", "vault": "personal", "title": "GitHub",
    "username": "octocat", "hasPassword": true, "hasTotp": true,
    "urls": ["https://github.com"] } ] }
```

`username` is left out when the login has none. `title` is the login's name,
else its URL's host. Accounts are sorted by title.

### fill: values of one login

```json
{ "id": "3", "type": "fill", "origin": "https://github.com", "ref": "…",
  "want": ["username", "password", "totp"] }
{ "id": "3", "type": "fill", "username": "octocat", "password": "…", "totp": "123456" }
```

`want` holds one to three of `username`, `password` and `totp`. The reply has
only those the login has. `totp` is the current code, computed by the agent.
A login that isn't on the page's site gets `domain_mismatch`, and an unknown
`ref` gets `not_found`.

### check: was what was typed saved?

```json
{ "id": "4", "type": "check", "origin": "https://github.com",
  "username": "octocat", "password": "…" }
{ "id": "4", "type": "check", "status": "update", "matches": ["<ref>"] }
```

Among the site's logins with the same username (compared trimmed and
case-insensitively; a blank username matches logins that have none):

- `same`: some have that password. `matches` lists them.
- `update`: none do. `matches` lists those with that username.
- `new`: no login has that username. `matches` is empty.

The password is 1 to 4096 characters and the username at most 500.

### save

```json
{ "id": "5", "type": "save", "origin": "https://github.com",
  "entry": { "title": "github.com", "url": "https://github.com/login",
             "username": "octocat", "password": "…" } }
{ "id": "5", "type": "save", "ref": "<ref>", "created": true }
```

- **Without `ref`:** creates a login in the default vault with `url`,
  `username` (when not blank) and `password`, named `title` unless that is
  just the site. Runs of spaces and control characters in `title` become one
  space.
- **With `ref`:** changes only that login's password (`created: false`), and
  only if one of its URLs is on the page's site, else `domain_mismatch`.
- **Validation:** `entry.url` is trimmed, then must be a whole URL of a page
  Deadbolt fills, by the rule for origins (https, or http on local hosts), with
  no spaces, at most 2048 bytes (`bad_request`), and on the page's site
  (`domain_mismatch`). `title` is 1 to 128 characters.

### passkey-list: the passkeys for a page

```json
{ "id": "6", "type": "passkey-list", "origin": "https://github.com", "rpId": "github.com" }
{ "id": "6", "type": "passkeys", "rpId": "github.com", "canVerify": true, "passkeys": [
  { "ref": "<64 hex>:<32 hex>", "vault": "personal", "credentialId": "<base64url>",
    "username": "octocat", "created": "2026-10-27" } ] }
```

Every vault's passkeys for the relying party id, which is `rpId` if it's
allowed for the page (see Passkeys), else `domain_mismatch`, and the page's
host when left out. `canVerify` says whether Touch ID can verify the user
now. `username` and `created` are left out when the passkey has none.

### passkey-create: register a passkey

```json
{ "id": "7", "type": "passkey-create", "origin": "https://github.com", "rpId": "github.com",
  "challenge": "<base64url>", "user": { "id": "<base64url>", "name": "octocat" },
  "exclude": ["<base64url>"], "userVerification": "preferred" }
{ "id": "7", "type": "passkey-created", "ref": "<ref>", "credentialId": "<base64url>",
  "clientDataJSON": "<base64url>", "attestationObject": "<base64url>",
  "authenticatorData": "<base64url>", "publicKey": "<base64url SPKI>", "verified": true }
```

Makes an ES256 passkey in the default vault, replacing one there for the same
`user.id` on that relying party, and fails if one of `exclude` is already
saved for it (`exists`), checked again just before saving. `userVerification` is `required`, `preferred` or
`discouraged`; `verified` says whether Touch ID verified the user (the UV
flag). Binary values are base64url without padding: the challenge up to 1024
bytes, `user.id` up to 64, each `exclude` id up to 1023, and at most 64 of
them. `user.name` is kept to 256 characters.

### passkey-get: sign in with a passkey

```json
{ "id": "8", "type": "passkey-get", "origin": "https://github.com", "rpId": "github.com",
  "ref": "<ref>", "challenge": "<base64url>", "userVerification": "preferred" }
{ "id": "8", "type": "passkey-assertion", "credentialId": "<base64url>",
  "clientDataJSON": "<base64url>", "authenticatorData": "<base64url>",
  "signature": "<base64url DER>", "userHandle": "<base64url>", "verified": false }
```

Signs with the passkey `ref`, which must be for that relying party
(`domain_mismatch`, or `not_found`).

### passkey-cancel

```json
{ "id": 9, "type": "passkey-cancel", "request": "8" }
{ "id": 9, "type": "passkey-cancelled", "found": true }
```

Stops the `passkey-create` or `passkey-get` whose id is `request` and closes
its Touch ID prompt. That request is answered first, with a `cancelled`
error. `found` is false when it had already finished.

### changed (pushed)

```json
{ "type": "changed", "change": "locked" }
```

`change` is one of:

- `locked` or `unlocked`.
- `items`: logins or vaults changed, here or by sync.
- `stopped`: the agent stopped, which locks it.
- `started`: an agent is running again after the one watched went away, or
  after a hello found none, so ask hello. The agent a hello starts isn't
  announced.

Pushes carry no id and no values. Refetch what's on screen.

### error

```json
{ "id": "3", "type": "error", "code": "domain_mismatch", "message": "github.com isn't saved for gitlab.com" }
```

`code` is one of:

- `locked`: the store is locked, not set up, or no agent runs.
- `not_found`: no such login.
- `domain_mismatch`: the login or URL isn't on the page's site.
- `bad_request`: a malformed message, a page that gets no logins, or a value
  out of range.
- `rate_limited`: too many checks, fills or passkey requests; try again in a
  moment.
- `cancelled`: a passkey request stopped by `passkey-cancel`.
- `exists`: a passkey the registration excluded is already saved.
- `failed`: anything else.

`message` is for people and never holds a secret.

## Not supported yet

- **Passkeys:** ES256 only, no attestation other than `none`, no
  extensions (`prf`, `largeBlob`, `credProps`), no editing a passkey, and no
  import or export. A passkey from another manager can't be brought over.
- **"Sign in with…" (SSO):** remembering which identity provider a site uses
  isn't supported.
- **Firefox and Safari:** Firefox passes different host arguments and uses a
  different manifest. Safari needs an app extension.
- **Touch ID on fill:** an unlocked vault fills without asking again.
  Passkeys ask (see Passkeys).
- **Unlocking from the browser:** the extension can say Deadbolt is locked but
  can't unlock it. Use the app or `deadbolt unlock`.
- **Choosing the vault for a new login:** new logins go to the default vault.
- **Opening the app from the browser:** Deadbolt registers no URL scheme and
  the host has no message for it, so the popup says where to find the app
  instead.
- **Generating passwords** (see The extension).

## Prior art

[Foyer](https://github.com/R44VC0RP/foyer), by Ryan Vogel, is an autofill
extension that learns sign-in flows and asks pluggable password managers for
credentials through its own native host. Its protocol and safety rules shaped
this design: an extension-only native host, matching by host or registrable
domain with the private suffixes, https-only filling, secret-free lists, and
check-then-save. The host is Deadbolt's own. The extension adapts parts of
Foyer's: form detection, Shadow DOM traversal, filling, the inline menu and
save prompt frames, frame targeting, the save flow, and the passkey hook,
channel and frame and relying party checks (Foyer kept passkeys in the
extension; here the agent holds and signs with them). Each adapted file says
so in its header, and `extension/README.md` lists what was kept and dropped.
