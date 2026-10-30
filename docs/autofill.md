# Browser autofill

Deadbolt fills and saves passwords, and makes and signs in with passkeys, in
Chromium browsers (Chrome, Brave, Arc, Edge, Chromium, Helium) through its own
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
  `site-generate` and its check, keep and drop, `site-check`, `site-save`,
  `passkey-list`, `passkey-create`, `passkey-get`) and passes the agent's
  watch stream back as `changed` messages. It never prompts for a passphrase
  or Touch ID; the agent asks for Touch ID itself before it signs with a
  passkey (see Passkeys).
- **The extension** finds login forms, asks the host, and fills. Saves need a
  click in the extension's own UI.

## Install

```sh
deadbolt browser install                      # browsers found on this computer
deadbolt browser install --browser brave      # or name them: chrome brave arc edge chromium helium all
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
| Helium   | `net.imput.helium`                        | `net.imput.helium`                          |

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

## Load the extension unpacked (Brave, Chrome, Arc, Edge, Helium)

There's no store listing yet. Build it and load it from disk:

```sh
cd extension
bun install
bun run build                  # writes extension/dist
deadbolt browser install       # lets the browser start deadbolt browser-host
```

1. Open `brave://extensions` (`chrome://extensions` in Chrome, Arc and
   Helium, `edge://extensions` in Edge).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose `extension/dist`.

The manifest's `key` gives it the id `jhocodkhpifjndffenppfmdkmiolngal`, the
one `install` allows. After rebuilding, click the reload arrow on its card.
If the toolbar popup says the helper isn't installed, run
`deadbolt browser install` and open the popup again.

## The extension

### Opt-in corner sign-in authority

**Default off.** “Offer to sign in” extends a trusted account pick in the
extension-owned corner menu to same-origin navigation and submission. Page
arrival and detector confidence never authorize a fill. The existing 500 ms
visible dwell and fresh 400 ms post-pick visibility check remain mandatory;
ordinary inline, popup and Browse-agent fills retain manual-submit behavior.

The automatic session is bound to the selected account, exact saved origin
(scheme, host and port), top frame and current document/form snapshots. Its
entry window is 20 seconds, followed by the existing bounded sign-in session.
It permits at most four automatic submit requests. Once a password has filled,
the identifier re-fill exemption is removed. Escape, lock, setting-off and
unrelated navigation cancel it, including pending backend calls.

A TOTP can fill without another pick, but Deadbolt submits a code step only
when the site's learned `Flow.code` is true. A current SMS/email-looking prompt
vetoes that submission even with a learned flow. Site scripts can submit on fill;
Deadbolt does not duplicate an observed trusted submit event or mint a user-gesture timestamp.
Every explicit submit rechecks visible fields, the button's form ownership and
containment, and the effective form/submitter action and target: same origin,
same browsing context only. Provider/OAuth clicks remain manual guidance.

Auth-state evidence is local and value-free. The probe does not receive vault
usernames or compare arbitrary text, aria-labels, titles or alt text with them.
Open offers are stable instead of being re-probed as page text changes. Fresh
signed-in memory and cooldowns skip probes; URL/form evidence is cached locally.
Only a trusted click on a visible real link/button no larger than 320×96 pixels
inside the viewport invalidates sign-out memory, not a large `role=button`
wrapper. Pointer coordinates must hit that bounded control; keyboard activation
must focus it. Navigation, pick, dismissal, lock and setting-off end the offer. These
bounds reduce probing; surface presence is not invisible to the page.

### Host connection

One service worker owns the extension's only port to the host
(`chrome.runtime.connectNative("pw.deadbolt.browser")`). It sends hello on
connect, reconnects with backoff (1s up to 60s) when the host goes away, and
follows `changed`. It never asks for the passphrase: a locked vault shows
"Unlock Deadbolt" and waits for `unlocked`. A `stopped` push shows Deadbolt as
not running without sending hello, which would start the agent again.

- **Inline menu.** Focusing a username, email, password or code field in the
  top page after a click or keypress opens a menu of that site's logins,
  title and username, under the field. It's as wide as the field and
  left-aligned with it, at least 240 px (room for the avatar, title
  and username) and at most the viewport less 4 px each side. It doesn't
  name the site: logins are only ever offered for the page's own site, or a
  same-site frame's own site, which the page already shows. ↓/↑ choose, ⏎
  fills, esc or ⇥ closes it with focus back in the field, and ↓ reopens it.
  Inside, the rows are a listbox that takes focus itself and points at the
  active row (`aria-activedescendant`); "Filled", "Saved" and why a pick
  didn't go ahead are said through a live region in the frame. None of it,
  ARIA included, is in the page's DOM. While Deadbolt is locked, the menu's
  "locked" row opens on focus once per site until Deadbolt locks or unlocks
  again; after that it takes a click into the field or ↓. A login field in a
  frame of the page's own site gets the menu too, opened in the top page
  under the field; any other frame's fields get none (see Frames). It's an
  extension page in an iframe inside a closed shadow root, so the page can't
  read it or click it for you. It opens on the form as it is right then (a
  fresh scan, not the last periodic one), so a password box the page has
  just shown is part of the pick rather than a change that voids it.
- **Menu in the top layer.** The host element of Deadbolt's surface (the
  menu, the pill it folds into and the save offer, see One surface) gets a
  fresh random custom-element name and inline `!important` styles, so page
  stylesheets can't aim at it or restyle it. It's a manual popover, shown in
  the top layer above any `z-index`. When the field is in a modal dialog or
  the full-screen element, the menu mounts inside it (in its shadow root
  when the field is there), because content outside is inert or not drawn.
  If the page puts something in the top layer after the surface (a popover,
  a modal dialog, full screen) or hides its popover, the surface goes back
  on top and waits its 500 ms again. It does this at most three times, then
  closes. A modal dialog or full screen that the surface isn't inside closes
  it. Each frame it hit-tests five points of its own box, and anything else
  there (such as a popover in a shadow root it can't watch) counts as
  covering it and is answered the same way; a surface fading out, which
  lets clicks through, isn't raised. A page script can still rewrite the
  host's inline style; then the pill stops counting as Deadbolt's own (see
  the pill's cover check under Filling).
- **One surface.** That frame is Deadbolt's only UI in the page, and it
  morphs between modes rather than swapping for another: the account list
  grows from the field; a pick folds it into a pill at the end of the field
  that says "Filling…", then "Filled" once the content script says it wrote
  something (or "Couldn't fill"), and goes by itself; after a confirmed
  sign-in it shows the save offer in the top right corner (see Saving). The frame
  says what size each mode needs and the content script springs the frame
  there, so no transparent part of it is left over the page. Motion follows
  springs with no bounce, retargets from where it is, and is a short fade
  when the system asks for reduced motion (`ui/motion.ts`). The frame only
  moves after a pick passed its checks, so moving it can't help a page. A
  press shows at once inside the frame (a darker highlight and a still ring
  on the avatar, or a pressed button); the ring spins once the pick goes
  ahead.
- **Narrowing as you type.** Typing in the field the menu is open on
  narrows it to the logins whose title or username contains the text: the
  content script hands the text to the menu frame over their private
  channel, nothing else gets it, and only the user's own (trusted) typing
  counts. Rows that stop matching fade where they are and the rest slide up;
  the menu's height follows. When nothing matches, the menu goes, and stays
  away from that field until it's cleared, clicked again, or ↓; the rest of
  that form, now being filled by hand, gets no menu on focus or click either,
  only on ↓ or a second click. Typing a password by hand puts the menu
  away the same way.
- **Menu visibility.** The menu samples its own visibility rather than
  watching it continuously: an `IntersectionObserver` with `trackVisibility`
  gives a reading at most every 100 ms, saying whether the menu is fully on
  screen, unscaled, opaque and uncovered. A pick, by mouse or keyboard,
  counts only if every reading for at least 500 ms before the key or button
  went down said so and the menu hadn't moved or changed size, and nothing
  changes until a fresh reading taken 400 ms after the press confirms it. A
  frame hears about changes the page makes to it only after a short delay,
  so a reading right at the press can predate them. Every change starts the
  500 ms again, with one exception: when the browser resizes the viewport
  (an infobar such as "started debugging this browser" comes or goes, or
  the window is resized) and the page reflows, a move of the menu in the
  next frame that keeps its size and shifts it no further than the viewport
  changed doesn't count. That needs a trusted `resize` event in a normal
  tabbed window: a page can't resize a tab's viewport (only a popup's, so
  popups get no exception), and any other move still counts. If it's covered, faded, clipped, shown only at the press or
  can't be measured, it fills nothing and says so. A page that covers the
  menu briefly between two readings can go unseen (see the threat model).
  The browser pauses these readings while anything animates inside the
  frame, so nothing does while a press is checked (transitions are off, the
  avatar's ring is still, the save offer's bar is stepped frame by frame,
  never animated), and after narrowing's row animations the half second
  starts again, as after a move.
- **A press takes no focus.** A pointer press in the menu leaves focus where
  it was, in the page's field (the menu cancels the press's default
  action). The page never sees its field blur at the moment of the press,
  so it has nothing to time a cover or a fade by, and a field that redraws
  on blur (a floating label dropping back, an outlined border thinning: the
  real-site sweep found this on Google, Microsoft, Reddit, Chase and others)
  can't move the menu under the press and cancel the pick. So a habit of
  clicking a row and then pressing ⏎ sends that ⏎ to the page's field while
  the pill says "Filling…" (it can submit the form there). A press that
  passed its checks but picked nothing (a right click, a press dragged off
  its row) leaves no ⏎ allowed: focus that comes in later without the
  user's ↓, by Tab for one, starts with none.
- **Keyboard picks.** ⏎ picks only after the user's own ↓ in the field
  moved focus into the menu, or, with focus already there, a real press
  inside the menu passed the same visibility checks as a pick. A press the
  menu refused lets no later ⏎ pick either. Focus that got into the menu any other way, such as by Tab from a field
  the page made last in the tab order or by a script, doesn't count, and
  leaving the menu ends it even if focus comes back. Such a menu says "Press
  ↓ in the field to choose." The locked menu's Unlock Deadbolt row takes ⏎
  on the same terms. The save offer has no ↓ to enter it, so its buttons
  take only a press; ⏎ or Space on one says to click or answer in the
  toolbar button.
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
  (when the user picks, Deadbolt's own open menu doesn't count as covering a
  field; anything of the page's still does). A pick from the menu folds it
  into a pill at the end of the field, and nothing is written until the pill
  has settled there. The pill's host is an element of the page, which a page
  script can restyle, so it's exempt from the cover check only while it's exactly where and
  as big as the content script put it, and no bigger than a pill; stretched
  over a field, it's a cover like any other and the field gets nothing.
  A field the page enables or shows later, such as a disabled password it
  turns on when the username is focused for the fill, gets nothing. If the
  sign-in was cancelled (Esc, or a
  navigation the page didn't make) while the host was answering, the values
  are dropped instead of delivered.
  A value the field can't take isn't written: longer than its
  `maxlength` (a person couldn't type or paste it there either), or a
  username that isn't a phone number into a phone box; a phone box's menu
  lists only logins whose username is one.
  Each field is checked again right before its value is written, and before
  each digit of a split code: it must still be in the form and under the
  parent it was found in, enabled, editable, and visible through every
  ancestor up to the top of the page, across shadow roots (display,
  visibility, opacity, clip, size, on screen, not covered). Clips follow
  CSS: a clip-path counts unless it is an inset() whose rectangle, resolved
  against the clipping box, contains the whole field (any rounded corners
  no larger than the room left), with no transform on the way (design
  systems leave a focus ring room that way; Stripe's sign-in); paint
  containment clips like overflow; and a scrolling or clipping box clips
  only what it holds (an absolutely positioned field escapes a box between
  it and its containing block, Intercom's sign-in; a fixed one every box up
  to a transformed or contained one). The centre of what shows is
  hit-tested too, and only the centre. Split one-time
  code boxes fill only as one whole group within one form. One exception
  to "the field it was found as": some pages re-render their form on every
  input event, with new elements. When a single field (never a box of a
  split code or a new-password pair) was in the page as the fill's last
  write began and is gone at its turn, the one box the page put in its
  place (under the same parent, in the same form, with the same id, name,
  type and autocomplete, covering at least half of where the field was
  when the fill began) takes its value instead, after every check above; a
  look-alike anywhere else, or two of them, takes nothing, and nothing is
  ever written into a box that wasn't there when the fill began unless one
  of its own writes replaced it. The pill on such a field follows its
  successor.
- **Sign-in sessions.** Many sign-ins take more than one step: the
  username on its own, then the password, sometimes a code. Picking a login
  on any step starts a session in that tab, bound to the login, the tab and
  the site (registrable domain). When the top page then shows the next step,
  the session fills it from the same login without another pick, and a pill
  on the field says so ("Password filled", "Code filled"):
  - a password field gets the password (and the username, if its box is
    there beside the password and empty);
  - a one-time-code field, split boxes included, gets the current code, if
    the login has one, and only an authenticator's code: a box for a code
    the site sent (its label or the page says text message, SMS, email,
    "we sent", Resend), or for a backup or recovery code, is the user's to
    fill. The field's own label decides first, then the page, where an
    authenticator app named anywhere wins. Such a box gets no menu and no
    fill, and its page still counts as a code step of the sign-in;
  - a username box on its own, empty, is "Not you? Use a different
    account": the session ends.
  Only a sign-in step fills: a password goes only into a login form's
  current-password box. An address the site doesn't know often gets a
  sign-up form instead (Dropbox's "Sign up for Dropbox", found by the
  real-site sweep), so a sign-up or change-password form ends the session,
  and a login form with a new-password box, or whose password box asks for
  a new password by autocomplete (a sign-up the detector may take for a
  login), fills nothing. An explicit pick still can.
  The bounds: each step fills once, and only after the user's own submit of
  the step before: their trusted click on its submit control or Enter in
  one of its fields. A submit event without one just before it (a page's
  `form.requestSubmit()` fires one the browser marks trusted) doesn't
  count, and neither does the page taking the filled fields away, unless
  the user clicked or pressed Enter in the last two seconds. A step in
  another document needs that submit to have come from the document the
  last step filled, after it filled. (Saving asks less: any trusted click on
  the submit control, Enter in a field or trusted submit event captures what
  was submitted, since a capture only ever leads to an offer the user has to
  accept, after the outcome is judged.) Deadbolt never submits. A step fills
  only on the origin the pick was on, or one whose host (and scheme) a
  saved URL of the login names exactly: the agent lists a login on every
  subdomain of its sites, so its say alone isn't enough here. Every fill
  goes through the same field checks and is bound to that frame, document
  and form snapshot. A frame gets a session only when it may have the menu
  (see Frames), and its step fills only the fields that show through every
  frame above, checked as for a pick; one whose fields don't show yet (a
  password box still collapsed, as Apple's is until Continue) isn't the step
  yet, and the frame reports again once they show. Its pill opens in the top
  page, on the field. It
  ends after three minutes (four on a site known to step by navigation),
  when the code is filled or a password with no code to follow, and on Esc
  or closing the menu, picking another login, a page of another site, a
  navigation the page didn't make (a typed address, a bookmark, a reload,
  back or forward), closing the tab, or Deadbolt locking, including for
  fills still on their way. The session is kept in the extension's session
  storage, so a service worker restart doesn't drop a step; it holds the
  login's ref, the site, what it filled and when, never a value.
- **Security questions.** A field whose label is a question that names no
  login field ("What was your first pet's name?"), or that says answer,
  security question or memorable word, is never a login field, even masked:
  no menu, and no session fills it.
- **Signing in by hand.** On a password or code field, the username the
  sign-in is for narrows the menu: the form's own username box, if the user
  typed what's in it (or Deadbolt filled it), or else the one the user
  submitted on an earlier step (bg/save.ts keeps it in memory with the rest
  of what was submitted). A username the page put in the box itself is
  ignored, so whether a menu shows never depends on a name the page chose. The menu then shows only the logins
  whose username is exactly that; when none is, the user is signing in by
  hand, and the field opens no menu, unless they press ↓ or click it again.
  So a failed sign-in that comes back with an unknown username doesn't
  offer the whole list on its password field.
- **Passwords masked with CSS.** A text box the page masks with
  `-webkit-text-security` (to keep the browser's own password handling
  away) is a password box like any other: it gets the password, and the
  learning log keeps no shape of what's typed in it.
- **A provider's own password step.** Google's password page already names
  the account it's for (it remembered it, so the user typed nothing): a chip
  carrying `data-profile-identifier`, and a hidden `identifier` box in the
  page (no `<form>`). On `https://accounts.google.com` only (a provider marked
  `pageAccount` in `signin.ts`, exact host, over https), with no username of
  the user's own, the content script sends that account as `pageAccount`
  (the visible chip first, then the hidden box; an email address or plain
  username of at most 500 characters). The background takes it only when
  the asking frame's origin is that exact origin, and uses it after the
  linked sign-in-with account and the user's own username. It only narrows:
  when it names logins, the menu shows those; when it names none, the menu
  shows the whole list, as if nothing were sent. It never hides the menu.
- **What's remembered of a site's sign-in.** When a sign-in works (judged as
  for saving: confirmed or likely), the extension records its shape in
  local storage under `signinFlows`, with no usernames or values: whether
  the username comes on a step of its own, whether a code step usually
  follows, whether the steps are separate pages, how many sign-ins it was
  learned from and when the last was. Sites are kept under a salted hash
  (SHA-256 of a random per-install salt, `signinFlowsSalt`, and the site,
  cut to 128 bits), not by name. Up to 300 sites are kept, the most recent,
  at roughly a hundred bytes each. On a site that asks for the username first and
  has one login, the menu on the first step says "Continue as <username>";
  on one whose steps are pages, the session gets an extra minute for a slow
  one. A username step on its own is never judged as a sign-in (only a
  password is), so it neither waits for the page to settle nor counts as a
  failure.
- **Frames.** Every frame runs the content script, but only frames on the same
  site as the top page get logins, and sandboxed frames get none. Some sites
  sign in only in a frame of their own: appstoreconnect.apple.com has no
  fields itself, and Apple's sign-in widget is a frame from idmsa.apple.com,
  with no `<form>`, the account box first and the password box opening in
  the same frame after Continue.
  - **Which frames get the menu.** A login field in a frame gets the inline
    menu only when the frame and every frame between it and the top page are
    on the top page's site (registrable domain, as `siteOf` computes it) and
    https (http only on the local development hosts that get logins at all),
    by the browser's own frame records (`sameSiteTop` in `bg/frames.ts`).
    idmsa.apple.com inside appstoreconnect.apple.com qualifies; a frame of
    another site doesn't, and nor does a frame of the site inside one of
    another site. Nor does a sandboxed frame, or one with a sandboxed frame
    anywhere above it: a sandbox without `allow-same-origin` gives the
    frame an opaque origin, which never gets logins at all, and every frame
    above checks the element the frame below sits in for a `sandbox`
    attribute as the field's box goes up (from the menu's opening to the
    fill), whatever its flags, and answers only if its own origin isn't
    opaque. That last check catches a frame on the way sandboxed by a
    `Content-Security-Policy: sandbox` header without `allow-same-origin`,
    whose URL (all the browser's frame records show) still names the site.
    Chromium also gives the frames inside such a frame its flags, so the
    login frame's own origin is opaque too and the sender check refuses it
    first; the check above is there in case that ever changes. Two gaps
    remain, both open only to the site itself: a CSP `sandbox` header with
    `allow-same-origin`, and an attribute removed after the frame loaded. Schwab (a 630×65 sign-in bar framed from
    sws-gateway-nr.schwab.com) and account.apple.com qualify, as does App
    Store Connect. The reason is what a page can do with a frame it embeds:
    where it sits, how big it is, what's over it and what's under the
    pointer are all up to the embedder. A hostile embedder (an ad, a widget
    host, a page that frames a real sign-in) could lay a decoy over the
    frame, slide the frame under the user's click, or show the menu for
    fields the user can't see (clickjacking), and would learn which site's
    logins Deadbolt has. A page on the frame's own site could already read
    its own logins' fills in its own frames, so it gains nothing.
  - **How it opens.** The menu never opens inside a frame. The frame says
    where its field shows in its own viewport (after the checks a field
    gets before a fill); the background carries that box up through every
    frame, each checking the element the frame below sits in (see
    `boxesInTop`), and opens the menu in the top page under it, following
    the page's scroll. It lists the logins for the frame's own origin, as a
    top page on that origin would, and a pick fills only that frame. Every
    check on a pick holds: the dwell and the menu's own visibility
    readings in the top page, trusted events only, the user's recent click
    or keypress in the frame, and, before the host is asked and again once
    the values are in hand, the frame's fields through every frame above
    (with Deadbolt's login pill put away while they're measured; with any
    other surface showing, a card's pill say, nothing is measured or
    filled). The fields get the checks a top page's fields get, and every
    frame above takes a fresh `trackVisibility` reading of the element the
    frame below sits in, so a cover over the frame that lets clicks through
    still stops the fill. That element only has to be unobscured and partly
    on screen, since a sign-in frame can be taller than the viewport; the
    fields' boxes are cut to what shows separately. (A
    reading of the field itself, as the popup takes, says no on Apple's
    widget: its label floats over its own field.) Typing in the
    field, clicking elsewhere in the frame, scrolling the field elsewhere,
    or esc there (which the top page can't see) puts the menu away. Esc on
    an open menu ends the sign-in session, as in the top page; once a pick
    has filled, it says nothing of it. A frame never gets a generated password.
  - **The popup.** Any same-site frame's form also fills from the popup,
    and only if the user can see it through every frame above it, checked
    when the user clicks Fill and again once the values are in hand.
  Both checks cover exactly the fields that will be written. The frame
  checks its fields (style up the tree, size, clipping, on screen, nothing
  over them, and a fresh `trackVisibility` reading, which also sees covers
  that let clicks through). Then each frame above, up to the top page,
  checks the element the frame below sits in the same way, unscaled, and
  that the fields' middles land on it. Any frame on the way that can't
  answer, such as one without the content script, means no fill. If more
  than one frame's form shows, the popup fills nothing.
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
  Passwords stay with the origin they were submitted on, and the check and
  save go there. A password from another of the site's hosts replaces the
  earlier ones and their username, and passwords never carry to another
  username. A username carries to another host only as a sign-in's own
  step: submitted alone in a login or sign-up form on the top page, before
  any password, with the password then submitted on the top page (an email
  step on one host, the password on another). A username submitted alone
  after a password joins it only from the same origin and only if it has
  none, and never takes over the check for the password's form failing.
- **Did the sign-in work?** The top page says when it settles: no login form
  for a couple of seconds, a code step, or a couple of seconds after a
  submit. The service worker then asks that document what it shows (see
  Sign-in outcomes) and judges it. Only a sign-in that worked gets a `check`.
  Two signs from the form itself end the sign-in with nothing offered,
  whatever comes after: the submitted form's password or code box still
  showing five seconds after the submit in the same document, or the form
  posted back to its page as a new document. That's judged per submit and
  document, so a retry starts over and an earlier submit's failure doesn't
  end it. Going elsewhere by hand (a typed address or a bookmark), on the
  site or off it, ends the sign-in too, with any check on its way or offer
  waiting. A page with no form that still looks like a sign-in step (its
  path, sign-in-provider buttons, an authenticator picker, a captcha, a
  spinner with little else) is never taken for a finished sign-in without
  the account or a Sign out control showing.
  On `new` or `update` the toolbar button gets a badge and the popup holds
  the offer. After a confirmed sign-in, at most once per site every ten
  minutes (see the threat model), the offer also shows in the page: the
  service worker hands the settled document's content script a one-time
  token, and it opens the surface in the top right corner, 12 px in, near
  the toolbar button: out of the way, over the corner of the site's own
  header if that's where it falls. It comes in from the corner as a small
  pill: Deadbolt's mark, "Save login?" (or "Update password?") and Save.
  The surface frame gets the site, the username and whether it's an update,
  never the password. When the pointer comes onto it or it gets keyboard
  focus, it opens down and to the left from the corner to show the username
  and site, Not now and Never for this site, and it closes again 300 ms
  after the pointer leaves. The card is laid out once at its open size and
  anchored to the corner, so only the frame's clip and corners move. A 2 px
  bar along the pill's bottom edge empties over twelve seconds (paused while
  it's open, under the pointer or focus, or the pointer comes near). When
  it runs out, or the user clicks anywhere else in the page, the pill
  shrinks to a dot: Deadbolt's mark with a small red badge, in the same
  corner. Hovering or clicking the dot brings the pill back for eight more
  seconds; otherwise the dot leaves toward the toolbar after twenty, and the
  offer waits in the toolbar.
  Save rolls to "Saving…", folds into a "Saved" pill (the same for a new
  login and an update) in the same corner and leaves toward the toolbar
  button; a locked or busy Deadbolt opens the card and says so there, and a
  save that fails after the time ran out gets six more seconds. Not now and
  Never for this site leave the same way, toward the toolbar button; Not now
  only puts the surface away, and the offer stays in the toolbar. Every
  button, in the pill and in the open card, takes only real presses that
  pass the menu's visibility and dwell checks, and the frame changing shape
  restarts the dwell like any move, so a button that just came into view
  takes no press until it has sat still. The surface closes when the page navigates,
  when Deadbolt locks, and when the offer expires or is answered in the
  popup (if the offer went while the page was still opening it, a close
  follows the open). The content script closes it too if its frame hasn't
  loaded the offer within three seconds, and after a minute in any
  case. Where the page can't take it (a hidden tab, say), the popup
  opens by itself instead. A likely sign-in only badges. The popup asks
  "Save login for <site>?" or "Update password for <username>?" with Save,
  Not now and Never for this site, and sends `save` only on Save; the page's
  surface and the popup answer the same offer id. Not now also holds back the same
  username on the site for a day (the service worker keeps a SHA-256 of the
  site and username, salted once per browser session, in session storage,
  not the username). Never for this
  site keeps the site in the extension's local storage, and from then on
  nothing typed there is kept or checked; the popup says "Saving is off for
  <site>" with Turn on. Each offer has its own id, and Save or Not now answers only
  the offer the popup showed; if another took its place, the popup shows that
  one instead. A check that finishes after the tab left the site, closed, or
  Deadbolt locked offers nothing. Offers expire after five minutes. A new login is named after
  the title of the page the password was submitted on, the part of it that names the site
  ("GitHub" of "Sign in to GitHub · GitHub", "Acme" of "Create your account · Acme") without
  the page's action ("Sign in to", "Create your account"), else the site; it's saved with that page's URL, without its query or
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
- **Generated passwords.** On a sign-up or change-password form, the menu
  under a new-password box offers "Use a strong password". Picking it sends
  `generate` with what the boxes ask for: `minlength`, `maxlength`,
  `passwordrules`, and the characters and lengths their `pattern` takes. The
  agent makes the password (Apple's quirks for the site win over
  `passwordrules`, see generate) and it goes into every new-password box, the
  new one and its confirmation. Nothing is saved then. The agent holds the
  password for the page's origin under an id, and a submit names it by that
  id, so the password doesn't travel back. It's offered under the rules above
  only if the submit goes through.
  - **Only strong ones.** Before the menu shows the row, `generate-check` asks
    whether the field's rules allow at least 60 bits; if not (a six-digit PIN,
    a two-letter alphabet), there's no row. Length can't make up for an
    alphabet of under 10 characters.
  - **Patterns aren't run.** A page's `pattern` is never compiled as a regular
    expression, so it can't stall the page. The content script reads a small
    subset itself: literal characters, `[…]` classes, `.`, `\d \w \s` and their
    opposites, `* + ? {n} {n,} {n,m}` (lazy too) and `^`/`$` at the ends, in
    at most 200 characters. It takes from it one set of characters and a
    length range, intersected with `minlength` and `maxlength`. A pattern
    outside the subset, one that needs a mix of character sets, or lengths
    that don't meet means no row. One attempt is made: a password the page
    still turns down isn't retried.
  - **Held only once it's in the page.** A fresh password is a candidate. The
    extension sends `generate-keep` once it's in the page's new-password box,
    and `generate-drop` otherwise, such as when the page turned it down or the
    user left. The page names it by id only once the agent has kept it; if
    the keep fails (locked, disconnected), a submit sends it as typed, so a
    sign-up that goes through still gets an offer. Kept passwords expire
    after 15 minutes and locking wipes them; candidates go after two minutes,
    and can't push out kept ones.
- **Changing a password.** A change-password form with a username updates
  the login whose password is the current one. Without a username, it's the
  one login here whose password is the current one (a `check` with no
  username), else the only login here, else nothing. With a username the
  extension always checks both the current and the new password, so the host
  sees the same requests (and spends the same rate limit) whether or not the
  current one matched; a new password that is the current one offers nothing.
- **Passkeys.** A script in the page's own world answers
  `navigator.credentials.create` and `get` from Deadbolt, through the
  toolbar popup or the inline menu, and hands anything Deadbolt can't do back
  to the browser (see Passkeys).

## Site icons

Login rows can show their site's icon. Two switches, under Appearance in the
standalone build's Settings and behind the gear in the native popup's footer,
saved in `chrome.storage.local` (`siteIconsMenu`, `siteIconsVault`) and
followed live by every open page:

- **Site icons in the fill menu**, off by default. Every login in the inline
  menu is for the page's own site, so its icon would only repeat. Off, a
  login row is its title and username, left-aligned; on, it has its icon
  tile. Rows stay 46 px either way (`MENU_ROW`). Passkey and "Sign in with …"
  rows in a login list lose their glyph tile with it, so the list stays
  aligned; the generated-password row and address and card menus keep theirs.
- **Site icons in the vault**, on by default: the popup's rows, and the
  standalone vault's list and a login's detail. Off, they show the letter.

Turning both off deletes the kept icons and stops keeping more.

### Where icons come from

Deadbolt never sends a request for an icon. Fetching one for every saved
login, from the sites or an icon service, would tell those servers which
sites the vault has accounts on, and even fetching a site's own icon when its
page loads would tell that site (and any server the page names) "this
visitor has a saved login here". The first source that has one wins:

1. **The site's own SVG**, read only after Deadbolt filled a login on the
   site (a pick in the menu or the popup) or saw a sign-in there go through,
   in a top page on https or a local dev host, outside incognito, while
   unlocked and a switch is on. The background asks that exact document
   (`db:site-icon`, by `documentId`) for its `<link rel="icon"
   type="image/svg+xml">`, else its `mask-icon` (one colour, with its
   `color`), from an inline `data:` URL or the page's own origin. The content
   script reads it with `mode: "same-origin"`, `credentials: "omit"`, no
   referrer and `cache: "only-if-cached"`: only what the browser already
   loaded for the page, never the network. An icon on another origin (a CDN,
   as GitHub's and Linear's are) or not in the cache is skipped. It stops
   reading past 32 KiB and sanitizes what it read (below). The page's own
   script could still notice the cache read, but only after the fill or
   sign-in, when the site already knows this visitor has an account there;
   a page load alone reads nothing. The background decides which host the
   icon is for from the browser's record of the top document, never the
   page's word, and keeps it under that exact host only (less a leading
   `www.`), so a blog on one subdomain of a shared host can't set the icon of
   another subdomain's login, or of the parent domain's. Each is read again
   after 30 days; a page with no cached SVG icon isn't asked again for 6
   hours. Those hosts, and those whose icon a menu already revealed, are kept
   in `chrome.storage.session` as salted SHA-256 hashes, not by name.
2. **A bundled Simple Icons subset** (`static/site-icons/simple-icons.json`):
   the brand mark and colour of 511 popular domains, loaded the first time a
   tile needs it. See below.
3. **Chrome's favicon cache**, `chrome-extension://<id>/_favicon/?pageUrl=…&size=64`
   (the `favicon` permission), local and only for sites the browser has
   shown. It loads in the inline menu's frame too (checked headless: the
   frame, loaded from its dynamic web-accessible URL, still has the
   extension's origin). Chrome's generic globe counts as none. A raster at most half the
   drawn size scales by whole pixels without smoothing, so a 16 px icon stays
   crisp.
4. **The letter tile.**

Kept SVG icons are in the extension's own IndexedDB (`deadbolt-site-icons`),
at most 400, oldest out first. Content scripts can read
`chrome.storage.local` but not the extension's IndexedDB, so a page (or a
compromised renderer) can't list which sites have saved logins from their
icons. They aren't encrypted: someone who can read the browser profile can
see which sites have icons, as they can see its history and favicon
database. The inline menu, an extension frame inside a web page, doesn't
open the store itself: the background includes the kept icons for its
logins' hosts in `menu-load`.

### Simple Icons

[Simple Icons](https://simpleicons.org) (CC0 data, the `simple-icons`
devDependency, pinned) has about 3,500 brand marks: 4.6 MB of path data,
2 MB gzipped, too much to add to every install for a 28 px tile.
`bun scripts/simple-icons.ts` keeps the brands whose own domain (their
`source` URL's registrable domain, when its name is the brand's slug) ranks
highest on a pinned [Tranco](https://tranco-list.eu) list (`PYK6J`), the top
500, plus a hand map for big sites whose source is elsewhere (google.com,
facebook.com, twitter.com and the like): 511 domains, 697 KB, 303 KB
gzipped. A host matches its own entry or its nearest parent's
(`accounts.google.com` is `google.com`'s); private suffixes are never in the
map, so `someone.vercel.app` isn't Vercel. Regenerate it when bumping
`simple-icons`.

Simple Icons' disclaimer applies: the marks are trademarks of their owners,
shown only to identify the site a login is for, which implies no
endorsement, and some icons carry licences of their own (see the
`simple-icons` package's `DISCLAIMER.md` and each icon's `license` entry).

### Drawing them safely

Untrusted SVG never runs in an extension page. It's sanitized twice, in the
content script before it's sent and again before it's drawn, by
`ui/svg-safe.ts`: the markup is parsed (no DOCTYPE or entities at all) and
rebuilt into fresh elements from an allowlist of shapes, groups, gradients,
clips and masks, with geometry and paint attributes only. Scripts,
`foreignObject`, `style`, `image`, `use`, text, event handlers, namespaced
attributes (`xlink:href`) and any `url()` other than `url(#id)` are dropped.
The result is then only ever an `<img>` from a `blob:` URL of the page,
drawn into a canvas: an SVG image can't run script or load anything, so the
sanitizer is the second wall, not the only one. None of the sources taints
the canvas (`_favicon/` is the extension's own origin, a blob: is the page's,
checked in headless Chromium), so the reveal can read its pixels.

### The reveal

A tile shows its letter at once. When the icon resolves it dithers in, in
about 320 ms: a Bayer 8×8 threshold, one cell per CSS pixel, sweeps from 0
to 1, so the icon arrives in a crisp dot pattern, first in the tile's own
ink (the Rune palette's one tone), then in its own colours, while the
letter dithers out under it. A one-colour icon that would vanish into the
tile (GitHub's black mark on the dark theme) is drawn in the tile's ink.
Reduced motion: no reveal, the icon just appears. A list's rows reveal one
after another, 28 ms apart (the first nine). It runs once per resolve: the
first time a page shows a site's icon in its list or a login's detail, and
in the inline menu the first time this browser session; repaints, searches
and later menus just show it.

In the menu, the reveal never touches the pick checks: it only redraws a
canvas inside a row, so nothing moves, resizes or fades (the
`IntersectionObserver` v2 reading stays visible, and `dwell.moved` isn't
called), and the menu opens and is pickable exactly as without icons. An
icon that isn't ready within 250 ms of the list showing just appears, and a
press stops a reveal where it is and shows the icon at rest, as nothing in
the frame may animate while `confirmPick` checks the press.

### Tracing rasters

A quick colour-quantize-then-trace of 64 px favicons (k-means to four
colours, marching squares on each colour's mask) was tried against the plain
raster at the menu's and the list's sizes (GitHub's, Vercel's and a generic
globe, 64 px from `_favicon/`). At 17–26 px the traced icon is no sharper,
its edges come out lumpier, and it's 90–175 KB of path per icon, so rasters
stay rasters: the dither works on pixels anyway.

## Learning a site

When Deadbolt misses a site's form, the popup's **Learn this site** records
the user signing in by hand, to build the detector from. It isn't a fill:
while the tab learns, Deadbolt's surface (the menu, a generated password)
stays away and a sign-in session's later steps fill nothing.

- **A session** belongs to one tab. It ends when the user clicks Stop, 2.5 s
  after the save judge sees the sign-in work (so the page it lands on is
  recorded), after 5 minutes, or with the tab. It needs no unlocked vault;
  unlocked, it can also tell a saved username (below). The background keeps
  its sessions in `chrome.storage.session` too, so a service worker that
  restarts picks them up (one whose time ran out meanwhile ends then). A
  frame whose step the background refuses ends the session on its side, so
  the inline menu doesn't stay away for a session nobody logs.
- **Every frame** of the tab joins, from any site, including frames that load
  later (they ask the background on load). Steps from frames on another site
  than the top page are marked `sameSite: false`, judged from the frame's
  origin as Chrome reports it, not from the step. The popup says so: chat
  widgets and ads are logged too, by shape only.
- **A step** is recorded when the session starts, when the inputs a frame
  shows or the detector's verdict change, and when the user submits: a
  trusted click on a button, Enter in an input or a trusted submit event,
  found without the detector, since a page it gets wrong is what learning
  is for. A step holds each input in the corpus probe's terms
  (`extension/corpus/probe.ts`: type, name, id, autocomplete, label,
  placeholder, size and place, shadow root, form), the detector's role for
  it and the page's kind, the submit control it picked, what the user
  clicked and whether that was the same control, the frame's place (origin,
  path, the query's parameter names, never values) and its iframes.
- **Typed fields** get what the typing shows instead of the value: the order
  they were typed in, the value's shape (`secret` in a password box, then
  `email`, `phone`, `digits` or `text`), a length band (not for a secret),
  whether it repeats an earlier field (`sameAs`), whether it's the username
  of a saved login for the site (`savedUsername`), and from those the field's
  `truth`: the role the detector is judged against. For `sameAs` and `savedUsername` the content
  script keeps SHA-256 digests of the session's random salt and the value,
  from the last trusted keystroke; only the username digest of a field that
  isn't a password box leaves the frame, and the background compares it with
  the saved usernames' digests, then drops it before logging. A field that
  was a password box at any point of the session, or that the detector takes
  for one, counts as a password box, so a show-password toggle doesn't make
  a password a username.
- **Page text** in a step (labels, placeholders, the title, button text, and
  what the page controls: input names, ids, autocomplete and inputmode, the
  form's action host, iframe hosts and paths, the frame's path and query
  parameter names) has email addresses, runs of four or more digits and the
  values typed into the frame's non-password fields replaced (`<email>`,
  `<n>`, `<typed>`), since a step 2 often names the account.
- **The log** is `~/.local/state/deadbolt/learn/<session>.jsonl` (beside the
  agent's log), one `start` line, then `step` lines, then an `end` line with
  its reason. The native host writes it (see `learn` under Host messages);
  the agent and the vault are never involved, and nothing syncs. Starting a
  session's log removes logs older than 30 days, then the oldest beyond the
  newest 50. `bun corpus/learned.ts` reports on the logs. The browser-only
  build keeps the same lines in the extension's IndexedDB under the same
  limits, and downloads them from Settings for `bun corpus/learned.ts --file`
  (docs/extension-device.md, Learning logs).

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

## Sign in with Google, Apple, GitHub…

Many sites are signed in to with another account rather than a password.
Deadbolt keeps that on the site's login, in two fields that aren't secret:

- `sign-in-with`: the provider. A known one is stored by id: `google`,
  `apple`, `github`, `microsoft`, `facebook`, `x` (Twitter too), `amazon`,
  `discord`, `slack`, `okta`, `linkedin`, `gitlab`. Any other is kept as its
  name, one line of at most 64 characters.
- `sign-in-account`: the id of the login it signs in with (the Google
  account's own login), 32 lowercase hex digits. Only meaningful when that
  login is in one of your vaults; nothing breaks when it isn't.

They're fields of a login, not a type of their own, so the login still
matches its site by URL, syncs, keeps history, mirrors and lists like any
other, and can have a password as well (a site that takes both). 1Password
does the same: its "Sign in with" is a field of a login.

A 1Password `.1pux` import fills both: the provider from 1Password's
`ssoLogin` field, and the account from its link to the provider's login,
once that login is in the vault (made by the same import, already there as a
duplicate, or imported or mirrored from 1Password before). The import says
"kept 114 sign-in methods (Google 95, …)" and "linked 96 to their accounts",
and warns about links to a login that isn't in the export; those keep the
provider only. A login with only a provider isn't an empty item.

`list` gives such a login's provider and, when the linked login is in one of
your unlocked vaults, its username (or its title when it has none) as
`signIn`. Nothing else of that login is ever read for it: a `fill` of the
site's login fills only that login's own values, so one with only a provider
fills nothing. The extension shows it as "Sign in with Google ·
dax@gmail.com" in place of a password (see "In the extension" below).
`deadbolt show` prints
`sign-in-with  Google · dax@gmail.com`, and `ls` shows "Sign in with Google"
for one without a username.

### In the extension

- **The menu.** On any login field, identifier fields included, a login with
  `signIn` is a row "Sign in with Google" with its account (or the login's
  title) beneath and the provider's initial as its mark; Deadbolt draws no
  third-party logos. One with a password too gets two rows: its fill row,
  then the sign-in row. One with only a provider never offers a fill, and the
  background refuses one if asked. The toolbar popup shows "Sign in with
  Google · kit@gmail.com" on the login and no Fill button when there's no
  password.
- **Picking it fills and clicks nothing.** The page's content script looks
  for the site's own button (a Google Identity Services or Sign in with Apple
  widget, or a button or link whose text, label or `data-provider` says
  "continue / sign in with Google" and at most one other word; "Sign in with
  Google to sync your calendar" and share or follow buttons don't count),
  scrolls it into view and rings it, with a pill "Your Google sign-in". The user
  clicks it. The ring follows the button as the page lays out and goes on any
  click, Escape, the button scrolling away, or after 10 s; with reduced
  motion it only fades. With no such button, the row says "Look for
  “Continue with Google”" and nothing is ringed.
- **On the provider's side.** Picking the row also starts a sign-in with the
  provider in that tab (`bg/signinwith.ts`): the provider, the linked account
  and the site, for 3 minutes. A popup the tab opens follows it. It ends on
  coming back to the site, closing the tab, or locking. While it lasts:
  - on Google's own sign-in host, `accounts.google.com`, over https, the
    top page is told the account, and on the account chooser Deadbolt rings
    the tile carrying it in `data-identifier` (or `data-email`) with a pill
    "Your linked account". Never a tile found by its text, which the page
    could make name anyone. The user picks it. Only Google's chooser has
    such a pattern on a host that is only sign-in pages; no other provider's
    page (GitHub, X, Discord, Slack and the like host their users' own
    content) is ever told the account.
  - the menu on the provider's own pages (its known sign-in hosts, over
    https) narrows to the linked login (the Google account's own), as usual
    on a click; this sends the page nothing. With no login for the linked
    account, the username on the form narrows it as anywhere else. Nothing
    fills by itself there.
- **Test hosts, in e2e builds only.** `scripts/build.ts --e2e <dir>`
  (which `e2e/run.ts` runs for itself) defines `DEADBOLT_E2E`: only that
  build takes a provider host ending in `.test` for the same one in `.com`
  (`accounts.google.test` for `accounts.google.com`), over http too. Every
  other build, `bun run build` included, defines it false and the alias
  isn't in its code, so a resolver answering for `.test` names can't pose
  as a provider.

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
  `username`, `display-name` (the page's `user.displayName`), `credential-id`,
  `user-handle` (both base64url), `private-key`
  (a base64url PKCS#8 P-256 key, a secret field), `created` and `notes`. Its
  own kind, rather than fields on a login, because a passkey belongs to a
  relying party id, not to URLs, and because a login and its passkey change
  and go away independently. An item kind gets core's rules for free:
  required fields, and a secret field that listings, search and the app
  never show. The agent alone reads the private key, to sign. Registering again for
  the same user on the same relying party creates a new item and preserves the
  old key: the site may reject or never receive the new registration. The agent
  checks `excludeCredentials` again just before saving, refusing duplicates the
  site excluded even if they appeared while the user was asked. Neither a new
  registration nor an assertion retires the old item automatically. Explicit
  native passkey deletion asks for Touch ID when enabled and enrolled; standalone
  Strict deletion requires the local passphrase.
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
- **Agent sign-ins** (`agent-passkey-get`, `docs/agent-control.md`,
  "Standing grants") sign for a paired agent client, such as Browse's relay,
  under a grant with `passkeys` for the site. Nobody is at the Mac, so UP is
  set because the grant is the user's standing consent to sign in there, and
  UV is never set: no finger touched anything. A `required` request fails
  before anything is signed; sites that demand verification don't get
  agents in, which is correct. Client data comes from the frame origin the
  relay read over CDP, and the relying party id is checked as below. The
  passkey is the one the client names by ref (`agent-logins` lists each
  with its user name and display name), else the only one the grant covers
  among `allowCredentials` (all of the site's when empty); with several the
  agent replies `choose-passkey` listing them, never their keys. A grant for
  one login covers the passkeys with that login's username.
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
  isolated world. The one exception is an autofill request in a login frame
  (see below). Incognito tabs go to the browser.
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
  device and Cancel.
- **Autofill sign-in** (`mediation: "conditional"`) is Deadbolt's wherever
  its inline menu opens on the page's login fields: the top page, or a frame
  whose every frame up to the top page is its site (`sameSiteTop`, see
  Frames above), such as Apple's sign-in frame in App Store Connect. The
  browser draws its own autofill dropdown (passkeys from Apple Passwords,
  Google Password Manager or a phone) in browser UI, over anything a page or
  extension shows, so there Deadbolt holds the request whenever it has
  logins or passkeys for the site, and the browser never sees it. Its
  passkeys join the inline menu's rows on the username and password fields,
  under the menu's visibility and keyboard rules: picking one signs in;
  picking a login fills it and leaves the request waiting, as the browser's
  own does. It waits until a passkey is picked, the page aborts or the
  document goes away. One request per document waits; a newer one replaces
  it. In a frame on another origin of the site, the agent's client data
  (never `crossOrigin`) wouldn't be true, so there the request is held for
  the logins alone. With neither logins nor usable passkeys for the site,
  the request goes to the browser, so its dropdown still shows other
  providers' passkeys on sites Deadbolt doesn't know. Where Deadbolt holds
  it, other providers' passkeys are a modal sign-in away: the site's own
  "Sign in with a passkey" button makes a call without `mediation`, which
  goes to the browser's sheet whenever Deadbolt has no passkey for it (or
  through Use another device when it does).
- **Back to the browser:** Deadbolt hands the call to the browser's own
  WebAuthn, unchanged, when the site wants another algorithm or a
  `cross-platform` authenticator, asks `silent`, has no passkey Deadbolt
  holds (for an autofill request: no passkey and no login), needs `required`
  verification Deadbolt can't give, Deadbolt isn't ready (locked, not
  running, or a host without `passkeys`, which still holds an autofill
  request for its logins), or the user chooses Use another device.
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
  site's passkeys (or, for an autofill request, its logins) 4 times at once,
  then once a second, and requests for the same relying party id while one
  lists share it. The host allows 20 lists
  a quarter-second, 10 ceremonies a second and 4 at once, and answers
  `rate_limited` past them, which the page sees as `NotAllowedError`.
- **The page↔extension channel:** the content script offers the hook one
  `MessagePort` at `document_start` and nothing more. The hook is the first
  content script in the manifest and runs in the page's world before any page
  script; its capturing listener takes that one offer and stops it reaching
  the page. The content script accepts requests only after the hook's ack on
  that port. (Foyer, which this ports, offered a port whenever asked and took
  whichever acked first, so a page could take it over.)

## Forms: addresses, contact details and cards

Besides logins, Deadbolt fills what people type into forms all the time:
name, email, phone, postal address, company, birthday, and payment cards.
Below: the data and the protocol, then the extension's side (detecting the
fields, the menu, which frames get what), then the safety rules.

### The data

An `identity` item holds a person's details in the parts forms ask for,
named after the HTML `autocomplete` tokens so a field maps without guessing:
`honorific`, `given-name`, `additional-name`, `family-name`, `nickname`,
`organization`, `job-title`, `email`, `phone`, `address-line1` to
`address-line3`, `city` (`address-level2`), `region` (`address-level1`, a
state or province), `postal-code`, `country` and `birthday`, besides its ID
numbers (`national-id`, `passport`, `license`) and `notes`, which never fill
a form. A phone that reads as international is kept in E.164 form
(`+17185550100`), else as typed; a country is its ISO 3166-1 alpha-2 code in
upper case (`US`); a birthday is a date. People keep several (Home, Work),
named by the item's title. The content script turns parts into what a page
wants: a full name, the street as one field or lines, a national phone
number, a country's name or a `<select>`'s option, birthday parts.

A `card` holds `number`, `cvv` (the security code), `expiry` (a month,
`YYYY-MM`), `cardholder`, `brand` and `pin`, and may name its billing address
with `billing`, the item id of an identity. A PIN never fills a form.

Identities made before names and addresses had parts keep their one-line
`name` and multi-line `address` as extra fields: shown, searched and used for
the label as before, but not offered to forms. Importing again, or a sync
from 1Password, writes the parts: 1Password's `.1pux` and `op` identities
(first name, initial, last name, company, job title, the structured address,
the default phone, else the mobile, home or business one, and email) and
Bitwarden's.

### The protocol

The host's `forms` lists the identities and cards of every vault without
values: an identity's title, a summary ("Kit Langton · 123 Main St,
Brooklyn") and which form fields it has; a card's title, brand, last four
digits, expiry, cardholder and billing identity. `fill-form` returns only the
fields asked for, of one item. Both go to the agent as `form-items` and
`form-fill` (agent protocol 16; host protocol 3, capability `forms`). See
Host messages.

### Detection

`extension/src/content/forms.ts` gives each visible input, select and
textarea a role named by its HTML autocomplete token (`given-name`,
`address-line1`, `postal-code`, `cc-number`, `cc-exp-month`…):

1. The `autocomplete` attribute first, after its section words
   (`section-*`, `shipping`, `billing`, `home`, `work`…). `country-name`
   counts as `country`. Login tokens (`username`, `current-password`…)
   leave the field to login detection.
2. Then the field's labels, aria label, placeholder and title, then its id
   and name, against short word lists in English, German, French, Spanish,
   Italian, Dutch and Portuguese, with a few Japanese, Chinese and Russian
   words. Narrow roles are tried before the ones they'd be mistaken for
   (security code before card number, email before address). Coupons, gift
   cards and search boxes are never fields.
3. Then shape: `type=email`, `type=tel`, `type=date`, `type=month`; a
   select's options (twelve months, 28–31 days, years in the past or the
   future, a country list, a US, Canadian or Australian region list); and a
   card number split over short boxes (`maxlength` up to 6), where the
   first box says what it is and the next ones say nothing. A birth date
   box whose text shows a whole date's format (`MM/DD/YYYY`, `DD.MM.YYYY`,
   `YYYY-MM-DD`) takes the whole date in that format, not just its day.

Fields are grouped into sections, which is what one pick fills: per form
(or the page, for fields outside one), then by the autocomplete section
words, then by their surroundings (an ancestor's id, class or aria label,
or a legend or heading in it, saying billing, shipping or delivery), and a
role seen twice with neither starts a new section (two address blocks one
after the other). A form's card fields are one section.

Login detection (`detect.ts`) is unchanged and runs first: a field a login
form claims (the email box of a sign-in) stays the login's. The same
opt-out marks apply (`data-1p-ignore`, `data-lpignore="true"`,
`data-deadbolt-ignore`, …).

A select the page fills in only once an earlier field is chosen (a state
list that loads, or is disabled, until its country is picked) is approved
with the rest of the section when it's on screen, disabled or not, and
written last: only if the same fill wrote something before it, once it has
an option for the value, within two and a half seconds, and after the full
field check again (enabled, on screen, uncovered). Nothing else the page
enables later is filled.

### The menu

A click into an identity or card field (or ↓ in it) opens Deadbolt's
surface under it, on the logins' rules: only right after the user's own
click or keypress, a token bound to the one menu document and the field's
document, the half second of rest and the visibility checks before a pick
counts, and Enter only after the user came into the menu themselves. An
identity field lists identities, each with what it will fill of the
section and its summary ("Home: Fills name, phone, address · Kit Langton ·
123 Main St, Brooklyn"); a card field lists cards ("Visa ••4242 · 08/28").
The caption names where a pick goes: "On shop.com", or "Into Stripe on
shop.com" from a provider's frame. A card field also says, when the
host says Touch ID is on (`canVerify`), that Deadbolt may ask for it. Only
items with at least one value the section's fields need are listed (from
the reply's `fields`). Nothing shows while the host doesn't list the
`forms` capability.

A pick folds the list into the pill, which says Filled. The content
script first fixes which fields of the section may be filled
(`db:forms-approve`); the background asks the host for only the values
those fields need (`fill-form`, a full name asks for the name's parts, a
phone also for the country, …), and the content script writes each one
after checking it again, as for logins. Values are shaped per field
(`content/transform.ts`): a full or split name, a street address joined in
one box or in lines in a textarea, a phone international or national (a
short box, or a form with its own country code box), a country or region as
its code, its name (in the page's language) or the matching option, a
birthday whole (in the order a placeholder shows) or in parts, an expiry as
`MM/YY`, `MM/YYYY`, `MMYY` or month and year inputs or selects, and a card
number with spaces when the placeholder shows groups, or one slice per box
(all the boxes or none). A select with no matching option is left alone.

An identity goes only into fields the user can see as the page stands:
nothing is scrolled into view to fill it, and a field smaller than 40×16
CSS pixels, not wholly on screen, or covered at its middle (Deadbolt's own
pill aside) is skipped, so a page can't collect an address through boxes
tucked out of sight. The menu's "Fills …" counts only those fields. A field
holding what the user typed themselves is never overwritten (the same keyed
digest of the last trusted input as for logins); a value Deadbolt filled
before is, so picking Work after Home replaces Home's values.

A card's number and security code make the agent ask for Touch ID; the
extension waits up to 90 seconds for that answer with the pill on
"Filling…". Turned down, nothing is written, not even the cardholder's
name, and the pill says so.

### Frames and payment providers

Identities go only to the top page and to frames on the top page's site,
as logins do. Cards go there too, and into a payment provider's own
cross-origin frame, only when:

- the frame's origin is https, on the default port, on one of these hosts
  (`extension/src/payments.ts`):

  | Provider       | Card frame hosts                                                                 |
  | -------------- | -------------------------------------------------------------------------------- |
  | Stripe         | `js.stripe.com`                                                                  |
  | Braintree      | `assets.braintreegateway.com`                                                    |
  | PayPal         | `www.paypal.com`, only paths starting `/smart/card-field` (the JS SDK's hosted CardFields) |
  | Adyen          | `checkoutshopper-live.adyen.com`, `checkoutshopper-test.adyen.com` and regional `checkoutshopper-live-<region>.adyen.com` |
  | Checkout.com   | `js.checkout.com`                                                                |
  | Square         | `web.squarecdn.com`, `sandbox.web.squarecdn.com`, `pci-connect.squareup.com`     |
  | Shopify        | `checkout.pci.shopifyinc.com`                                                    |

- and the top page is https.

Why: these providers keep card fields out of the merchant's page on
purpose (PCI scope), so the number can only be typed into their frame. A
cross-origin frame is otherwise someone else's content, an ad or a widget,
and gets no card; the list is short and exact (no suffix matching) so a
look-alike host gets nothing, and https on both sides keeps the card off
the network in the clear. PayPal is the one provider whose card frames
share a host with its whole site, so for it the path counts too: only the
hosted card fields take a card. That path is what PayPal's SDK uses today
and isn't a documented contract; if it moves, PayPal card fields stop
filling (closed, not open) until the list is updated. Sandboxed and opaque frames, incognito tabs and
every other cross-origin frame get nothing, identity or card.

A field in a frame can't open the surface itself (the page around the frame
decides where and how the frame shows). It says where the field shows in
its own viewport; the background carries that box up through every frame
above, with the checks a fill makes at each one (`boxesInTop` in
`bg/frames.ts`), and opens the surface in the top page under it, as wide
as the box (the logins' rule), following the page's scroll. A card's
surface names both when a provider's frame takes it: "Into Stripe on
shop.com". One pick hands a card to one party
only. From a provider's frame, it fills that frame and the same
provider's other frames that reported card fields (a Braintree page has a
frame per field), never the page around them or another provider. From the
top page or a frame of its site, it fills the top page and that site's
frames, never a provider's frame; a cardholder's name in the page and the
number in Stripe's frame are two picks. Each pick is one `fill-form`, so
one Touch ID prompt. Each frame below the top page fills only if all
its fields show through every frame above, checked before the host is asked
and again once the values are in hand. While those checks run, the pill
steps out of the top layer and isn't drawn for a moment (Chromium reads
nothing as fully visible while anything shows there, and a frame's pill
sits on its field).

e2e builds (`scripts/build.ts --e2e`) also take a provider host with `.test`
for `.com` over http, and an http top page on `localhost` or a `.test` host,
so the e2e run can serve a Stripe-like frame on `js.stripe.test`. Every
other build defines that branch away.

### Security

- **Origins:** forms aren't bound to a site: any page autofill takes may list
  identities and cards, but only that: https, http only on a local host,
  never a sandboxed or opaque frame (`null`). The extension offers them only
  where the user is on a form, never in incognito windows, and decides which
  frames get card fields (a short allowlist of payment providers'
  cross-origin frames).
- **Listing gives no values:** never a card's number or code, and no
  identity value beyond the summary.
- **Fills give only what was asked,** and only form fields: an identity's ID
  numbers and notes and a card's PIN and notes are refused (`bad_request`).
- **A card's number or security code verifies the user each time:** with
  Touch ID on and enrolled, the agent raises it for "fill Visa •••• 4242 on
  shop.com" and fills nothing if it is cancelled or fails. Without Touch ID,
  the user's explicit pick in the extension's menu is the verification (the
  same rule as a login's password), so `canVerify` tells the menu which it
  will be. The expiry, cardholder and brand need no prompt, nor does an
  identity.
- **Activity** records every card fill from the browser (which card, which
  page, which fields), never an identity's: addresses fill on every checkout,
  and they're not secrets. Listing is never an entry. A fill asked by
  anything else than the browser host is recorded, whatever the item.
- **Waiting on Touch ID** holds the host's other requests behind it (they're
  answered in order), which is fine while the user is at the prompt.
- **Idle lock:** listing, which comes with every form, doesn't count as use;
  a fill does.

### What's next

- Saving a new address or card typed into a checkout, and updating one.
- Agent grants for forms: Browse and other agent clients fill logins only.
- A billing address picker in the app (the field is an item id today).
- Filling forms from the toolbar popup: only the in-page menu fills them.

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
- **What a check tells the page.** A check is a password oracle for the
  page's site, so what a page can see of it is kept to one bit per site per
  ten minutes. A page can still choose a password and submit it in a way that
  passes the noise filters; the result is an offer the user sees and can
  decline, and no value reaches the page. The offer's surface is an element
  the page can see appear and change shape (it can't read or click into
  it), and the popup, where it opens instead, takes focus from the page,
  which a page can see too. Exactly what the page can infer from the
  surface:
  - That an offer appeared: a confirmed check found a new or changed login,
    so the password it chose isn't the one saved, and Deadbolt is installed
    (which any menu already shows). Not which: a new login and an update
    have the same size, and both fold into the same "Saved" pill.
  - That the user pressed Save: the surface folds into the pill before it
    leaves. Not now and Never for this site leave the same way, so they
    look alike.
  - That the user came near it or focused it (it opens), and that they
    clicked elsewhere or let it be (it shrinks to the dot).
  - That Deadbolt is locked or busy, if a save fails: the card opens and its
    status line makes it taller.
  - Roughly how long the user took, from when the surface leaves.

  Every check that finishes uses up the site's (registrable domain's) ten-minute turn, across
  tabs, whatever it said: `same`, `new`, `update`, or `rate_limited`. The
  offer shows by itself only when that check offered something and took the
  turn; every other offer only badges the toolbar button. Only a confirmed
  sign-in (see Sign-in outcomes) can show it, so only its check takes the
  turn; a page decides what it shows, so it can choose which checks those
  are, but a check that can't show anything tells it nothing. That's the
  same one bit the popup opening by itself always gave away, and in return
  the offer appears where the user is looking; the badge and popup remain
  for every other offer. Not now and Never for this site stop checks, so a
  page that sees nothing where an offer would have shown may learn the user
  said one of them.

  The account menu tells the page a little too, as the user types an
  identifier into it: the menu's height follows how many saved logins for
  this site match the text, and it goes when none do. So the page, which
  sees the text anyway, learns whether Deadbolt holds a login for this site
  whose title or username contains it. Only the user's own typing narrows
  it; a page's script can't type into it to ask.

  A username the page set itself counts in one place only: the account a
  provider's own password step shows, on `https://accounts.google.com`
  (the background checks the frame's origin; the content script's word for
  the host isn't trusted). That host serves nothing but Google's sign-in
  pages, so the name there is Google's, not one a site or its users chose,
  and the page already knows which account it asks for. Even there it only
  narrows: a name matching no login shows the whole list, so whether a menu
  shows never depends on it, and the menu's height (one row or all of
  them) tells Google at most whether Deadbolt holds a login for the account
  it named. Anywhere else, including Google's other hosts, a page-set name
  is ignored.

  The probe itself puts nothing in the page. A fill's values reach only the content script's isolated world
  and the fields it writes. The host rate-limits checks and fills as well, so
  a runaway or compromised caller can't guess quickly.
- **Later steps fill without a click, within bounds.** A sign-in session
  fills a password or code into a step the user didn't pick on. It's bound
  to the login the user picked, the tab, the pick's origin or a host a saved
  URL of the login names exactly, and a few minutes; it fills each step
  once, only after the user's own submit of the step before (a trusted
  click on the submit control or Enter in a field; a page submitting its
  own form, or taking the fields away, doesn't count), and only into fields
  that pass the usual checks, in the top page. A page on such an origin
  that shows a password field right after the user submitted their username
  gets the password, as it would with a pick; that is the site the user is
  signing in to. A sibling subdomain (user content, say) that no saved URL
  names gets nothing. A page of another site
  ends the session, and an empty username step ("Use a different account")
  does too, so a different person's sign-in never gets the first login's
  password. The pill on the field is an extension frame, as for any fill.
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
  whose placement the page around them controls, get the menu only when
  every frame up to the top page is the same site, and why a frame's
  fields are checked through every frame above before and after the host
  is asked.
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
- **Sign in with a provider: what the pages learn.** The ring and its pill
  are drawn in a closed shadow root on an element of Deadbolt's own, which
  lets clicks through. The page can see that an element appeared, and work
  out roughly where the ring points, but not read what it says, and the
  pill names no one ("Your Google sign-in", "Your linked account"). So the site learns
  that the user picked "Sign in with" in Deadbolt (as it would see the
  click anyway), and the provider's chooser learns which of the accounts it
  already shows Deadbolt points at. The linked account goes only to the
  provider's own top page in the tab (or its popup) following the sign-in,
  by its document id and origin, never to another origin or a frame, and
  only to `https://accounts.google.com`: a provider whose chooser carries
  the account in an attribute, on a host with nothing but its sign-in
  pages. A provider whose hosts serve user content never gets it. No
  password, fill or click is ever made for it.
- **The idle lock:** fill, generate, save, and a passkey registration or
  sign-in count as use. Hello, list, check, `generate-check`,
  `generate-drop` and passkey-list don't, because a browser asks for those on
  every page and would otherwise hold the vault open.
- **Locked means locked.** While the store is locked, every request but hello
  and `generate-check` gets `locked`. Hello starts the agent if it isn't running but never unlocks
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
- **Rate limits:** per connection, `check` and `generate-check` share a
  burst of 20 then one a second, `fill` and `generate` share a burst of 60
  then four a second, and `passkey-create` and `passkey-get` together a burst
  of 10 then one a second, with at most four running at once. Past that a
  request gets `rate_limited`; nothing else is limited.
- **Requests** carry an `id`, a string of up to 200 characters or a number. The
  reply echoes it. A message without a usable id, or one that isn't JSON, gets
  `bad_request` with `"id": null`.
- **`origin`** is the origin of the frame the form is in, such as
  `https://gist.github.com` or `http://localhost:3000`.
- **Unknown fields** are ignored. Values are strings unless noted otherwise.

### hello

```json
{ "id": "1", "type": "hello" }
{ "id": "1", "type": "hello", "protocol": 3, "version": "0.1.0+abc123",
  "status": "ready", "capabilities": ["list", "fill", "check", "save", "generate", "passkeys", "learn", "forms"] }
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
    "urls": ["https://github.com"],
    "signIn": { "provider": "google", "account": "octocat@gmail.com" } } ] }
```

`username` is left out when the login has none. `signIn` is there only for a
login that signs in with another account (see Sign in with Google, Apple,
GitHub…); its `account` is left out when the linked login isn't in an
unlocked vault. `title` is the login's name, else its URL's host. Accounts
come closest first, by their closest URL: the page's origin (port included,
so `localhost:3000` isn't `localhost:5173`), then its host on another scheme
or port, then a parent or child host or one sharing a parent below the site,
then the rest of the site. Ties go to the login last filled on this device,
then to the title.

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

### generate: a new password for a sign-up form

```json
{ "id": "6", "type": "generate", "origin": "https://github.com",
  "rules": "minlength: 12; required: digit;", "minLength": 8, "maxLength": 64,
  "allowed": "abc…789" }
{ "id": "6", "type": "generate", "password": "…", "generated": "<id>" }
```

Every field but `origin` is optional: `rules` is the field's
`passwordrules` (at most 1024 bytes), `minLength` and `maxLength` its
limits (numbers), and `allowed` the only characters to use. A site in
Apple's [password-manager-resources](https://github.com/apple/password-manager-resources)
quirks (vendored in `crates/core/data/password-rules`, MIT) gets those rules
instead of `rules`, and the field's limits always apply. Without either, it's
20 characters of letters, digits and symbols with one of each kind. Limits no
password fits get `failed`, and ones that allow under 60 bits get `weak`.

Nothing is saved. The password is a candidate for two minutes, until
`generate-keep` or `generate-drop` names it; at most four are held. A kept
one is held for `origin` until a `save` names it, 15 minutes pass, 16 newer
kept ones push it out or it locks. `check` and `save` take
`"generated": "<id>"` in place of `password`, for kept ones only; from
another origin, or once it's gone, that's `not_found`.

```json
{ "id": "7", "type": "generate-check", "origin": "https://github.com", "maxLength": 6, "allowed": "0123456789" }
{ "id": "7", "type": "error", "code": "weak", "message": "…" }
{ "id": "8", "type": "generate-keep", "origin": "https://github.com", "generated": "<id>" }
{ "id": "8", "type": "generate-keep" }
```

`generate-check` takes `generate`'s fields and makes nothing: it answers
`generate-check`, or the error `generate` would get. It works while locked.
`generate-keep` and `generate-drop` take the `generated` id (1 to 64 bytes)
and answer with their own type; keeping one from another origin, or one
that's gone, is `not_found`, and dropping it does nothing.

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

Without `username`, every login on the site counts, by password alone: `same`
with those that have it, else `new`. A generated password goes as
`"generated": "<id>"` instead of `password` (see generate). The password is 1
to 4096 characters and the username at most 500.

### save

```json
{ "id": "5", "type": "save", "origin": "https://github.com",
  "entry": { "title": "github.com", "url": "https://github.com/login",
             "username": "octocat", "password": "…" } }
{ "id": "5", "type": "save", "ref": "<ref>", "created": true }
```

`entry` takes `"generated": "<id>"` in place of `password`; saving it lets the
agent forget it.

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

### forms: identities and cards for a form

```json
{ "id": "9", "type": "forms", "origin": "https://shop.com", "kinds": ["identity", "card"] }
{ "id": "9", "type": "forms", "canVerify": true,
  "identities": [
    { "ref": "<64 hex>:<32 hex>", "vault": "personal", "title": "Home",
      "summary": "Kit Langton · 123 Main St, Brooklyn",
      "fields": ["given-name", "family-name", "email", "phone", "address-line1", "city", "region", "postal-code", "country"] } ],
  "cards": [
    { "ref": "<64 hex>:<32 hex>", "vault": "personal", "title": "Visa •••• 4242",
      "brand": "Visa", "last4": "4242", "expiry": "2028-08", "cardholder": "Kit Langton",
      "billing": "<64 hex>:<32 hex>", "fields": ["cardholder", "number", "expiry", "cvv", "brand"] } ] }
```

`kinds` names `identity` and/or `card`. Every vault's items of those kinds,
by title, with no values (see Forms). `fields` are the form fields the item
has a value for; `summary` may be empty; `brand`, `expiry` (`YYYY-MM`),
`cardholder` and `billing` (the ref of its billing identity, if that is in a
vault here) are left out when the card has none. `canVerify` says whether a
card's number or code would raise Touch ID now. A page autofill doesn't take
gets `bad_request`.

### fill-form: some fields of one identity or card

```json
{ "id": "10", "type": "fill-form", "origin": "https://shop.com", "ref": "…",
  "fields": ["cardholder", "number", "expiry", "cvv"] }
{ "id": "10", "type": "fill-form", "verified": true,
  "values": { "cardholder": "Kit Langton", "number": "4242424242424242", "expiry": "2028-08", "cvv": "737" } }
```

`fields` names an identity's form fields (`honorific`, `given-name`,
`additional-name`, `family-name`, `nickname`, `organization`, `job-title`,
`email`, `phone`, `address-line1`, `address-line2`, `address-line3`, `city`,
`region`, `postal-code`, `country`, `birthday`) or a card's (`cardholder`,
`number`, `expiry`, `cvv`, `brand`); any other, or one the item's kind
doesn't have, is `bad_request`. `values` has only those the item has. Asking
for a card's `number` or `cvv` raises Touch ID when it's on; `verified` says
whether it did. A cancelled or failed prompt is `failed`. Rate-limited with
`fill`. An unknown `ref`, or one that isn't an identity or card, gets
`not_found`.

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
  "challenge": "<base64url>", "user": { "id": "<base64url>", "name": "octocat", "displayName": "The Octocat" },
  "exclude": ["<base64url>"], "userVerification": "preferred" }
{ "id": "7", "type": "passkey-created", "ref": "<ref>", "credentialId": "<base64url>",
  "clientDataJSON": "<base64url>", "attestationObject": "<base64url>",
  "authenticatorData": "<base64url>", "publicKey": "<base64url SPKI>", "verified": true }
```

Makes a new ES256 passkey item in the default vault, preserving any existing
credential for the same `user.id` on that relying party, and fails if one of `exclude` is already
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

### learn: a line of a learning log

```json
{ "id": 10, "type": "learn", "session": "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b",
  "line": { "event": "step", "seq": 3, "inputs": [] } }
{ "id": 10, "type": "learned" }
```

Appends `line`, a JSON object, as one line of
`~/.local/state/deadbolt/learn/<session>.jsonl` (see Learning a site).
`session` is a lowercase UUID, since it names the file; the directory is
`0700` (set again on every line) and the file `0600`. A session's first line
prunes the directory: logs older than 30 days go, then the oldest until 50
are left with the new one. The host doesn't read the line: the extension
puts no values in it. Lines come at most 100 at once, then one per 100 ms
(`rate_limited`), and a session's log stops at 4 MiB (`bad_request`). It
works without an agent and while locked.

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
- `not_found`: no such login, identity or card.
- `domain_mismatch`: the login or URL isn't on the page's site.
- `bad_request`: a malformed message, a page that gets no logins, or a value
  out of range.
- `rate_limited`: too many checks, fills, generated passwords or passkey
  requests; try again in a moment.
- `weak`: the field's rules allow only passwords under 60 bits.
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
  Passkeys and a card's number or code ask (see Passkeys, Forms).
- **Unlocking from the browser:** the extension can say Deadbolt is locked but
  can't unlock it. Use the app or `deadbolt unlock`.
- **Choosing the vault for a new login:** new logins go to the default vault.
- **Opening the app from the browser:** Deadbolt registers no URL scheme and
  the host has no message for it, so the popup says where to find the app
  instead.

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
