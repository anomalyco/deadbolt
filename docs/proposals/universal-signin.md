# Universal sign-in: prototype and next decisions

2026-10-29. Implemented opt-in prototype, with headless standalone verification
reported below. This document records behavior, rationale and remaining product
questions; it does not claim CI approval or completed security review. Research
and verification use public material and synthetic accounts, never a personal
vault or personal account data.

## What the prototype does

**One account pick can start on a homepage and complete a same-origin sign-in.**
The person enables “Offer to sign in” (default off). On an eligible page,
Deadbolt shows a compact top-right offer without moving focus. Picking an account
can activate the site's visible Sign in entry, navigate to its login page, then
fill and submit identifier, password and TOTP steps using that selected account.
A form does not have to be present when the offer appears.

This broad homepage-entry behavior is intentional. It is not deferred or limited
to login forms. Page arrival alone never authorizes navigation, filling or
submission: the person must first pick through Deadbolt's guarded menu. The
setting explains that a pick fills and submits; Escape stops the automatic flow.

Signed-in clues veto an unsolicited offer, including when a dashboard contains
a stray provider button. Unknown or conflicting state stays quiet. Existing
inline and toolbar fills remain available. Provider-account rows reuse existing
guidance: point at the site's provider control and let the person click it;
there is no automatic OAuth/provider click.

## Public precedent and clean-room boundary

Only public, user-facing 1Password documentation was consulted. Its documented
behavior supports a page-level account choice, multi-step completion after a
choice, an automatic-submission preference and saved provider relationships
[P1–P3]. Its security and troubleshooting material describes user-directed
filling and the risks of automatic submission and deceptive overlays [P4–P5].

These sources establish observable product behavior, not implementation. No
extension package, private source, selectors, vocabulary lists, rule tables or
internal scoring were inspected or copied. Deadbolt's detector, thresholds and
policy use its own implementation. This is not a provenance audit of older
Deadbolt code. No hands-on competitor run was performed, and no source establishes
how 1Password detects signed-out state, uses cookies or suppresses Gmail prompts.

## Current implementation paths

| Area | Paths and responsibility |
| --- | --- |
| Detection and local evidence | `extension/src/auth-state.ts`, `extension/src/content/auth-state.ts`, `extension/src/content/detect.ts`, `extension/src/content/outcome.ts`: state judgment, visible entry handles, account matching and existing outcome facts. |
| Offer and local memory | `extension/src/bg/universal.ts`, `extension/src/background.ts`: exact-origin accounts, suppression, offer tokens, callbacks and message routing. |
| Fill and continuation | `extension/src/bg/autofill.ts`, `extension/src/content.ts`, `extension/src/content/approvals.ts`, `extension/src/bg/frames.ts`: bounded automatic sessions, approved fields, effective submit destination and browser-derived document identity. |
| Surface and setting | `extension/src/content/inline.ts`, `extension/src/menu.ts`, `extension/src/ui/dom.ts`, `extension/src/vault/settings.ts`: compact corner surface, trusted entry, visibility guard and default-off toggle. |
| Existing integrations | `extension/src/bg/save.ts`, `extension/src/bg/signinwith.ts`, `extension/src/signin.ts`, `extension/src/bg/backend.ts`: save outcomes, manual provider guidance and shared native/standalone backend boundary. Browse's separate authority is described in `docs/agent-control.md`. |

The implementation reuses Deadbolt's existing menu frame, frame-token machinery,
field approvals and session code rather than creating a second credential path.
The shared core site policy still applies; the automatic path adds exact-origin
restrictions. See also `docs/autofill.md` and `docs/extension-device.md`.

## Auth-state signals and their limits

Page evidence is not proof of authentication and never authorizes secret release.
Its purpose is to decide whether a suggestion is useful or should be suppressed.

| Signal | Reliability and false positives | Prototype policy / local privacy cost |
| --- | --- | --- |
| Visible classified login form | Strong task evidence; password changes, resets, reauthentication and widgets can resemble sign-in. | A login form contributes 6 points. Other classified form kinds and uncertainty prevent a new offer; continuation separately supports MFA. Existing field checks still apply. |
| Visible Sign in entry | An obvious next action can exist on a homepage without fields. Public navigation can coexist with an authenticated session. | A recognized visible entry contributes 6 points; same-origin links are constrained. This broad gate is intentional, with signed-in vetoes applied first. No action until the guarded account pick. |
| Known login route | Weak alone: stale SPA routes, public content, callbacks and errors can look like login paths. | Contributes 2 points, below the threshold of 6. URL hints alone never produce an offer. |
| Visible sign-out control | Strong suppression clue, but stale markup or a chooser may not represent an app session. Absence proves nothing. | Vetoes an offer. A trusted sign-out action clears that origin's remembered suppression so fresh signed-out state can offer again. |
| Account avatar/menu or app shell | Avatars can be placeholders, public profiles or remembered accounts. Loading shells can hide all useful clues. | Account-menu/app-shell uncertainty stays quiet. Gmail has an explicit shell suppression; this is not a general classifier for every app. |
| Full email/username matching this origin's vault metadata | Strong suppression, but body text, public posts and login choosers can mention the same person while signed out. | Match full tokens, case-insensitively, not email local-parts. Broad visible-text matching deliberately favors suppression and can miss useful offers. Only exact-origin candidates are considered locally. |
| Own recent outcome | A field write or passkey signature does not establish server acceptance. Existing outcomes include both confirmed and likely. | Short-lived per-origin memory suppresses offers only. A likely outcome is never proof, nor permission to fill, submit or report a successful login. |
| Learned `Flow` | Useful for expected step order/timing; history does not establish current auth state. Learning can include likely outcomes. | Existing session machinery can use learned shape; it does not authorize a pick or add points to the prototype's offer score. |
| Navigation/redirects | Sign-in, sign-out, errors, consent and canonicalization all redirect. An app URL alone proves nothing. | Observe/reassess alongside page evidence. `webNavigation` exposes redirect qualifiers and SPA history events, **not HTTP response status codes** [T1]. No inferred 401/403 detector. |
| SPA/DOM changes | Forms can appear or disappear without navigation; loading can resemble success. | Rescan and reevaluate. SPA logout and subsequent offer are verified below; disappearing fields alone are not success proof. |
| `document.cookie` | HttpOnly auth cookies are inaccessible; readable cookies may be preferences, and server-invalid sessions can leave cookies [T2]. Reading is synchronous [T3]. | Not read. Cookie presence is weak evidence with unnecessary data access and runtime cost. |
| `chrome.cookies` | Broader access still cannot establish whether a server accepts a session. | No cookies permission or cookie inspection. The API requires cookie and host permissions [T4], expanding exposure without solving state inference. |

### Decision order

1. Require opt-in, an unlocked backend, a visible top document and an eligible
   exact-origin account. Respect an occupied surface, active session and cooldown.
2. Apply sign-out/account evidence and recent suppression memory before scoring.
   Account-menu, app-shell, challenge, error or other uncertainty keeps it quiet.
3. Use the implemented score: login form 6, visible sign-in entry 6, login route
   2; threshold 6. The origin must have an actionable form or entry handle.
4. Recheck the selected account and page after the trusted pick. That pick can
   authorize the homepage entry followed by same-origin multi-step completion.
5. Stop on cancellation, disabled setting, invalid destination or unusable step.
   Never treat detector confidence as authorization or automatically try another
   account after failure.

A route alone stays quiet; a homepage entry can qualify; signed-in evidence wins
even against an entry or form. Stronger route/Flow corroboration for homepage
entries is a possible future tightening, not a requirement the requested
prototype claims to implement.

### Local identity matching and privacy

The prototype sends at most 50 usernames from exact-origin login metadata into
that top document's **isolated content-script world**, not page JavaScript. It
compares full tokens against visible text/labels in memory and returns booleans.
There is no whole-vault page scan, remote classifier or cookie dependency. The
matching preserves the full email rather than matching its local-part, but folds
case and accepts matches outside account-specific UI. These choices can suppress
legitimate login offers; a mismatch never proves the person is signed out.

A future privacy refinement could extract a small bounded set of page candidates
and compare inside privileged background/backend code, with account-context and
site-appropriate identifier normalization. That is an alternative to the current
local transport, not a claim about this build.

The page can observe surface presence even though it cannot read the extension
frame. Vault-dependent suppression therefore retains a membership-probing side
channel. Bounded work and cooldowns reduce repeated probes; they do not eliminate
it. This remains part of the required security review.

### Memory, timing and origin boundaries

Account lists are cached for 5 seconds with at most 100 entries; a pick requests
fresh account metadata. Suppression records use hashed exact-origin keys in
extension session storage, are capped at 100 and have expiry pruning. Recent
outcome suppression lasts 5 minutes from its recorded observation; current
account/logout evidence can refresh it. Offer/dismissal cooldown is 30 minutes,
including across reloads. These records contain timestamps, not passwords or
stored page text. A field-fill acknowledgement is never successful-auth evidence.

Observed sign-out clears remembered signed-in suppression. A fresh SPA login
view may offer again when otherwise eligible and not under an offer cooldown.
That is the verified prototype behavior; an extra “stay quiet after intentional
logout” policy is a product decision, not an implemented guarantee. Remote or
unobserved logout may remain unknown until expiry or fresh visible evidence.
Lock closes offers and cancels credential work; session-memory retention should
not be confused with durable proof of authentication.

`https://mail.google.com` and `https://accounts.google.com` are distinct origins.
A Gmail-like shell stays quiet; an account chooser/chip is not proof of a Gmail
session. Neither suppression nor automatic credential authority is transferred
between sibling hosts. Separate-host auth/SSO expansion requires a new policy;
this prototype's automatic path is same-origin, including effective port.

## Interaction and security boundary

**Security review needed.** The prototype deliberately extends a guarded account
pick to navigation and submission. Default off and passing functional tests do
not constitute a completed security review.

1. **Trusted pick and visible UI.** Reuse the extension-owned menu and token
   bound to tab, frame, document and origin. Keep the existing 500 ms stable,
   visible dwell before the press and fresh visibility confirmation at least
   400 ms afterward. Preserve deliberate keyboard entry; do not autofocus or
   borrow the page's Enter key. Unknown visibility fails closed.
2. **Same-origin, top-frame work.** A chosen homepage entry can navigate within
   that origin. Automatic steps require exact parsed saved-origin matching,
   including scheme and effective port, and target only the top frame. Sibling
   hosts and cross-site iframes do not inherit this authority.
3. **Approved fields and bounded continuation.** Retain document/form snapshots,
   one-shot field approvals, visibility checks and serialized session work.
   Explicit automatic-session state comes from the guarded offer pick, not a
   synthetic page event. `SubmitEvent.isTrusted` alone is insufficient because
   `requestSubmit()` can produce a trusted submit event. Ordinary manual sessions
   keep their existing genuine-submit requirement.
4. **Effective submit destination.** Before submitting, check the current form,
   required fields, visible enabled control and effective `formaction`/`formtarget`
   overrides as well as the form defaults. Cross-origin action or another target
   is blocked. Escape and disabling the setting stop pending automatic work,
   including during backend RPC. These checks cannot authenticate site scripts
   or recall a request already sent.
5. **Surface and authority coexistence.** Reuse one page surface; existing menus,
   hand typing and pending save work can keep the offer from opening. Dismiss/Not
   now uses the origin cooldown, independently of saving preferences. Provider
   guidance remains manual; passkeys retain their existing ceremony checks.
   Browse's standing grants remain separate and gain no authority from this
   setting. There is no authenticated Browse-activity coordination signal yet.

No implicit provider-to-password fallback or arbitrary OAuth click is added.
A failure to safely advance must not become a retry against another account.
Visibility sampling reduces deceptive-overlay risk; it does not prove the page
trustworthy. Per-site Never and richer dismissal policy remain product options.

## Verification

The implementation run reported the following results using the real standalone
build in headless Chromium on exos with synthetic accounts. These are functional
results, not a claim that every site works or that the full security matrix/CI
has passed. Clips are being delivered separately.

| Environment | Verified result |
| --- | --- |
| Local fixture: entry and completion | Default off; compact top-right offer without focus theft; one account pick completes home → identifier → password → TOTP → dashboard. Modal sign-in also completes fully. |
| Local fixture: state and suppression | Signed-in dashboard with a stray Google button stays quiet; full-email matching suppresses; SPA logout changes state and allows an eligible offer; errors suppress. |
| Local fixture: boundaries and dismissal | Cross-site iframe gets no offer; dismissal cooldown survives reload; cross-origin form submission is blocked. |
| Real HTTPS demo | On `https://acme-demo.i.vogel.dev`, a newly created synthetic account completes home → identifier → password → `/app` from one pick; signed-in suppression is verified. |
| Focused tests | Five new session tests and nine detector tests passed, including setting-off-during-RPC and Escape cancellation coverage. |

**TOTP evidence is local-fixture only.** The newly created real-demo account had
no exposed MFA setup. Probes of `/settings/security`, `/settings/2fa`, `/mfa`,
`/otp` and `/login/otp` returned 404. The real-demo result therefore does not
establish TOTP completion or that the service lacks MFA elsewhere.

### Final prototype limits

| Limit | Consequence / next evaluation |
| --- | --- |
| Broad homepage entry gate | Intentional, default-off scope. Evaluate signed-in false positives across more sites; stricter corroboration is a future policy option. Security review is still required. |
| Same-origin automatic flow; manual provider guidance | Separate auth hosts and OAuth/provider clicks are not automated by this feature. Existing provider guidance is reused. |
| Exact-origin username metadata in isolated top-world, up to 50 | Local but wider metadata exposure than privileged-only matching. Broad case-insensitive body-text matching can cause safe false negatives. |
| Likely outcomes contribute suppression | Suppression can outlast an unsuccessful/ambiguous attempt for its short lifetime. It is never authentication proof or extra fill authority. |
| No authenticated Browse-activity signal | UI backs off using existing surface/form/session state; this is not complete coordination with independently authorized agent fills. |

## Measurement still needed

The verified flows establish working examples, not production precision or
latency. Keep future instrumentation local and value-free; do not persist raw
page text, usernames, item refs, URL queries, cookies or browsing-history logs.

1. Measure unsolicited offers per independently labelled signed-in/unknown page
   state, alongside recall on real login forms and homepage entries. Report
   numerator, denominator and page families; prefer silence to noisy guesses.
2. Measure pick → approved fill → submit → independently observed authentication
   separately. Include manual fallback and unknown outcomes; a successful fill
   is not a successful login.
3. Measure repeat offers, dismissals, cross-tab cooldowns, save/inline contention
   and account-switch/logout behavior. Extend coverage to BFCache, worker restart,
   challenges, reauthentication and separate auth hosts without assuming support.
4. Measure p50/p95 scan and offer latency on large DOMs and SPAs, cache hit rates
   and node budgets. Include the 500/400 ms guard in perceived latency; do not
   remove it to improve measurements. No measured latency claim is made here.
5. Exercise deceptive overlays, replaced forms/submitters, effective action/target
   changes, cancellation races and synthetic events. Expand verification for both
   native and standalone paths before claiming parity or security acceptance.

## Product questions (five)

1. Keep the explained offer-and-submit bundle, or separate automatic submission
   into its own default-off preference?
2. Should a later version support separate auth hosts, and what additional
   explicit authorization should cross-origin continuation require?
3. Keep the 30-minute origin cooldown, or add separate dismissal, post-logout and
   Never offer here controls?
4. Before broader rollout, should homepage entries require more corroboration,
   and should account comparison move entirely into privileged code to reduce
   metadata exposure and the residual surface-presence side channel?
5. Should ambiguous reauthentication/account-switch pages always require explicit
   manual invocation? Recommendation: yes until independently verified.

## Sources

Public references consulted 2026-10-29. Product sources establish public behavior
only; technical sources establish browser capabilities, not competitor internals.

- [P1] [1Password public launch announcement](https://1password.com/blog/introducing-universal-sign-in), 2026-09-03.
- [P2] [1Password browser filling instructions](https://support.1password.com/1password-extension/), 2026-09-11.
- [P3] [1Password provider sign-in instructions](https://support.1password.com/sign-in-with-provider/), 2026-08-28.
- [P4] [1Password browser autofill security discussion](https://support.1password.com/browser-autofill-security/), 2026-08-17.
- [P5] [1Password browser troubleshooting](https://support.1password.com/1password-browser-troubleshooting/), 2026-08-28.

Technical references:

- [T1] [Chrome webNavigation API](https://developer.chrome.com/docs/extensions/reference/api/webNavigation): document identity, redirects and history-state events; no HTTP status field.
- [T2] [MDN: Using HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies): HttpOnly visibility and server-side session validity.
- [T3] [MDN: Cookie Store API](https://developer.mozilla.org/en-US/docs/Web/API/Cookie_Store_API): synchronous/blocking `document.cookie`.
- [T4] [Chrome cookies API](https://developer.chrome.com/docs/extensions/reference/api/cookies): cookie and host-permission requirements.
