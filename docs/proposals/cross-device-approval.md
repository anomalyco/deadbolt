# Proposal: approve on any of your devices

Status: idea, not built. Ryan, 2026-10-30.

## The idea

When something on one device needs your approval, every one of your devices that
can ask you shows the same request, and you answer on whichever is in reach.

The motivating case is an AI agent on a Mac: it runs `deadbolt run` or a Browse
sign-in, and Deadbolt needs a Touch ID approval. Today the prompt only appears on
the Mac the agent runs on (docs/agent-control.md, "Approving"). If you're away from
that Mac, or it's a headless dev box like exos, the agent stalls or fails. With
this, the request also appears on your phone (a future iOS app), your other Mac, or
the standalone browser extension, and you approve with Face ID or Touch ID there.
The agent's flow never breaks.

It covers every request that asks for a person today:

- an AI caller resolving secrets (`run`, `inject`, `read`) without a standing grant
- Browse or another agent asking to sign in or choose a passkey
- Strict-mode reveals and card fills
- admitting a new device (`deadbolt pair`), instead of only showing the code on the
  inviting device

## How it would work

1. **Request.** The device where the request starts (the *origin*) builds an
   approval request: who is asking (the verified caller identity from
   `agent/caller.rs`, its program and session), what for (the exact command,
   items, fields, site), the origin device, a nonce and an expiry (e.g. 2 min).
   It signs it with its device key.
2. **Fan-out.** The origin sends the request to every member device that is online
   and can ask a person (see "Approver devices"), over the existing iroh
   connections between members. These requests are ephemeral messages on their own
   ALPN, never entries in the vault log: nothing is stored or synced, and a
   device that comes online after expiry never sees it.
3. **Wake-up.** A phone isn't usually connected. The origin also sends a push
   (APNs through Hark or our own relay) that carries no request content, only
   "Deadbolt needs you". It wakes the app, which connects and fetches the request
   from the origin directly.
4. **Show and answer.** Each approver device shows the request in its own words,
   built from the signed fields and not from caller-supplied text: who is asking,
   on which device, what it will get, for how long. You approve with user
   verification (Face ID, Touch ID, the vault passphrase), or deny.
5. **Response.** The approver signs `{request hash, decision, approver device,
   time}` with its device key and sends it to the origin. The origin checks:
   - the approver is a current member of the vault and allowed to approve
   - the hash matches the outstanding request
   - the request hasn't expired or been answered
   The first valid answer wins; every other device's prompt is withdrawn.
6. **Effect.** The origin applies the decision exactly as a local approval:
   one-time, scoped to that request, logged in Activity with "approved on
   <device>".

## Approver devices

A device can approve only if it can verify a person:

- the Mac app (Touch ID through the enclave helper)
- an iOS app (Face ID), the main target
- the standalone extension with Touch ID unlock (PRF, #98), possibly only for
  low-risk requests, since the browser is a weaker place to approve from
- not the CLI on a headless box, and not the device that started the request
  acting for itself

Which devices may approve should be a per-vault setting, and approval itself
should be a membership capability: admitting a device doesn't automatically let it
approve.

## Security

- **No approval without a person:** user verification on the approver is
  mandatory. A synthetic tap, an accessibility click or an agent on the approver
  can't answer, the same rule as "A finger approves, not a click" in
  agent-control.md.
- **Bound to the exact request:** the response signs the request hash. It can't
  be replayed for another command, another item or later.
- **No content in push payloads:** the push only wakes the device, and the
  request travels end to end between members.
- **Phishing and fatigue:** show the origin device and caller prominently, rate-
  limit requests per caller (the existing buckets), collapse repeats, and never
  let a request auto-approve. Consider number matching for high-risk requests
  (device admission, `read`): the origin shows two digits and the approver
  picks them.
- **A compromised member device** could approve anything it's shown. That's
  already within the vault's trust model (a member can read the vault), but
  approval as a separate capability limits it to devices you chose.
- **Offline origin:** if the origin goes away, the request dies with it.

## Open questions

1. Is the iOS app the first approver, or should the Mac app approve for exos
   first? The second needs no new app.
2. Push: Hark (already on Ryan's phone) as a stopgap, or our own APNs relay from
   the start?
3. Should an approval be able to create a standing grant ("allow for an hour"),
   or always be one-time?
4. Does the browser extension count as an approver, and for which requests?
5. Device admission over approval: replace typing the pairing code with "approve
   new device Chrome on Linux?" on your phone?

## Related

docs/agent-control.md (tiers, grants, Approving), docs/touch-id.md,
docs/extension-device.md (PRF unlock), docs/proposals/universal-signin.md.
